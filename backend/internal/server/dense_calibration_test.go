package server

import (
	"math"
	"testing"
)

// anisotropicCorpus builds embeddings the way a real model produces them: a large
// component every document shares, plus a small one that actually distinguishes
// them. That shared mass is what makes raw cosine sit in a narrow band and puts
// a MEANINGLESS query -- which has no direction of its own, so it lands on the
// shared component -- closest to everything.
func anisotropicVector(dim int, pairs ...float64) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = 1 // the shared component every document carries
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		if index := int(pairs[i]); index >= 0 && index < dim {
			v[index] += float32(pairs[i+1])
		}
	}
	return v
}

func centroidOf(vectors [][]float32) []float32 {
	if len(vectors) == 0 {
		return nil
	}
	out := make([]float32, len(vectors[0]))
	for _, v := range vectors {
		for i := range v {
			out[i] += v[i]
		}
	}
	for i := range out {
		out[i] /= float32(len(vectors))
	}
	return out
}

func TestDenseScoreCalibrationGivesRawCosineAUsableRange(t *testing.T) {
	const dim = 64
	docs := map[string][]float32{
		"gpu-hardware":   anisotropicVector(dim, 0, 0.6, 10, 0.8),
		"oomkilled":      anisotropicVector(dim, 1, 0.6),
		"missing-config": anisotropicVector(dim, 2, 0.6),
		"missing-secret": anisotropicVector(dim, 3, 0.6),
		"gpu-shortage":   anisotropicVector(dim, 4, 0.6),
	}
	corpus := make([][]float32, 0, len(docs))
	for _, v := range docs {
		corpus = append(corpus, v)
	}
	centroid := centroidOf(corpus)

	// A query about the GPU incident, and one that means nothing at all. The
	// meaningless one has no direction of its own, so it sits on the component
	// every document shares -- which is why it is close to all of them.
	domain := anisotropicVector(dim, 0, 0.6, 10, 1.0)
	gibberish := anisotropicVector(dim)

	top := func(q []float32, calibrated bool) (string, float64) {
		queryToCentroid := cosineFloat32(q, centroid)
		bestName, best := "", -1.0
		for name, v := range docs {
			score := cosineFloat32(q, v)
			if calibrated {
				score = calibrateDenseScore(score, queryToCentroid)
			}
			if score > best {
				bestName, best = name, score
			}
		}
		return bestName, best
	}

	// The disease: raw cosine cannot tell a precise query from a meaningless one.
	// Live, an XID-48 incident's neighbours came back 0.933 / 0.932 / 0.931 --
	// an OOMKilled, a missing ConfigMap and a missing Secret inside 0.002.
	_, rawDomain := top(domain, false)
	_, rawGibberish := top(gibberish, false)
	if rawDomain-rawGibberish > 0.01 {
		t.Fatalf("fixture is not anisotropic enough to be worth testing: "+
			"raw domain %.4f vs gibberish %.4f", rawDomain, rawGibberish)
	}

	// Calibrated, the same two queries are finally distinguishable.
	domainName, calDomain := top(domain, true)
	_, calGibberish := top(gibberish, true)
	if domainName != "gpu-hardware" {
		t.Fatalf("expected the GPU incident to rank first, got %q", domainName)
	}
	if calDomain-calGibberish < 0.5 {
		t.Fatalf("calibration left no usable range: domain %.4f, gibberish %.4f",
			calDomain, calGibberish)
	}
	if calGibberish > 0.05 {
		t.Fatalf("a query that means nothing must not look like a match: %.4f", calGibberish)
	}

	// And the match must separate from the unrelated incidents, not sit a hair away.
	queryToCentroid := cosineFloat32(domain, centroid)
	noise := calibrateDenseScore(cosineFloat32(domain, docs["missing-secret"]), queryToCentroid)
	if calDomain-noise < 0.5 {
		t.Fatalf("calibrated match is still indistinguishable from noise: %.4f vs %.4f",
			calDomain, noise)
	}
	t.Logf("raw: domain=%.4f gibberish=%.4f (gap %.4f) | calibrated: domain=%.4f gibberish=%.4f noise=%.4f",
		rawDomain, rawGibberish, rawDomain-rawGibberish, calDomain, calGibberish, noise)
}

// A corpus with nothing on the query's topic must not manufacture a match: this
// is the XID-48 case, where the neighbours returned were an OOMKilled, a missing
// ConfigMap and a missing Secret, all above 0.93.
func TestDenseScoreCalibrationReportsNoMatchWhenTheCorpusHasNone(t *testing.T) {
	const dim = 64
	docs := [][]float32{
		anisotropicVector(dim, 1, 0.6),
		anisotropicVector(dim, 2, 0.6),
		anisotropicVector(dim, 3, 0.6),
	}
	centroid := centroidOf(docs)
	offTopic := anisotropicVector(dim, 40, 1.0)
	queryToCentroid := cosineFloat32(offTopic, centroid)

	for _, doc := range docs {
		raw := cosineFloat32(offTopic, doc)
		calibrated := calibrateDenseScore(raw, queryToCentroid)
		if raw < 0.9 {
			t.Fatalf("fixture should still show the anisotropic raw score, got %.4f", raw)
		}
		if calibrated > 0.05 {
			t.Fatalf("an off-topic corpus must not produce a match: raw %.4f -> %.4f",
				raw, calibrated)
		}
	}
}

func TestCalibrateDenseScoreLeavesScoresAloneWithoutACentroid(t *testing.T) {
	// No corpus, an unsupported avg(vector), or a degenerate query: report what
	// the index produced rather than guessing at a correction.
	for _, qc := range []float64{0, -0.2, 1, 1.5} {
		if got := calibrateDenseScore(0.42, qc); got != 0.42 {
			t.Fatalf("queryToCentroid=%v should pass the raw score through, got %v", qc, got)
		}
	}
	if got := calibrateDenseScore(0.10, 0.90); got != 0 {
		t.Fatalf("a candidate no better than an arbitrary document must floor at 0, got %v", got)
	}
	if got := calibrateDenseScore(1.0, 0.5); math.Abs(got-1) > 1e-9 {
		t.Fatalf("an identical document must stay at 1, got %v", got)
	}
}
