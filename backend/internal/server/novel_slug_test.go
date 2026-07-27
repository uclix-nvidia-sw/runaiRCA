package server

import "testing"

// Pinned against the agent's Python implementation
// (app/services/root_cause_ranking.novel_family_slug). Both paths mint novel
// families — the agent from an LLM mechanism, the backend from an operator's
// RCA correction — and the fingerprint is the dedup key, so a divergence would
// silently create two families for one mechanism. Expected values produced by
// running the Python function; regenerate the same way if it ever changes.
func TestNovelFamilySlugMatchesThePythonImplementation(t *testing.T) {
	for _, test := range []struct {
		mechanism   string
		family      string
		fingerprint string
	}{
		{"ConfigMap race on startup", "novel_configmap_race_on_startup_f1b5a4d1", "f1b5a4d1"},
		// Non-ASCII collapses to the "mechanism" slug but keeps a distinct
		// fingerprint (the fingerprint hashes the UNICODE canonical form).
		{"설정맵 경합", "novel_mechanism_e45aee04", "e45aee04"},
		// Whitespace runs collapse before hashing.
		{"Thanos Receive OOMKilled  repeatedly", "novel_thanos_receive_oomkilled_repeatedly_68623ae3", "68623ae3"},
		{"GPU  fell   off the BUS", "novel_gpu_fell_off_the_bus_48d50b3e", "48d50b3e"},
		// Full Unicode casefold: ß -> ss (strings.ToLower would NOT do this).
		{"ß straße", "novel_ss_strasse_2a851b9c", "2a851b9c"},
		{"", "novel_mechanism_e3b0c442", "e3b0c442"},
	} {
		family, fingerprint := novelFamilySlug(test.mechanism)
		if family != test.family || fingerprint != test.fingerprint {
			t.Errorf("novelFamilySlug(%q) = (%q, %q), want (%q, %q)",
				test.mechanism, family, fingerprint, test.family, test.fingerprint)
		}
	}
}

func TestNovelFamilySlugIsBoundedAndStable(t *testing.T) {
	long := ""
	for i := 0; i < 60; i++ {
		long += "verylongmechanism "
	}
	family, fingerprint := novelFamilySlug(long)
	if len(family) > 64 {
		t.Fatalf("family exceeds the 64-char cap: %d (%q)", len(family), family)
	}
	if len(fingerprint) != 8 {
		t.Fatalf("fingerprint must be 8 hex chars, got %q", fingerprint)
	}
	// Same input, same output — the operator may retype the identical cause.
	again, _ := novelFamilySlug(long)
	if again != family {
		t.Fatalf("slug is not deterministic: %q vs %q", family, again)
	}
}
