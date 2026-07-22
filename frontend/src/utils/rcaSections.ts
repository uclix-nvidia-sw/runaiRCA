// ponytail: line-based "## " splitter — this markdown is machine-generated
// (agent/app/services/pipeline.py _HEADINGS), no full remark parse needed on screen.
export type RcaSection = { heading: string; body: string; pinned: boolean; defaultOpen: boolean };

// Pinned = the core RCA an operator reads at a glance (Problem/Root Cause/Actions,
// EN and KO both start "1."/"2."/"3."). Rendered always-open, no toggle.
const PINNED = /^[1-3]\./;
// Of the collapsible rest, only the operator questions open by default.
const OPEN_BY_DEFAULT = /^(Questions for the Operator|추가 확인 요청)/;

const APPENDIX_HEADING = /^(?:\d+\.\s*)?(?:appendix|부록(?:\s*\(appendix\))?)$/i;
const EVIDENCE_HEADING = /^(?:evidence|증거(?:\s*\(evidence\))?)$/i;

// Older stored reports may still contain a collector dump under Appendix.
// Evidence Trace is the single citable report-level view; raw artifacts remain
// available in Collector Evidence Trail, so hide only the duplicated appendix
// subsection without touching either of those sources.
export function stripAppendixEvidence(markdown: string): string {
  const kept: string[] = [];
  let inAppendix = false;
  let dropping = false;
  let inFence = false;

  for (const line of markdown.split('\n')) {
    const stripped = line.trim();
    if (!inFence && line.startsWith('## ')) {
      inAppendix = APPENDIX_HEADING.test(line.slice(3).trim());
      dropping = false;
    } else if (!inFence && inAppendix && line.startsWith('### ')) {
      dropping = EVIDENCE_HEADING.test(line.slice(4).trim());
      if (dropping) continue;
    }

    if (!dropping) kept.push(line);
    if (stripped.startsWith('```')) inFence = !inFence;
  }

  return kept.join('\n').trim();
}

export function splitRcaReport(markdown: string): { preamble: string; sections: RcaSection[] } {
  const preamble: string[] = [];
  const sections: Array<{ heading: string; lines: string[]; pinned: boolean; defaultOpen: boolean }> = [];
  let inFence = false;
  for (const line of markdown.split('\n')) {
    if (line.trimStart().startsWith('```')) inFence = !inFence;
    if (!inFence && line.startsWith('## ')) {
      const heading = line.slice(3).trim();
      const pinned = PINNED.test(heading);
      sections.push({ heading, lines: [], pinned, defaultOpen: pinned || OPEN_BY_DEFAULT.test(heading) });
    } else if (sections.length > 0) {
      sections[sections.length - 1].lines.push(line);
    } else {
      preamble.push(line);
    }
  }
  return {
    preamble: preamble.join('\n'),
    sections: sections.map(({ heading, lines, pinned, defaultOpen }) => ({
      heading,
      body: lines.join('\n'),
      pinned,
      defaultOpen,
    })),
  };
}

// Evidence bullets are machine-generated as "- **agent**: finding via <query>"
// (pipeline.py _artifact_evidence_line). The <query> is a raw loki/kubectl/param
// string; inline in prose it reads as noise. Drop it to its own monospace line
// so the finding stays scannable.
// ponytail: greedy up to the LAST " via " — the query separator is always last;
// not fence-aware, but evidence bullets never appear inside code fences.
export function formatEvidenceQueries(markdown: string): string {
  return markdown.replace(
    /^(\s*[-*]\s+\*\*[^*]+\*\*:.*)\s+via\s+(\S.*)$/gm,
    (_m, head, query) => `${head}  \n  \`${query.replace(/`/g, "'")}\``,
  );
}
