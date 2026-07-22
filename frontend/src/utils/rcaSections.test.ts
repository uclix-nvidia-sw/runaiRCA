import { describe, expect, it } from 'vitest';

import { formatEvidenceQueries, splitRcaReport, stripAppendixEvidence } from './rcaSections';

describe('splitRcaReport', () => {
  it('splits on ## outside fences, keeps ### inside sections, flags pinned/open', () => {
    const md = [
      '# Incident Analysis Report — GPUDown', '', 'Fired: t · Severity: critical', '',
      '## 1. Problem', '', 'text', '',
      '## 4. Appendix', '', '### Evidence', '```', '## not a heading', '```',
      '## 추가 확인 요청', '', 'q1',
    ].join('\n');
    const { preamble, sections } = splitRcaReport(md);
    expect(preamble).toContain('# Incident Analysis Report');
    expect(sections.map((s) => s.heading)).toEqual(['1. Problem', '4. Appendix', '추가 확인 요청']);
    expect(sections[1].body).toContain('### Evidence');
    expect(sections[1].body).toContain('## not a heading');
    expect(sections.map((s) => s.pinned)).toEqual([true, false, false]);
    expect(sections.map((s) => s.defaultOpen)).toEqual([true, false, true]);
  });

  it('returns no sections for heading-less markdown (caller falls back to raw render)', () => {
    const { preamble, sections } = splitRcaReport('just a blob\nof text');
    expect(sections).toEqual([]);
    expect(preamble).toBe('just a blob\nof text');
  });
});

describe('formatEvidenceQueries', () => {
  it('moves the "via <query>" tail to a monospace continuation line', () => {
    const md = '- **loki**: matching lines present. via {namespace="runai"} |~ "oom"';
    expect(formatEvidenceQueries(md)).toBe(
      '- **loki**: matching lines present.  \n  `{namespace="runai"} |~ "oom"`',
    );
  });

  it('splits on the last via and leaves non-evidence lines alone', () => {
    expect(formatEvidenceQueries('via the proxy, traffic died')).toBe('via the proxy, traffic died');
    expect(formatEvidenceQueries('- **k8s**: reached via proxy. via kubectl get pods')).toBe(
      '- **k8s**: reached via proxy.  \n  `kubectl get pods`',
    );
  });
});

describe('stripAppendixEvidence', () => {
  it('removes only the appendix Evidence subsection and preserves Evidence Trace', () => {
    const md = [
      '## Appendix', '', '### Evidence', '', '- **kubernetes**: duplicated collector result',
      '```', '### not a real heading', '```', '', '### Investigation Plan', '', '- inspect pod',
      '', '## Evidence Trace', '', '- [E01] kubernetes: ImagePullBackOff',
    ].join('\n');

    const stripped = stripAppendixEvidence(md);

    expect(stripped).not.toContain('### Evidence\n');
    expect(stripped).not.toContain('duplicated collector result');
    expect(stripped).toContain('### Investigation Plan');
    expect(stripped).toContain('## Evidence Trace');
    expect(stripped).toContain('[E01] kubernetes: ImagePullBackOff');
  });

  it('also removes the Korean appendix evidence heading', () => {
    const md = '## 부록 (Appendix)\n\n### 증거 (Evidence)\n\n- 중복\n\n### 참고\n\n- 유지';
    expect(stripAppendixEvidence(md)).toBe('## 부록 (Appendix)\n\n### 참고\n\n- 유지');
  });
});
