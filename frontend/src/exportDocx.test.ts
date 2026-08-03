import { describe, expect, it } from 'vitest';
import { alertRows, artifactRows, markdownToBlocks, markdownToDocxElements, similarRows, summaryParagraphText } from './exportDocx';
import type { AlertRecord, Artifact, SimilarIncident } from './types';

describe('markdownToBlocks', () => {
  it('preserves inline formatting in the remark AST', () => {
    const blocks = markdownToBlocks([
      '**bold** *italic* `kubectl get pods` [runbook](https://example.com/runbook)',
    ].join('\n'));

    expect(blocks[0]).toMatchObject({ kind: 'paragraph' });
    expect((blocks[0] as { children: { type: string; value?: string; url?: string }[] }).children.map((node) => node.type)).toEqual([
      'strong',
      'text',
      'emphasis',
      'text',
      'inlineCode',
      'text',
      'link',
    ]);
    const inlineChildren = (blocks[0] as { children: { url?: string }[] }).children;
    expect(inlineChildren[inlineChildren.length - 1]?.url).toBe('https://example.com/runbook');
  });

  it('keeps GFM tables and nested ordered/bullet lists as structured blocks', () => {
    const blocks = markdownToBlocks([
      '1. investigate',
      '   - inspect quota',
      '     1. compare limits',
      '',
      '| key | value |',
      '| --- | --- |',
      '| queue | gpu-a |',
    ].join('\n'));

    const list = blocks[0];
    expect(list).toMatchObject({ kind: 'list', ordered: true });
    const nestedList = (list as Extract<typeof list, { kind: 'list' }>).children[0].children?.find((node) => node.type === 'list');
    expect(nestedList).toMatchObject({ type: 'list', ordered: false });
    expect(nestedList?.children?.[0].children?.find((node) => node.type === 'list')).toMatchObject({ type: 'list', ordered: true });
    const table = blocks[blocks.length - 1];
    expect(table?.kind).toBe('table');
    if (table?.kind === 'table') {
      expect(table.rows[0].children?.[0].children?.[0].value).toBe('key');
      expect(table.rows[0].children?.[1].children?.[0].value).toBe('value');
    }
  });

  it('keeps fenced code text and language', () => {
    expect(markdownToBlocks('```sh\nkubectl get pods\n--all-namespaces\n```')).toEqual([
      { kind: 'code', language: 'sh', text: 'kubectl get pods\n--all-namespaces' },
    ]);
  });

  it('renders a GFM table as a real docx Table', async () => {
    const docx = await import('docx');
    const elements = markdownToDocxElements(docx, '| key | value |\n| --- | --- |\n| queue | gpu-a |');

    expect(elements).toHaveLength(1);
    expect(elements[0]).toBeInstanceOf(docx.Table);
  });
});

// remark-gfm sets a list item's `checked` to `null` (not `undefined`) for an
// ordinary `- ` bullet, and to `true`/`false` only for a real `- [ ]` / `- [x]`
// GFM task-list item. renderList must tell these apart, not stamp every
// bullet with a checkbox marker.
describe('list checkbox markers', () => {
  it('does not prefix ordinary bullet items with a checkbox marker', async () => {
    const docx = await import('docx');
    const elements = markdownToDocxElements(docx, '- one\n- two');
    const serialized = JSON.stringify(elements);

    expect(serialized).not.toContain('[ ] ');
    expect(serialized).not.toContain('[x] ');
  });

  it('still prefixes real GFM task-list items with checkbox markers', async () => {
    const docx = await import('docx');
    const elements = markdownToDocxElements(docx, '- [ ] todo\n- [x] done');
    const serialized = JSON.stringify(elements);

    expect(serialized).toContain('[ ] ');
    expect(serialized).toContain('[x] ');
  });
});

// The exported Word document's own content is Korean by chart default; an
// English "No summary captured." placeholder in the same slot as the report
// content is what the product owner flagged reading the export (a
// mixed-language document). These placeholders must match the report, not
// stay hardcoded English with no language context.
describe('exported-document placeholders match the report language', () => {
  it('falls back to a Korean placeholder when analysis_summary is empty', () => {
    expect(summaryParagraphText('실제 요약입니다.')).toBe('실제 요약입니다.');
    expect(summaryParagraphText('')).toBe('요약이 생성되지 않았습니다.');
    expect(summaryParagraphText(undefined)).toBe('요약이 생성되지 않았습니다.');
  });

  it('artifactRows falls back to a Korean empty-state row, not an English one', () => {
    expect(artifactRows([])).toEqual([['-', '-', '수집된 증거 카드가 없습니다.']]);
    const artifact: Artifact = { agent: 'kubernetes', source: 'kubernetes', type: 'pod_status', confidence: 'medium', status: 'ok', summary: 'Pod is Running.' };
    expect(artifactRows([artifact])).toEqual([['kubernetes', 'ok', 'Pod is Running.']]);
  });

  it('alertRows falls back to a Korean empty-state row, not an English one', () => {
    expect(alertRows([])).toEqual([['-', '-', '수집된 알림이 없습니다.']]);
    const alert = { alert_id: 'ALT-1', status: 'firing', alarm_title: 'KubePodNotReady' } as AlertRecord;
    expect(alertRows([alert])).toEqual([['ALT-1', 'firing', 'KubePodNotReady']]);
  });

  it('similarRows falls back to a Korean empty-state row, not an English one', () => {
    expect(similarRows([])).toEqual([['-', '-', '유사한 과거 인시던트가 없습니다.']]);
    const similar = { incident_id: 'INC-1', similarity: 0.9, title: 'fallback title', analysis_summary: '' } as SimilarIncident;
    expect(similarRows([similar])).toEqual([['INC-1', '90%', 'fallback title']]);
  });
});
