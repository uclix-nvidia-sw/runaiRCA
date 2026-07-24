import { describe, expect, it } from 'vitest';
import { markdownToBlocks, markdownToDocxElements } from './exportDocx';

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
