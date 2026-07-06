import { describe, expect, it } from 'vitest';
import { markdownToBlocks } from './exportDocx';

describe('markdownToBlocks', () => {
  it('maps headings lists tables and code', () => {
    const blocks = markdownToBlocks([
      '## Root Cause',
      '',
      '- quota exhausted',
      '',
      '| key | value |',
      '| --- | --- |',
      '| queue | gpu-a |',
      '',
      '```sh',
      'kubectl get pods',
      '```',
    ].join('\n'));

    expect(blocks).toEqual([
      { kind: 'heading', level: 2, text: 'Root Cause' },
      { kind: 'listItem', text: 'quota exhausted' },
      { kind: 'tableRow', text: 'key | value' },
      { kind: 'tableRow', text: 'queue | gpu-a' },
      { kind: 'code', text: 'kubectl get pods' },
    ]);
  });
});
