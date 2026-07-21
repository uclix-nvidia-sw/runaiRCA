import { describe, expect, it } from 'vitest';

import { parseCorrectionActions } from './operatorCorrection';

describe('parseCorrectionActions', () => {
  it('splits non-empty, trimmed actions by line', () => {
    expect(parseCorrectionActions(' Drain node \r\n\nReplace GPU\n ')).toEqual([
      'Drain node',
      'Replace GPU',
    ]);
  });
});
