import { describe, expect, it } from 'vitest';

import { manualChunks } from './buildChunks';

/**
 * Naming a chunk in manualChunks overrides Rollup's code splitting, so a
 * dependency reached only through `await import(...)` gets pulled into the
 * eager vendor chunk and the dynamic import buys nothing. That is not visible
 * in tsc, lint, or the unit tests — exportDocx.ts has read as lazy the whole
 * time while docx shipped to every visitor on first paint (239 kB gzip of
 * vendor, of which docx was 119 kB).
 */
describe('vite manual chunking', () => {
  it('leaves dynamic-import-only dependencies out of the eager vendor chunk', () => {
    expect(manualChunks('/repo/frontend/node_modules/docx/build/index.js')).toBeUndefined();
  });

  it('still groups the statically imported vendors it is there to group', () => {
    expect(manualChunks('/repo/frontend/node_modules/recharts/es6/chart/LineChart.js')).toBe('vendor-charts');
    expect(manualChunks('/repo/frontend/node_modules/d3-scale/src/band.js')).toBe('vendor-charts');
    expect(manualChunks('/repo/frontend/node_modules/react-markdown/index.js')).toBe('vendor-markdown');
    expect(manualChunks('/repo/frontend/node_modules/react-dom/client.js')).toBe('vendor');
  });

  it('does not chunk first-party source', () => {
    expect(manualChunks('/repo/frontend/src/AppRoot.tsx')).toBeUndefined();
  });
});
