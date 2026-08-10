/**
 * Rollup manual-chunk assignment, kept out of vite.config.ts so it can be
 * tested without pulling the vite config into the app's type-check scope.
 *
 * Naming a chunk here OVERRIDES code splitting, so a dependency that is only
 * ever reached through `await import(...)` must be left unnamed or it lands in
 * the eager vendor chunk and the dynamic import buys nothing. exportDocx.ts
 * imports docx that way, and docx was shipping to every visitor on first paint
 * — 119 kB gzip of a 239 kB vendor chunk, for a Word export most sessions
 * never trigger.
 */
export function manualChunks(id: string): string | undefined {
  if (!id.includes('node_modules')) return undefined;
  if (id.includes('/docx/')) return undefined;
  if (id.includes('/recharts/') || id.includes('/d3-')) return 'vendor-charts';
  if (id.includes('/react-markdown/') || id.includes('/remark-') || id.includes('/unified/')) {
    return 'vendor-markdown';
  }
  return 'vendor';
}
