// Derived client-side: the run payload already carries the raw signals — the
// budget-skip markers collectors stamp into missing_data ("<name>.analysis_budget")
// and the artifact count. A run that ended with zero artifacts because the shared
// evidence budget expired must not present itself like a normal analysis.
export type EvidenceState = 'complete' | 'partial' | 'budget_exhausted' | null;

export function evidenceState(
  missingData: string[] | undefined,
  artifactCount: number,
): EvidenceState {
  const budgetSkips = (missingData ?? []).filter((item) =>
    item.endsWith('.analysis_budget'),
  ).length;
  if (artifactCount === 0) {
    return budgetSkips > 0 ? 'budget_exhausted' : null;
  }
  return budgetSkips > 0 ? 'partial' : 'complete';
}
