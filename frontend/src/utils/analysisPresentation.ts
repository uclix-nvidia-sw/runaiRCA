export type CollectorEvidencePresentationInput = {
  isAnalyzing: boolean;
  runStatus?: string;
  firstCompletedAt?: string;
  artifactCount: number;
};

// Global collector summaries have no per-card provenance banner. Only a
// completed run can safely contribute artifacts there; analyzing runs retain
// the previous result, while failed runs can contain either retained or partial
// artifacts.
export function shouldPresentRunArtifacts(runStatus: string) {
  return runStatus === 'complete';
}

export function collectorEvidencePresentation({
  isAnalyzing,
  runStatus,
  firstCompletedAt,
  artifactCount,
}: CollectorEvidencePresentationInput) {
  if (isAnalyzing) {
    return {
      hidden: true,
      notice: 'Analyzing… previous collector evidence is hidden until the current run completes.',
    };
  }
  if (runStatus === 'failed' && artifactCount > 0) {
    return {
      hidden: false,
      notice: firstCompletedAt
        ? 'The latest analysis attempt failed. The evidence below is the last completed result.'
        : 'The analysis failed. The evidence below is partial evidence from the failed attempt.',
    };
  }
  return { hidden: false, notice: '' };
}
