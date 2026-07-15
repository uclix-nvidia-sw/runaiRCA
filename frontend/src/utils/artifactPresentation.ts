import type { Artifact } from '../types';

type PresentedArtifact = Pick<Artifact, 'summary' | 'result'>;

const EXEC_WEBSOCKET_403 = /WSServerHandshakeError[\s\S]*?\b403\b/i;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function isExecWebsocket403(value: unknown): boolean {
  return EXEC_WEBSOCKET_403.test(stringValue(value));
}

/**
 * Keep pod-exec failures actionable without printing the same Kubernetes
 * WebSocket URL (including its long command query string) once per probe.
 * This changes presentation only; the stored artifact remains untouched.
 */
export function artifactForPresentation(artifact: Artifact): PresentedArtifact {
  if (artifact.type !== 'pod_exec') {
    return { summary: artifact.summary, result: artifact.result };
  }

  const result = isPlainObject(artifact.result) ? artifact.result : undefined;
  const probes = result && Array.isArray(result.probes) ? result.probes : [];
  const failedExecProbes = probes.filter(
    (probe) => isPlainObject(probe) && isExecWebsocket403(probe.error),
  );
  const summaryHasExec403 = isExecWebsocket403(artifact.summary);

  if (failedExecProbes.length === 0 && !summaryHasExec403) {
    return { summary: artifact.summary, result: artifact.result };
  }

  const failedCount = failedExecProbes.length || 1;
  const summary =
    `컨테이너 읽기 전용 exec ${failedCount}개가 HTTP 403으로 거부되었습니다 ` +
    '(WSServerHandshakeError). ServiceAccount의 pods/exec RBAC 또는 ' +
    'Kubernetes API 프록시의 exec WebSocket 허용 여부를 확인하세요.';

  if (!result || probes.length === 0) {
    return { summary, result: artifact.result };
  }

  const presentedProbes = probes.map((probe) => {
    if (!isPlainObject(probe) || !isExecWebsocket403(probe.error)) return probe;
    const { error: _rawError, ...details } = probe;
    return {
      ...details,
      status: 'failed',
      error: 'HTTP 403 exec WebSocket access denied (see failure_summary)',
    };
  });

  return {
    summary,
    result: {
      ...result,
      probes: presentedProbes,
      failure_summary: {
        failed_probes: failedCount,
        status_code: 403,
        error: 'WSServerHandshakeError: Kubernetes exec WebSocket access denied',
        diagnostic: 'Check ServiceAccount pods/exec RBAC and API proxy WebSocket authorization.',
      },
    },
  };
}
