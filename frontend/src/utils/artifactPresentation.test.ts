import { describe, expect, it } from 'vitest';

import type { Artifact } from '../types';
import { artifactForPresentation } from './artifactPresentation';

const websocketError = (command: string) =>
  `exec failed: WSServerHandshakeError: 403, message='Invalid response status', ` +
  `url='wss://kubernetes.default.svc/api/v1/namespaces/runai-test/pods/test-pod/exec?command=${command}&stdout=true'`;

function podExecArtifact(): Artifact {
  const probes = ['free', 'df', 'nvidia-smi'].map((command) => ({
    namespace: 'runai-test',
    pod: 'test-pod',
    command: [command, '-h'],
    error: websocketError(command),
  }));
  return {
    agent: 'kubernetes',
    source: 'kubernetes',
    type: 'pod_exec',
    status: 'partial',
    confidence: 'medium',
    summary: probes.map((probe) => probe.error).join('; '),
    result: { probes, observation: { polarity: 'unknown', coverage: 'partial' } },
  };
}

describe('artifactForPresentation', () => {
  it('collapses repeated pod exec websocket URLs into one actionable 403 diagnosis', () => {
    const presented = artifactForPresentation(podExecArtifact());
    const rendered = JSON.stringify(presented);

    expect(presented.summary).toContain('exec 3개');
    expect(presented.summary).toContain('HTTP 403');
    expect(presented.summary).toContain('pods/exec RBAC');
    expect(presented.summary).toContain('API 프록시');
    expect(rendered).not.toContain('wss://');
    expect(rendered.match(/WSServerHandshakeError/g)).toHaveLength(2);
  });

  it('keeps probe identity and commands after compacting the repeated failure', () => {
    const result = artifactForPresentation(podExecArtifact()).result as {
      probes: Array<Record<string, unknown>>;
      failure_summary: Record<string, unknown>;
    };

    expect(result.probes).toHaveLength(3);
    expect(result.probes[2]).toMatchObject({
      namespace: 'runai-test',
      pod: 'test-pod',
      command: ['nvidia-smi', '-h'],
      status: 'failed',
    });
    expect(result.failure_summary).toMatchObject({ failed_probes: 3, status_code: 403 });
  });

  it('does not rewrite unrelated artifacts or non-websocket exec errors', () => {
    const unrelated: Artifact = {
      ...podExecArtifact(),
      type: 'pod_inspection',
    };
    expect(artifactForPresentation(unrelated)).toEqual({
      summary: unrelated.summary,
      result: unrelated.result,
    });

    const exec = podExecArtifact();
    exec.summary = 'pod exec is disabled';
    exec.result = { probes: [{ error: 'pod exec is disabled' }] };
    expect(artifactForPresentation(exec)).toEqual({ summary: exec.summary, result: exec.result });
  });
});
