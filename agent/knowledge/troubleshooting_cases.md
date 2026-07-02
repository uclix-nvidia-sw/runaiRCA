# Run:ai RCA Troubleshooting Cases

Use these cases as operator memory, not as proof. Match them against live
Run:ai, Kubernetes, Prometheus, and Loki evidence before naming a root cause.

## Run:ai Control Plane Or Backend Log Review

Signals:
- User workload is pending, stuck, or suddenly unschedulable.
- Workload pod events are sparse, but Run:ai queue/project state looks wrong.
- Multiple workloads are affected across a project or queue.

Evidence to collect:
- Loki error logs from namespaces `runai` and `runai-backend`.
- Kubernetes warning events in the affected workload namespace.
- Run:ai workload, project, and queue API state.
- Prometheus queue/project GPU request and allocation metrics.

Common interpretation:
- If workload events show scheduling delay and Run:ai backend logs show queue,
  quota, scheduler, admission, or database errors at the same time, treat the
  control-plane symptom as a strong contributing factor.
- If only application pod logs show failures and Run:ai backend logs are quiet,
  keep focus on workload image, startup, dependency, or resource configuration.

Recommended actions:
- Inspect recent Run:ai backend errors around the alert window.
- Compare Run:ai queue/project quota with requested GPU count.
- Check whether several workloads in the same queue changed state together.
- Escalate to Run:ai platform owners when backend namespace logs contain repeated
  scheduler, authorization, database, or reconciliation errors.

## Queue Or Project GPU Saturation

Signals:
- Pending workload with project and queue labels present.
- Prometheus shows requested GPUs near or above allocated/available GPUs.
- Kubernetes pod has no application-level crash evidence.

Evidence to collect:
- Run:ai project and queue API response.
- `runai_queue_requested_gpus`, `runai_queue_allocated_gpus`, and project GPU
  metrics if available.
- Pod scheduling events for insufficient resources, quota, or preemption.

Recommended actions:
- Confirm queue quota and project limits.
- Check whether higher-priority workloads are consuming the allocation.
- Review whether the workload request changed recently.

## Workload Startup Or Image Failure

Signals:
- Kubernetes pod is created but container status is waiting or terminated.
- Loki workload logs contain image pull, crash, import, dependency, or permission
  errors.
- Run:ai queue/project state looks healthy.

Evidence to collect:
- Pod `containerStatuses`, restart count, waiting reason, and last termination.
- Warning events for image pull, backoff, or failed mounts.
- Loki error logs for the workload pod.

Recommended actions:
- Check image tag, registry credentials, entrypoint, mounted secrets, and PVCs.
- Compare with the previous successful workload revision when available.

## Node Or Kubelet Pressure

Signals:
- Affected pod is bound to a node, then evicted or repeatedly restarted.
- Node conditions show memory, disk, PID, network, or GPU device pressure.
- Multiple unrelated workloads on the same node alert together.

Evidence to collect:
- Kubernetes node conditions and allocatable resources.
- Pod events mentioning eviction, pressure, device plugin, or kubelet errors.
- Prometheus node and container resource metrics around the alert window.

Recommended actions:
- Drain or isolate the node if multiple workloads are affected.
- Check GPU device plugin and kubelet logs outside this app if node evidence is
  strong.

## Run:ai Operational Notes (config & expected behavior)

Signature-matched known issues (version regressions, observability quirks,
expected behaviors) live in `runai_known_issues.yaml` and surface automatically.
These are operator FAQ items with no single error signature to key on:

Node Pool structure:
- Every Kubernetes node joins the Default node pool, so Master/Ingress/Mgmt nodes
  appear there too; split by node Label into e.g. default(cpu) + training pools
  (~10 min once nodes and labels are chosen).
- A node belongs to exactly one node pool. Node Pool Label Value takes a single
  value (no comma-separated multi-value).
- Quota flows Department -> Project: set per-node-pool GPU quota on the Department,
  then split it across Projects. One node pool can be shared by multiple
  Departments/Projects via their quotas.

Distributed Training restart/backoff (see the known-issue entry for detail):
- Only the Worker backoffLimit is used; restart count is Master+Worker summed;
  restartPolicy Always behaves like OnFailure (completions=1 Job).
