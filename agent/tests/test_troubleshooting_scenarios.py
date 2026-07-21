from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import CollectorResult
from app.schemas import Alert, AlertAnalysisRequest, SimilarIncidentContext
from app.services import pipeline, self_check
from app.services.kg_enrichment import GraphRemediation
from app.services.orchestrator import AnalysisOrchestrator
from tests.test_orchestrator import make_settings

CONFIG = "configs/runai_rca_engine.yml"


class StaticCollector:
    def __init__(self, result: CollectorResult) -> None:
        self.result = result

    async def collect(self, _target, _plan=None) -> CollectorResult:
        return self.result


def _request(alertname: str, summary: str) -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": alertname, "namespace": "runai"},
            annotations={"summary": summary},
            fingerprint=f"fp-{alertname.lower()}",
        )
    )


def _top_family(response) -> str:
    top = response.context.get("top_root_cause") or {}
    return str(top.get("family") or "")


def _actions_section(response) -> str:
    start = response.analysis_detail.find("## 3. Recommended Actions")
    if start < 0:
        return ""
    end = response.analysis_detail.find("\n## Appendix", start)
    return response.analysis_detail[start : end if end >= 0 else len(response.analysis_detail)]


def _playbook_section(response) -> str:
    start = response.analysis_detail.find("### Troubleshooting Playbook")
    if start < 0:
        return ""
    end = response.analysis_detail.find("\n### ", start + 5)
    return response.analysis_detail[start : end if end >= 0 else len(response.analysis_detail)]


@pytest.mark.asyncio
async def test_refuted_known_issue_does_not_remain_headline(monkeypatch) -> None:
    issue = {
        "issue": "scheduler reclaim panic",
        "family": "platform_version_bug",
        "keywords": ["reclaim panic"],
        "reason": "synthetic keyword hit that verifier will refute",
        "actions": ["Upgrade Run:ai."],
    }

    monkeypatch.setattr(pipeline, "load_runai_known_issues", lambda _path: [issue])

    async def refute_issue(_settings, _issues, _results):
        return {"scheduler reclaim panic"}

    async def keep_other_matches(*_args, **_kwargs):
        return set()

    monkeypatch.setattr(self_check, "verify_known_issues", refute_issue)
    monkeypatch.setattr(self_check, "verify_matches", keep_other_matches)

    result = CollectorResult(
        agent="loki",
        status="ok",
        summary=(
            "runai-scheduler log contains the words reclaim panic, but the surrounding "
            "trace says the scheduler recovered and no known-version bug is supported"
        ),
        confidence="medium",
    )
    state = pipeline.new_state(
        make_settings(),
        _request("RunAISchedulerRestarting", "scheduler emitted reclaim panic text"),
        collectors=[StaticCollector(result)],
    )

    response = await pipeline.run_pipeline(state)

    assert _top_family(response) != "platform_version_bug"
    assert "Likely cause: Run:ai version bug" not in response.analysis_detail
    assert "Upgrade Run:ai." not in response.analysis_detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alertname", "summary", "expected"),
    [
        (
            "DistributedTrainingNCCLTimeout",
            "NCCL WARN unhandled system error; watchdog caught collective operation timeout",
            "network_fabric_error",
        ),
        (
            "PodDNSResolutionFailure",
            "Pods report temporary failure in name resolution and CoreDNS SERVFAIL",
            "cluster_network_error",
        ),
        (
            "VolumeMultiAttachFailure",
            "FailedAttachVolume: unable to attach or mount volumes; multi-attach error",
            "k8s_storage_error",
        ),
        (
            "KubePodImagePullBackOff",
            "ErrImagePull: dial tcp: lookup registry.airgap.local: no such host "
            "while pulling image",
            "image_pull_error",
        ),
        (
            "GpuPodSandboxFailure",
            'failed to create pod sandbox: no runtime for "nvidia" is configured; '
            "failed to get sandbox runtime",
            "gpu_hardware_error",
        ),
        (
            "KubePodImagePullBackOff",
            "Traceback torch.cuda.OutOfMemoryError: CUDA out of memory while allocating tensor",
            "workload_runtime_error",
        ),
        (
            "RunAIWorkloadPending",
            "FailedScheduling 0/6 nodes had volume node affinity conflict for pvc data",
            "k8s_storage_error",
        ),
        (
            "RunAISchedulerRestarting",
            'failed to create pod sandbox: no runtime for "nvidia" is configured; '
            "failed to get sandbox runtime",
            "gpu_hardware_error",
        ),
        (
            "VolumeMultiAttachFailure",
            "SAML assertion missing AttributeStatement email; Entity ID mismatch",
            "platform_auth_error",
        ),
    ],
)
async def test_nat_and_direct_agree_on_new_troubleshooting_signatures(
    alertname: str, summary: str, expected: str
) -> None:
    request = _request(alertname, summary)
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        direct_response = await direct.analyze(request)
        nat_response = await nat.analyze(request)
    finally:
        await direct.close_engine()
        await nat.close_engine()

    assert _top_family(direct_response) == expected
    assert _top_family(nat_response) == expected
    assert bool(nat_response.analysis_summary.strip())
    assert bool(nat_response.analysis_detail.strip())


@pytest.mark.asyncio
async def test_nat_and_direct_keep_generic_noise_insufficient() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        for i, summary in enumerate(
            [
                "pod reported an error but recovered after retry",
                "dashboard loaded and no metrics are missing after refresh",
                "python exception was caught and training continued",
                "no runai-backend-workloads-manager is present after the upgrade; "
                "memory is stable",
                "imagepullbackoff 아님, pull 성공함",
                "cuda out of memory 없음, 메모리 안정적",
                "runai-backend-workloads-manager 아님, 메모리 안정적",
                "pod is running; quota is not exceeded; GPU quota has plenty available; "
                "no preemption",
                "scheduler is healthy; quota is not the issue; preemption was ruled out",
                "webhook is not implicated; admission requests succeeded",
                "runai-backend-workloads-manager unrelated; cache and memory normal",
                "웹훅 원인 아님, admission 성공",
                "imagepullbackoff resolved after registry credentials were refreshed; "
                "pod is running",
                "runai-backend-workloads-manager memory growth resolved after upgrade; "
                "cache normal",
                "webhook timeout 정상화, admission 성공",
                "previously imagepullbackoff was seen, but now the pod is running",
                "stale admission webhook timeout event; admission now succeeds",
                "과거 imagepullbackoff 이벤트, 현재 pod running",
                "cleared alert crashloopbackoff; restart count is zero",
                "resolved known issue runai-backend-workloads-manager memory growth "
                "after upgrade",
                "operator asked whether this is imagepullbackoff; no evidence yet",
                "hypothesis: quota preemption might be involved, needs evidence",
                "support case says runai-backend-workloads-manager memory growth can happen",
                'promql query kube_pod_container_status_waiting_reason{reason="ImagePullBackOff"} '
                "returned 0 series",
                'logql filter |~ "oomkilled|crashloopbackoff" returned no matching lines',
                "Node condition DiskPressure=False MemoryPressure=False PIDPressure=False",
                "pod status reason ImagePullBackOff=false ErrImagePull=false",
                "container lastState reason OOMKilled=false and restartCount=0",
                "0 ImagePullBackOff events in the selected window",
                "zero ErrImagePull pods found",
                "OOMKilled 컨테이너 0개",
                "PromQL absent("
                'kube_pod_container_status_waiting_reason{reason="ImagePullBackOff"}) '
                "== 1",
                "config key imagePullBackOffAlertEnabled is set to true",
                "metric name runai_preemption_victim_total is defined in rules",
                "환경변수 OOMKilledAlertEnabled=true",
                "catalog entry alertname=KubePodImagePullBackOff exists for docs only",
                "sample payload reason=OOMKilled shown in documentation",
                "prometheus rule expression has ImagePullBackOff but alert state inactive",
                "schema field lastState.reason can equal OOMKilled",
            ]
        ):
            request = _request(f"GenericNoise{i}", summary)
            direct_response = await direct.analyze(request)
            nat_response = await nat.analyze(request)
            assert _top_family(direct_response) == "insufficient_evidence"
            assert _top_family(nat_response) == "insufficient_evidence"
            assert (
                "Workloads Manager Memory Grows To Cache Cap"
                not in direct_response.analysis_detail
            )
            assert "Workloads Manager Memory Grows To Cache Cap" not in nat_response.analysis_detail
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alertname", "summary", "expected", "has_typed_support", "forbidden_actions"),
    [
        (
            "NVIDIA Run:ai Agent Cluster Info Push Rate Low",
            "Traceback torch.cuda.OutOfMemoryError: CUDA out of memory while allocating tensor",
            "workload_runtime_error",
            False,
            ("cluster-sync", "network connectivity between cluster and control plane"),
        ),
        (
            "NVIDIA Run:ai Project Controller Reconcile Failure",
            "ErrImagePull: dial tcp: lookup registry.airgap.local: no such host "
            "while pulling image",
            "image_pull_error",
            True,
            ("project-controller", "kubectl get project"),
        ),
    ],
)
async def test_misleading_alert_catalog_does_not_override_observed_failure(
    alertname: str,
    summary: str,
    expected: str,
    has_typed_support: bool,
    forbidden_actions: tuple[str, ...],
) -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request(alertname, summary)
        for response in (await direct.analyze(request), await nat.analyze(request)):
            actions = _actions_section(response)
            assert _top_family(response) == expected
            assert (
                "Not enough evidence for concrete actions yet" not in actions
            ) is has_typed_support
            for forbidden in forbidden_actions:
                assert forbidden not in actions
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_precise_signature_actions_do_not_include_unrelated_similar_fix() -> None:
    response = await AnalysisOrchestrator(make_settings()).analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "TrainingJobFailed", "namespace": "runai"},
                annotations={
                    "summary": "torch.cuda.OutOfMemoryError: CUDA out of memory "
                    "while allocating tensor"
                },
                fingerprint="fp-similar-noise",
            ),
            similar_incidents=[
                SimilarIncidentContext(
                    incident_id="INC-OLD",
                    similarity=0.99,
                    title="cluster-sync down",
                    analysis_summary=(
                        "Restart cluster-sync and check control-plane network connectivity"
                    ),
                )
            ],
        )
    )

    actions = _actions_section(response)
    assert _top_family(response) == "workload_runtime_error"
    assert "Not enough evidence for concrete actions yet" in actions
    assert "INC-OLD" not in actions
    assert "cluster-sync" not in actions
    assert "INC-OLD" in response.analysis_detail


@pytest.mark.asyncio
async def test_side_signal_from_other_family_does_not_pollute_image_pull_actions() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request(
            "ImagePullWithOldRuntimeNoise",
            "ErrImagePull: manifest unknown for trainer image; no container started, "
            "later dashboard mentioned cuda out of memory from old run",
        )
        for response in (await direct.analyze(request), await nat.analyze(request)):
            actions = _actions_section(response)
            playbook = _playbook_section(response)
            assert _top_family(response) == "image_pull_error"
            assert "image tag" in response.analysis_detail
            assert "Reduce batch size" not in actions
            assert "activation checkpointing" not in actions
            assert "CUDA Out Of Memory" not in playbook
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alertname", "summary", "forbidden_actions"),
    [
        (
            "Low Memory Node Alert",
            "node memory is stable; no memorypressure is present; "
            "no low memory condition observed",
            ("kubectl top node", "Resize the node"),
        ),
        (
            "NVIDIA Run:ai Container Memory Usage Critical",
            "container memory is stable; no out of memory; no high memory usage observed",
            ("Raise the container memory", "memory growth"),
        ),
    ],
)
async def test_insufficient_builtin_alert_does_not_emit_catalog_actions(
    alertname: str, summary: str, forbidden_actions: tuple[str, ...]
) -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request(alertname, summary)
        for response in (await direct.analyze(request), await nat.analyze(request)):
            actions = _actions_section(response)
            assert _top_family(response) == "insufficient_evidence"
            for forbidden in forbidden_actions:
                assert forbidden not in actions
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_insufficient_evidence_does_not_dump_full_troubleshooting_library() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request("GenericNoise", "pod reported an error but recovered after retry")
        for response in (await direct.analyze(request), await nat.analyze(request)):
            playbook = _playbook_section(response)
            assert _top_family(response) == "insufficient_evidence"
            assert "Specific playbook remediation is withheld" in playbook
            assert "Run:ai RCA Troubleshooting Cases" not in playbook
            assert "Queue Or Project GPU Saturation" not in playbook
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_negated_symptom_does_not_hide_separate_reclaim_signal() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request(
            "MixedNegatedAndReclaim",
            "no imagepullbackoff is present, but the workload was evicted so another "
            "project could use the gpus",
        )
        for response in (await direct.analyze(request), await nat.analyze(request)):
            assert _top_family(response) == "runai_scheduling_quota"
            assert "ImagePullBackOff" not in response.analysis_detail
            assert "another project" in response.analysis_detail
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_exact_signature_keeps_medium_confidence_when_ranker_family_agrees() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request("ImageManifest", "ErrImagePull: manifest for tag not found")
        for response in (await direct.analyze(request), await nat.analyze(request)):
            top = response.context.get("top_root_cause") or {}
            assert top.get("family") == "image_pull_error"
            assert top.get("confidence") == "medium"
            assert "signature" in (top.get("evidence_agents") or [])
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_admission_webhook_x509_is_not_registry_tls() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request(
            "AdmissionFailures",
            "failed calling webhook validate.run.ai: x509 certificate signed by unknown "
            "authority; apiserver admission webhook failing",
        )
        for response in (await direct.analyze(request), await nat.analyze(request)):
            actions = _actions_section(response)
            assert _top_family(response) == "k8s_control_plane_error"
            assert "Not enough evidence for concrete actions yet" in actions
            assert "registry's TLS certificate" not in actions
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_unrelated_similar_incident_stopwords_do_not_trigger_action() -> None:
    response = await AnalysisOrchestrator(make_settings()).analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "NCCLTimeout", "namespace": "runai"},
                annotations={
                    "summary": "NCCL WARN socket timeout and ibv_poll_cq failed during allreduce"
                },
                fingerprint="fp-similar-stopword",
            ),
            similar_incidents=[
                SimilarIncidentContext(
                    incident_id="INC-OLD",
                    similarity=0.98,
                    title="old Run:ai control-plane auth incident",
                    analysis_summary="restart cluster-sync and rotate SAML credentials",
                )
            ],
        )
    )

    actions = _actions_section(response)
    assert _top_family(response) == "network_fabric_error"
    assert "INC-OLD" not in actions
    assert "restart cluster-sync" not in actions


def test_negated_similar_tokens_do_not_make_prior_incident_relevant() -> None:
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "GenericHealthCheck", "namespace": "runai"},
            annotations={"summary": "no disk pressure observed; node has enough free space"},
        ),
        similar_incidents=[
            SimilarIncidentContext(
                incident_id="INC-DISK",
                similarity=0.98,
                title="node disk pressure",
                analysis_summary="drain node and clean kubelet imagefs",
            )
        ],
    )

    assert not pipeline._similar_incident_relevant(
        request, "no disk pressure observed; node has enough free space"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alertname", "summary", "expected", "similar", "forbidden_actions"),
    [
        (
            "TrainingRunFailed",
            "training run failed because NCCL allreduce timed out over ib fabric",
            "network_fabric_error",
            SimilarIncidentContext(
                incident_id="INC-RUNAI",
                similarity=0.97,
                title="Run:ai cluster-sync auth outage",
                analysis_summary="Restart cluster-sync and rotate SAML metadata",
            ),
            ("INC-RUNAI", "cluster-sync", "SAML"),
        ),
        (
            "GpuXid",
            "NVRM: Xid 79 GPU has fallen off the bus on node dgx-1",
            "gpu_hardware_error",
            SimilarIncidentContext(
                incident_id="INC-GPU",
                similarity=0.96,
                title="GPU quota backlog",
                analysis_summary="raise the queue quota after a fairshare backlog",
            ),
            ("INC-GPU", "raise the queue quota", "quota"),
        ),
    ],
)
async def test_generic_similar_tokens_do_not_pull_unrelated_actions(
    alertname: str,
    summary: str,
    expected: str,
    similar: SimilarIncidentContext,
    forbidden_actions: tuple[str, ...],
) -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": alertname, "namespace": "runai"},
                annotations={"summary": summary},
                fingerprint=f"fp-generic-similar-{alertname}",
            ),
            similar_incidents=[similar],
        )
        for response in (await direct.analyze(request), await nat.analyze(request)):
            actions = _actions_section(response)
            assert _top_family(response) == expected
            for forbidden in forbidden_actions:
                assert forbidden not in actions
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_control_plane_cert_expiry_is_not_registry_tls() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request(
            "KubeCertExpired",
            "kube-apiserver client certificate has expired; controller-manager "
            "cannot update lease",
        )
        for response in (await direct.analyze(request), await nat.analyze(request)):
            actions = _actions_section(response)
            assert _top_family(response) == "k8s_control_plane_error"
            assert "kubeadm certs" in response.analysis_detail
            assert "registry's TLS certificate" not in actions
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
async def test_insufficient_evidence_does_not_emit_fuzzy_failure_mode_actions() -> None:
    direct = AnalysisOrchestrator(replace(make_settings(), enable_nat_runtime=False))
    nat = AnalysisOrchestrator(
        replace(make_settings(), enable_nat_runtime=True, nat_config_file=CONFIG)
    )
    try:
        request = _request(
            "GenericRecovered",
            "pod logged a transient error; retry succeeded; no failed scheduling, "
            "no image pull failure, memory stable",
        )
        for response in (await direct.analyze(request), await nat.analyze(request)):
            actions = _actions_section(response)
            assert _top_family(response) == "insufficient_evidence"
            assert "Insufficient evidence" in response.analysis_detail
            assert "Unauthorized" not in actions
            assert "ImagePullBackOff" not in actions
    finally:
        await direct.close_engine()
        await nat.close_engine()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alertname", "summary", "expected_text", "forbidden_texts"),
    [
        (
            "GpuPodSandboxFailure",
            'failed to create pod sandbox: no runtime for "nvidia" is configured; '
            "failed to get sandbox runtime",
            "nvidia-container-toolkit",
            ("PLEG Not Healthy", "Pod Sandbox / CNI Failure"),
        ),
        (
            "TrainingJobFailed",
            "Traceback torch.cuda.OutOfMemoryError: CUDA out of memory while allocating tensor",
            "Reduce batch size",
            ("**OOMKilled**",),
        ),
        (
            "KubePodImagePullBackOff",
            "ErrImagePull: dial tcp: lookup registry.airgap.local: no such host "
            "while pulling image",
            "NODE can't resolve the registry hostname",
            ("Pod DNS Resolution Failure",),
        ),
    ],
)
async def test_unrelated_known_issues_do_not_pollute_precise_playbook(
    alertname: str, summary: str, expected_text: str, forbidden_texts: tuple[str, ...]
) -> None:
    response = await AnalysisOrchestrator(make_settings()).analyze(_request(alertname, summary))

    assert expected_text in response.analysis_detail
    for forbidden_text in forbidden_texts:
        assert forbidden_text not in response.analysis_detail
    assert "GPU Allocation Shows Zero On Dashboard" not in response.analysis_detail
    assert "Workloads Manager Memory Grows To Cache Cap" not in response.analysis_detail


@pytest.mark.asyncio
async def test_refuting_one_xid_keeps_other_supported_xids(monkeypatch) -> None:
    async def fake_graph_remediation(*_args, **_kwargs):
        return GraphRemediation(
            xid_fixes={45: ["do not use app-crash fix"], 74: ["reset the NVLink fabric"]},
            root_xids={45: [74]},
    )

    async def fake_verify_matches(_settings, candidates, _results, *, subject=""):
        xid_names = {
            candidate["name"] for candidate in candidates if candidate["name"].startswith("XID")
        }
        assert xid_names == {
            "XID 45",
            "XID 74",
        }
        return {"XID 45"}

    async def keep_known_issues(*_args, **_kwargs):
        return set()

    monkeypatch.setattr(pipeline, "graph_remediation", fake_graph_remediation)
    monkeypatch.setattr(self_check, "verify_matches", fake_verify_matches)
    monkeypatch.setattr(self_check, "verify_known_issues", keep_known_issues)

    response = await AnalysisOrchestrator(make_settings()).analyze(
        _request("NVRMXidCritical", "NVRM: Xid 45 followed by Xid 74 on gpu-0")
    )

    assert _top_family(response) == "gpu_hardware_error"
    # XID 74 remains an explicit, typed alert observation after XID 45 is
    # refuted, so its code-specific action is still evidence-backed.
    assert "Not enough evidence for concrete actions yet" not in response.analysis_detail
    assert "reset the NVLink fabric" in response.analysis_detail
    assert "do not use app-crash fix" not in response.analysis_detail
