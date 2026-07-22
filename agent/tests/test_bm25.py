from __future__ import annotations

from app.bm25 import BM25Index, tokenize
from app.knowledge import (
    load_failure_modes,
    load_runai_known_issues,
    match_failure_mode_symptoms,
    match_runai_known_issues,
)

FAILURE_MODES = "knowledge/failure_modes.yaml"
KNOWN_ISSUES = "knowledge/runai_known_issues.yaml"


def test_tokenize_drops_stopwords_and_noise() -> None:
    assert tokenize("The pod is OOMKilled!") == ["pod", "oomkilled"]
    assert tokenize("") == []


def test_single_generic_shared_token_is_never_a_match() -> None:
    # "workload" appears in both docs (df/N too high for the signature rule and
    # only one query token hits) — one common word must not produce a match.
    index = BM25Index(
        [
            ("a", "workload crashloopbackoff restart"),
            ("b", "workload disk pressure kubelet"),
            ("c", "gang podgroup scheduling"),
        ]
    )
    assert index.search("some unrelated workload text") == []


def test_synonyms_bridge_vocabulary() -> None:
    # "evicted" reaches the preemption doc through the domain synonym group,
    # and the matched terms are signature-grade (df=1, long) — single hit is enough.
    index = BM25Index(
        [
            ("preempt", "preempted higher priority preemption victim preemptor"),
            ("quota", "over quota contention overquota exceeded"),
            ("image", "imagepullbackoff registry manifest"),
            ("probe", "startup probe failed unhealthy"),
            ("nfs", "nfs server unresponsive stale mount"),
        ]
    )
    hits = index.search("the training job was evicted by the scheduler")
    assert [key for key, _ in hits] == ["preempt"]


def test_empty_index_and_empty_query() -> None:
    assert BM25Index([]).search("anything") == []
    assert BM25Index([("a", "text")]).search("") == []


def test_failure_mode_fuzzy_fallback_recovers_paraphrase() -> None:
    # No curated keyword substring-matches this alert text (no bare "evicted"
    # keyword; "preempted by higher priority" etc. all miss), so the substring
    # layer returns nothing — the synonym group (evicted→preempt/reclaim) must
    # surface the scheduling symptoms, tagged as fuzzy.
    fm = load_failure_modes(FAILURE_MODES)
    text = "workload evicted by the scheduler after a priority shuffle"
    matches = match_failure_mode_symptoms(fm, text, "", fuzzy_query=text)
    assert matches, "fuzzy fallback found nothing"
    families = {family for family, _ in matches}
    assert "runai_scheduling_quota" in families
    assert all(sym.get("matched_via") == "bm25" for _, sym in matches)


def test_failure_mode_fuzzy_does_not_promote_generic_workload_words() -> None:
    fm = load_failure_modes(FAILURE_MODES)

    crash = match_failure_mode_symptoms(
        fm,
        "python process crashed with a traceback after loading data",
        "",
        fuzzy_query="python process crashed with a traceback after loading data",
    )
    assert any(sym["symptom"] == "Application Crash / Traceback" for _, sym in crash)
    assert not any(sym["symptom"] == "CrashLoopBackOff" for _, sym in crash)
    assert not any(sym["symptom"] == "Illegal Workload Crashing Controllers" for _, sym in crash)

    pending = match_failure_mode_symptoms(
        fm,
        "pod remains unscheduled because no suitable gpu node can host it",
        "",
        fuzzy_query="pod remains unscheduled because no suitable gpu node can host it",
    )
    assert any(sym["symptom"] == "Unschedulable GPU" for _, sym in pending)
    assert not any(sym["symptom"] == "Illegal Workload Crashing Controllers" for _, sym in pending)

    readonly = match_failure_mode_symptoms(
        fm,
        "kernel reports ext4 errors and remounted the filesystem read-only",
        "",
        fuzzy_query="kernel reports ext4 errors and remounted the filesystem read-only",
    )
    assert any(sym["symptom"] == "Node Filesystem Read-Only" for _, sym in readonly)
    assert not any(sym["symptom"] == "Volume Attach/Mount Failure" for _, sym in readonly)
    assert not any(
        sym["symptom"] == "Volume Expansion Failed / Orphaned Pod Volume Dir"
        for _, sym in readonly
    )


def test_failure_mode_fuzzy_ignores_generic_log_language() -> None:
    fm = load_failure_modes(FAILURE_MODES)
    for text in [
        "pod reported an error but recovered after retry",
        "job failed for an unknown reason with no platform signal",
        "workload logs mention storage and network during startup banner",
        "application printed filesystem path /mnt/data/output.txt then exited zero",
        "user deleted old experiment after successful completion",
        "python exception was caught and training continued",
    ]:
        assert match_failure_mode_symptoms(fm, text, "", fuzzy_query=text) == []


def test_fuzzy_is_off_without_a_fuzzy_query() -> None:
    # Callers that don't pass the alert text keep the exact pre-BM25 behaviour —
    # collector summaries must never be fuzzy-matched (their status boilerplate,
    # e.g. "service account token is not available", false-matches symptoms).
    fm = load_failure_modes(FAILURE_MODES)
    text = "workload evicted by the scheduler after a priority shuffle"
    assert match_failure_mode_symptoms(fm, text, "") == []


def test_exact_matches_keep_priority_and_are_untagged() -> None:
    # When a curated keyword hits, behaviour is byte-for-byte the old one:
    # substring matches only, no bm25 tag, no fuzzy additions.
    fm = load_failure_modes(FAILURE_MODES)
    matches = match_failure_mode_symptoms(
        fm, "pod stuck in crashloopbackoff", "", fuzzy_query="pod stuck in crashloopbackoff"
    )
    assert matches
    assert all("matched_via" not in sym for _, sym in matches)


def test_exact_keyword_mentions_ignore_negated_context() -> None:
    fm = load_failure_modes(FAILURE_MODES)
    for text in [
        "dashboard loaded and no metrics are missing after refresh",
        "there is no imagepullbackoff on this pod; pull succeeded",
        "pod is not crashloopbackoff; it is running",
        "not out of memory; cuda memory usage is stable",
        "quota is not exceeded and gpu quota has plenty available",
        "not preempted and no preemption victim is present",
        "no failedattachvolume event is present",
        "not a multi-attach error, volume is mounted",
        "servfail is not present in coredns logs",
        "quota is not the issue and the scheduler is healthy",
        "preemption was not the root cause; the job completed",
        "node pressure was ruled out; kubelet is healthy and pods are running",
        "image pull was ruled out; registry is reachable and pulls succeeded",
        "dns issue was ruled out; coredns is healthy and no servfail was seen",
        "storage problem was ruled out; volume mounted and pvc bound",
        "oom was ruled out; cuda memory has enough free capacity",
        "crashloop was ruled out; container succeeded and app is healthy",
        "webhook was ruled out; admission is healthy",
        "preemption unrelated to this incident; workload completed normally",
        "image pull is unrelated; registry auth succeeded and image already cached",
        "crashloop excluded after restart count stayed zero",
        "oom excluded because memory usage remained below limit",
        "webhook is not implicated; admission requests succeeded",
        "coredns is not implicated; dns lookups succeeded and servfail absent",
        "storage is not implicated; pvc is bound and volume attached normally",
        "kubelet is not implicated; node ready and heartbeats normal",
        "imagepullbackoff resolved after registry credentials were refreshed; pod is running",
        "errimagepull cleared and the image is now cached on every node",
        "crashloopbackoff recovered after user fixed app args; container is running",
        "oomkilled resolved after batch size was reduced; memory is stable",
        "failedattachvolume cleared after detach completed; pvc is mounted",
        "servfail recovered after coredns rollout; dns lookups now succeed",
        "preemption cleared after quota update; workload completed",
        "node diskpressure resolved after log cleanup; node ready",
        "admission webhook timeout recovered after endpoint rollout; admission now succeeds",
        "administrator prohibited modifying item was fixed by granting permission; retry succeeded",
        "previously imagepullbackoff was seen, but now the pod is running",
        "historical errimagepull during yesterday deploy; current image pulls succeed",
        "last week crashloopbackoff occurred; current restart count is zero",
        "past oomkilled event from old job; current memory is stable",
        "old failedattachvolume event remains in history; pvc is mounted now",
        "earlier servfail in coredns logs; dns lookups now succeed",
        "cleared alert crashloopbackoff; restart count is zero",
        "ruled out oomkilled after checking events",
        "resolved known issue runai-backend-workloads-manager memory growth after upgrade",
        "operator asked whether this is imagepullbackoff; no evidence yet",
        'promql query kube_pod_container_status_waiting_reason{reason="ImagePullBackOff"} '
        "returned 0 series",
        "Node condition DiskPressure=False MemoryPressure=False PIDPressure=False",
        "pod status reason ImagePullBackOff=false ErrImagePull=false",
        "container lastState reason OOMKilled=false and restartCount=0",
        "CoreDNS metric servfail=false and request errors=0",
        "preemption_victim=false; preemption_count=0",
        "CrashLoopBackOff=False restartCount=0",
        "0 ImagePullBackOff events in the selected window",
        "zero ErrImagePull pods found",
        "0 OOMKilled containers in namespace runai",
        "zero CrashLoopBackOff restarts today",
        "0 FailedAttachVolume events after rollout",
        "zero servfail responses from coredns",
        "0 preemption victims during the interval",
        "zero DiskPressure nodes currently",
        "0 admission webhook timeout requests",
        'logql filter |~ "oomkilled|crashloopbackoff" returned no matching lines',
        "dashboard panel legend includes FailedAttachVolume but current value is 0",
        "alert rule expression contains DiskPressure but alert is inactive",
        'metric label reason="OOMKilled" has value 0 for all pods',
        'sample query: {namespace="runai"} |~ "servfail"; no lines found',
        "prometheus recording rule tracks preemption victim count, currently zero",
        "runbook command grep -i imagepullbackoff should be used if pods are pending",
        "please check for errimagepull during triage",
        "runbook says to rule out crashloopbackoff before blaming platform",
        "question: could this be oomkilled?",
        "next step is to inspect failedattachvolume events",
        "playbook mentions servfail as a possible DNS symptom",
        "hypothesis: quota preemption might be involved, needs evidence",
        "todo check diskpressure on the node",
        "template includes admission webhook timeout examples",
        "quota 문제 아님, GPU 여유 있음",
        "쿼터 원인 아님, GPU 여유 있고 스케줄러 정상",
        "이미지 풀 문제 아님, 레지스트리 인증 성공",
        "OOM 원인 아님, 메모리 사용량 정상",
        "웹훅 원인 아님, admission 성공",
        "imagepullbackoff 해결됨, pod running",
        "OOMKilled 해결됨, 메모리 정상",
        "servfail 복구됨, DNS 정상",
        "webhook timeout 정상화, admission 성공",
        "과거 imagepullbackoff 이벤트, 현재 pod running",
        "이전 OOMKilled 이벤트, 지금 메모리 정상",
        "지난주 servfail 로그, 현재 DNS 정상",
        "OOMKilled 여부 확인 요청",
        "servfail 가능성 점검",
        '쿼리 예시 reason="OOMKilled", 현재 값 0',
        "대시보드 범례 ImagePullBackOff, 현재 발생 없음",
        "ImagePullBackOff 이벤트 0건",
        "OOMKilled 컨테이너 0개",
        'PromQL absent(kube_pod_container_status_waiting_reason{reason="ImagePullBackOff"}) '
        "== 1",
        "config key imagePullBackOffAlertEnabled is set to true",
        "label key oomkilled_policy exists on namespace",
        "annotation example_crashloopbackoff_threshold=5",
        "dashboard field failedattachvolume_count is hidden",
        "column name servfail_total exists in the report table",
        "metric name runai_preemption_victim_total is defined in rules",
        "helm value diskPressureAlert.enabled=true in values.yaml",
        "환경변수 OOMKilledAlertEnabled=true",
        "대시보드 필드 ImagePullBackOffCount 표시 설정",
        "catalog entry alertname=KubePodImagePullBackOff exists for docs only",
        "example alert KubePodImagePullBackOff in runbook sample payload",
        "sample payload reason=OOMKilled shown in documentation",
        "alert rule name CrashLoopBackOffHighRestarts is loaded but inactive",
        "threshold CrashLoopBackOffHighRestarts is set to 5 in config",
        "series name kube_pod_container_status_waiting_reason reason ImagePullBackOff "
        "is present in metrics docs",
        "recording rule example includes runai_preemption_victim_total",
        "grafana panel query uses FailedAttachVolume in legend only",
        "sample log line contains ErrImagePull as placeholder only",
        "doc example: failedattachvolume event message format",
        "runbook example servfail response from coredns",
        "prometheus rule expression has ImagePullBackOff but alert state inactive",
        "alert label alertname=KubePodImagePullBackOff exists in Alertmanager config",
        "schema field lastState.reason can equal OOMKilled",
        "imagepullbackoff 아님, pull 성공함",
        "cuda out of memory 없음, 메모리 안정적",
        "servfail 관찰되지 않음",
        "failedattachvolume 발생하지 않음",
    ]:
        assert match_failure_mode_symptoms(fm, text, "", fuzzy_query=text) == []


def test_positive_signature_survives_near_negated_sibling() -> None:
    fm = load_failure_modes(FAILURE_MODES)
    cases = [
        ("there is no imagepullbackoff, but errimagepull occurs on every node", "ImagePullBackOff"),
        (
            "servfail is not present, but temporary failure in name resolution is present",
            "Pod DNS Resolution Failure",
        ),
        (
            "no failedattachvolume event is present, but multi-attach error blocks attach",
            "Volume Attach/Mount Failure",
        ),
        ("imagepullbackoff 아님, errimagepull 발생", "ImagePullBackOff"),
        ("resolved yesterday but imagepullbackoff returned now", "ImagePullBackOff"),
        (
            "promql query returned 2 pods with reason imagepullbackoff",
            "ImagePullBackOff",
        ),
        ("Node condition DiskPressure=True MemoryPressure=False", "Node Disk Pressure"),
        ("pod status reason ImagePullBackOff=true", "ImagePullBackOff"),
        ("container lastState reason OOMKilled=true", "OOMKilled"),
        ("2 ImagePullBackOff events in the selected window", "ImagePullBackOff"),
        ("3 OOMKilled containers in namespace runai", "OOMKilled"),
        ("KubePodImagePullBackOff firing", "ImagePullBackOff"),
        ("CrashLoopBackOffHighRestarts firing", "CrashLoopBackOff"),
        ("not zero ImagePullBackOff events", "ImagePullBackOff"),
        ("nonzero ImagePullBackOff events", "ImagePullBackOff"),
        ("pod status reason=ImagePullBackOff", "ImagePullBackOff"),
        ("last terminated reason=OOMKilled", "OOMKilled"),
        (
            "crashloopbackoff was resolved earlier, but crashloopbackoff restarted now",
            "CrashLoopBackOff",
        ),
        (
            "servfail recovered yesterday; however servfail is back now",
            "NetworkPolicy / MTU / CoreDNS-Forward Timeout",
        ),
        (
            "servfail 관찰되지 않음, temporary failure in name resolution 발생",
            "Pod DNS Resolution Failure",
        ),
    ]
    for text, symptom in cases:
        assert any(
            sym["symptom"] == symptom
            for _family, sym in match_failure_mode_symptoms(fm, text, "", fuzzy_query=text)
        )


def test_fuzzy_signature_survives_near_negated_exact_keyword() -> None:
    fm = load_failure_modes(FAILURE_MODES)
    text = (
        "no imagepullbackoff is present, but the workload was evicted so another "
        "project could use the gpus"
    )
    matches = match_failure_mode_symptoms(fm, text, "", fuzzy_query=text)

    assert any(family == "runai_scheduling_quota" for family, _sym in matches)
    assert not any(sym["symptom"] == "ImagePullBackOff" for _family, sym in matches)


def test_duplicate_single_signatures_are_not_over_deduped() -> None:
    fm = load_failure_modes(FAILURE_MODES)

    dns_families = {
        family
        for family, _sym in match_failure_mode_symptoms(
            fm, "dial tcp: lookup registry.internal: no such host", ""
        )
    }
    assert {"cluster_network_error", "image_pull_error"} <= dns_families

    runtime_families = {
        family
        for family, _sym in match_failure_mode_symptoms(
            fm, "failed to get sandbox runtime", ""
        )
    }
    assert {"node_kubelet_pressure", "gpu_hardware_error"} <= runtime_families


def test_known_issue_fuzzy_fallback_is_conservative() -> None:
    catalog = load_runai_known_issues(KNOWN_ISSUES)
    # Benign text stays unmatched even through the fuzzy path (same contract as
    # test_no_false_match)...
    benign = "a perfectly healthy cluster log line"
    assert match_runai_known_issues(catalog, benign, fuzzy_query=benign) == []
    assert (
        match_runai_known_issues(
            catalog,
            'failed to create pod sandbox: no runtime for "nvidia" is configured',
            fuzzy_query='failed to create pod sandbox: no runtime for "nvidia" is configured',
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "torch.cuda.OutOfMemoryError: CUDA out of memory",
            fuzzy_query="torch.cuda.OutOfMemoryError: CUDA out of memory",
        )
        == []
    )
    # ...and an exact signature still returns the untagged exact entry.
    exact = "Error: the administrator prohibited modifying item 'project-data'"
    hits = match_runai_known_issues(catalog, exact, fuzzy_query=exact)
    assert hits and all("matched_via" not in h for h in hits)


def test_known_issue_nested_keyword_mentions_ignore_negated_context() -> None:
    catalog = load_runai_known_issues(KNOWN_ISSUES)
    assert (
        match_runai_known_issues(
            catalog,
            "no runai-backend-workloads-manager is present after the upgrade",
            fuzzy_query="no runai-backend-workloads-manager is present after the upgrade",
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "runai-backend-workloads-manager 아님, 메모리 안정적",
            fuzzy_query="runai-backend-workloads-manager 아님, 메모리 안정적",
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "runai-backend-workloads-manager was not the root cause; memory stayed flat",
            fuzzy_query=(
                "runai-backend-workloads-manager was not the root cause; memory stayed flat"
            ),
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "runai-backend-workloads-manager unrelated; cache and memory normal",
            fuzzy_query="runai-backend-workloads-manager unrelated; cache and memory normal",
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "runai-backend-workloads-manager excluded; memory stayed flat",
            fuzzy_query="runai-backend-workloads-manager excluded; memory stayed flat",
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "runai-backend-workloads-manager memory growth resolved after upgrade; cache normal",
            fuzzy_query=(
                "runai-backend-workloads-manager memory growth resolved after upgrade; "
                "cache normal"
            ),
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "administrator prohibited modifying item was fixed by granting permission; "
            "retry succeeded",
            fuzzy_query=(
                "administrator prohibited modifying item was fixed by granting permission; "
                "retry succeeded"
            ),
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "resolved known issue runai-backend-workloads-manager memory growth after upgrade",
            fuzzy_query=(
                "resolved known issue runai-backend-workloads-manager memory growth "
                "after upgrade"
            ),
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "support case says runai-backend-workloads-manager memory growth can happen",
            fuzzy_query=(
                "support case says runai-backend-workloads-manager memory growth can happen"
            ),
        )
        == []
    )
    assert (
        match_runai_known_issues(
            catalog,
            "operator prompt: administrator prohibited modifying item?",
            fuzzy_query="operator prompt: administrator prohibited modifying item?",
        )
        == []
    )
