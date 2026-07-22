"""Deploy-time guardrails: catch cross-component config drift and chart image
mistakes in CI, before they become production incidents.

Every assertion here encodes a bug that actually shipped:
- backend hung up its agent call (180s) while the agent worked to its 20-min
  deadline -> every long analysis was abandoned mid-flight.
- systemAgent.image.repository was the bare `python`, so global.imageRegistry
  rewrote a public base image into the private org -> ImagePullBackOff 403.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

VALUES = Path(__file__).parents[2] / "charts" / "runai-rca" / "values.yaml"
MCP_TEMPLATE = (
    Path(__file__).parents[2] / "charts" / "runai-rca" / "templates" / "mcp-services.yaml"
)
AGENT_TEMPLATE = Path(__file__).parents[2] / "charts" / "runai-rca" / "templates" / "agent.yaml"
# Images we build and publish to the org registry — the ONLY repositories allowed
# to be short (unqualified), because global.imageRegistry is meant to prefix them.
OWN_IMAGES = {
    "runai-rca-agent",
    "runai-rca-backend",
    "runai-rca-frontend",
    "runai-rca-postgres-mcp",
}


def _values() -> dict[str, Any]:
    return yaml.safe_load(VALUES.read_text(encoding="utf-8"))


def test_backend_agent_call_outlives_agent_deadline() -> None:
    v = _values()
    agent_deadline = int(v["agent"]["env"]["analysisDeadlineSeconds"])
    backend = v["backend"]["env"]
    assert int(backend["agentRequestTimeoutSeconds"]) > agent_deadline, (
        "backend.agentRequestTimeoutSeconds must exceed agent.analysisDeadlineSeconds: "
        "the agent works up to its deadline then returns a degraded report — if the "
        "backend hangs up first, the report is lost and the alert gets a useless fallback"
    )
    assert int(backend["manualAgentRequestTimeoutSeconds"]) > agent_deadline, (
        "backend.manualAgentRequestTimeoutSeconds must exceed agent.analysisDeadlineSeconds"
    )


def test_agent_response_budget_fits_backend_transport_limit() -> None:
    values = _values()
    agent_budget = int(values["agent"]["env"]["analysisResponseMaxBytes"])
    backend_limit = int(values["backend"]["env"]["agentMaxResponseBodyBytes"])
    agent_template = AGENT_TEMPLATE.read_text(encoding="utf-8")
    backend_template = (
        Path(__file__).parents[2] / "charts" / "runai-rca" / "templates" / "backend.yaml"
    ).read_text(encoding="utf-8")

    assert 0 < agent_budget < backend_limit
    assert "ANALYSIS_RESPONSE_MAX_BYTES" in agent_template
    assert ".Values.agent.env.analysisResponseMaxBytes" in agent_template
    assert "AGENT_MAX_RESPONSE_BODY_BYTES" in backend_template
    assert ".Values.backend.env.agentMaxResponseBodyBytes" in backend_template


def test_agent_step_ceilings_fit_inside_the_deadline() -> None:
    env = _values()["agent"]["env"]
    deadline = int(env["analysisDeadlineSeconds"])
    for key in ("llmRequestTimeoutSeconds",):
        assert int(env[key]) < deadline, (
            f"agent.env.{key} must stay below analysisDeadlineSeconds so a single "
            "hung step cannot eat the whole analysis budget"
        )


def test_helm_defaults_run_analysis_through_nat() -> None:
    env = _values()["agent"]["env"]
    assert env["enableNatRuntime"] is True
    assert env["natConfigFile"] == "/app/configs/runai_rca_engine.yml"


def test_collector_insight_budget_supports_reasoning_models() -> None:
    env = _values()["agent"]["env"]
    template = AGENT_TEMPLATE.read_text(encoding="utf-8")

    assert int(env["llmInsightMaxTokens"]) >= 512
    assert "LLM_INSIGHT_MAX_TOKENS" in template
    assert ".Values.agent.env.llmInsightMaxTokens" in template


def test_synthesis_budget_is_explicit_and_bounded() -> None:
    env = _values()["agent"]["env"]
    template = AGENT_TEMPLATE.read_text(encoding="utf-8")

    assert 8192 <= int(env["llmSynthesisMaxTokens"]) <= 16384
    assert "LLM_SYNTHESIS_MAX_TOKENS" in template
    assert ".Values.agent.env.llmSynthesisMaxTokens" in template


def _image_repos(node: Any, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        repo = node.get("repository")
        if isinstance(repo, str) and repo:
            found.append((path or "<root>", repo))
        for key, child in node.items():
            found.extend(_image_repos(child, f"{path}.{key}" if path else str(key)))
    return found


def test_third_party_images_are_fully_qualified() -> None:
    # global.imageRegistry prefixes SHORT repos (our own images). Any third-party
    # image left short gets rewritten into the private org and 403s on pull.
    for path, repo in _image_repos(_values()):
        first = repo.split("/", 1)[0]
        qualified = "." in first or ":" in first or first == "localhost"
        assert qualified or repo in OWN_IMAGES, (
            f"{path}: image repository {repo!r} is unqualified but not one of our own "
            f"images {sorted(OWN_IMAGES)} — global.imageRegistry would rewrite it into "
            "the private org where it does not exist (ImagePullBackOff). Fully qualify "
            "it (e.g. docker.io/library/...)"
        )


def test_managed_mcp_values_keep_expected_secret_and_images() -> None:
    values = _values()
    assert values["runaiMcp"]["enabled"] is True
    assert values["grafanaMcp"]["enabled"] is True
    assert values["kubernetesMcp"]["enabled"] is True
    assert values["postgresMcp"]["enabled"] is True
    assert values["grafanaMcp"]["grafanaUrl"]
    assert values["secrets"]["keys"]["grafanaServiceAccountToken"] == (
        "GRAFANA_SERVICE_ACCOUNT_TOKEN"
    )
    assert values["runaiMcp"]["image"]["repository"] == (
        "nvcr.io/nvidia/runai/runai-mcp-server"
    )
    assert values["runaiMcp"]["image"]["tag"] == "2.26.13"
    assert values["runaiMcp"]["oidcIssuerUrl"] == ""
    assert values["runaiMcp"]["oidcProxy"]["image"]["repository"] == (
        "docker.io/nginxinc/nginx-unprivileged"
    )
    assert values["grafanaMcp"]["image"]["repository"] == "docker.io/grafana/mcp-grafana"
    assert values["grafanaMcp"]["image"]["tag"] == "0.14.0"
    assert values["kubernetesMcp"]["image"]["repository"] == (
        "quay.io/containers/kubernetes_mcp_server"
    )
    assert values["kubernetesMcp"]["image"]["tag"] == "v0.0.62"
    assert values["kubernetesMcp"]["image"]["pullPolicy"] == "IfNotPresent"
    assert values["postgresMcp"]["image"]["repository"] == "runai-rca-postgres-mcp"


def test_runai_mcp_requires_explicit_runai_api_url() -> None:
    template = MCP_TEMPLATE.read_text(encoding="utf-8")
    assert "agent.env.runaiBaseUrl is required when runaiMcp.enabled=true" in template
    assert "RUNAI_BASE_URL" in template
    assert "RUNAI_API_BASE_URL" not in template
    assert "RUNAI_API_TOKEN" not in template


def test_runai_mcp_uses_official_http_transport_and_scoped_pull_secret() -> None:
    values = _values()["runaiMcp"]
    template = MCP_TEMPLATE.read_text(encoding="utf-8")
    assert values["port"] == 8080
    assert values["metricsPort"] == 9090
    assert values["args"] == ["serve", "--transport", "http"]
    assert "runaiMcp.imagePullSecrets" in template
    assert "containerPort: {{ .Values.runaiMcp.metricsPort }}" in template
    assert "RUNAI_MCP_LISTEN_PORT" in template
    assert "RUNAI_MCP_METRICS_PORT" in template
    assert "runaiClientId" not in template
    assert "runaiClientSecret" not in template
    assert values["readinessProbe"]["tcpSocket"]["port"] == "mcp"
    assert values["extraEnv"] == []
    assert values["extraVolumeMounts"] == []
    assert values["extraVolumes"] == []
    assert ".Values.runaiMcp.extraEnv" in template
    assert ".Values.runaiMcp.extraVolumeMounts" in template
    assert ".Values.runaiMcp.extraVolumes" in template


def test_runai_mcp_can_proxy_only_oidc_discovery_to_the_token_issuer() -> None:
    template = MCP_TEMPLATE.read_text(encoding="utf-8")
    assert "runaiMcp.oidcIssuerUrl" in template
    assert "runai-mcp-oidc-proxy-config" in template
    assert "location = /.well-known/openid-configuration" in template
    assert "proxy_pass {{ $runaiMcpIssuerUrl }}/.well-known/openid-configuration;" in template
    assert "http://127.0.0.1:%v" in template


def test_runai_private_ca_bundle_is_shared_without_application_credentials() -> None:
    values = _values()
    tls = values["runaiTls"]
    agent = AGENT_TEMPLATE.read_text(encoding="utf-8")
    mcp = MCP_TEMPLATE.read_text(encoding="utf-8")

    assert tls == {"caBundleSecretName": "", "caBundleSecretKey": "ca.crt"}
    for template in (agent, mcp):
        assert ".Values.runaiTls.caBundleSecretName" in template
        assert ".Values.runaiTls.caBundleSecretKey" in template
        assert "SSL_CERT_FILE" in template
        assert "/etc/runai/tls/ca-bundle.pem" in template
        assert "name: runai-ca-bundle" in template
    # The official MCP receives only a CA-only Secret mount; runtime Run:ai
    # credentials continue to be forwarded as per-request bearer headers.
    assert "runaiClientId" not in mcp
    assert "runaiClientSecret" not in mcp
    assert "runaiBearerToken" not in mcp


def test_helm_secret_change_scan_is_opt_in_and_not_granted_by_chart_rbac() -> None:
    values = _values()
    agent = AGENT_TEMPLATE.read_text(encoding="utf-8")
    assert values["agent"]["env"]["enableHelmChangeDetection"] is False
    assert "ENABLE_HELM_CHANGE_DETECTION" in agent


def test_agent_env_uses_shared_mcp_service_urls_when_managed_enabled() -> None:
    text = AGENT_TEMPLATE.read_text(encoding="utf-8")
    assert "RUNAI_MCP_URL" in text and "runai-rca.runaiMcp.fullname" in text
    assert "http://localhost:%v/mcp" not in text
    assert "name: runai-mcp" not in text
    assert "runai-rca.runaiMcp.fullname" in MCP_TEMPLATE.read_text(encoding="utf-8")
    assert "PROMETHEUS_MCP_URL" in text and "runai-rca.grafanaMcp.fullname" in text
    assert "LOKI_MCP_URL" in text and "runai-rca.grafanaMcp.fullname" in text
    assert "PROMETHEUS_DATASOURCE_UID" in text
    assert "grafanaMcp.prometheusDatasourceUid" in text
    assert "LOKI_DATASOURCE_UID" in text
    assert "grafanaMcp.lokiDatasourceUid" in text
    assert "KUBERNETES_MCP_URL" in text and "runai-rca.kubernetesMcp.fullname" in text
    assert "POSTGRES_MCP_URL" in text and "runai-rca.postgresMcp.fullname" in text
    values = _values()["agent"]
    assert values["extraVolumeMounts"] == []
    assert values["extraVolumes"] == []
    assert ".Values.agent.extraVolumeMounts" in text
    assert ".Values.agent.extraVolumes" in text


def test_grafana_mcp_args_match_current_image_flags() -> None:
    text = MCP_TEMPLATE.read_text(encoding="utf-8")
    assert "--allowed-hosts" not in text
    assert "--endpoint-path" in text
    assert "--enabled-tools" in text
    assert "datasource,prometheus,loki" in text
    assert "--disable-write" in text
    assert "--disable-snapshot" not in text
    assert "--disable-provisioning" not in text


def test_kubernetes_mcp_rbac_is_read_only_and_excludes_sensitive_subresources() -> None:
    text = MCP_TEMPLATE.read_text(encoding="utf-8")
    assert "pods/exec" not in text
    assert "- secrets" not in text
    assert 'resources: ["secrets"]' not in text
    assert "verbs: [\"create\"" not in text
    assert "verbs: [\"update\"" not in text
    assert "verbs: [\"patch\"" not in text
    assert "verbs: [\"delete\"" not in text
    assert "verbs: [\"get\", \"list\", \"watch\"]" in text
    assert "resources: [\"pods/log\"]" in text


def test_agent_pod_exec_rbac_allows_websocket_get_and_post_create() -> None:
    # The agent uses aiohttp.ws_connect, whose WebSocket handshake is an HTTP
    # GET. Kubernetes therefore checks `get` on pods/exec. Keep `create` too for
    # the POST connect method used by conventional Kubernetes exec clients.
    text = (AGENT_TEMPLATE.parent / "agent-rbac.yaml").read_text(encoding="utf-8")
    assert text.count('resources: ["pods/exec"]') == 2
    assert text.count('verbs: ["get", "create"]') == 2
    assert text.count(".Values.agent.env.enablePodExec") == 2


def test_system_agent_supports_time_bounded_journal_reads() -> None:
    text = (Path(__file__).parents[2] / "charts" / "runai-rca" / "templates" / "system-agent-daemonset.yaml").read_text(encoding="utf-8")
    assert '"--since", since' in text
    assert '"--until", until' in text
    assert '"--output=short-iso"' in text
    assert "def rfc3339(value):" in text


def test_runai_crd_rbac_matches_the_k8s_read_allowlist_exactly() -> None:
    # Least privilege that stays in sync: the chart must grant read access to
    # EXACTLY the Run:ai CRDs k8s_read can query — no wildcard (accessrules/
    # applications/policies stay out), and no kind the code can read but RBAC
    # would 403 (which silently demotes the read to the direct API). The
    # namespaced Role variant carries only the NAMESPACED kinds: a Role cannot
    # authorize cluster-scoped resources (projects/queues/departments/nodepools
    # need rbac.clusterWide, same as nodes/storageclasses).
    from app.collectors.kubernetes import _RUNAI_CRD_KINDS

    all_by_group: dict[str, set[str]] = {}
    namespaced_by_group: dict[str, set[str]] = {}
    for kind, (group, _kind_name, namespaced) in _RUNAI_CRD_KINDS.items():
        all_by_group.setdefault(group, set()).add(kind)
        if namespaced:
            namespaced_by_group.setdefault(group, set()).add(kind)

    agent_template = AGENT_TEMPLATE.parent / "agent-rbac.yaml"
    for template in (agent_template, MCP_TEMPLATE):
        text = template.read_text(encoding="utf-8")
        assert '- apiGroups: ["run.ai", "scheduling.run.ai"]' not in text, template.name
        for group in all_by_group:
            # Variant order in both templates: the ClusterRole comes first,
            # then the namespaced Role inside the range loop.
            blocks = text.split(f'- apiGroups: ["{group}"]')[1:]
            assert len(blocks) == 2, (template.name, group, len(blocks))
            expected_per_block = [all_by_group[group], namespaced_by_group.get(group, set())]
            for block, expected in zip(blocks, expected_per_block, strict=True):
                resources_block = block.split("verbs:")[0]
                granted = {
                    line.strip().removeprefix("- ")
                    for line in resources_block.splitlines()
                    if line.strip().startswith("- ")
                }
                assert granted == expected, (template.name, group, granted ^ expected)
