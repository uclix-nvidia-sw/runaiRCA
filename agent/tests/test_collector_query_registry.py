from app.collectors.registry import QUERY_CAPABILITIES, READ_ONLY_QUERY_CAPABILITIES


def test_read_only_query_capabilities_have_explicit_source_groups() -> None:
    assert QUERY_CAPABILITIES is READ_ONLY_QUERY_CAPABILITIES
    assert set(READ_ONLY_QUERY_CAPABILITIES) == {"system_log_query", "change_query"}
    assert READ_ONLY_QUERY_CAPABILITIES["system_log_query"]["source_group"] == "node_system"
    assert READ_ONLY_QUERY_CAPABILITIES["system_log_query"]["independence_group"] == "node_system"
    assert READ_ONLY_QUERY_CAPABILITIES["change_query"]["source_group"] == "kubernetes_api"
    assert READ_ONLY_QUERY_CAPABILITIES["change_query"]["independence_group"] == "kubernetes_api"
    assert callable(READ_ONLY_QUERY_CAPABILITIES["system_log_query"]["call"])
    assert callable(READ_ONLY_QUERY_CAPABILITIES["change_query"]["call"])
