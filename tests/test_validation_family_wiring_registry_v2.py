from sift_sentinel.analysis.validation_family_registry import (
    expected_families_for_tool,
    family_role,
    get_validation_family_registry,
    tool_role_summary,
)


def test_target_tools_have_registered_validation_families():
    target_tools = [
        "decode_base64_strings",
        "extract_network_iocs",
        "parse_event_logs",
        "parse_scheduled_tasks_disk",
        "parse_wmi_subscription",
        "run_jlecmd",
        "run_lecmd",
        "vol_cmdline",
        "vol_dlllist",
        "vol_filescan",
        "vol_getsids",
        "vol_handles",
        "vol_privileges",
        "vol_reg_hivelist",
        "vol_sessions",
        "vol_ssdt",
        "vol_svcscan",
        "vol_svescan",
    ]
    missing = [tool for tool in target_tools if not expected_families_for_tool(tool)]
    assert missing == []


def test_context_only_tools_are_explicitly_labeled():
    assert tool_role_summary("vol_getsids")["context_or_health_only"] is True
    assert tool_role_summary("vol_reg_hivelist")["context_or_health_only"] is True
    assert tool_role_summary("vol_sessions")["context_or_health_only"] is True


def test_finding_capable_tools_are_explicitly_labeled():
    for tool in [
        "parse_event_logs",
        "parse_scheduled_tasks_disk",
        "parse_wmi_subscription",
        "run_jlecmd",
        "run_lecmd",
        "extract_network_iocs",
        "vol_filescan",
        "vol_handles",
        "vol_svcscan",
    ]:
        assert tool_role_summary(tool)["finding_capable"] is True


def test_registry_has_no_empty_roles_or_claim_types():
    reg = get_validation_family_registry()
    assert reg
    for family, spec in reg.items():
        assert family.endswith("_fact")
        assert spec["role"]
        assert spec["producer_tools"]
        assert spec["candidate_policy"]
        assert spec["validator_policy"]
