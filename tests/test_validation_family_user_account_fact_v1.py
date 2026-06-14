from sift_sentinel.analysis.validation_family_registry import get_validation_family_registry


def test_user_account_fact_registered_as_context_attribution_family():
    reg = get_validation_family_registry()
    spec = reg["user_account_fact"]
    assert spec["family"] == "user_account_fact"
    assert "context_only" in spec.get("roles", [])
    assert "vol_cmdline" in spec.get("producer_tools", [])
    assert "vol_handles" in spec.get("producer_tools", [])
    assert "user_account" in spec.get("claim_types", [])
