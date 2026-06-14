"""Tests for src/sift_sentinel/prompts.py composition blocks."""


def test_inv2_attack_granularity_enumerates_all_10_tactics():
    """CC#17b: Verify granularity prompt enumerates all MITRE tactics."""
    from src.sift_sentinel.prompts import INV2_ATTACK_GRANULARITY
    required_tactics = [
        "Initial Access (TA0001)",
        "Execution (TA0002)",
        "Persistence (TA0003)",
        "Privilege Escalation (TA0004)",
        "Defense Evasion (TA0005)",
        "Credential Access (TA0006)",
        "Discovery (TA0007)",
        "Lateral Movement (TA0008)",
        "Collection (TA0009)",
        "Command and Control (TA0011)",
        "Exfiltration (TA0010)",
        "Impact (TA0040)",
    ]
    for tactic in required_tactics:
        assert tactic in INV2_ATTACK_GRANULARITY, f"Missing tactic: {tactic}"


def test_inv2_attack_granularity_requires_cross_domain_for_high():
    """CC#17b: Verify cross-domain source_tools requirement is documented."""
    from src.sift_sentinel.prompts import INV2_ATTACK_GRANULARITY
    assert "source_tools MUST span" in INV2_ATTACK_GRANULARITY
    assert "Memory domain" in INV2_ATTACK_GRANULARITY
    assert "Disk domain" in INV2_ATTACK_GRANULARITY
    assert "Single-domain findings default to MEDIUM" in INV2_ATTACK_GRANULARITY


def test_inv2_attack_granularity_allows_no_evidence_note():
    """CC#17b: Verify explicit 'no evidence observed' allowance."""
    from src.sift_sentinel.prompts import INV2_ATTACK_GRANULARITY
    assert "no evidence observed" in INV2_ATTACK_GRANULARITY


def test_compose_inv2_system_prompt_integrates_granularity():
    """CC#17b: Verify the granularity block reaches the composed prompt."""
    from src.sift_sentinel.prompts import compose_inv2_system_prompt
    s = compose_inv2_system_prompt()
    assert "MITRE ATT&CK enterprise tactics" in s
    assert "source_tools MUST span" in s
    assert len(s) > 2500, f"Composed prompt suspiciously short: {len(s)} chars"
