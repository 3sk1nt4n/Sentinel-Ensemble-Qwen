"""Commit 22: SSDT cap-policy disclosure across judge surfaces.

Property tests. Dataset-agnostic. Tool names verified against
TOOL_TO_ARTIFACT_TYPE dict in production. Tests assert:
  - confidence_cap_reason attached when cap fires
    (memory tool present AND non-full SSDT AND above-MEDIUM ceiling)
  - confidence_cap_reason NOT attached when any precondition absent
  - reason text is policy-constant with interpolated ssdt_trust only
  - self-assessment + HTML disclosure blocks present in run_pipeline.py
"""
from __future__ import annotations

from sift_sentinel.analysis.confidence import calibrate_confidence


def _make_finding(confidence_level="HIGH", source_tools=None):
    return {
        "finding_id": "synthetic_test",
        "confidence_level": confidence_level,
        "source_tools": source_tools or [],
        "claims": [],
    }


def test_L22_1_cap_reason_attached_on_ssdt_degraded_memory():
    """Property: cap fires AND reason attached when ssdt_trust != 'full'
    AND memory-artifact tool present AND current is above MEDIUM.

    Tool combo: vol_pstree (M) + vol_netscan (N) + get_amcache (A)
    = 3 distinct artifact types -> HIGH ceiling. has_memory=True
    via vol_pstree -> cap fires -> reason attached."""
    finding = _make_finding(
        confidence_level="HIGH",
        source_tools=["vol_pstree", "vol_netscan", "get_amcache"],
    )
    calibrate_confidence(finding, ssdt_trust="degraded")
    assert "confidence_cap_reason" in finding, \
        "cap fired but no reason attached"
    reason = finding["confidence_cap_reason"]
    assert "Memory-dependent" in reason
    assert "MEDIUM" in reason
    assert "SSDT trust" in reason


def test_L22_2_no_reason_when_ssdt_full():
    """Property: reason NOT attached when ssdt_trust == 'full'."""
    finding = _make_finding(
        confidence_level="HIGH",
        source_tools=["vol_pstree", "vol_netscan", "get_amcache"],
    )
    calibrate_confidence(finding, ssdt_trust="full")
    assert "confidence_cap_reason" not in finding, \
        "reason attached despite ssdt_trust=full"


def test_L22_3_no_reason_when_no_memory_tool():
    """Property: reason NOT attached when no memory tool in source_tools.

    Tool combo: get_amcache (A) + extract_mft_timeline (T) + parse_event_logs (E)
    = 3 distinct types -> HIGH ceiling. has_memory=False -> cap does NOT fire."""
    finding = _make_finding(
        confidence_level="HIGH",
        source_tools=["get_amcache", "extract_mft_timeline", "parse_event_logs"],
    )
    calibrate_confidence(finding, ssdt_trust="degraded")
    assert "confidence_cap_reason" not in finding, \
        "reason attached despite no memory tool"


def test_L22_4_reason_text_is_policy_constant():
    """Property: reason text contains policy-constant phrases,
    with ssdt_trust value interpolated (not a dataset id)."""
    finding = _make_finding(
        confidence_level="HIGH",
        source_tools=["vol_pstree", "vol_netscan", "get_amcache"],
    )
    calibrate_confidence(finding, ssdt_trust="untrusted")
    reason = finding.get("confidence_cap_reason", "")
    assert "conservative policy" in reason
    assert "Disk, network, and Prefetch" in reason
    assert "untrusted" in reason


def test_L22_5_self_assessment_includes_ssdt_disclosure():
    """Structural: run_pipeline.py generate_self_assessment contains
    the SSDT disclosure block with distinctive comment anchor."""
    from pathlib import Path
    content = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()
    assert "Commit 22: SSDT-specific disclosure distinct from degraded_profile" in content, \
        "Commit 22 self-assessment SSDT block missing"
    assert 'summary.get("ssdt_trust")' in content


def test_L22_6_html_report_includes_ssdt_disclosure():
    """Structural: run_pipeline.py HTML report contains SSDT Trust Policy section."""
    from pathlib import Path
    content = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()
    assert "SSDT Trust Policy" in content, \
        "HTML SSDT disclosure section missing"
    assert "conservative cap policy" in content, \
        "HTML SSDT policy constant phrase missing"


def test_L22_7_no_reason_when_cap_does_not_fire():
    """Property: cap does not fire (hence no reason) when ceiling
    was already at or below MEDIUM.

    Tool combo: vol_pstree alone = 1 distinct type -> MEDIUM ceiling.
    No downgrade needed -> cap does not fire."""
    finding = _make_finding(
        confidence_level="MEDIUM",
        source_tools=["vol_pstree"],
    )
    calibrate_confidence(finding, ssdt_trust="degraded")
    assert "confidence_cap_reason" not in finding, \
        "reason attached despite ceiling already at MEDIUM"
