"""Commit 31: server-side source_tools attachment for Inv2 claims.

L31-1 structural: _attach_inv2_claim_source_tools is defined and callable
L31-2 behavioral: claims without source_tools receive finding-level tools
L31-3 behavioral: existing claim source_tools preserved (no overwrite)
L31-4 behavioral: finding without source_tools yields empty-list sentinel
L31-5 regression: calibrator _extract_claim_tools finds attached tools
                  with no duplicates
"""
from __future__ import annotations


def test_L31_1_attachment_function_exists():
    """Structural: function is importable and callable."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    assert callable(_attach_inv2_claim_source_tools)


def test_L31_2_claims_receive_finding_tools():
    """Behavioral: Inv2 claim without source_tools gets finding-level list."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    findings = [{
        "finding_id": "F-TEST",
        "source_tools": ["vol_pstree", "vol_netscan"],
        "claims": [
            {"type": "pid", "pid": 123, "process": "x.exe"},
            {"type": "connection", "pid": 123, "foreign_addr": "1.2.3.4"},
        ],
    }]
    result = _attach_inv2_claim_source_tools(findings)
    for claim in result[0]["claims"]:
        assert claim.get("source_tools") == ["vol_pstree", "vol_netscan"], (
            f"claim source_tools not attached: {claim}"
        )


def test_L31_3_existing_claim_source_tools_preserved():
    """Behavioral: if AI ever emits claim source_tools, server does not overwrite."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    findings = [{
        "finding_id": "F-TEST",
        "source_tools": ["vol_pstree", "vol_netscan"],
        "claims": [
            {"type": "pid", "pid": 123, "process": "x.exe",
             "source_tools": ["vol_cmdline"]},
        ],
    }]
    result = _attach_inv2_claim_source_tools(findings)
    assert result[0]["claims"][0]["source_tools"] == ["vol_cmdline"], (
        "existing claim source_tools was overwritten"
    )


def test_L31_4_empty_finding_source_tools_yields_empty_list():
    """Behavioral: finding without source_tools yields empty-list sentinel
    so _extract_claim_tools treats it as no-provenance rather than crashing."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    findings = [{
        "finding_id": "F-TEST",
        "claims": [{"type": "pid", "pid": 123, "process": "x.exe"}],
    }]
    result = _attach_inv2_claim_source_tools(findings)
    assert result[0]["claims"][0]["source_tools"] == [], (
        "missing finding source_tools should yield empty list, not None"
    )


def test_L31_5_calibrator_finds_attached_tools_deduped():
    """Regression: after attachment, _extract_claim_tools finds the tools
    with no duplicates. Proves CC#15 mechanism is restored end-to-end at
    calibrator input AND calibrator dedupes across claims sharing the
    same attached list."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    from sift_sentinel.analysis.confidence import _extract_claim_tools
    findings = [{
        "finding_id": "F-TEST",
        "source_tools": ["vol_pstree", "vol_netscan"],
        "claims": [
            {"type": "pid", "pid": 123, "process": "x.exe"},
            {"type": "connection", "pid": 123, "foreign_addr": "1.2.3.4"},
        ],
    }]
    attached = _attach_inv2_claim_source_tools(findings)
    claim_tools = _extract_claim_tools(attached[0])
    assert set(claim_tools) == {"vol_pstree", "vol_netscan"}, (
        f"claim_tools set mismatch: expected {{vol_pstree, vol_netscan}}, got {set(claim_tools)}"
    )
    assert len(claim_tools) == len(set(claim_tools)), (
        f"claim_tools not deduped: {claim_tools}"
    )
