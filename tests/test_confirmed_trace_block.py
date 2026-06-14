"""Confirmed-section 'Trace to tool execution' block (Criterion 5 — Audit Trail).

Universal / dataset-agnostic: the block maps each validator-backed claim to the
tool(s) that produced it, using ONLY the finding's own fields (per-claim
source_tool when present, else the finding-level source_tools) plus the constant
verify pointer. No case literals, no answer keys. Kill-switch SIFT_CONFIRMED_TRACE_BLOCK=0.
"""
import step0_onboard  # noqa: F401  (ensures repo on path in this test layout)
from sift_sentinel.reporting.deterministic_confirmed_section import (
    render_confirmed_findings_section,
)


def _finding(**over):
    f = {
        "finding_id": "F001",
        "title": "Example confirmed finding",
        "severity": "CRITICAL",
        "confidence_level": "HIGH",
        "source_tools": ["get_amcache", "extract_mft_timeline"],
        "claims": [
            {"type": "hash", "sha1": "a" * 40},
            {"type": "path", "path": "X:\\staging\\sample.exe"},
        ],
    }
    f.update(over)
    return f


# ── the block appears and maps claims -> the finding's source tools ──────────
def test_trace_block_present_and_maps_claim_to_source_tools(monkeypatch):
    monkeypatch.delenv("SIFT_CONFIRMED_TRACE_BLOCK", raising=False)
    section, audit = render_confirmed_findings_section([_finding()])
    assert audit["gate"] == "PASS"
    assert "Trace to tool execution" in section
    # claim value mapped to its producing tool(s)
    assert "← get_amcache" in section or "← get_amcache, extract_mft_timeline" in section
    # the constant verify pointer (universal, same every run)
    assert "agent_execution_log.txt" in section


# ── a per-claim source_tool wins over the finding-level list ─────────────────
def test_per_claim_tool_used_when_present(monkeypatch):
    monkeypatch.delenv("SIFT_CONFIRMED_TRACE_BLOCK", raising=False)
    f = _finding(claims=[{"type": "pid", "pid": 8260, "source_tool": "vol_malfind"}])
    section, _ = render_confirmed_findings_section([f])
    assert "← vol_malfind" in section


# ── kill-switch removes the block, leaving the rest intact ───────────────────
def test_kill_switch_off_no_trace_block(monkeypatch):
    monkeypatch.setenv("SIFT_CONFIRMED_TRACE_BLOCK", "0")
    section, audit = render_confirmed_findings_section([_finding()])
    assert audit["gate"] == "PASS"
    assert "Trace to tool execution" not in section
    # the existing content still renders
    assert "Source tools:" in section


# ── dataset-agnostic: the block contains only the finding's own field values ─
def test_block_carries_no_injected_case_literals(monkeypatch):
    monkeypatch.delenv("SIFT_CONFIRMED_TRACE_BLOCK", raising=False)
    f = _finding(source_tools=["tool_x"], claims=[{"type": "hash", "sha1": "b" * 40}])
    section, _ = render_confirmed_findings_section([f])
    # only tool_x (the finding's own tool) appears as a producer — nothing invented
    assert "← tool_x" in section
    assert "get_amcache" not in section
