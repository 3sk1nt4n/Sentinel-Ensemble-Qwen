"""#3 (light-tier corroborator preference) -- the NON-BREAKING part.

vol_vadinfo (120s) / vol_hollowprocesses (90s) routinely time out as ReAct
corroborators. The full "skip the heavy scan at dispatch" mechanism collides with
the committed D3-P1 timeout->inconclusive tests (they drive vol_vadinfo to time
out) and with the deliberate "ReAct sees all tools" invariant -- so it's deferred
pending reconciliation. What ships here is the safe, non-breaking steer: the ReAct
prompt PREFERS the light equivalents (vol_psxview process-view inconsistency,
vol_ldrmodules hidden DLLs) while keeping all tools visible. If the model still
picks vadinfo, the existing D3-P1 timeout->inconclusive safety net handles it.
Dataset-agnostic: no IOCs/case data.
"""
from __future__ import annotations

from sift_sentinel import coordinator as C


def test_react_prompt_prefers_light_corroborators_but_keeps_all_tools():
    finding = {
        "finding_id": "F001",
        "title": "Process injection with PAGE_EXECUTE_READWRITE in x.exe",
        "claims": [{"type": "pid", "pid": 4242, "process": "x.exe"}],
    }
    prompt = C._build_react_prompt(finding, [], turn=0)
    # The light, high-value corroborator is offered + a preference signal present.
    assert "vol_psxview" in prompt
    assert "PREFER" in prompt or "prefer" in prompt
    # Invariant preserved: heavy scanners remain visible (escalation still possible).
    assert "vol_vadinfo" in prompt


def test_tools_remain_in_registry():
    assert "vol_vadinfo" in C._TOOL_REGISTRY
    assert "vol_hollowprocesses" in C._TOOL_REGISTRY
