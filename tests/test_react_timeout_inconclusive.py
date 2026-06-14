"""TDD (D3 Part 1): a corroborating high-cost tool timing out inside the Step 11
ReAct loop must route the finding to INCONCLUSIVE, not be silently filed BENIGN.

Live Acme run: 8 malfind findings each ran vol_vadinfo as their only
corroborator; vol_vadinfo timed out at 120s. The exception escaped
``_investigate_one_finding`` because the ``high_cost_dispatch`` call
(coordinator.py:3598) -- unlike the ``run_tool`` path -- had no try/except, so the
finding received no ``react_conclusion`` -> verdict None -> the disposition benign
floor filed an uninvestigated injected-code finding as benign.

This locks the fix: a timed-out corroborator yields an explicit inconclusive
react_conclusion (is_false_positive=False), which disposition's step-2 override
(disposition.py:988) routes to inconclusive_unresolved -- a visible finding.

Dataset-agnostic: keys on the timeout only, never on PID/path/IOC.
"""
import subprocess

import sift_sentinel.coordinator as coord


def _finding(fid="F001", pid=1234):
    return {
        "finding_id": fid,
        "claims": [{"type": "pid", "pid": pid, "process": "SearchApp.exe"}],
    }


def _ask_vadinfo(*_a, **_k):
    # The ReAct AI always asks for the high-cost corroborator vol_vadinfo.
    return {"action": "tool", "tool": "vol_vadinfo", "pid": 1234,
            "reasoning": "examine the RWX VAD region"}


def _run_step11(monkeypatch, tmp_path, raiser, fid="F001"):
    monkeypatch.setattr(coord, "high_cost_dispatch", raiser)
    f = _finding(fid=fid)
    coord.step_11_investigate(
        findings=[f], state_dir=tmp_path, dry_run=False,
        invoke_fn=_ask_vadinfo, mandatory_results={}, image_path="/evidence.raw",
    )
    return f


def test_corroborator_timeoutexpired_routes_inconclusive(tmp_path, monkeypatch):
    def _boom(tool_name, key, runner):
        raise subprocess.TimeoutExpired(cmd="vol_vadinfo", timeout=120)
    f = _run_step11(monkeypatch, tmp_path, _boom)
    rc = f.get("react_conclusion")
    assert rc is not None, "timeout left finding with no react_conclusion (D3 bug)"
    assert rc.get("verdict") == "inconclusive"
    # MUST be False: extract_react_verdict maps inconclusive+is_fp -> likely_fp -> BENIGN
    assert rc.get("is_false_positive") is False


def test_corroborator_timeout_message_class_routes_inconclusive(tmp_path, monkeypatch):
    # The MCP/Vol layer commonly surfaces a timeout as a generic exception whose
    # message contains "timed out after Ns" (mcp_client regex). Must also route.
    def _boom(tool_name, key, runner):
        raise RuntimeError("vol_vadinfo timed out after 120s")
    f = _run_step11(monkeypatch, tmp_path, _boom, fid="F002")
    rc = f.get("react_conclusion")
    assert rc is not None and rc.get("verdict") == "inconclusive"
    assert rc.get("is_false_positive") is False
