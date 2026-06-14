"""ReAct redirects a vol_vadinfo request to vol_ldrmodules.

vol_vadinfo only re-confirms the RWX malfind already found -- a slow full-image
scan that has repeatedly timed out (30s) and pushed injection findings to
inconclusive. vol_ldrmodules answers the SAME injection question (unlinked /
hidden DLLs) deterministically and far cheaper, and is paired into collection
alongside vol_malfind (pair_injection_corroborators) so it is normally already
cached -> the redirect resolves from cache with no Vol re-run.

Universal / dataset-agnostic: keyed only on tool identity, never on case data.
"""

from sift_sentinel.coordinator import _react_redirect_tool


def test_vadinfo_redirects_to_ldrmodules():
    assert _react_redirect_tool("vol_vadinfo") == "vol_ldrmodules"


def test_other_tools_pass_through_unchanged():
    for t in (
        "vol_ldrmodules",
        "vol_psxview",
        "vol_handles",
        "vol_malfind",
        "vol_pstree",
        "vol_hollowprocesses",  # a different question (hollowing) -> NOT redirected
        "",
    ):
        assert _react_redirect_tool(t) == t


def test_redirect_is_idempotent():
    # Redirecting the redirect target is a no-op (never loops back to vadinfo).
    assert _react_redirect_tool(_react_redirect_tool("vol_vadinfo")) == "vol_ldrmodules"


def test_cached_ldrmodules_redirect_skips_high_cost_vadinfo(tmp_path, monkeypatch):
    """Production path: when vol_ldrmodules is already cached, a ReAct vol_vadinfo
    request resolves from that cache -- the slow full-image high_cost_dispatch
    (the cause of the 30s timeouts) is never invoked."""
    import sift_sentinel.coordinator as coord

    high_cost_calls: list[str] = []

    def _track_high_cost(tool_name, key, runner):
        high_cost_calls.append(tool_name)
        raise AssertionError("high_cost_dispatch ran despite a cached redirect target")

    monkeypatch.setattr(coord, "high_cost_dispatch", _track_high_cost)

    def _ask_vadinfo(*_a, **_k):
        return {"action": "tool", "tool": "vol_vadinfo", "pid": 1234,
                "reasoning": "examine the RWX VAD region"}

    # vol_ldrmodules collected at Step 6 (pair_injection_corroborators); all DLLs
    # linked -> no injection -> the discriminator answers from cache.
    mandatory = {"vol_ldrmodules": {"output": [
        {"PID": 1234, "Process": "SearchApp.exe",
         "InInit": True, "InLoad": True, "InMem": True}]}}
    f = {"finding_id": "F001",
         "claims": [{"type": "pid", "pid": 1234, "process": "SearchApp.exe"}]}

    coord.step_11_investigate(
        findings=[f], state_dir=tmp_path, dry_run=False,
        invoke_fn=_ask_vadinfo, mandatory_results=mandatory,
        image_path="/evidence.raw",
    )

    assert high_cost_calls == [], (
        "vol_vadinfo high-cost scan ran; redirect to cached vol_ldrmodules failed"
    )
