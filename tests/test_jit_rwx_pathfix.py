"""JIT-RWX gate Fix-4: resolve the FULL process path (Part A, default ON) and
optional Electron host-shape (Part B, SIFT_JIT_RWX_V2, default OFF).

On the acme run all 8 RWX-injection FPs failed Rail 2 (not_a_managed_jit_host)
because the gate read the basename ('SearchApp.exe') while the full UWP path
('c:/windows/systemapps/microsoft.windows.search_.../searchapp.exe') was also
present in process_fact. Resolving the full path lets the existing safe UWP
rail fire on the genuine UWP apps. Rails 1 (payload) and 3 (egress/unlinked)
are untouched, so a real injection still never downgrades. Synthetic values
only; keyed on path SHAPE, no process-name list.
"""
from __future__ import annotations

from sift_sentinel.analysis.injection_fp_filter import is_managed_jit_host
from sift_sentinel.analysis.jit_rwx_gate import (
    _best_process_path,
    jit_rwx_downgrade,
)


# ── Part A: full-path resolution ─────────────────────────────────────────

def test_best_process_path_prefers_full_uwp_path():
    procs = [
        {"image_name": "SearchApp.exe"},
        {"path": "c:/windows/systemapps/microsoft.windows.search_cw5n1h2/searchapp.exe"},
    ]
    assert "systemapps" in _best_process_path(procs)


def test_best_process_path_basename_only_returns_something():
    assert _best_process_path([{"image_name": "x.exe"}]) in ("x.exe", "")


def _evdb(pid, path, *, payload=False, unlinked=False, egress_ip=None):
    facts = {
        "memory_injection_fact": [{
            "fact_id": "memory_injection_fact-0", "fact_type": "memory_injection_fact",
            "injection_corroborated": payload,
            "characterization": "mz_pe" if payload else "private_rwx",
            "index": {"by_pid": [str(pid)]},
        }],
        "process_fact": [
            {"fact_id": "process_fact-0", "fact_type": "process_fact",
             "image_name": path.rsplit("/", 1)[-1], "index": {"by_pid": [str(pid)]}},
            {"fact_id": "process_fact-1", "fact_type": "process_fact",
             "path": path, "index": {"by_pid": [str(pid)]}},
        ],
    }
    if unlinked:
        facts["ldrmodules_unlinked_fact"] = [{
            "fact_id": "ldrmodules_unlinked_fact-0",
            "fact_type": "ldrmodules_unlinked_fact", "index": {"by_pid": [str(pid)]}}]
    if egress_ip:
        facts["network_connection_fact"] = [{
            "fact_id": "network_connection_fact-0",
            "fact_type": "network_connection_fact", "remote_ip": egress_ip,
            "index": {"by_pid": [str(pid)]}}]
    idx = {}
    for ft, fl in facts.items():
        for f in fl:
            for k in f.get("index", {}).get("by_pid", []):
                idx.setdefault("by_pid", {}).setdefault(str(k), []).append(f["fact_id"])
    return {"typed_facts": facts, "indexes": idx}


def _finding(pid):
    return {"finding_id": "F1", "title": "Memory injection RWX",
            "claims": [{"type": "pid", "pid": pid}]}


def test_uwp_app_downgrades_with_full_path():
    evdb = _evdb(8312, "c:/windows/systemapps/microsoft.windows.search_x/searchapp.exe")
    down, reason = jit_rwx_downgrade(_finding(8312), evdb)
    assert down is True, reason


def test_payload_never_downgraded_even_uwp():
    # Rail 1 safety: a real PE/shellcode payload blocks regardless of host
    evdb = _evdb(8312, "c:/windows/systemapps/microsoft.windows.search_x/searchapp.exe",
                 payload=True)
    down, reason = jit_rwx_downgrade(_finding(8312), evdb)
    assert down is False and reason in ("payload_corroborated", "payload_signature_present")


def test_egress_blocks_downgrade_even_uwp():
    evdb = _evdb(8312, "c:/windows/systemapps/microsoft.windows.search_x/searchapp.exe",
                 egress_ip="203.0.113.9")
    down, reason = jit_rwx_downgrade(_finding(8312), evdb)
    assert down is False and reason == "external_egress_present"


def test_unlinked_blocks_downgrade_even_uwp():
    evdb = _evdb(8312, "c:/windows/systemapps/microsoft.windows.search_x/searchapp.exe",
                 unlinked=True)
    down, reason = jit_rwx_downgrade(_finding(8312), evdb)
    assert down is False and reason == "unlinked_dll_present"


def test_system32_process_not_downgraded():
    # RuntimeBroker/smartscreen live in System32 -- NOT a JIT host by path,
    # stays inconclusive (the honest disposition, no answer-key list)
    evdb = _evdb(9964, "c:/windows/system32/runtimebroker.exe")
    down, reason = jit_rwx_downgrade(_finding(9964), evdb)
    assert down is False and reason == "not_a_managed_jit_host"


# ── Part B: Electron host-shape, gated ───────────────────────────────────

_TEAMS = "c:/users/bobby/appdata/local/microsoft/teams/current/teams.exe"


def test_electron_off_by_default():
    assert is_managed_jit_host([], _TEAMS) is False


def test_electron_recognized_when_enabled():
    assert is_managed_jit_host([], _TEAMS, electron=True) is True


def test_electron_gate_flag(monkeypatch):
    monkeypatch.setenv("SIFT_JIT_RWX_V2", "1")
    evdb = _evdb(15636, _TEAMS)
    down, reason = jit_rwx_downgrade(_finding(15636), evdb)
    assert down is True, reason


def test_electron_not_downgraded_when_flag_off(monkeypatch):
    monkeypatch.delenv("SIFT_JIT_RWX_V2", raising=False)
    evdb = _evdb(15636, _TEAMS)
    down, reason = jit_rwx_downgrade(_finding(15636), evdb)
    assert down is False and reason == "not_a_managed_jit_host"


def test_metamorphic_uwp_package_relabel():
    a = jit_rwx_downgrade(_finding(1), _evdb(1, "c:/windows/systemapps/microsoft.alpha_x/alpha.exe"))
    b = jit_rwx_downgrade(_finding(2), _evdb(2, "c:/windows/systemapps/microsoft.beta_y/beta.exe"))
    assert a[0] is b[0] is True
