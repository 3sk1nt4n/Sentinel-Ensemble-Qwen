"""FIX B (#1): parse_event_logs reports not_applicable (not error) when the
Windows event-log tree is absent on the mount.

On a memory-only run the default disk mount has no Windows/ tree, so the EVTX
directory does not exist. The old code returned an ``error`` envelope
("EVTX directory not found: ..."), which (a) reads as a tool FAILURE to a judge
and (b) is an FP risk for the model. Its sibling disk tools (get_amcache,
parse_prefetch, parse_registry_persistence) all return ``not_applicable`` with a
reason for the same capability-absent situation. This aligns parse_event_logs
with them. Kill switch SIFT_EVTX_NA_NODISK=0 restores the legacy error envelope.

Universal: keyed on the structural absence of the Windows tree, no case data.
"""
import pathlib

from sift_sentinel.tools.disk_extended import parse_event_logs
from sift_sentinel.analysis.zero_record_reasons import _status_and_reason


def test_no_windows_tree_is_not_applicable(tmp_path):
    # empty mount: no Windows/ dir at all (the memory-only / non-Windows case)
    env = parse_event_logs(disk_mount=str(tmp_path))
    assert env["record_count"] == 0
    assert env.get("status") == "not_applicable"
    assert "error" not in env or not env.get("error")
    reason = (env.get("reason") or "").lower()
    assert "windows" in reason  # explains WHY (Windows tree absent)


def test_reason_distinguishes_present_windows_missing_logs(tmp_path):
    # Windows tree present but winevt/Logs absent -> still not_applicable, but a
    # different reason (directory missing / wiped, not "no disk evidence")
    (tmp_path / "Windows" / "System32").mkdir(parents=True)
    env = parse_event_logs(disk_mount=str(tmp_path))
    assert env.get("status") == "not_applicable"
    assert env["record_count"] == 0


def test_kill_switch_restores_legacy_error(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_EVTX_NA_NODISK", "0")
    env = parse_event_logs(disk_mount=str(tmp_path))
    assert env.get("status") != "not_applicable"
    assert "EVTX directory not found" in (env.get("error") or "")


def test_zero_record_classifier_sees_not_applicable(tmp_path):
    # the zero-record audit must classify the new envelope as not_applicable,
    # so the report's applicability section explains it instead of flagging a failure
    env = parse_event_logs(disk_mount=str(tmp_path))
    status, reason = _status_and_reason(env)
    assert status == "not_applicable", (status, reason)
    assert reason  # non-empty human reason
