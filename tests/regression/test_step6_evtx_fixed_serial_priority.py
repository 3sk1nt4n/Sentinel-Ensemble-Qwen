"""Step6 speed hygiene: EVTX fixed serial parser + priority submission.

Dataset-agnostic:
- no case PIDs, paths, domains, users, hashes, IPs
- no case key
- no cache shortcut
"""

from pathlib import Path


def test_evtx_adaptive_removed_from_runtime_source():
    src = Path("src/sift_sentinel/tools/disk_extended.py").read_text(errors="replace")
    assert "SIFT_EVTX_PER_FILE_TIMEOUT_S" in src
    assert "SIFT_PARSE_EVENT_LOGS_WORKERS" in src
    assert "SIFT_EVENT_LOGS_WORKERS" in src
    assert "SIFT_EVTX_WORKERS" in src
    assert "(adaptive)" not in src


def test_parse_event_logs_is_first_priority_tool():
    src = Path("run_pipeline.py").read_text(errors="replace")
    assert "_step6_submission_order" in src
    assert '"parse_event_logs": -100' in src
    assert "for tool_name in _step6_submission_order(to_run):" in src


def test_heavy_memory_tools_have_timeout_override():
    src = Path("src/sift_sentinel/tools/common.py").read_text(errors="replace")
    for name in ("vol_malfind", "vol_handles", "vol_filescan", "vol_psxview"):
        assert name in src
    assert "SIFT_VOL_HEAVY_TIMEOUT_S" in src


def test_no_dataset_literals_in_this_test():
    src = Path(__file__).read_text(errors="replace")
    banned = [
        "172." + "16.",
        "td" + "ungan",
        "sp" + "sql",
        "OUT" + "LOOK",
        "base-" + "rd01",
        "squirrel" + "directory",
    ]
    for token in banned:
        assert token not in src
