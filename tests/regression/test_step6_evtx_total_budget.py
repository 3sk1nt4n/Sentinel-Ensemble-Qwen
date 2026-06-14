from pathlib import Path
import ast


def test_parse_event_logs_has_total_budget_and_record_cap():
    src = Path("src/sift_sentinel/tools/disk_extended.py").read_text(errors="replace")
    assert "SIFT_PARSE_EVENT_LOGS_TOTAL_BUDGET_S" in src
    assert "SIFT_EVENT_LOG_RECORD_CAP" in src
    assert "_parse_event_logs_deadline" in src
    assert "_parse_event_logs_budget_exhausted" in src


def test_evtx_per_file_timeout_is_clamped_to_remaining_budget():
    src = Path("src/sift_sentinel/tools/disk_extended.py").read_text(errors="replace")
    assert "_remaining_budget_s" in src
    assert "per_file_timeout = min(int(per_file_timeout), _remaining_budget_s)" in src


def test_disk_extended_syntax_ok():
    src = Path("src/sift_sentinel/tools/disk_extended.py").read_text(errors="replace")
    ast.parse(src)


def test_no_dataset_literals_in_budget_test():
    text = Path(__file__).read_text(errors="replace")
    banned = [
        "172." + "16.",
        "td" + "ungan",
        "sp" + "sql",
        "base-" + "rd",
        "OUT" + "LOOK",
        "Wmi" + "PrvSE",
    ]
    for token in banned:
        assert token not in text
