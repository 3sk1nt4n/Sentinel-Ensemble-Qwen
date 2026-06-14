"""Universal: an image/file-consumer tool handed a None/empty target (e.g. on a
disk-only run where the memory image_path is None) returns a clean
``not_applicable`` envelope -- never ``error: X not found: None``, which reads
as a tool failure and clutters the report. A real, non-empty-but-missing path
still reports an error (that's a genuine bad-input case). Keyed on
target-is-None only; no case data.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.tools import generic  # noqa: E402


def test_run_foremost_none_target_is_not_applicable():
    r = generic.run_foremost(None)
    assert r["record_count"] == 0
    assert r.get("status") == "not_applicable"
    assert "error" not in r or not r["error"]
    assert "None" not in str(r.get("not_applicable_reason", ""))


def test_run_strings_none_target_is_not_applicable():
    r = generic.run_strings(None)
    assert r["record_count"] == 0
    assert r.get("status") == "not_applicable"
    assert "error" not in r or not r["error"]


def test_run_strings_empty_target_is_not_applicable():
    r = generic.run_strings("")
    assert r.get("status") == "not_applicable"


def test_run_foremost_real_missing_path_still_errors():
    # A genuine bad path (non-empty) is still an honest error, not N/A.
    r = generic.run_foremost("/nonexistent/disk-image.E01")
    assert r["record_count"] == 0
    assert r.get("status") != "not_applicable"
    assert r.get("error")
