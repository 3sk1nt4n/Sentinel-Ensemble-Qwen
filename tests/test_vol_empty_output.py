"""A vol3 plugin that exits rc=0 with EMPTY stdout means '0 records', not a
failure. Regression for vol_mftscan (and any vol_* tool) crashing with
JSONDecodeError on an empty result set. Universal / dataset-agnostic.
"""
from unittest import mock

from sift_sentinel.tools import common


def _proc(rc=0, out="", err=""):
    return mock.Mock(returncode=rc, stdout=out, stderr=err)


def test_empty_stdout_is_zero_records_not_failure():
    # rc=0, no output -> the plugin scanned and found nothing.
    with mock.patch("subprocess.run", return_value=_proc(0, "")):
        out = common._run_volatility_impl("vol_mftscan", "/e/mem.img")
    assert out == []          # honest 0 records, no exception


def test_whitespace_only_stdout_is_zero_records():
    with mock.patch("subprocess.run", return_value=_proc(0, "   \n")):
        out = common._run_volatility_impl("vol_mftscan", "/e/mem.img")
    assert out == []


def test_valid_json_still_parses():
    payload = '[{"PID": 4, "Name": "System"}]'
    with mock.patch("subprocess.run", return_value=_proc(0, payload)):
        out = common._run_volatility_impl("vol_pslist", "/e/mem.img")
    assert isinstance(out, list) and out and out[0]["PID"] == 4


def test_genuine_garbage_still_raises():
    # rc=0 but non-empty non-JSON (and CSV path won't save it) -> real error.
    def fake(cmd, *a, **k):
        return _proc(0, "not json at all")   # both json and csv attempts see garbage
    with mock.patch("subprocess.run", side_effect=fake):
        try:
            common._run_volatility_impl("vol_pslist", "/e/mem.img")
            raised = False
        except RuntimeError:
            raised = True
    assert raised
