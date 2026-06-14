from sift_sentinel.analysis.phase1_extractors import PHASE1_COMPILERS


def _compile(records):
    return list(PHASE1_COMPILERS["vol_cmdline"](records))


def test_vol_cmdline_preserves_observed_empty_args():
    rows = _compile([
        {"PID": 99999, "Process": "example.exe", "Args": ""},
    ])

    assert len(rows) == 1
    idx, fact, err = rows[0]
    assert idx == 0
    assert err is None
    assert fact["fact_type"] == "process_cmdline_fact"
    assert fact["entity_id"] == "cmdline:pid:99999"
    assert fact["pid"] == 99999
    assert fact["process_name"] == "example.exe"
    assert fact["cmdline"] == ""
    assert fact["cmdline_is_empty"] is True


def test_vol_cmdline_preserves_observed_none_args_as_empty():
    rows = _compile([
        {"PID": 99998, "Process": "emptyhost.exe", "Args": None},
    ])

    assert len(rows) == 1
    _, fact, err = rows[0]
    assert err is None
    assert fact["pid"] == 99998
    assert fact["cmdline"] == ""
    assert fact["cmdline_is_empty"] is True


def test_vol_cmdline_preserves_non_empty_args():
    rows = _compile([
        {"PID": 99997, "Process": "runner.exe", "Args": "runner.exe -alpha beta"},
    ])

    assert len(rows) == 1
    _, fact, err = rows[0]
    assert err is None
    assert fact["pid"] == 99997
    assert fact["cmdline"] == "runner.exe -alpha beta"
    assert fact["cmdline_is_empty"] is False


def test_vol_cmdline_missing_args_field_is_unobserved_not_empty():
    rows = _compile([
        {"PID": 99996, "Process": "missingargs.exe"},
    ])

    assert len(rows) == 1
    _, fact, err = rows[0]
    assert fact is None
    assert err == "no_args_field"


def test_vol_cmdline_still_rejects_missing_pid():
    rows = _compile([
        {"Process": "nopid.exe", "Args": ""},
    ])

    assert len(rows) == 1
    _, fact, err = rows[0]
    assert fact is None
    assert err == "no_pid"
