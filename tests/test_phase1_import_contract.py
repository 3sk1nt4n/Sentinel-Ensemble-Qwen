def test_phase1_extractors_importable_before_evidence_db():
    # This must work even when evidence_db has not been imported first.
    from sift_sentinel.analysis import phase1_extractors as p1

    assert "vol_cmdline" in p1.PHASE1_COMPILERS
    assert "vol_dlllist" in p1.PHASE1_COMPILERS
    assert "vol_handles" in p1.PHASE1_COMPILERS


def test_phase1_compiler_can_run_after_direct_import():
    from sift_sentinel.analysis.phase1_extractors import PHASE1_COMPILERS

    rows = list(PHASE1_COMPILERS["vol_cmdline"]([
        {"PID": 99999, "Process": "example.exe", "Args": ""},
    ]))

    assert len(rows) == 1
    _, fact, err = rows[0]
    assert err is None
    assert fact["fact_type"] == "process_cmdline_fact"
    assert fact["pid"] == 99999
    assert fact["cmdline"] == ""
    assert fact["cmdline_is_empty"] is True
