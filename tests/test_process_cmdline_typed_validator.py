from sift_sentinel.validation import typed_validator as tv


def _fact(
    *,
    fact_id="process_cmdline_fact-test-1",
    pid=99999,
    process_name="synthetic.exe",
    cmdline="synthetic.exe --alpha beta",
    empty=False,
):
    return {
        "fact_id": fact_id,
        "fact_type": "process_cmdline_fact",
        "pid": pid,
        "process_name": process_name,
        "cmdline": cmdline,
        "cmdline_is_empty": empty,
        "source_tool": "vol_cmdline",
        "source_tools": ["vol_cmdline"],
    }


def _tdb(facts, *, with_index=True):
    indexes = {}
    if with_index:
        by_pid = {}
        for f in facts:
            by_pid.setdefault(str(f["pid"]), []).append(f["fact_id"])
        indexes["by_pid"] = by_pid
    return tv.TypedEvidenceDB(
        {
            "typed_facts": {"process_cmdline_fact": list(facts)},
            "indexes": indexes,
        }
    )


def _status(claim, tdb):
    out = tv.typed_check_claim(claim, tdb)
    return None if out is None else out[0]


def test_process_cmdline_exact_match_with_index():
    tdb = _tdb([_fact()])
    assert _status(
        {
            "type": "process_cmdline",
            "pid": 99999,
            "process_name": "synthetic.exe",
            "cmdline": "synthetic.exe --alpha beta",
        },
        tdb,
    ) == "MATCH"


def test_process_cmdline_contains_match_without_index_scan_fallback():
    tdb = _tdb([_fact()], with_index=False)
    assert _status(
        {
            "type": "process_cmdline_contains",
            "pid": 99999,
            "contains": "--alpha",
        },
        tdb,
    ) == "MATCH"


def test_process_cmdline_contains_mismatch_when_pid_fact_exists():
    tdb = _tdb([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "process_cmdline_contains",
            "pid": 99999,
            "contains": "--missing-token",
        },
        tdb,
    )
    assert out[0] == "MISMATCH"


def test_process_cmdline_wrong_pid_falls_back_none():
    tdb = _tdb([_fact()])
    assert tv.typed_check_claim(
        {
            "type": "process_cmdline_contains",
            "pid": 11111,
            "contains": "--alpha",
        },
        tdb,
    ) is None


def test_process_cmdline_empty_match():
    tdb = _tdb([
        _fact(
            fact_id="process_cmdline_fact-test-empty",
            pid=22222,
            process_name="emptyproc.exe",
            cmdline="",
            empty=True,
        )
    ])
    assert _status(
        {
            "type": "process_cmdline_empty",
            "pid": 22222,
            "process_name": "emptyproc.exe",
        },
        tdb,
    ) == "MATCH"


def test_process_cmdline_empty_mismatch_when_nonempty():
    tdb = _tdb([_fact(pid=33333, process_name="nonempty.exe")])
    out = tv.typed_check_claim(
        {
            "type": "process_cmdline_empty",
            "pid": 33333,
            "process_name": "nonempty.exe",
        },
        tdb,
    )
    assert out[0] == "MISMATCH"


def test_process_cmdline_process_mismatch_blocks_cross_contamination():
    tdb = _tdb([_fact(pid=44444, process_name="owner-a.exe")])
    out = tv.typed_check_claim(
        {
            "type": "process_cmdline_contains",
            "pid": 44444,
            "process_name": "owner-b.exe",
            "contains": "--alpha",
        },
        tdb,
    )
    assert out[0] == "MISMATCH"


def test_process_cmdline_claim_types_registered():
    keys = set(tv._TYPED_CHECKERS)
    supported = set(tv.TYPED_SUPPORTED_CLAIM_TYPES)

    for name in (
        "process_cmdline",
        "process_cmdline_contains",
        "process_cmdline_empty",
    ):
        assert name in keys
        assert name in supported


def test_validator_fact_ref_mapping_for_process_cmdline():
    from sift_sentinel.validation import validator

    mapping = validator._CLAIM_TYPE_TO_FACT_TYPE
    assert mapping["process_cmdline"] == "process_cmdline_fact"
    assert mapping["process_cmdline_contains"] == "process_cmdline_fact"
    assert mapping["process_cmdline_empty"] == "process_cmdline_fact"
