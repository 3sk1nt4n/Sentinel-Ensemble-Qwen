from sift_sentinel.validation import typed_validator as tv


def _db(facts):
    indexes = {"by_pid": {}}
    for f in facts:
        fid = f["fact_id"]
        pid = f.get("pid")
        if pid is not None:
            indexes["by_pid"].setdefault(str(pid), []).append(fid)

    return {
        "typed_facts": {"sid_fact": facts},
        "indexes": indexes,
    }


def _fact(
    fact_id="sid_fact-1",
    pid=4242,
    process_name="genericproc.exe",
    sid="S-1-5-21-100-200-300-400",
    account="EXAMPLE\\generic-user",
):
    return {
        "fact_id": fact_id,
        "fact_type": "sid_fact",
        "pid": pid,
        "process_name": process_name,
        "sid": sid,
        "account": account,
        "source_tool": "vol_getsids",
    }


def _check(claim, facts):
    return tv.typed_check_claim(claim, tv.TypedEvidenceDB(_db(facts)))


def test_process_sid_matches_by_pid_process_and_sid():
    out = _check(
        {
            "type": "process_sid",
            "pid": 4242,
            "process": "genericproc.exe",
            "sid": "S-1-5-21-100-200-300-400",
        },
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_process_account_sid_matches_account_label():
    out = _check(
        {
            "type": "process_account_sid",
            "pid": 4242,
            "process": "genericproc.exe",
            "account": "EXAMPLE\\generic-user",
        },
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_process_account_sid_matches_account_leaf_name():
    out = _check(
        {
            "type": "process_account_sid",
            "pid": 4242,
            "process": "genericproc.exe",
            "account": "generic-user",
        },
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_process_account_sid_matches_sid_and_account_together():
    out = _check(
        {
            "type": "process_account_sid",
            "pid": 4242,
            "process": "genericproc.exe",
            "sid": "S-1-5-21-100-200-300-400",
            "account": "generic-user",
        },
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_process_sid_mismatches_wrong_sid_for_known_pid():
    out = _check(
        {
            "type": "process_sid",
            "pid": 4242,
            "process": "genericproc.exe",
            "sid": "S-1-5-21-999-888-777-666",
        },
        [_fact()],
    )
    assert out[0] == "MISMATCH"


def test_process_account_sid_mismatches_wrong_account_for_known_sid():
    out = _check(
        {
            "type": "process_account_sid",
            "pid": 4242,
            "process": "genericproc.exe",
            "sid": "S-1-5-21-100-200-300-400",
            "account": "other-user",
        },
        [_fact()],
    )
    assert out[0] == "MISMATCH"


def test_process_sid_mismatches_wrong_process_for_known_pid():
    out = _check(
        {
            "type": "process_sid",
            "pid": 4242,
            "process": "otherproc.exe",
            "sid": "S-1-5-21-100-200-300-400",
        },
        [_fact()],
    )
    assert out[0] == "MISMATCH"


def test_process_sid_without_process_context_falls_back():
    out = _check(
        {
            "type": "process_sid",
            "sid": "S-1-5-21-100-200-300-400",
        },
        [_fact()],
    )
    assert out is None


def test_process_sid_without_facts_falls_back():
    out = _check(
        {
            "type": "process_sid",
            "pid": 4242,
            "sid": "S-1-5-21-100-200-300-400",
        },
        [],
    )
    assert out is None


def test_registered_sid_claim_types_are_first_class():
    for claim_type in ("process_sid", "process_account_sid"):
        assert claim_type in tv._TYPED_CHECKERS
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
