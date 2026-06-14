from sift_sentinel.validation import typed_validator as tv


def _db(facts):
    indexes = {"by_pid": {}}
    for f in facts:
        fid = f["fact_id"]
        pid = f.get("pid")
        if pid is not None:
            indexes["by_pid"].setdefault(str(pid), []).append(fid)

    return {
        "typed_facts": {"privilege_fact": facts},
        "indexes": indexes,
    }


def _fact(
    fact_id="privilege_fact-1",
    pid=4242,
    process_name="genericproc.exe",
    privilege="SeExamplePrivilege",
    attributes="Enabled",
):
    return {
        "fact_id": fact_id,
        "fact_type": "privilege_fact",
        "pid": pid,
        "process_name": process_name,
        "privilege": privilege,
        "attributes": attributes,
        "source_tool": "vol_privileges",
    }


def _check(claim, facts):
    return tv.typed_check_claim(claim, tv.TypedEvidenceDB(_db(facts)))


def test_process_privilege_matches_by_pid_process_and_name():
    out = _check(
        {
            "type": "process_privilege",
            "pid": 4242,
            "process": "genericproc.exe",
            "privilege": "SeExamplePrivilege",
        },
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_process_privilege_enabled_matches_enabled_attribute():
    out = _check(
        {
            "type": "process_privilege_enabled",
            "pid": 4242,
            "process": "genericproc.exe",
            "privilege": "SeExamplePrivilege",
        },
        [_fact(attributes="Enabled")],
    )
    assert out[0] == "MATCH"


def test_process_privilege_enabled_mismatches_disabled_attribute():
    out = _check(
        {
            "type": "process_privilege_enabled",
            "pid": 4242,
            "process": "genericproc.exe",
            "privilege": "SeExamplePrivilege",
        },
        [_fact(attributes="Disabled")],
    )
    assert out[0] == "MISMATCH"


def test_process_privilege_optional_enabled_false_matches_disabled():
    out = _check(
        {
            "type": "process_privilege",
            "pid": 4242,
            "process": "genericproc.exe",
            "privilege": "SeExamplePrivilege",
            "enabled": False,
        },
        [_fact(attributes="Disabled")],
    )
    assert out[0] == "MATCH"


def test_process_privilege_mismatches_wrong_privilege_for_known_pid():
    out = _check(
        {
            "type": "process_privilege",
            "pid": 4242,
            "process": "genericproc.exe",
            "privilege": "SeOtherPrivilege",
        },
        [_fact()],
    )
    assert out[0] == "MISMATCH"


def test_process_privilege_mismatches_wrong_process_for_known_pid():
    out = _check(
        {
            "type": "process_privilege",
            "pid": 4242,
            "process": "otherproc.exe",
            "privilege": "SeExamplePrivilege",
        },
        [_fact()],
    )
    assert out[0] == "MISMATCH"


def test_process_privilege_without_process_context_falls_back():
    out = _check(
        {
            "type": "process_privilege",
            "privilege": "SeExamplePrivilege",
        },
        [_fact()],
    )
    assert out is None


def test_process_privilege_without_facts_falls_back():
    out = _check(
        {
            "type": "process_privilege",
            "pid": 4242,
            "privilege": "SeExamplePrivilege",
        },
        [],
    )
    assert out is None


def test_registered_privilege_claim_types_are_first_class():
    for claim_type in ("process_privilege", "process_privilege_enabled"):
        assert claim_type in tv._TYPED_CHECKERS
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
