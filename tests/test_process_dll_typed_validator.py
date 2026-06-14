from sift_sentinel.validation import typed_validator as tv


def _db(facts):
    indexes = {"by_pid": {}}
    for f in facts:
        fid = f["fact_id"]
        pid = f.get("pid")
        if pid is not None:
            indexes["by_pid"].setdefault(str(pid), []).append(fid)

    return {
        "typed_facts": {"dll_load_fact": facts},
        "indexes": indexes,
    }


def _fact(
    fact_id="dll_load_fact-1",
    pid=4242,
    process_name="genericproc.exe",
    dll_name="genericmodule.dll",
    dll_path="/windows/system32/genericmodule.dll",
):
    return {
        "fact_id": fact_id,
        "fact_type": "dll_load_fact",
        "pid": pid,
        "process_name": process_name,
        "dll_name": dll_name,
        "dll_path": dll_path,
        "source_tool": "vol_dlllist",
    }


def _check(claim, facts):
    return tv.typed_check_claim(claim, tv.TypedEvidenceDB(_db(facts)))


def test_process_dll_loaded_matches_by_pid_and_name():
    out = _check(
        {
            "type": "process_dll_loaded",
            "pid": 4242,
            "process": "genericproc.exe",
            "dll_name": "genericmodule.dll",
        },
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_process_dll_loaded_matches_by_pid_and_path():
    out = _check(
        {
            "type": "process_dll_loaded",
            "pid": 4242,
            "process": "genericproc.exe",
            "dll_path": "/windows/system32/genericmodule.dll",
        },
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_dll_loaded_matches_globally_by_name():
    out = _check(
        {"type": "dll_loaded", "dll_name": "genericmodule.dll"},
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_dll_loaded_matches_name_from_path_basename():
    out = _check(
        {"type": "dll_loaded", "dll_name": "genericmodule.dll"},
        [
            _fact(
                dll_name="",
                dll_path="/windows/system32/genericmodule.dll",
            )
        ],
    )
    assert out[0] == "MATCH"


def test_dll_path_loaded_matches_normalized_path():
    out = _check(
        {"type": "dll_path_loaded", "path": "/windows/system32/genericmodule.dll"},
        [_fact()],
    )
    assert out[0] == "MATCH"


def test_process_dll_loaded_mismatches_wrong_module_for_known_pid():
    out = _check(
        {
            "type": "process_dll_loaded",
            "pid": 4242,
            "process": "genericproc.exe",
            "dll_name": "othermodule.dll",
        },
        [_fact()],
    )
    assert out[0] == "MISMATCH"


def test_process_dll_loaded_mismatches_wrong_process_for_known_pid():
    out = _check(
        {
            "type": "process_dll_loaded",
            "pid": 4242,
            "process": "otherproc.exe",
            "dll_name": "genericmodule.dll",
        },
        [_fact()],
    )
    assert out[0] == "MISMATCH"


def test_dll_claim_without_facts_falls_back():
    out = _check(
        {"type": "dll_loaded", "dll_name": "genericmodule.dll"},
        [],
    )
    assert out is None


def test_registered_dll_claim_types_are_first_class():
    for claim_type in ("process_dll_loaded", "dll_loaded", "dll_path_loaded"):
        assert claim_type in tv._TYPED_CHECKERS
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
