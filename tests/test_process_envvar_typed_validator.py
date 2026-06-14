from sift_sentinel.validation import typed_validator as tv
from sift_sentinel.validation import validator


def _db(facts):
    indexes = {"by_pid": {}}
    for fact in facts:
        pid = fact.get("pid")
        if pid is not None:
            indexes["by_pid"].setdefault(str(pid), []).append(fact["fact_id"])
    return tv.TypedEvidenceDB(
        {
            "typed_facts": {"environment_variable_fact": facts},
            "indexes": indexes,
        }
    )


def _fact(**kw):
    out = {
        "fact_id": kw.pop("fact_id", "environment_variable_fact-1"),
        "fact_type": "environment_variable_fact",
        "pid": 1234,
        "process_name": "generic.exe",
        "variable": "GENERIC_VARIABLE",
        "variable_name": "generic_variable",
        "value": "generic-value",
    }
    out.update(kw)
    return out


def test_process_envvar_matches_pid_name_and_value():
    result = tv.typed_check_claim(
        {
            "type": "process_envvar",
            "pid": 1234,
            "process": "generic.exe",
            "variable": "GENERIC_VARIABLE",
            "value": "generic-value",
        },
        _db([_fact()]),
    )
    assert result[0] == "MATCH"


def test_process_envvar_contains_matches_value_substring():
    result = tv.typed_check_claim(
        {
            "type": "process_envvar_contains",
            "pid": 1234,
            "contains": "value",
        },
        _db([_fact()]),
    )
    assert result[0] == "MATCH"


def test_envvar_matches_globally_by_name():
    result = tv.typed_check_claim(
        {
            "type": "envvar",
            "variable": "GENERIC_VARIABLE",
        },
        _db([_fact()]),
    )
    assert result[0] == "MATCH"


def test_process_envvar_mismatches_wrong_value_for_known_pid():
    result = tv.typed_check_claim(
        {
            "type": "process_envvar",
            "pid": 1234,
            "variable": "GENERIC_VARIABLE",
            "value": "different",
        },
        _db([_fact()]),
    )
    assert result[0] == "MISMATCH"


def test_process_envvar_without_facts_falls_back():
    result = tv.typed_check_claim(
        {
            "type": "process_envvar",
            "pid": 1234,
            "variable": "GENERIC_VARIABLE",
        },
        _db([]),
    )
    assert result is None


def test_envvar_claims_registered_and_mapped():
    for claim_type in ("process_envvar", "process_envvar_contains", "envvar"):
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
        assert claim_type in tv._TYPED_CHECKERS
        assert validator._CLAIM_TYPE_TO_FACT_TYPE[claim_type] == "environment_variable_fact"
