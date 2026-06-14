from sift_sentinel.validation import typed_validator as tv
from sift_sentinel.validation import validator


def _tdb(facts):
    return tv.TypedEvidenceDB(
        {
            "typed_facts": {"service_fact": facts},
            "indexes": {
                "by_service_name": {
                    f["service_name"]: [f["fact_id"]]
                    for f in facts
                    if f.get("service_name")
                }
            },
        }
    )


def _fact(**overrides):
    base = {
        "fact_id": "service_fact-1",
        "fact_type": "service_fact",
        "service_name": "genericservice",
        "display_name": "generic service",
        "state": "running",
        "binary_path": "/services/genericdaemon.exe",
        "pid": 123,
    }
    base.update(overrides)
    return base


def test_service_matches_name_and_pid():
    out = tv.typed_check_claim(
        {"type": "service", "service_name": "genericservice", "pid": 123},
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MATCH"


def test_service_state_matches_observed_state():
    out = tv.typed_check_claim(
        {"type": "service_state", "service_name": "genericservice", "state": "running"},
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MATCH"


def test_service_binary_matches_full_path():
    out = tv.typed_check_claim(
        {
            "type": "service_binary",
            "service_name": "genericservice",
            "binary_path": "/services/genericdaemon.exe",
        },
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MATCH"


def test_service_binary_matches_basename_when_only_basename_claimed():
    out = tv.typed_check_claim(
        {
            "type": "service_binary",
            "service_name": "genericservice",
            "binary_path": "genericdaemon.exe",
        },
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MATCH"


def test_service_state_mismatches_wrong_state_for_known_service():
    out = tv.typed_check_claim(
        {"type": "service_state", "service_name": "genericservice", "state": "stopped"},
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MISMATCH"


def test_service_binary_mismatches_wrong_binary_for_known_service():
    out = tv.typed_check_claim(
        {
            "type": "service_binary",
            "service_name": "genericservice",
            "binary_path": "/services/otherdaemon.exe",
        },
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MISMATCH"


def test_service_generic_without_discriminator_falls_back():
    assert tv.typed_check_claim({"type": "service"}, _tdb([_fact()])) is None


def test_service_without_facts_falls_back():
    assert tv.typed_check_claim(
        {"type": "service", "service_name": "genericservice"},
        _tdb([]),
    ) is None


def test_service_claim_types_registered_and_mapped():
    for claim_type in ("service", "service_state", "service_binary"):
        assert claim_type in tv._TYPED_CHECKERS
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
        assert validator._CLAIM_TYPE_TO_FACT_TYPE[claim_type] == "service_fact"


def test_service_binary_artifact_shape_does_not_become_state():
    fact = {
        "fact_id": "service_fact-artifact-binary",
        "fact_type": "service_fact",
        "artifact": ["genericservice", "/services/genericdaemon.exe"],
        "service_name": "genericservice",
    }
    out = tv.typed_check_claim(
        {
            "type": "service_binary",
            "service_name": "genericservice",
            "binary_path": "/services/genericdaemon.exe",
        },
        _tdb([fact]),
    )
    assert out is not None
    assert out[0] == "MATCH"

    # The same binary-path artifact must not be treated as an observed state.
    assert tv.typed_check_claim(
        {
            "type": "service_state",
            "service_name": "genericservice",
            "state": "running",
        },
        _tdb([fact]),
    ) is None


def test_service_state_artifact_shape_matches_only_state_like_values():
    fact = {
        "fact_id": "service_fact-artifact-state",
        "fact_type": "service_fact",
        "artifact": ["genericservice", "running"],
        "service_name": "genericservice",
    }
    out = tv.typed_check_claim(
        {
            "type": "service_state",
            "service_name": "genericservice",
            "state": "running",
        },
        _tdb([fact]),
    )
    assert out is not None
    assert out[0] == "MATCH"
