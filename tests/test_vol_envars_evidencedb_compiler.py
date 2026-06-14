from sift_sentinel.analysis.evidence_db import build_typed_evidence_db


def test_vol_envars_compiles_environment_variable_fact():
    state = {
        "vol_envars": {
            "output": [
                {
                    "PID": 1234,
                    "Process": "generic.exe",
                    "Block": "0x1000",
                    "Variable": "GENERIC_VARIABLE",
                    "Value": "generic-value",
                }
            ]
        }
    }

    db = build_typed_evidence_db(state)
    facts = db["typed_facts"].get("environment_variable_fact") or []

    assert len(facts) == 1
    fact = facts[0]
    assert fact["fact_type"] == "environment_variable_fact"
    assert fact["pid"] == 1234
    assert fact["process_name"] == "generic.exe"
    assert fact["variable"] == "GENERIC_VARIABLE"
    assert fact["variable_name"] == "generic_variable"
    assert fact["value"] == "generic-value"


def test_vol_envars_skips_records_without_variable():
    state = {
        "vol_envars": {
            "output": [
                {"PID": 1, "Process": "generic.exe", "Value": "value"},
            ]
        }
    }
    db = build_typed_evidence_db(state)
    assert db["typed_facts"].get("environment_variable_fact") in (None, [])



def test_vol_envars_artifact_is_not_character_split():
    from sift_sentinel.analysis.evidence_db import build_typed_evidence_db

    state = {
        "vol_envars": {
            "output": [
                {
                    "PID": 1234,
                    "Process": "generic.exe",
                    "Variable": "GENERIC_VARIABLE",
                    "Value": "generic-value",
                }
            ]
        }
    }

    db = build_typed_evidence_db(state)
    facts = db["typed_facts"].get("environment_variable_fact") or []
    assert facts

    artifact = facts[0].get("artifact")
    assert isinstance(artifact, list)
    assert artifact == ["GENERIC_VARIABLE=generic-value"]
    assert artifact != list("GENERIC_VARIABLE=generic-value")
