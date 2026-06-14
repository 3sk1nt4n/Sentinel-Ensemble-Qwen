from sift_sentinel.validation import typed_validator as tv
from sift_sentinel.validation import validator


def _db(facts):
    indexes = {"by_task_name": {}}
    for fact in facts:
        fid = fact["fact_id"]
        for value in (
            fact.get("task_name"),
            fact.get("task_path"),
            fact.get("name"),
            fact.get("path"),
        ):
            if value:
                raw = str(value).strip().lower()
                compact = "\\".join(part for part in raw.replace("/", "\\").split("\\") if part)
                for key in {raw, compact}:
                    if key:
                        indexes["by_task_name"].setdefault(key, []).append(fid)
    return tv.TypedEvidenceDB({
        "typed_facts": {"scheduled_task_fact": facts},
        "indexes": indexes,
    })


def _fact(**overrides):
    base = {
        "fact_id": "scheduled_task_fact-1",
        "fact_type": "scheduled_task_fact",
        "task_name": "generic_task",
        "task_path": "\\generic\\generic_task",
        "actions": "generic-runner --mode audit",
        "hidden": False,
        "enabled": True,
        "artifact": ["generic_task", "generic-runner --mode audit"],
    }
    base.update(overrides)
    return base


def test_scheduled_task_matches_name():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "scheduled_task", "task_name": "generic_task"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_scheduled_task_matches_task_path():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "scheduled_task", "task_path": "\\generic\\generic_task"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_scheduled_task_action_matches_action_contains():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "scheduled_task_action", "contains": "--mode audit"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_scheduled_task_name_and_action_both_match():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "scheduled_task",
            "task_name": "generic_task",
            "contains": "generic-runner",
        },
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_scheduled_task_hidden_constraint_matches():
    tdb = _db([_fact(hidden=True)])
    out = tv.typed_check_claim(
        {"type": "scheduled_task", "task_name": "generic_task", "hidden": True},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_scheduled_task_enabled_constraint_mismatches():
    tdb = _db([_fact(enabled=False)])
    out = tv.typed_check_claim(
        {"type": "scheduled_task", "task_name": "generic_task", "enabled": True},
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_scheduled_task_mismatches_wrong_name_when_facts_exist():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "scheduled_task", "task_name": "other_task"},
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_scheduled_task_action_mismatches_wrong_action_when_facts_exist():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "scheduled_task_action", "contains": "other-action"},
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_scheduled_task_supported_and_mapped():
    for claim_type in ("scheduled_task", "scheduled_task_action"):
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
        assert claim_type in tv._TYPED_CHECKERS
        assert validator._CLAIM_TYPE_TO_FACT_TYPE[claim_type] == "scheduled_task_fact"
