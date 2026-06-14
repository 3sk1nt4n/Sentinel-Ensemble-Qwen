from sift_sentinel.validation import typed_validator as tv
from sift_sentinel.validation import validator


def _db(facts):
    return tv.TypedEvidenceDB({
        "typed_facts": {"wmi_subscription_fact": facts},
        "indexes": {},
    })


def _fact(**overrides):
    base = {
        "fact_id": "wmi_subscription_fact-1",
        "fact_type": "wmi_subscription_fact",
        "extracted_name": "GenericSubscription",
        "filter_name": "GenericFilter",
        "consumer_name": "GenericConsumer",
        "query": "SELECT * FROM GenericEvent",
        "command": "/generic/bin/action",
        "namespace": "root/subscription",
        "artifact_type": "event_consumer",
        "source_tool": "parse_wmi_subscription",
        "artifact": [
            "GenericSubscription",
            "GenericFilter",
            "GenericConsumer",
            "SELECT * FROM GenericEvent",
            "/generic/bin/action",
        ],
    }
    base.update(overrides)
    return base


def test_wmi_subscription_matches_name():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "wmi_subscription", "name": "GenericSubscription"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_wmi_subscription_matches_filter_name():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "wmi_subscription", "filter_name": "GenericFilter"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_wmi_subscription_matches_consumer_name():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "wmi_subscription", "consumer_name": "GenericConsumer"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_wmi_subscription_matches_query():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "wmi_subscription", "query": "GenericEvent"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_wmi_subscription_matches_command():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "wmi_subscription", "command": "/generic/bin/action"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_wmi_subscription_matches_contains():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "wmi_subscription", "contains": "genericconsumer"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_wmi_subscription_matches_multiple_constraints():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "wmi_subscription",
            "filter_name": "GenericFilter",
            "consumer_name": "GenericConsumer",
            "query": "GenericEvent",
        },
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_wmi_subscription_mismatches_wrong_consumer_when_facts_exist():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "wmi_subscription",
            "filter_name": "GenericFilter",
            "consumer_name": "OtherConsumer",
        },
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_wmi_subscription_without_constraints_falls_back():
    tdb = _db([_fact()])
    assert tv.typed_check_claim({"type": "wmi_subscription"}, tdb) is None


def test_wmi_subscription_supported_and_mapped():
    assert "wmi_subscription" in tv.TYPED_SUPPORTED_CLAIM_TYPES
    assert "wmi_subscription" in tv._TYPED_CHECKERS
    assert validator._CLAIM_TYPE_TO_FACT_TYPE["wmi_subscription"] == "wmi_subscription_fact"
