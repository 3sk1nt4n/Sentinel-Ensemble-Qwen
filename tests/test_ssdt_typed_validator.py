from sift_sentinel.validation import typed_validator as tv
from sift_sentinel.validation import validator


def _tdb(facts):
    return tv.TypedEvidenceDB(
        {
            "typed_facts": {"ssdt_integrity_fact": facts},
            "indexes": {
                "by_index": {
                    str(f.get("index")): [f["fact_id"]]
                    for f in facts
                    if f.get("index") is not None
                }
            },
        }
    )


def _fact(**overrides):
    base = {
        "fact_id": "ssdt_integrity_fact-1",
        "fact_type": "ssdt_integrity_fact",
        "index": 7,
        "module": "genericdriver.sys",
        "symbol": "NtGenericCall",
        "status": "observed",
        "hooked": False,
    }
    base.update(overrides)
    return base


def test_ssdt_integrity_matches_exact_row_constraints():
    out = tv.typed_check_claim(
        {
            "type": "ssdt_integrity",
            "index": 7,
            "module": "genericdriver.sys",
            "symbol": "NtGenericCall",
        },
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MATCH"


def test_kernel_ssdt_entry_matches_row_discriminator():
    out = tv.typed_check_claim(
        {
            "type": "kernel_ssdt_entry",
            "index": 7,
            "symbol": "NtGenericCall",
        },
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MATCH"


def test_ssdt_integrity_mismatches_wrong_module_for_known_rows():
    out = tv.typed_check_claim(
        {
            "type": "ssdt_integrity",
            "index": 7,
            "module": "otherdriver.sys",
        },
        _tdb([_fact()]),
    )
    assert out is not None
    assert out[0] == "MISMATCH"


def test_kernel_ssdt_entry_without_discriminator_falls_back():
    assert tv.typed_check_claim(
        {"type": "kernel_ssdt_entry"},
        _tdb([_fact()]),
    ) is None


def test_ssdt_integrity_without_facts_falls_back():
    assert tv.typed_check_claim(
        {"type": "ssdt_integrity", "index": 7},
        _tdb([]),
    ) is None


def test_ssdt_claim_types_registered_and_mapped():
    for claim_type in ("ssdt_integrity", "kernel_ssdt_entry"):
        assert claim_type in tv._TYPED_CHECKERS
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
        assert validator._CLAIM_TYPE_TO_FACT_TYPE[claim_type] == "ssdt_integrity_fact"
