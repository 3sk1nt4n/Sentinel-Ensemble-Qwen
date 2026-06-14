from sift_sentinel.validation import typed_validator as tv
from sift_sentinel.validation import validator
from sift_sentinel.analysis.evidence_db import normalize_path


def _db(facts):
    indexes = {"by_path": {}}
    for fact in facts:
        fid = fact["fact_id"]
        for key in ("normalized_path", "path", "file_path"):
            value = fact.get(key)
            if value:
                indexes["by_path"].setdefault(normalize_path(value), []).append(fid)
    return tv.TypedEvidenceDB({
        "typed_facts": {"filesystem_listing_fact": facts},
        "indexes": indexes,
    })


def _fact(**overrides):
    base = {
        "fact_id": "filesystem_listing_fact-1",
        "fact_type": "filesystem_listing_fact",
        "path": "/generic/staging/artifact.bin",
        "normalized_path": "/generic/staging/artifact.bin",
        "artifact": ["artifact.bin", "/generic/staging/artifact.bin"],
    }
    base.update(overrides)
    return base


def test_filesystem_listing_matches_exact_path():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "filesystem_listing", "path": "/generic/staging/artifact.bin"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_file_object_matches_contains_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "file_object", "contains": "artifact.bin"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_filesystem_listing_mismatches_wrong_path_when_facts_exist():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "filesystem_listing", "path": "/generic/other/object.bin"},
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_filesystem_listing_process_context_falls_back_when_fact_lacks_context():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "filesystem_listing",
            "path": "/generic/staging/artifact.bin",
            "pid": 1234,
            "process": "generic.exe",
        },
        tdb,
    )
    assert out is None


def test_filesystem_listing_matches_process_context_when_fact_has_context():
    tdb = _db([
        _fact(pid=1234, process_name="generic.exe"),
    ])
    out = tv.typed_check_claim(
        {
            "type": "filesystem_listing",
            "path": "/generic/staging/artifact.bin",
            "pid": 1234,
            "process": "generic.exe",
        },
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_filesystem_listing_supported_and_mapped():
    for claim_type in ("filesystem_listing", "file_object"):
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
        assert claim_type in tv._TYPED_CHECKERS
        assert validator._CLAIM_TYPE_TO_FACT_TYPE[claim_type] == "filesystem_listing_fact"
