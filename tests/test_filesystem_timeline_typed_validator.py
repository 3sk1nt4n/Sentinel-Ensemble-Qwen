from sift_sentinel.analysis.evidence_db import normalize_path
from sift_sentinel.validation import typed_validator as tv
from sift_sentinel.validation import validator


def _db(facts):
    indexes = {"by_path": {}}
    for fact in facts:
        fid = fact["fact_id"]
        for value in (
            fact.get("path"),
            fact.get("file_path"),
            fact.get("normalized_path"),
            fact.get("filename"),
        ):
            if value:
                n = normalize_path(str(value))
                if n:
                    indexes["by_path"].setdefault(n, []).append(fid)
    return tv.TypedEvidenceDB({
        "typed_facts": {"filesystem_timeline_fact": facts},
        "indexes": indexes,
    })


def _fact(**overrides):
    base = {
        "fact_id": "filesystem_timeline_fact-1",
        "fact_type": "filesystem_timeline_fact",
        "path": "/generic/stage/tool.bin",
        "normalized_path": normalize_path("/generic/stage/tool.bin"),
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "created",
        "source_tool": "extract_mft_timeline",
        "artifact": ["/generic/stage/tool.bin", "created"],
    }
    base.update(overrides)
    return base


def test_filesystem_timeline_matches_exact_path():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "filesystem_timeline", "path": "/generic/stage/tool.bin"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_mft_timeline_matches_same_fact_family():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "mft_timeline", "path": "/generic/stage/tool.bin"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_filesystem_timeline_matches_contains_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "filesystem_timeline", "contains": "stage/tool"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_filesystem_timeline_matches_timestamp_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "filesystem_timeline",
            "path": "/generic/stage/tool.bin",
            "timestamp": "2026-01-01",
        },
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_filesystem_timeline_matches_event_type_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "filesystem_timeline",
            "path": "/generic/stage/tool.bin",
            "event_type": "created",
        },
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_filesystem_timeline_mismatches_wrong_path_when_facts_exist():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "filesystem_timeline", "path": "/generic/other/tool.bin"},
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_filesystem_timeline_mismatches_wrong_timestamp_when_path_matches():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "filesystem_timeline",
            "path": "/generic/stage/tool.bin",
            "timestamp": "2099-01-01",
        },
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_filesystem_timeline_without_path_or_contains_falls_back():
    tdb = _db([_fact()])
    assert tv.typed_check_claim({"type": "filesystem_timeline"}, tdb) is None


def test_filesystem_timeline_supported_and_mapped():
    for claim_type in ("filesystem_timeline", "mft_timeline"):
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
        assert claim_type in tv._TYPED_CHECKERS
        assert validator._CLAIM_TYPE_TO_FACT_TYPE[claim_type] == "filesystem_timeline_fact"
