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
            fact.get("source_path"),
            fact.get("normalized_path"),
        ):
            if value:
                n = normalize_path(str(value))
                if n:
                    indexes["by_path"].setdefault(n, []).append(fid)
    return tv.TypedEvidenceDB({
        "typed_facts": {"rdp_artifact_fact": facts},
        "indexes": indexes,
    })


def _fact(**overrides):
    base = {
        "fact_id": "rdp_artifact_fact-1",
        "fact_type": "rdp_artifact_fact",
        "artifact_type": "connection_history",
        "path": "/generic/profile/rdp-cache.bin",
        "normalized_path": normalize_path("/generic/profile/rdp-cache.bin"),
        "user": "generic-user",
        "remote_host": "remote.example.internal",
        "timestamp": "2026-01-01T00:00:00Z",
        "source_tool": "parse_rdp_artifacts",
        "artifact": [
            "connection_history",
            "/generic/profile/rdp-cache.bin",
            "remote.example.internal",
            "generic-user",
        ],
    }
    base.update(overrides)
    return base


def test_rdp_artifact_matches_exact_path():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "rdp_artifact", "path": "/generic/profile/rdp-cache.bin"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_rdp_artifact_matches_contains():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "rdp_artifact", "contains": "rdp-cache"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_rdp_artifact_matches_user_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "rdp_artifact", "user": "generic-user"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_rdp_artifact_matches_remote_host_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "rdp_artifact", "remote_host": "remote.example.internal"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_rdp_artifact_matches_artifact_type_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "rdp_artifact", "artifact_type": "connection_history"},
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_rdp_artifact_matches_timestamp_constraint():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "rdp_artifact",
            "path": "/generic/profile/rdp-cache.bin",
            "timestamp": "2026-01-01",
        },
        tdb,
    )
    assert out and out[0] == "MATCH"


def test_rdp_artifact_mismatches_wrong_path_when_facts_exist():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {"type": "rdp_artifact", "path": "/generic/other/rdp-cache.bin"},
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_rdp_artifact_mismatches_wrong_host():
    tdb = _db([_fact()])
    out = tv.typed_check_claim(
        {
            "type": "rdp_artifact",
            "path": "/generic/profile/rdp-cache.bin",
            "host": "other.example.internal",
        },
        tdb,
    )
    assert out and out[0] == "MISMATCH"


def test_rdp_artifact_without_constraints_falls_back():
    tdb = _db([_fact()])
    assert tv.typed_check_claim({"type": "rdp_artifact"}, tdb) is None


def test_rdp_artifact_supported_and_mapped():
    assert "rdp_artifact" in tv.TYPED_SUPPORTED_CLAIM_TYPES
    assert "rdp_artifact" in tv._TYPED_CHECKERS
    assert validator._CLAIM_TYPE_TO_FACT_TYPE["rdp_artifact"] == "rdp_artifact_fact"
