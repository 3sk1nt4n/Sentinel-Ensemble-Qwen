"""slot31AV-beta regression: phase2 _c_reg_hivelist extractor.

Property-based tests with secrets.token_hex random tokens. Dataset-
agnostic. _c_reg_hivelist consumes vol_reg_hivelist records and emits
registry_hive_fact (structural metadata, no judgment).
"""
import secrets
from sift_sentinel.analysis.phase2_extractors import _c_reg_hivelist


def _records_from(*recs):
    """Pass records through _c_reg_hivelist, collect facts + skips."""
    facts = []
    skips = []
    for idx, fact, reason in _c_reg_hivelist(recs):
        if fact is not None:
            facts.append((idx, fact))
        else:
            skips.append((idx, reason))
    return facts, skips


def test_valid_hive_path_emits_fact():
    rnd = secrets.token_hex(4)
    rec = {
        "FileFullPath": "\\REGISTRY\\MACHINE\\TEST_" + rnd,
        "Offset": 100000 + secrets.randbelow(900000),
        "TreeDepth": 0,
    }
    facts, skips = _records_from(rec)
    assert len(facts) == 1
    assert len(skips) == 0
    fact = facts[0][1]
    assert fact["fact_type"] == "registry_hive_fact"
    assert fact["hive_path"] == "\\REGISTRY\\MACHINE\\TEST_" + rnd
    assert fact["entity_id"].startswith("hive:/registry/machine/test_")


def test_empty_hive_path_skipped():
    rec = {"FileFullPath": "", "Offset": 12345, "TreeDepth": 0}
    facts, skips = _records_from(rec)
    assert len(facts) == 0
    assert len(skips) == 1
    assert skips[0][1] == "empty_hive_path"


def test_missing_hive_path_skipped():
    rec = {"Offset": 12345, "TreeDepth": 0}
    facts, skips = _records_from(rec)
    assert len(facts) == 0
    assert skips[0][1] == "empty_hive_path"


def test_non_dict_record_skipped():
    facts, skips = _records_from("not_a_dict", 42, None)
    assert len(facts) == 0
    assert len(skips) == 3
    for _, reason in skips:
        assert reason == "non_dict_record"


def test_backslash_normalization_in_entity_id():
    rnd = secrets.token_hex(3)
    rec = {
        "FileFullPath": "\\SystemRoot\\System32\\Config\\" + rnd,
        "Offset": 0,
    }
    facts, _ = _records_from(rec)
    fact = facts[0][1]
    assert "\\" not in fact["entity_id"]
    assert fact["entity_id"].startswith("hive:/systemroot/system32/config/")


def test_multiple_records_distinct_entity_ids():
    recs = []
    for _ in range(5):
        recs.append({
            "FileFullPath": "\\REGISTRY\\USER\\" + secrets.token_hex(4),
            "Offset": secrets.randbelow(1000000),
        })
    facts, _ = _records_from(*recs)
    assert len(facts) == 5
    eids = [f[1]["entity_id"] for f in facts]
    assert len(set(eids)) == 5, "expected 5 distinct entity_ids"


def test_compiler_registered_in_PHASE2_COMPILERS():
    from sift_sentinel.analysis.phase2_extractors import (
        PHASE2_COMPILERS, PHASE2_FACT_TYPES,
    )
    assert "vol_reg_hivelist" in PHASE2_COMPILERS
    assert PHASE2_COMPILERS["vol_reg_hivelist"] is _c_reg_hivelist
    assert "registry_hive_fact" in PHASE2_FACT_TYPES
