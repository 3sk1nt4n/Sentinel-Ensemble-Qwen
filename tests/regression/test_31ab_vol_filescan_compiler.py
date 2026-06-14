"""31AB: vol_filescan → filesystem_listing_fact compiler.

Block 2 deep probe (HEAD 7828e3c) found vol_filescan produced 25,857
records but emitted 0 typed facts because _TOOL_COMPILERS had no
entry for vol_filescan. The filesystem_listing_fact family is in
FACT_TYPES but was 0-count for the same reason (sleuthkit_fls wasn't
selected by Inv1 in this run).

This compiler closes the gap. Tests use the REAL vol_filescan record
shape captured from /tmp/sift-sentinel-run-1779132602_1693:
    {"Name": "\\path", "Offset": int, "TreeDepth": int}
"""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))


def _compiler():
    mod = importlib.import_module("sift_sentinel.analysis.evidence_db")
    return mod._TOOL_COMPILERS.get("vol_filescan")


def test_31ab_compiler_registered_in_tool_compilers():
    """Runtime: _TOOL_COMPILERS contains vol_filescan after PHASE1 merge."""
    c = _compiler()
    assert c is not None, "31AB: vol_filescan compiler not registered"
    assert callable(c), "31AB: compiler is not callable"


def test_31ab_real_records_produce_filesystem_listing_facts():
    """Synthetic harness using real Block 2 record shape."""
    c = _compiler()
    # Real schema from probe:
    records = [
        {"Name": "\\Windows\\System32\\shfolder.dll",
         "Offset": 154518673474608, "TreeDepth": 0},
        {"Name": "\\$Extend\\$RmMetadata\\$Repair",
         "Offset": 154518673450176, "TreeDepth": 0},
        {"Name": "\\CMApi", "Offset": 154518673462992, "TreeDepth": 0},
    ]
    facts = [f for _, f, _ in c(records) if f is not None]
    assert len(facts) == 3, f"31AB: expected 3 facts, got {len(facts)}"
    for f in facts:
        assert f["fact_type"] == "filesystem_listing_fact"
        assert len(f["path"]) > 0
        assert f["flags"] == "memory_resident"
        assert f["confidence_hint"] == "low"
        assert f["inode"].startswith("0x"), \
            f"31AB: inode should be hex offset, got {f['inode']!r}"
        assert "by_path" in f["index"]


def test_31ab_empty_name_skipped_with_reason():
    """Defensive: records without Name field skipped, not crashed."""
    c = _compiler()
    results = list(c([{"Name": "", "Offset": 0, "TreeDepth": 0}]))
    assert len(results) == 1
    i, fact, reason = results[0]
    assert fact is None
    assert reason is not None and "empty" in reason.lower()


def test_31ab_malformed_offset_handled():
    """Defensive: non-numeric Offset doesn't crash; falls back to string."""
    c = _compiler()
    results = list(c([{"Name": "\\test", "Offset": "not_a_number",
                       "TreeDepth": 0}]))
    assert len(results) == 1
    i, fact, reason = results[0]
    assert fact is not None
    assert fact["fact_type"] == "filesystem_listing_fact"
    assert fact["path"] == "\\test"


def test_31ab_non_dict_records_skipped():
    """Defensive: heterogeneous record types don't crash."""
    c = _compiler()
    results = list(c(["string_record", 42, None]))
    assert len(results) == 3
    for i, fact, reason in results:
        assert fact is None
        assert reason == "vol_filescan_record_not_dict"
