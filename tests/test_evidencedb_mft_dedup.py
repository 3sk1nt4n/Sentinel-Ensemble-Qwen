"""Step-7 speed: when BOTH extract_mft_timeline and run_mftecmd are present they
parse the SAME $MFT (100K overlapping path rows -> O(n^2) by_path index inserts,
the 225s-vs-9s build blowup). Compile only the fuller source (run_mftecmd on
disk runs); the other's RAW output still feeds the timeline. Memory-only (no
run_mftecmd) keeps extract_mft_timeline. Universal: redundant-artifact dedup by
tool identity, no case data. Kill-switch SIFT_DEDUP_MFT_COMPILE=0.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis import evidence_db as e  # noqa: E402


def _ok(rc):
    return {"output": [{"x": 1}] * 1, "record_count": rc}


def test_both_present_skips_extract_mft_timeline():
    outs = {"run_mftecmd": _ok(50000), "extract_mft_timeline": _ok(50000)}
    assert e._redundant_mft_to_skip(outs) == {"extract_mft_timeline"}


def test_only_extract_mft_kept_when_no_ecmd():
    outs = {"extract_mft_timeline": _ok(50000)}
    assert e._redundant_mft_to_skip(outs) == set()


def test_ecmd_error_envelope_does_not_trigger_skip():
    outs = {"run_mftecmd": {"error": "boom"}, "extract_mft_timeline": _ok(50000)}
    assert e._redundant_mft_to_skip(outs) == set()


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_DEDUP_MFT_COMPILE", "0")
    outs = {"run_mftecmd": _ok(50000), "extract_mft_timeline": _ok(50000)}
    assert e._redundant_mft_to_skip(outs) == set()


def test_build_skips_redundant_mft_in_coverage():
    outs = {"run_mftecmd": _ok(5), "extract_mft_timeline": _ok(5)}
    db = e.build_typed_evidence_db(outs)
    pt = db["coverage"]["per_tool"]
    # extract_mft_timeline marked skipped (deduped), run_mftecmd compiled.
    assert pt["extract_mft_timeline"]["skipped"] is True
    assert pt["extract_mft_timeline"]["dropped_reasons"].get("redundant_mft_source") == 5
    assert "run_mftecmd" in pt
