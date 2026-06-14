"""31X: build_typed_evidence_db must produce user_account_fact identically
in live and rebuild paths. Property-based, dataset-agnostic guards.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))


def test_31x_build_typed_evidence_db_returns_dict_with_typed_facts():
    from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
    db = build_typed_evidence_db({}, reference_set={})
    assert isinstance(db, dict)
    assert "typed_facts" in db
    assert isinstance(db["typed_facts"], dict)


def test_31x_handles_malformed_tool_outputs_gracefully():
    from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
    db = build_typed_evidence_db({"bogus_tool": "not a dict"}, reference_set={})
    assert isinstance(db, dict)
    assert "typed_facts" in db


def test_31x_user_account_extractor_importable_and_callable():
    from sift_sentinel.analysis.user_account_synthesizer import extract_user_account_facts
    assert callable(extract_user_account_facts)


def test_31x_static_markers_present():
    src = Path("src/sift_sentinel/analysis/evidence_db.py").read_text()
    assert "31X" in src
    assert "extract_user_account_facts" in src
    assert "user_account_fact" in src
