from __future__ import annotations

import json
from pathlib import Path

from sift_sentinel.analysis.provenance_taxonomy import (
    classify_provenance_label,
    enforce_state_provenance_taxonomy,
    load_tool_manifest,
)


def _write_state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir()
    (state / "tool_outputs").mkdir()

    (state / "tool_outputs" / "vol_good.json").write_text(
        json.dumps({"records": [{"pid": 1}], "status": "ok"})
    )
    (state / "tool_outputs" / "get_empty.json").write_text(
        json.dumps({"records": [], "status": "not_applicable"})
    )
    (state / "tool_outputs" / "run_appcompatcacheparser.json").write_text(
        json.dumps({"records": [{"path": "x"}], "status": "ok"})
    )

    (state / "finding_disposition_buckets.json").write_text(
        json.dumps(
            {
                "confirmed_malicious_atomic": [
                    {
                        "id": "F1",
                        "title": "valid tool and pseudo backend",
                        "source_tools": ["vol_good", "typed_evidence_db", "check_ancestry"],
                        "claims": [{"type": "pid", "tool": "vol_good"}],
                    },
                    {
                        "id": "F2",
                        "title": "zero tool only should be routed",
                        "source_tools": ["get_empty"],
                        "claims": [{"type": "path", "tool": "get_empty"}],
                    },
                    {
                        "id": "F3",
                        "title": "alias should canonicalize",
                        "source_tools": ["parse_appcompatcacheparser"],
                    },
                ],
                "suspicious_needs_review": [],
                "inconclusive_unresolved": [],
                "benign_or_false_positive": [],
                "synthesis_narrative": [],
            }
        )
    )
    return state


def test_taxonomy_classifies_real_zero_and_non_tool(tmp_path):
    state = _write_state(tmp_path)
    manifest = load_tool_manifest(state)

    assert classify_provenance_label("vol_good", manifest)["class"] == "real_data_producing_tool"
    assert classify_provenance_label("get_empty", manifest)["class"] == "zero_or_nonhit_tool"
    assert classify_provenance_label("typed_evidence_db", manifest)["class"] == "non_tool_provenance"


def test_repair_moves_pseudo_sources_and_routes_zero_only(tmp_path):
    state = _write_state(tmp_path)

    before = enforce_state_provenance_taxonomy(state, repair=False)
    assert before["status"] == "fail"

    fixed = enforce_state_provenance_taxonomy(state, repair=True)
    assert fixed["status"] == "pass"
    assert fixed["removed_refs"] >= 1
    assert fixed["moved_non_tool_refs"] >= 2

    buckets = json.loads((state / "finding_disposition_buckets.json").read_text())
    confirmed_ids = [f["id"] for f in buckets["confirmed_malicious_atomic"]]
    inconclusive_ids = [f["id"] for f in buckets["inconclusive_unresolved"]]

    assert "F1" in confirmed_ids
    assert "F2" not in confirmed_ids
    assert "F2" in inconclusive_ids

    f1 = next(f for f in buckets["confirmed_malicious_atomic"] if f["id"] == "F1")
    assert f1["source_tools"] == ["vol_good"]
    assert "typed_evidence_db" in f1["validation_backends"]
    assert "check_ancestry" in f1["rule_ids"]

    f3 = next(f for f in buckets["confirmed_malicious_atomic"] if f["id"] == "F3")
    assert f3["source_tools"] == ["run_appcompatcacheparser"]


def test_repaired_state_gate_passes(tmp_path):
    state = _write_state(tmp_path)
    enforce_state_provenance_taxonomy(state, repair=True)
    result = enforce_state_provenance_taxonomy(state, repair=False)
    assert result["status"] == "pass"
