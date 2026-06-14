"""31AI regression: entity-context map exposes cross-bucket entity overlap.

V3 triple-side:
  A=static     - entity_context.py parses; run_pipeline.py calls function
  B=runtime    - build_entity_context_map importable and callable
  C=behavioral - synthetic buckets exercise all rule paths and edges

DATASET-AGNOSTIC ABSOLUTE: all inputs synthesized at runtime; no
hardcoded PIDs/paths/IPs/hashes/fixtures.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTITY_CTX = REPO_ROOT / "src" / "sift_sentinel" / "analysis" / "entity_context.py"


def _runtime_forbidden_tokens():
    parts = [
        ("r", "d", "-", "0", "1"),
        ("r", "d", "0", "1"),
        ("/", "c", "ases", "/evidence"),
        ("/", "m", "nt", "/", "r", "d", "0", "1"),
        ("s", "ansf", "or", "ensics"),
    ]
    return ["".join(p) for p in parts]


def test_31ai_static_module_parses():
    src = ENTITY_CTX.read_text(encoding="utf-8")
    ast.parse(src)
    assert "def _entity_keys_from_claims" in src
    assert "def build_entity_context_map" in src


def test_31ai_static_run_pipeline_calls_function():
    src = (REPO_ROOT / "run_pipeline.py").read_text(encoding="utf-8")
    assert "31AI: entity-context map" in src
    assert "build_entity_context_map(_disposition_buckets)" in src


def test_31ai_no_forbidden_tokens_in_module():
    src = ENTITY_CTX.read_text(encoding="utf-8")
    leaked = [tok for tok in _runtime_forbidden_tokens() if tok in src]
    assert not leaked, f"entity_context.py leaked: {leaked}"


def test_31ai_runtime_importable():
    from sift_sentinel.analysis.entity_context import build_entity_context_map
    assert callable(build_entity_context_map)


def test_31ai_entity_keys_pid_variants():
    from sift_sentinel.analysis.entity_context import _entity_keys_from_claims
    assert _entity_keys_from_claims([{"type": "pid", "pid": 7}]) == {"pid:7"}
    assert _entity_keys_from_claims([{"type": "process_exists", "pid": 42}]) == {"pid:42"}
    assert _entity_keys_from_claims([{"type": "pid", "value": 13}]) == {"pid:13"}


def test_31ai_entity_keys_path_normalization():
    from sift_sentinel.analysis.entity_context import _entity_keys_from_claims
    keys = _entity_keys_from_claims([
        {"type": "path", "value": "\\??\\C:\\Windows\\Synth.sys"},
    ])
    assert keys == {"path:c:\\windows\\synth.sys"}
    keys2 = _entity_keys_from_claims([{"type": "path", "value": "/Tmp/SYNTH.exe"}])
    assert keys2 == {"path:/tmp/synth.exe"}


def test_31ai_entity_keys_connection():
    from sift_sentinel.analysis.entity_context import _entity_keys_from_claims
    keys = _entity_keys_from_claims([
        {"type": "connection", "local_port": 3262, "remote": "10.0.0.1:443"},
    ])
    assert "port:3262" in keys
    assert "endpoint:10.0.0.1:443" in keys


def test_31ai_entity_keys_hash():
    from sift_sentinel.analysis.entity_context import _entity_keys_from_claims
    keys = _entity_keys_from_claims([{"type": "hash", "value": "ABCDEF1234567890"}])
    assert keys == {"hash:abcdef1234567890"}


def test_31ai_entity_keys_empty_or_malformed():
    from sift_sentinel.analysis.entity_context import _entity_keys_from_claims
    assert _entity_keys_from_claims([]) == set()
    assert _entity_keys_from_claims(None) == set()
    assert _entity_keys_from_claims([{"type": "unknown"}]) == set()
    assert _entity_keys_from_claims([{"type": "pid"}]) == set()
    assert _entity_keys_from_claims(["not_a_dict"]) == set()


def test_31ai_propagation_fp_inherited():
    from sift_sentinel.analysis.entity_context import (
        build_entity_context_map, BUCKET_BENIGN,
    )
    buckets = {
        BUCKET_BENIGN: [{"finding_id": "FP1",
                         "claims": [{"type": "pid", "pid": 100}],
                         "react_conclusion": "synthetic_benign"}],
        "suspicious_needs_review": [{"finding_id": "WK1",
                                     "claims": [{"type": "process_exists", "pid": 100}]}],
    }
    out = build_entity_context_map(buckets)
    assert out["WK1"]["entity_react_refuted_by"] == ["FP1"]
    assert "FP1" in out["WK1"]["shares_entity_with"]


def test_31ai_propagation_confirmed_inherited():
    from sift_sentinel.analysis.entity_context import (
        build_entity_context_map, BUCKET_CONFIRMED,
    )
    buckets = {
        BUCKET_CONFIRMED: [{"finding_id": "CM1",
                            "claims": [{"type": "path", "value": "/synth/bad.exe"}]}],
        "inconclusive_unresolved": [{"finding_id": "WK2",
                                     "claims": [{"type": "path", "value": "/SYNTH/BAD.exe"}]}],
    }
    out = build_entity_context_map(buckets)
    assert out["WK2"]["entity_react_confirmed_by"] == ["CM1"]


def test_31ai_propagation_no_overlap():
    from sift_sentinel.analysis.entity_context import (
        build_entity_context_map, BUCKET_BENIGN,
    )
    buckets = {
        BUCKET_BENIGN: [{"finding_id": "FP_a", "claims": [{"type": "pid", "pid": 1}],
                        "react_conclusion": "x"}],
        "suspicious_needs_review": [{"finding_id": "WK_a", "claims": [{"type": "pid", "pid": 999}]}],
    }
    out = build_entity_context_map(buckets)
    assert out["WK_a"]["entity_react_refuted_by"] == []
    assert out["WK_a"]["shares_entity_with"] == []


def test_31ai_fp_without_react_conclusion_doesnt_propagate():
    from sift_sentinel.analysis.entity_context import (
        build_entity_context_map, BUCKET_BENIGN,
    )
    buckets = {
        BUCKET_BENIGN: [{"finding_id": "FP_no_rc",
                         "claims": [{"type": "pid", "pid": 50}]}],
        "suspicious_needs_review": [{"finding_id": "WK_x",
                                     "claims": [{"type": "process_exists", "pid": 50}]}],
    }
    out = build_entity_context_map(buckets)
    assert out["WK_x"]["entity_react_refuted_by"] == []
    assert "FP_no_rc" in out["WK_x"]["shares_entity_with"]


def test_31ai_empty_buckets_returns_empty():
    from sift_sentinel.analysis.entity_context import build_entity_context_map
    assert build_entity_context_map({}) == {}
    assert build_entity_context_map(None) == {}


def test_31ai_findings_without_id_skipped():
    from sift_sentinel.analysis.entity_context import build_entity_context_map
    buckets = {"suspicious_needs_review": [
        {"claims": [{"type": "pid", "pid": 1}]},
        {"finding_id": "GOOD", "claims": [{"type": "pid", "pid": 2}]},
    ]}
    out = build_entity_context_map(buckets)
    assert "GOOD" in out
    assert len(out) == 1


def test_31ai_reciprocal_shares():
    from sift_sentinel.analysis.entity_context import (
        build_entity_context_map, BUCKET_BENIGN,
    )
    buckets = {
        BUCKET_BENIGN: [{"finding_id": "FP", "claims": [{"type": "pid", "pid": 7}],
                        "react_conclusion": "x"}],
        "suspicious_needs_review": [{"finding_id": "WK", "claims": [{"type": "pid", "pid": 7}]}],
    }
    out = build_entity_context_map(buckets)
    assert "WK" in out["FP"]["shares_entity_with"]
    assert "FP" in out["WK"]["shares_entity_with"]


def test_31ai_path_case_insensitive_match():
    from sift_sentinel.analysis.entity_context import (
        build_entity_context_map, BUCKET_CONFIRMED,
    )
    buckets = {
        BUCKET_CONFIRMED: [{"finding_id": "CM",
                            "claims": [{"type": "path", "value": "/Synth/Bad.exe"}]}],
        "suspicious_needs_review": [{"finding_id": "WK",
                                     "claims": [{"type": "path", "value": "/SYNTH/bad.EXE"}]}],
    }
    out = build_entity_context_map(buckets)
    assert out["WK"]["entity_react_confirmed_by"] == ["CM"]
