"""THE GENERATION FIX - deterministic emission of behavioral candidates.

Root cause (proven in live runs): a validation-ready, non-weak behavioral
candidate (e.g. archive_in_staging_path at prompt rank 17) produced ZERO findings
because the models anchored on memory-RWX and never wrote it up. The floor/ReAct
guards can only act on a finding that EXISTS. This module emits such candidates
as findings BY CONSTRUCTION (model enriches, doesn't gatekeep), mirroring
ancestry_findings. Dataset-agnostic: keys on registered signal names + the
candidate's own entity; no case literals.
"""
from __future__ import annotations

from sift_sentinel.analysis.candidate_findings import (
    build_candidate_semantic_findings,
    _EMIT_ELIGIBLE,
)


def _cand(entity_key, signals, ctype="x", ready=True, score=120, cid="cand-0001",
          tools=("run_appcompatcacheparser",)):
    return {
        "candidate_id": cid,
        "candidate_type": ctype,
        "entity_key": entity_key,
        "validation_ready": ready,
        "signals": list(signals),
        "score": score,
        "source_tools": list(tools),
        "fact_ids": ["file_execution_fact-1"],
    }


def test_validation_ready_behavioral_candidate_becomes_a_finding():
    # The exact failure mode: a strong behavioral candidate the models ignored.
    obs = {"candidates": [
        _cand("path:c:/users/fred/downloads/sdelete64.exe",
              ["anti_forensics_execution"], ctype="defense_evasion_anti_forensics"),
    ]}
    out = build_candidate_semantic_findings(obs, existing_findings=[])
    assert len(out) == 1, out
    f = out[0]
    assert f["deterministic_finding"] is True
    assert "anti_forensics_execution" in f["malicious_semantic_signals"]
    assert f["claims"] and f["claims"][0]["type"] == "path"
    assert f["finding_id"].startswith("F")


def test_egress_signal_maps_to_registry_semantic_name():
    obs = {"candidates": [
        _cand("path:c:/dir/exfil.exe", ["srum_egress_self_relative_outlier"],
              ctype="data_exfiltration_egress_outlier", tools=("run_srumecmd",)),
    ]}
    out = build_candidate_semantic_findings(obs, existing_findings=[])
    assert len(out) == 1
    # candidate-side signal name maps to the disposition/registry name.
    assert out[0]["malicious_semantic_signals"] == ["srum_egress_outlier"]


def test_skips_non_ready_and_non_eligible():
    obs = {"candidates": [
        _cand("path:a", ["anti_forensics_execution"], ready=False),     # not ready
        _cand("pid:5", ["rwx_memory_region_with_unusual_protection"]),  # not eligible
        _cand("path:b", ["srum_network_usage_context"]),                # weak/context only
    ]}
    assert build_candidate_semantic_findings(obs, existing_findings=[]) == []


def test_dedupes_against_existing_model_finding_same_entity():
    # The model already wrote a finding for this PID -> do NOT emit a duplicate.
    existing = [{"finding_id": "F003", "claims": [
        {"type": "pid", "pid": 1248, "process": "svchost.exe"}]}]
    obs = {"candidates": [
        _cand("process:svchost.exe:1248", ["anti_forensics_execution"]),
    ]}
    assert build_candidate_semantic_findings(obs, existing_findings=existing) == []


def test_finding_ids_continue_after_existing():
    existing = [{"finding_id": "F041", "claims": []}]
    obs = {"candidates": [
        _cand("path:c:/x/sdelete.exe", ["anti_forensics_execution"]),
    ]}
    out = build_candidate_semantic_findings(obs, existing_findings=existing)
    assert out[0]["finding_id"] == "F042"


def test_per_family_claims_from_evidence_db():
    # (A): SDelete attested by amcache (path+sha1) + MFT (path) -> the finding
    # carries a path claim AND a hash claim = two distinct validatable claims,
    # so it clears the disposition one-claim gate honestly (-> needs-review).
    edb = {"typed_facts": {
        "file_execution_fact": [
            {"fact_id": "fe-1", "path": "c:/users/fred/downloads/sdelete/sdelete.exe",
             "sha1": "7bcd946326b67f806b3db4595ede9fbdf29d0c36"}],
        "filesystem_timeline_fact": [
            {"fact_id": "mft-1", "path": "c:/users/fred/downloads/sdelete/sdelete.exe"}],
    }}
    c = _cand("path:c:/users/fred/downloads/sdelete/sdelete.exe",
              ["anti_forensics_execution"], cid="cand-1",
              tools=("get_amcache", "extract_mft_timeline"))
    c["fact_ids"] = ["fe-1", "mft-1"]
    out = build_candidate_semantic_findings({"candidates": [c]},
                                            existing_findings=[], evidence_db=edb)
    assert len(out) == 1
    types = sorted({cl["type"] for cl in out[0]["claims"]})
    assert "path" in types and "hash" in types, types
    assert len(out[0]["claims"]) >= 2


def test_falls_back_to_single_entity_claim_without_evidence_db():
    # No evidence_db -> entity_key claim (single). Still emits; (B) backstop covers
    # routing for genuinely single-attribute evidence.
    c = _cand("path:c:/x/sdelete.exe", ["anti_forensics_execution"])
    out = build_candidate_semantic_findings({"candidates": [c]}, existing_findings=[])
    assert len(out) == 1 and out[0]["claims"][0]["type"] == "path"


def test_emit_eligible_names_are_registered_semantics():
    # Every emit target must be a real registered malicious_semantic (no typos).
    from sift_sentinel.analysis.malicious_semantics import MALICIOUS_SEMANTIC_SIGNALS
    for registry_name in _EMIT_ELIGIBLE.values():
        assert registry_name in MALICIOUS_SEMANTIC_SIGNALS, registry_name
