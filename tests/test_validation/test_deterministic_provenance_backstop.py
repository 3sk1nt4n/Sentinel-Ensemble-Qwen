"""(B) SIFT_DETERMINISTIC_PROVENANCE_V1 — provenance backstop for single-claim
deterministic behavioral findings.

A deterministically-emitted finding (candidate_findings) carrying a registered
non-weak semantic WITH provenance is grounded by construction -- like ancestry
deterministic findings. When the evidence is genuinely single-attribute (one
path, no hash/pid), the disposition one-claim gate would otherwise demote it to
INCONCLUSIVE; (B) routes it to needs-review instead. Scoped strictly to
deterministic_finding so model single-claim findings are untouched. Review-only:
never confirms. Dataset-agnostic: keys on the deterministic flag + registered
semantic + provenance, no case literal.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    derive_final_disposition,
)


def _det_finding(deterministic=True, signal="anti_forensics_execution", provenance=True):
    f = {
        "finding_id": "F047",
        "title": "anti-forensics: single-claim",
        "claims": [{"type": "path", "path": "users/x/downloads/sdelete.exe"}],
        "malicious_semantic_signals": [signal],
    }
    if deterministic:
        f["deterministic_finding"] = True
        f["deterministic_kind"] = "candidate_semantic"
    if provenance:
        f["malicious_semantic_provenance"] = {signal: {"source": "candidate_observation"}}
    return f


def test_single_claim_deterministic_behavioral_routes_to_needs_review():
    bucket, reasons = derive_final_disposition(_det_finding())
    assert bucket == BUCKET_SUSPICIOUS, reasons
    assert any("deterministic_provenance_backed" in r for r in reasons), reasons


def test_scoped_to_deterministic_only_model_finding_stays_inconclusive():
    # Same shape but NOT deterministic -> the backstop must not fire (no widening
    # of model single-claim findings).
    bucket, _ = derive_final_disposition(_det_finding(deterministic=False))
    assert bucket == BUCKET_INCONCLUSIVE


def test_requires_provenance():
    # Deterministic but no provenance -> falls through to inconclusive (no free pass).
    bucket, _ = derive_final_disposition(_det_finding(provenance=False))
    assert bucket == BUCKET_INCONCLUSIVE


def test_inhibit_and_egress_signals_also_backstopped():
    for sig in ("inhibit_system_recovery", "srum_egress_outlier",
                "archive_in_staging_path"):
        bucket, _ = derive_final_disposition(_det_finding(signal=sig))
        assert bucket == BUCKET_SUSPICIOUS, sig
