"""A single-claim finding the validator could not bind is UNVERIFIED, not benign.

Live base-rd01 run (a genuinely compromised host): 10 real-malicious findings --
HIGH PowerShell reflection (Mimikatz/PSReflect), PsExec persistence, PWDumpX
credential dumping, 4648 explicit-credential-logon -- were dumped into the
benign/false-positive bucket purely for being single-claim + unbound
(gate:one_claim_unsupported -> benign:one_claim_weak_or_history_only). That
conflates "the validator could not bind a typed fact" with "this is benign".

Fix: only LOW / SPECULATIVE severity may be buried as benign; a MEDIUM / HIGH /
CRITICAL single-claim finding goes to inconclusive_unresolved -- visible for
review, never silently dropped as an FP. Universal: keys on severity rank only,
no case data. ReAct-confirmed-benign routing (a different, earlier branch) is
unchanged.
"""
from sift_sentinel.analysis.disposition import (
    derive_final_disposition,
    BUCKET_BENIGN,
    BUCKET_INCONCLUSIVE,
)


def _single_claim(severity, confidence="MEDIUM"):
    # No malicious-semantic signal -> the _weak1 branch -> the one-claim floor.
    return {
        "finding_id": "F", "title": "t", "finding_type": "atomic",
        "evidence_type": "memory", "severity": severity,
        "confidence_level": confidence,
        "claims": [{"type": "pid", "pid": 1, "process": "x.exe"}],
        "source_tools": ["vol_pstree"], "raw_excerpt": "x",
    }


def test_high_single_claim_unbound_is_inconclusive_not_benign():
    bucket, reasons = derive_final_disposition(_single_claim("HIGH"))
    assert bucket == BUCKET_INCONCLUSIVE
    assert "benign:one_claim_weak_or_history_only" not in reasons


def test_medium_single_claim_unbound_is_inconclusive_not_benign():
    bucket, _ = derive_final_disposition(_single_claim("MEDIUM"))
    assert bucket == BUCKET_INCONCLUSIVE


def test_low_single_claim_unbound_still_benign():
    bucket, reasons = derive_final_disposition(_single_claim("LOW"))
    assert bucket == BUCKET_BENIGN
    assert "benign:one_claim_weak_or_history_only" in reasons


def test_speculative_single_claim_unbound_still_benign():
    bucket, _ = derive_final_disposition(_single_claim("SPECULATIVE"))
    assert bucket == BUCKET_BENIGN
