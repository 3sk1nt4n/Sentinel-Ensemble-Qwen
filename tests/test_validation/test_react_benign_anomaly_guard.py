"""SIFT_REACT_BENIGN_VS_ANOMALY_V1 (Fix B).

A ReAct "the program is legitimate software" benign verdict must NOT silently
bury a finding that carries a deterministic behavioral-anomaly semantic. Those
semantics (egress outlier vs the image's own baseline, data archived into a
staging path, system-recovery sabotage) describe ANOMALOUS ACTIVITY, not binary
identity -- so binary legitimacy does not refute them. Such a finding is held
for human review (suspicious_needs_review) instead of routed to benign.

Root cause this guards: on the insider-theft image, ReAct concluded every
exfil-channel finding benign ("OneDrive/RDP is legitimate software") and the
unconditional benign override buried them -- 0 surfaced. Dataset-agnostic:
keys only on the registered signal CLASS; no host/IP/path/process literal.
"""
from __future__ import annotations

import pytest

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_SUSPICIOUS,
    derive_final_disposition,
)


def _benign_verdict_finding(signals):
    """Minimal finding carrying a ReAct confirmed_benign verdict and the given
    declared (registry-known) malicious_semantic_signals. The benign override is
    reached before any later gate, so no other gate-clearing fields are needed."""
    return {
        "finding_id": "F001",
        "title": "synthetic finding",
        "claims": [{"type": "pid", "pid": 1000, "process": "a.exe"}],
        "malicious_semantic_signals": list(signals),
        "react_conclusion": {"verdict": "confirmed_benign",
                             "is_false_positive": True},
    }


@pytest.mark.parametrize("signal", [
    "srum_egress_outlier",
    "archive_in_staging_path",
    "inhibit_system_recovery",
])
def test_react_benign_cannot_bury_behavioral_anomaly(signal):
    f = _benign_verdict_finding([signal])
    bucket, reasons = derive_final_disposition(f)
    assert bucket == BUCKET_SUSPICIOUS, (signal, reasons)
    assert any("behavioral_anomaly" in r for r in reasons), reasons


def test_react_benign_still_buries_plain_finding():
    # Regression: a finding with NO behavioral-anomaly semantic (here a weak-alone
    # RWX signal) and a benign verdict still routes to benign -- the guard is
    # narrow and does not blunt the benign override for ordinary FPs.
    f = _benign_verdict_finding(["rwx_memory_region_with_unusual_protection"])
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_BENIGN


def test_react_benign_with_no_semantic_still_benign():
    f = _benign_verdict_finding([])
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_BENIGN
