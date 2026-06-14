"""Confirmed-bucket calibration (Fix B): validator-backed is not the same as
confidently malicious. A LOW-severity AND LOW-confidence "confirmed" finding (e.g. a
monitoring-agent installer staged in a temp dir) is demoted to needs-review -- still
surfaced, just not headlined as confirmed. Universal: keyed on the finding's own
severity+confidence only, no case literal. Never promotes.
"""
from sift_sentinel.analysis.signature_reconcile import demote_lowconfidence_confirmed


def _f(fid, sev, conf):
    return {"finding_id": fid, "severity": sev, "confidence": conf,
            "claims": [{"type": "path", "value": "c:/windows/temp/x.exe"}]}


def _b(confirmed):
    return {"confirmed_malicious_atomic": list(confirmed),
            "suspicious_needs_review": [], "benign_or_false_positive": [],
            "inconclusive_unresolved": [], "synthesis_narrative": []}


def test_low_low_confirmed_demoted():
    new, ledger = demote_lowconfidence_confirmed(_b([_f("F019", "LOW", "LOW")]))
    assert new["confirmed_malicious_atomic"] == []
    assert "F019" in {f["finding_id"] for f in new["suspicious_needs_review"]}
    assert len(ledger) == 1 and ledger[0]["to"] == "suspicious_needs_review"


def test_low_speculative_demoted():
    new, ledger = demote_lowconfidence_confirmed(_b([_f("X", "LOW", "SPECULATIVE")]))
    assert new["confirmed_malicious_atomic"] == []
    assert "X" in {f["finding_id"] for f in new["suspicious_needs_review"]}


def test_medium_confidence_confirmed_stays():
    new, ledger = demote_lowconfidence_confirmed(_b([_f("F006", "MEDIUM", "MEDIUM")]))
    assert "F006" in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}
    assert ledger == []


def test_high_severity_low_conf_stays():       # not BOTH low
    new, ledger = demote_lowconfidence_confirmed(_b([_f("Z", "HIGH", "LOW")]))
    assert "Z" in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}
    assert ledger == []


def test_low_sev_high_conf_stays():            # not BOTH low
    new, ledger = demote_lowconfidence_confirmed(_b([_f("Q", "LOW", "HIGH")]))
    assert "Q" in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}


def test_missing_confidence_not_demoted():     # absent signal -> never demote
    new, ledger = demote_lowconfidence_confirmed(_b([_f("Y", "LOW", "")]))
    assert "Y" in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}
    assert ledger == []


def test_critical_high_stays():
    new, ledger = demote_lowconfidence_confirmed(_b([_f("F035", "CRITICAL", "HIGH")]))
    assert ledger == []


def test_only_the_weak_one_moves():
    new, ledger = demote_lowconfidence_confirmed(
        _b([_f("F019", "LOW", "LOW"), _f("F035", "CRITICAL", "HIGH")]))
    assert {f["finding_id"] for f in new["confirmed_malicious_atomic"]} == {"F035"}
    assert {f["finding_id"] for f in new["suspicious_needs_review"]} == {"F019"}
