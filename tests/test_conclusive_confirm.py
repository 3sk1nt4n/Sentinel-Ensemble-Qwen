"""SIFT_CONCLUSIVE_CONFIRM (default OFF): a forensically-conclusive structural
signal may auto-confirm without corroboration count.

Property-based requirements:
  (a) a conclusive-structural finding auto-confirms (flag ON);
  (b) a NON-conclusive finding with the SAME corroboration count does NOT
      auto-confirm -- proving the predicate is the SIGNAL TYPE, not the count;
  (c) zero false-confirms: flag OFF restores prior routing, a ReAct-benign
      verdict still wins, and an ineligible finding does not confirm.

Synthetic values only; the predicate keys on signal type + driver-path shape,
never a product / case / hash / PID literal.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_SUSPICIOUS,
    derive_final_disposition,
)


def _reg_imagepath(path, service="genericsvc"):
    return {
        "fact_type": "registry_persistence_fact",
        "normalized_registry_path":
            "hklm/system/controlset001/services/%s/imagepath" % service,
        "value_name": "ImagePath", "value_data": path, "service_name": service,
        "fact_id": "registry_persistence_fact-0",
    }


# 7045 service-install excerpt carrying a kernel driver at a non-standard path:
# the matcher fires on this (its support comes from a real fact excerpt, not a
# bare declared string). Synthetic driver name, no case literal.
_DRIVER_EXCERPT = (
    "Service Control Manager: A service was installed (Event 7045). "
    "Service Name: genericsvc  ImagePath: \\??\\C:\\windows\\drv.sys  "
    "Service Type: kernel mode driver")


def _base_eligible(n_tools=2, excerpt=_DRIVER_EXCERPT):
    # A fully-formed POST-VALIDATION finding (the shape Step 10 produces): the
    # conclusive-confirm path requires the full evidence chain, so the fixture
    # carries tool_call_ids, raw_excerpt, and validator-attached typed_fact_refs.
    tools = ["parse_event_logs", "parse_registry_persistence",
             "extract_mft_timeline", "vol_filescan"][:n_tools]
    return {
        "confidence_level": "MEDIUM", "severity": "HIGH",
        "deterministic_finding": True, "deterministic_kind": "candidate_semantic",
        "source_tools": list(tools), "tool_call_ids": list(tools),
        "raw_excerpt": excerpt,
        "validation_status": "match",
        "typed_fact_refs": ["event_log_fact-0", "registry_persistence_fact-0"],
    }


def _conclusive_finding(n_tools=2):
    # Single-claim, like the real Event-7045 driver finding: without the flag a
    # single-claim deterministic finding is capped at review; the conclusive
    # flag is what releases it to confirmed.
    f = _base_eligible(n_tools)
    f.update({
        "finding_id": "F1", "title": "kernel driver service install",
        "malicious_semantic_signals": ["kernel_driver_nonstandard_path"],
        "malicious_semantic_provenance": {
            "kernel_driver_nonstandard_path": {"source": "candidate_observation"}},
        "claims": [{"type": "event_log", "event_id": 7045,
                    "fact_id": "event_log_fact-0"}],
    })
    return f


def _nonconclusive_finding(n_tools=2):
    # SAME corroboration count + same single-claim eligible shape, NON-conclusive
    f = _base_eligible(n_tools, excerpt="SRUM: outbound bytes 9907279800 (outlier)")
    f.update({
        "finding_id": "F2", "title": "srum egress outlier",
        "severity": "MEDIUM",
        "malicious_semantic_signals": ["srum_egress_outlier"],
        "malicious_semantic_provenance": {
            "srum_egress_outlier": {"source": "candidate_observation"}},
        "claims": [{"type": "srum_usage", "value": "9907279800",
                    "fact_id": "srum_usage_fact-0"}],
    })
    return f


def _evdb():
    return {"typed_facts": {}}


# ── (a) conclusive auto-confirms when the flag is ON ─────────────────────

def test_conclusive_auto_confirms_flag_on(monkeypatch):
    monkeypatch.setenv("SIFT_CONCLUSIVE_CONFIRM", "1")
    bucket, reasons = derive_final_disposition(_conclusive_finding(), _evdb())
    assert bucket == BUCKET_CONFIRMED, reasons
    assert any("conclusive_structural" in r for r in reasons)


# ── (b) SAME corroboration, non-conclusive signal -> NOT auto-confirmed ───

def test_nonconclusive_same_corroboration_not_confirmed(monkeypatch):
    monkeypatch.setenv("SIFT_CONCLUSIVE_CONFIRM", "1")
    # identical tool count to the conclusive case
    c_bucket, _ = derive_final_disposition(_conclusive_finding(n_tools=4), _evdb())
    n_bucket, _ = derive_final_disposition(_nonconclusive_finding(n_tools=4), _evdb())
    assert c_bucket == BUCKET_CONFIRMED
    assert n_bucket != BUCKET_CONFIRMED          # predicate is signal type, not count


# ── (c) zero false-confirms ──────────────────────────────────────────────

def test_flag_off_does_not_confirm(monkeypatch):
    monkeypatch.delenv("SIFT_CONCLUSIVE_CONFIRM", raising=False)
    bucket, _ = derive_final_disposition(_conclusive_finding(), _evdb())
    assert bucket != BUCKET_CONFIRMED            # default OFF -> prior routing


def test_react_benign_still_wins(monkeypatch):
    monkeypatch.setenv("SIFT_CONCLUSIVE_CONFIRM", "1")
    f = _conclusive_finding()
    f["react_conclusion"] = {"is_false_positive": True,
                             "verdict": "confirmed_benign",
                             "text": "signed vendor driver, legitimate"}
    bucket, reasons = derive_final_disposition(f, _evdb())
    assert bucket != BUCKET_CONFIRMED, reasons   # a benign verdict is never overridden


def test_benign_driver_in_driverstore_never_conclusive(monkeypatch):
    # a legit driver under System32\drivers: the matcher returns no conclusive
    # signal (driver store excluded), so even with the flag ON it cannot reach
    # the conclusive-confirm path
    monkeypatch.setenv("SIFT_CONCLUSIVE_CONFIRM", "1")
    f = _base_eligible(excerpt=(
        "Service Control Manager: A service was installed (Event 7045). "
        "ImagePath: \\??\\C:\\Windows\\System32\\drivers\\legit.sys"))
    f.update({
        "finding_id": "F3", "title": "driver service install",
        "severity": "MEDIUM", "malicious_semantic_signals": [],
        "claims": [_reg_imagepath(r"\??\C:\Windows\System32\drivers\legit.sys",
                                  service="legit")],
    })
    bucket, reasons = derive_final_disposition(f, _evdb())
    assert bucket != BUCKET_CONFIRMED, reasons


def test_metamorphic_driver_relabel_same_verdict(monkeypatch):
    # relabel the service/title -> identical CONFIRMED verdict (no case literal)
    monkeypatch.setenv("SIFT_CONCLUSIVE_CONFIRM", "1")
    def run(svc):
        f = _conclusive_finding()
        f["finding_id"] = svc
        f["title"] = "kernel driver service install: %s" % svc
        return derive_final_disposition(f, _evdb())[0]
    assert run("alpha") == run("beta") == BUCKET_CONFIRMED
