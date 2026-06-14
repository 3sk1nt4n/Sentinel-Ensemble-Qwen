"""A ReAct binary-legitimacy benign verdict cannot refute a CONCLUSIVE structural
persistence primitive (IFEO Debugger / non-default SafeBoot) -- it routes to
needs-review, never benign. Mirror of the behavioral-anomaly override. Universal:
keyed on the registered structural matcher name, no case value.
"""
from sift_sentinel.analysis.disposition import (
    derive_final_disposition, BUCKET_BENIGN, BUCKET_SUSPICIOUS,
)


def _f(fid, signals, fp=True):
    return {"finding_id": fid, "title": "persistence",
            "malicious_semantic_signals": signals,
            "react_conclusion": {"is_false_positive": fp, "verdict": "confirmed_benign"},
            "claims": [{"type": "registry_persistence", "registry_path": "HKLM\\...\\x"}]}


def test_react_benign_cannot_bury_safeboot():
    bucket, reasons = derive_final_disposition(_f("F016", ["safeboot_alternateshell_persistence"]))
    assert bucket == BUCKET_SUSPICIOUS
    assert any("react_benign_vs_persistence" in r for r in reasons)


def test_react_benign_cannot_bury_ifeo():
    bucket, _ = derive_final_disposition(_f("F033", ["ifeo_debugger_hijack"]))
    assert bucket == BUCKET_SUSPICIOUS


def test_react_benign_still_buries_a_non_conclusive_signal():
    # a weak/ambiguous signal (e.g. temp-staging) CAN still be ReAct-benigned --
    # the override only protects the conclusive persistence primitives
    bucket, _ = derive_final_disposition(_f("F021", ["executes_from_temp_path"]))
    assert bucket == BUCKET_BENIGN


def test_react_benign_with_no_signal_is_benign():
    bucket, _ = derive_final_disposition(_f("F009", []))
    assert bucket == BUCKET_BENIGN
