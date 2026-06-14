"""BUILD 1: deterministic claim-repair / bind pass.

Properties, never values (no case exe/IP/hash). Asserts the directive's success
criterion synthetically: a finding the universal IFEO matcher would confirm, but
which DIED at all-or-nothing Bind, is rescued by an exact index re-bind and then
reaches confirm-eligibility -- WITHOUT self-correction. MISMATCH (real fact
disagreement) and prose-only findings are never repaired.
"""
import pytest

from sift_sentinel.validation.typed_validator import TypedEvidenceDB, tf_bind_attempts
from sift_sentinel.analysis.claim_repair import (
    repair_finding_binding, repair_blocked_findings,
)
from sift_sentinel.analysis.disposition import evaluate_confirmed_bucket_eligibility

# A GENERIC IFEO Debugger key -- SHAPE only, no specific exe name.
_IFEO = (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion"
         r"\Image File Execution Options\app.exe\Debugger")


def _ifeo_edb_and_finding():
    fact = {
        "fact_id": "rp-1", "fact_type": "registry_persistence_fact",
        "normalized_registry_path": _IFEO.replace("\\", "/").lower(),
        "registry_path": _IFEO, "persistence_type": "ifeo",
        "value_name": "debugger", "value_data": r"C:\Windows\Temp\x.exe",
    }
    # index by_registry_path using the binder's OWN normalized keys (same path a
    # real compiler would index), so the test exercises the real bind.
    probe = {"value": _IFEO}
    reg_keys = [k for (idx, k) in tf_bind_attempts(probe) if idx == "by_registry_path"]
    assert reg_keys, "binder produced no registry variants"
    edb = {
        "typed_facts": {"registry_persistence_fact": [fact]},
        "indexes": {"by_registry_path": {k: ["rp-1"] for k in reg_keys}},
    }
    finding = {
        "finding_id": "F001",
        "title": "IFEO debugger-hijack persistence",
        "severity": "high", "confidence": "high", "confidence_level": "high",
        "source_tools": ["run_recmd"], "tool_call_ids": ["tc-1"],
        "raw_excerpt": "Image File Execution Options app.exe Debugger value set",
        "claims": [
            {"type": "registry_persistence", "registry_path": _IFEO,
             "value_name": "debugger", "value_data": r"C:\Windows\Temp\x.exe"},
            # a prose claim the validator cannot check -> all-or-nothing blocks all
            {"type": "path", "path": "credential-theft via accessibility backdoor"},
        ],
        "validation_status": "UNRESOLVED", "deterministic_check": "blocked",
    }
    return edb, finding


def test_blocked_ifeo_repairs_then_confirm_eligible():
    edb, finding = _ifeo_edb_and_finding()
    tdb = TypedEvidenceDB(edb)
    assert evaluate_confirmed_bucket_eligibility(finding, edb)["eligible"] is False
    assert repair_finding_binding(finding, tdb) is True
    assert finding["deterministic_check"] == "passed"
    assert finding["validator_metadata"]["typed_fact_refs"], "no fact attached"
    res = evaluate_confirmed_bucket_eligibility(finding, edb)
    assert res["eligible"] is True, res["blocking_reasons"]


def test_mismatch_finding_is_never_repaired():
    edb, finding = _ifeo_edb_and_finding()
    finding["validation_status"] = "MISMATCH"   # a real fact disagreement
    finding["deterministic_check"] = "blocked"
    tdb = TypedEvidenceDB(edb)
    assert repair_finding_binding(finding, tdb) is False
    assert finding["deterministic_check"] == "blocked"


def test_prose_only_finding_not_repaired():
    edb, _ = _ifeo_edb_and_finding()
    tdb = TypedEvidenceDB(edb)
    finding = {
        "finding_id": "F9", "title": "vague", "severity": "high",
        "claims": [{"type": "path", "path": "lateral movement technique observed"}],
        "validation_status": "UNRESOLVED", "deterministic_check": "blocked",
    }
    assert repair_finding_binding(finding, tdb) is False


def test_passed_finding_untouched():
    edb, finding = _ifeo_edb_and_finding()
    finding["deterministic_check"] = "passed"
    tdb = TypedEvidenceDB(edb)
    assert repair_finding_binding(finding, tdb) is False  # nothing to do


_SAFEBOOT = r"HKLM\System\CurrentControlSet\Control\SafeBoot\AlternateShell"


def test_blocked_safeboot_nondefault_repairs_then_confirm_eligible():
    # the OTHER conclusive structural primitive the directive names. Same repair
    # path, different universal matcher (SafeBoot AlternateShell != cmd.exe default).
    fact = {
        "fact_id": "rp-2", "fact_type": "registry_persistence_fact",
        "normalized_registry_path": _SAFEBOOT.replace("\\", "/").lower(),
        "registry_path": _SAFEBOOT, "persistence_type": "safeboot",
        "value_name": "alternateshell", "value_data": r"C:\Windows\Temp\evil.exe",
        "is_default": "false",
    }
    probe = {"value": _SAFEBOOT}
    reg_keys = [k for (idx, k) in tf_bind_attempts(probe) if idx == "by_registry_path"]
    edb = {"typed_facts": {"registry_persistence_fact": [fact]},
           "indexes": {"by_registry_path": {k: ["rp-2"] for k in reg_keys}}}
    finding = {
        "finding_id": "F050", "title": "SafeBoot AlternateShell persistence",
        "severity": "high", "confidence": "high", "confidence_level": "high",
        "source_tools": ["run_recmd"], "tool_call_ids": ["tc-1"],
        "raw_excerpt": "SafeBoot AlternateShell set to a non-default binary",
        "claims": [
            {"type": "registry_persistence", "registry_path": _SAFEBOOT,
             "value_name": "alternateshell", "value_data": r"C:\Windows\Temp\evil.exe"},
            {"type": "path", "path": "safe-mode evasion technique"},
        ],
        "validation_status": "UNRESOLVED", "deterministic_check": "blocked",
    }
    tdb = TypedEvidenceDB(edb)
    assert evaluate_confirmed_bucket_eligibility(finding, edb)["eligible"] is False
    assert repair_finding_binding(finding, tdb) is True
    res = evaluate_confirmed_bucket_eligibility(finding, edb)
    assert res["eligible"] is True, res["blocking_reasons"]


def test_repair_blocked_findings_counts():
    edb, f1 = _ifeo_edb_and_finding()
    tdb = TypedEvidenceDB(edb)
    f2 = {"finding_id": "F2", "claims": [{"type": "path", "path": "prose only"}],
          "validation_status": "UNRESOLVED", "deterministic_check": "blocked"}
    out = repair_blocked_findings([f1, f2], tdb)
    assert out["examined"] == 2 and out["repaired"] == 1
