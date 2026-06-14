"""History-only precision gate (structural-corroboration contract). A finding known
ONLY from execution-history tools (ShimCache/Amcache/MFT) is non-confirmable unless a
STRUCTURAL malicious signal corroborates it -- read from disposition_reasons /
malicious_semantic_signals / claim types, NEVER the AI free-text description. So an LLM
writing "rundll32 is commonly used for lateral movement and persistence" can no longer
false-corroborate. Universal: tool-class + structural signal, no binary name list."""
from sift_sentinel.analysis.baseline_confirm_gate import (
    is_baseline_history_only_confirm,
    demote_baseline_confirms,
    CONFIRMED, NEEDS_REVIEW,
)


def _hist(fid, path, desc="execution recorded in AppCompatCache", **extra):
    f = {"finding_id": fid, "title": "execution via AppCompatCache",
         "source_tools": ["run_appcompatcacheparser", "extract_mft_timeline"],
         "claims": [{"type": "path", "value": path}], "description": desc}
    f.update(extra)
    return f


def test_system32_lolbin_history_only_is_baseline():
    assert is_baseline_history_only_confirm(_hist("F1", "windows/system32/cmd.exe")) is True
    assert is_baseline_history_only_confirm(_hist("F2", "windows/syswow64/rundll32.exe")) is True


def test_temp_installer_history_only_is_also_baseline():
    assert is_baseline_history_only_confirm(_hist("F3", "Windows/Temp/{GUID}/isbew64.exe")) is True
    assert is_baseline_history_only_confirm(_hist("F4", "Users/alice/AppData/Local/Temp/setup.exe")) is True


def test_ai_boilerplate_description_does_NOT_corroborate():
    # the F014 regression: System32 LOLBin whose ONLY "corroboration" is the LLM's
    # generic prose -> must still be demoted (no structural signal).
    f = _hist("F14", "windows/system32/rundll32.exe",
              desc="LOLBins used for lateral movement and persistence. Common attack vehicles.")
    assert is_baseline_history_only_confirm(f) is True


def test_structural_anti_forensics_signal_survives():
    # SDelete/BCWipe carry the anti_forensics_execution SEMANTIC signal -> kept
    f = _hist("F5", "Users/x/Temp/~bcwipe5.tmp/setup.exe",
              desc="setup tool",
              malicious_semantic_signals=["anti_forensics_execution"])
    assert is_baseline_history_only_confirm(f) is False


def test_structural_persistence_reason_survives():
    f = {"finding_id": "F6", "title": "SafeBoot persistence",
         "source_tools": ["parse_registry_persistence"],
         "claims": [{"type": "registry", "value": "HKLM/.../SafeBoot/AlternateShell"}],
         "description": "registry key configured",
         "disposition_reasons": ["malicious_semantic:high_risk_persistence"]}
    assert is_baseline_history_only_confirm(f) is False


def test_weak_signal_only_is_baseline():
    # admin_or_lolbin / temp-execution are weak-alone -> NOT corroboration
    f = _hist("F7", "windows/system32/regsvr32.exe",
              malicious_semantic_signals=["admin_or_lolbin_artifact", "executes_from_temp_path"])
    assert is_baseline_history_only_confirm(f) is True


def test_behavioral_evidence_is_not_baseline():
    f = _hist("F8", "windows/system32/rundll32.exe")
    f["source_tools"] = ["vol_malfind", "run_appcompatcacheparser"]
    assert is_baseline_history_only_confirm(f) is False


def test_injection_corroborated_flag_survives():
    f = _hist("F9", "windows/system32/svchost.exe")
    f["disposition_reasons"] = ["injection_corroborated", "rwx region"]
    assert is_baseline_history_only_confirm(f) is False


def test_demote_moves_history_only_to_needs_review_keeps_structural():
    buckets = {
        CONFIRMED: [
            _hist("F1", "windows/system32/cmd.exe",
                  desc="cmd.exe commonly used for lateral movement and persistence"),   # boilerplate -> demote
            _hist("F3", "Windows/Temp/{GUID}/isbew64.exe"),                              # installer -> demote
            _hist("F5", "Users/x/Temp/~bcwipe5.tmp/setup.exe",
                  malicious_semantic_signals=["anti_forensics_execution"]),             # structural -> keep
        ],
        NEEDS_REVIEW: [], "inconclusive_unresolved": [],
        "benign_or_false_positive": [], "synthesis_narrative": [],
    }
    new, ledger = demote_baseline_confirms(buckets)
    assert {f["finding_id"] for f in new[CONFIRMED]} == {"F5"}          # only structural survives
    assert {"F1", "F3"} <= {f["finding_id"] for f in new[NEEDS_REVIEW]}
    assert len(ledger) == 2


def test_noop_when_no_history_only_confirms():
    buckets = {
        CONFIRMED: [_hist("F5", "Users/x/Temp/t.exe",
                          malicious_semantic_signals=["anti_forensics_execution"])],
        NEEDS_REVIEW: [], "inconclusive_unresolved": [],
        "benign_or_false_positive": [], "synthesis_narrative": [],
    }
    new, ledger = demote_baseline_confirms(buckets)
    assert ledger == [] and {f["finding_id"] for f in new[CONFIRMED]} == {"F5"}
