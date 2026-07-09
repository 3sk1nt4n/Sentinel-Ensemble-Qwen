"""#1 anti-forensics signal (T1070/T1485) - defense-evasion EXECUTION.

Secure-wipe (SDelete, cipher /w), event-log clearing (wevtutil cl / Clear-EventLog),
and USN-journal deletion are rare for normal users and common to BOTH ransomware
cleanup and insider track-covering -- a cross-case signal the pipeline missed
entirely (e.g. the acme SDelete x2 + Dropbox-uninstall chain). Dataset-agnostic:
universal command substrings + an execution-evidence fact-type scope; no family
names, no case paths. `cipher /w` only -- bare `cipher` (legit EFS) must NOT fire.
"""
from __future__ import annotations

import pytest

from sift_sentinel.analysis.malicious_semantics import (
    MALICIOUS_SEMANTIC_SIGNALS,
    match_anti_forensics_execution,
)
from sift_sentinel.analysis.candidate_observations import (
    _is_anti_forensics_execution,
    _candidate_type,
    _score_fact,
)


@pytest.mark.parametrize("cmd", [
    "sdelete.exe -p 3 -s C:\\stuff",
    "sdelete64.exe -accepteula -z C:",
    "cipher /w:C:\\Users\\fred",
    "cipher.exe /w:D:\\",
    "wevtutil cl Security",
    "wevtutil clearev",
    "Clear-EventLog -LogName Security",
    "fsutil usn deletejournal /D C:",
])
def test_matcher_fires_on_anti_forensics_commands(cmd):
    fact = {"fact_type": "file_execution_fact", "cmdline": cmd, "raw_excerpt": cmd}
    assert match_anti_forensics_execution(fact) is True, cmd
    assert _is_anti_forensics_execution(cmd.lower()) is True, cmd


@pytest.mark.parametrize("cmd", [
    "cipher /e C:\\Users\\fred\\docs",          # legit EFS encrypt -- NOT wipe
    "notepad.exe C:\\Users\\fred\\notes.txt",
    "powershell.exe -enc <legit>",
    "wevtutil qe Security",                      # query, not clear
])
def test_matcher_does_not_fire_on_benign(cmd):
    fact = {"fact_type": "file_execution_fact", "cmdline": cmd, "raw_excerpt": cmd}
    assert match_anti_forensics_execution(fact) is False, cmd


# ── Universal vocabulary: ANY well-known secure-delete / wipe / timestomp /
#    audit-clear tool, not just SDelete. Insider track-covering (and ransomware
#    cleanup) can use any of these; the deterministic rule must fire on the whole
#    family, keyed on universal tool/command substrings -- no case data. ──────────
@pytest.mark.parametrize("cmd", [
    "bleachbit.exe --clean system.freespace",                  # BleachBit
    "C:\\Users\\bobby\\Downloads\\bleachbit_console.exe",
    "bcwipe -md DoD C:\\stuff",                                 # Jetico BCWipe
    "Eraser.exe -folder C:\\evidence -method Gutmann",         # Eraser (anchored)
    "eraserl.exe addtask",
    "privazer.exe /scan",                                       # PrivaZer
    "hardwipe.exe C:\\secret",                                  # Hardwipe
    "freeraser.exe",                                            # Freeraser
    "wipefile.exe C:\\secret",                                  # WipeFile
    "timestomp.exe target.docx -z 2019-01-01",                 # timestomping
    "setmace.exe -x payload.exe",
    "auditpol /clear",                                          # audit-policy reset
])
def test_matcher_fires_on_expanded_anti_forensics_family(cmd):
    fact = {"fact_type": "file_execution_fact", "cmdline": cmd, "raw_excerpt": cmd}
    assert match_anti_forensics_execution(fact) is True, cmd
    # Single source of truth: candidate_observations sees the SAME vocabulary.
    assert _is_anti_forensics_execution(cmd.lower()) is True, cmd


@pytest.mark.parametrize("cmd", [
    "notepad.exe C:\\Users\\bobby\\eraser_manual.pdf",   # 'eraser' bare -> not eraser.exe
    "open pencil-eraser-review.docx",                    # English word 'eraser'
    "auditpol /get /category:*",                         # query audit, not /clear
])
def test_matcher_no_fp_on_benign_lookalikes(cmd):
    fact = {"fact_type": "file_execution_fact", "cmdline": cmd, "raw_excerpt": cmd}
    assert match_anti_forensics_execution(fact) is False, cmd
    assert _is_anti_forensics_execution(cmd.lower()) is False, cmd


def test_candidate_and_semantics_share_one_vocabulary():
    # No drift: the candidate-side helper uses the canonical list from
    # malicious_semantics (not a private copy).
    from sift_sentinel.analysis import candidate_observations as _co
    from sift_sentinel.analysis import malicious_semantics as _ms
    assert not hasattr(_co, "_ANTI_FORENSICS_TOKENS"), "candidate-side copy must be removed"
    for tok in ("bleachbit", "bcwipe", "timestomp"):
        assert tok in _ms._ANTI_FORENSICS_TOKENS


def test_registered_as_non_weak_semantic():
    # Registered (so it escapes the benign floor) with a callable matcher + fact types.
    spec = MALICIOUS_SEMANTIC_SIGNALS.get("anti_forensics_execution")
    assert spec is not None
    assert callable(spec.get("matcher"))
    assert spec.get("required_fact_types")


def test_signal_scoped_to_execution_facts_not_references():
    # F050 fix: a jump-list / filesystem REFERENCE to a path containing 'sdelete'
    # is access provenance, NOT execution -> must NOT fire the signal. An actual
    # execution fact MUST. (Stops chrome's recent-downloads jumplist false positive.)
    exec_fact = {"fact_type": "file_execution_fact", "process_name": "sdelete64.exe",
                 "cmdline": "sdelete64.exe -z c:", "raw_excerpt": "sdelete64.exe -z"}
    _, sig_exec, _ = _score_fact(exec_fact)
    assert "anti_forensics_execution" in sig_exec

    for ref_ft in ("jumplist_fact", "lnk_execution_fact", "filesystem_listing_fact",
                   "filesystem_timeline_fact"):
        ref = {"fact_type": ref_ft, "path": "c:/users/x/downloads/sdelete.zip",
               "raw_excerpt": "recent item: sdelete.zip"}
        _, sig_ref, _ = _score_fact(ref)
        assert "anti_forensics_execution" not in sig_ref, ref_ft


def test_score_fact_emits_signal_and_candidate_type():
    fact = {
        "fact_type": "file_execution_fact",
        "process_name": "sdelete64.exe",
        "cmdline": "sdelete64.exe -p 3 -s -q C:\\Users\\Public\\staged",
        "raw_excerpt": "sdelete64.exe secure delete",
    }
    score, signals, _supp = _score_fact(fact)
    assert "anti_forensics_execution" in signals
    assert score > 0
    assert _candidate_type(set(signals)) == "defense_evasion_anti_forensics"


# ── Event-side log clearing: 1102 (Security) / 104 (System) = T1070.001 ──────
# The audit-log-cleared EVENT is the artifact-side corroboration of the command-
# side `wevtutil cl` detector -- and is often the ONLY trace (cleared via API,
# command not captured). Near-zero FP: clearing the Security log is almost always
# adversarial. Reuses anti_forensics_execution so it rides the gen-fix + the now-
# validatable event_log claim path (no new registry/fixture plumbing). Universal
# Event IDs; no case data. 104 is guarded by a 'cleared' message (EID reused by
# other providers); 1102 is unambiguous (Security audit log cleared).

def _evt(eid, message):
    return {"fact_type": "event_log_fact", "type": "event_log_fact",
            "EventID": str(eid), "entity_id": str(eid),
            "Message": message, "raw_excerpt": message}


def test_security_log_cleared_1102_emits_anti_forensics():
    _, signals, _ = _score_fact(_evt(1102, "The audit log was cleared."))
    assert "anti_forensics_execution" in signals


def test_system_log_cleared_104_emits_anti_forensics():
    _, signals, _ = _score_fact(
        _evt(104, "The System log file was cleared."))
    assert "anti_forensics_execution" in signals


def test_event_104_without_cleared_message_does_not_fire():
    # 104 is reused by other providers -> require the 'cleared' message token.
    _, signals, _ = _score_fact(_evt(104, "Driver installed successfully."))
    assert "anti_forensics_execution" not in signals


def test_benign_logon_event_does_not_fire_anti_forensics():
    _, signals, _ = _score_fact(_evt(4624, "An account was successfully logged on."))
    assert "anti_forensics_execution" not in signals


def test_matcher_recognizes_log_cleared_event():
    # Matcher/score_fact consistency: has_malicious_semantic's matcher path also
    # recognizes the log-cleared event (not only the command form).
    assert match_anti_forensics_execution(_evt(1102, "The audit log was cleared.")) is True
    assert match_anti_forensics_execution(
        _evt(104, "The System log file was cleared.")) is True
    assert match_anti_forensics_execution(_evt(4624, "logon")) is False
