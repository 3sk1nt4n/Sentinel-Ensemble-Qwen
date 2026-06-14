"""TDD (track C, layer 1): ransomware Inhibit System Recovery (MITRE T1490).

Shadow-copy / backup / boot-recovery deletion is a near-universal ransomware
precursor. Detect the universal Windows recovery-sabotage commands in any fact's
text and register it as a NON-weak malicious semantic, so a corroborated finding
escapes the disposition benign-floor to suspicious_needs_review.

Dataset-agnostic: universal TTP command patterns (like the existing LOLBin /
encoded-PowerShell signals) -- no ransomware-family names, no case IOCs, no
self-tuned thresholds. Works on any Windows memory/disk image.
"""
from sift_sentinel.analysis import malicious_semantics as ms
from sift_sentinel.analysis import disposition as disp
from sift_sentinel.analysis.candidate_observations import _score_fact, _candidate_type


def _proc(cmdline):
    return {"fact_type": "process_fact", "process_name": "cmd.exe",
            "cmdline": cmdline, "raw_excerpt": cmdline,
            "fields": {"cmdline": cmdline}}


POS = [
    "vssadmin.exe delete shadows /all /quiet",
    "wmic shadowcopy delete",
    "wbadmin delete catalog -quiet",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "powershell -c Get-WmiObject Win32_Shadowcopy | Remove-WmiObject",
]
NEG = [
    "vssadmin list shadows",
    "wbadmin get status",
    "powershell -c Get-ChildItem C:\\Users\\someuser",
]


def test_score_fact_emits_inhibit_signal():
    for c in POS:
        _, sigs, _ = _score_fact(_proc(c))
        assert "inhibit_system_recovery" in sigs, c
    for c in NEG:
        _, sigs, _ = _score_fact(_proc(c))
        assert "inhibit_system_recovery" not in sigs, c


def test_candidate_type_for_inhibit():
    assert _candidate_type({"inhibit_system_recovery"}) == "system_recovery_inhibition"


def test_matcher_fires_only_on_sabotage():
    for c in POS:
        assert ms.match_inhibit_system_recovery(_proc(c)) is True, c
    for c in NEG:
        assert ms.match_inhibit_system_recovery(_proc(c)) is False, c


def test_signal_registered_non_weak():
    assert "inhibit_system_recovery" in ms.MALICIOUS_SEMANTIC_SIGNALS
    assert "inhibit_system_recovery" not in disp._WEAK_ALONE_SEMANTIC_SIGNALS
    assert "inhibit_system_recovery" not in disp._DISK_HISTORY_SEMANTIC_SIGNALS
