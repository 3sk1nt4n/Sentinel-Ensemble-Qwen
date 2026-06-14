"""polish_report must apply to AI reports that NUMBER their own sections.

Opus writes '## 2. Attack Timeline (UTC)' (numbered + parenthetical suffix);
Haiku writes '## Attack Timeline'. The polish pass bailed early on any numbered
report AND its title-match set ('attack timeline') never matched '2. attack
timeline (utc)' -- so Opus reports skipped the WHOLE polish: no boxed Executive
Summary, no section de-dup, and (the visible regression) the Attack Timeline
stayed a plain markdown table instead of the flowing ▼-arrow event chain.

These pin: numbered reports get the arrow timeline, sections renumber cleanly
(no '1. 2.'), and the pass is idempotent.
"""
from sift_sentinel.reporting.report_polish import polish_report


_OPUS_NUMBERED = """# Forensic Incident Report

## 1. Executive Summary

The host shows anti-forensic activity.

## 2. Attack Timeline (UTC)

| Timestamp (UTC) | Event | Finding(s) |
|---|---|---|
| 2020-11-16 02:30:00 | SDelete executed via PowerShell | F009 |
| 2020-11-01 22:17:29 | Service install synclogsvc | F035 |

## 3. MITRE ATT&CK Mapping

| Tactic | Technique (ID) | Evidence |
|---|---|---|
| Defense Evasion | T1070.004 | F009 |
"""


def test_numbered_attack_timeline_becomes_arrow_chain():
    out = polish_report(_OPUS_NUMBERED)
    assert "▼" in out, "Attack Timeline was not rendered as a ▼-arrow chain"
    # both events survive and are chronologically ordered (Nov 01 before Nov 16)
    assert out.index("synclogsvc") < out.index("SDelete"), "events not sorted by time"


def test_sections_renumber_cleanly_no_double_number():
    out = polish_report(_OPUS_NUMBERED)
    # a pre-numbered title must not become '## 1. 2. ...' or '## 2. 2. ...'
    import re
    assert not re.search(r"^##\s*\d+\.\s*\d+\.", out, re.MULTILINE), out
    # Executive Summary still present as a top section
    assert "Executive Summary" in out


def test_polish_is_idempotent_on_numbered_report():
    once = polish_report(_OPUS_NUMBERED)
    twice = polish_report(once)
    assert twice == once, "second polish changed an already-polished report"


def test_unnumbered_haiku_report_still_works():
    haiku = _OPUS_NUMBERED.replace("## 1. Executive Summary", "## Executive Summary") \
                          .replace("## 2. Attack Timeline (UTC)", "## Attack Timeline") \
                          .replace("## 3. MITRE ATT&CK Mapping", "## MITRE ATT&CK Mapping")
    out = polish_report(haiku)
    assert "▼" in out


def test_timeline_events_get_killchain_tactic_labels():
    from sift_sentinel.reporting.report_polish import _event_tactic
    assert "anti-forensics" in _event_tactic("sdelete.exe secure wipe of D:")
    assert "Exfiltration" == _event_tactic("msedge.exe SRUM egress outlier")
    assert "Collection" == _event_tactic("accessed 995 file artifacts")
    assert "Privilege Escalation" == _event_tactic("SeImpersonate privilege enabled")
    # most-specific-first: an event with BOTH anti-forensics + a tsclient vector
    # reads as its PRIMARY tactic (anti-forensics), not the vector.
    assert "anti-forensics" in _event_tactic("sdelete via tsclient RDP-mapped drive")
    assert "Lateral Movement" == _event_tactic("psexec to remote host over SMB share")
    assert _event_tactic("nothing recognizable here xyz") == ""   # no false label


def test_polished_timeline_contains_tactic_label():
    from sift_sentinel.reporting.report_polish import polish_report
    md = ("# R\n\n## Attack Timeline\n\n| Timestamp | Event | Finding |\n|---|---|---|\n"
          "| 2020-11-01 | sdelete secure wipe | F011 |\n")
    out = polish_report(md)
    assert "[Defense Evasion" in out and "▼" not in out.split("F011")[0][-3:]
