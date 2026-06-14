"""Deterministic report polish pass -- universal, no case values.
Asserts STRUCTURE (numbering / removal / boxing / arrow-timeline), never content.
"""
from sift_sentinel.reporting.report_polish import polish_report

_REPORT = """# Forensic Report

## Executive Summary

A coordinated multi-stage campaign was identified on the target host.

## Attack Timeline

| Timestamp (UTC) | Event | User | Finding ID | Details |
|---|---|---|---|---|
| 2001-01-01T00:00:00 | Staging | hostA | F001 | A tool was staged in a temp directory and a service registered. |
| 2001-01-01T00:00:05 | Listener | hostA | F002 | A network listener was deployed on a non-standard port. |

## Key Findings

### Confirmed Malicious Atomic Findings

| Finding ID | Title | Severity |
|---|---|---|
| F001 | thing | HIGH |

## Requiring Further Investigation

| Finding ID | Title |
|---|---|
| F003 | review |

## Evidence Insufficient to Confirm

| Finding ID | Title |
|---|---|
| F004 | maybe |

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1059 | F001 |

## Methodology & Limitations

### Validation Pipeline
Lots of boilerplate here.

## Per-User Attribution

### accountX
- Owned PIDs: 2

### Attack Chain Narrative
1. step one
2. step two

## Recommendations

1. Isolate affected systems.
2. Reset credentials.

## Confirmed Malicious Atomic Findings

This section is rendered deterministically.

### F001: campaign
- Severity: HIGH

**Report Date:** 2026-01-01 (UTC)
**Total Validator-Backed Observations:** 43
**Evidence Insufficient to Confirm:** 27
"""


def test_unwanted_sections_removed():
    out = polish_report(_REPORT)
    # NOTE: 'rendered deterministically' was dropped here only because polish used
    # to remove the WHOLE confirmed-malicious section -- a bug that deleted the
    # report's primary output and failed POSTRUN_REPORT_VALIDATION_GATE. The
    # confirmed section is now correctly KEPT (see test_confirmed_section_kept), so
    # that provenance string is no longer in the gone-list.
    for gone in ("## Key Findings", "Requiring Further Investigation",
                 "Evidence Insufficient to Confirm", "Methodology & Limitations",
                 "Attack Chain Narrative",
                 "Report Date", "Total Validator-Backed Observations"):
        assert gone not in out, gone


def test_confirmed_section_kept():
    # the confirmed-malicious section is the report's primary output -> never dropped
    out = polish_report(_REPORT)
    assert "Confirmed Malicious Atomic Findings" in out
    assert "F001" in out


def test_sections_are_numbered():
    out = polish_report(_REPORT)
    assert "## 1. Executive Summary" in out
    assert "## 2. Attack Timeline" in out
    # the kept sections are numbered contiguously
    import re
    nums = [int(m.group(1)) for m in re.finditer(r"^## (\d+)\. ", out, re.M)]
    assert nums == list(range(1, len(nums) + 1)), nums


def test_kept_sections_present():
    out = polish_report(_REPORT)
    for keep in ("Executive Summary", "Attack Timeline", "MITRE ATT&CK Mapping",
                 "Per-User Attribution", "Recommendations"):
        assert keep in out, keep


def test_boxed_sections_have_callouts():
    out = polish_report(_REPORT)
    assert "> [!IMPORTANT]" in out  # Executive Summary
    assert "> [!TIP]" in out        # Recommendations
    assert "> [!NOTE]" in out       # MITRE / Per-User


def test_timeline_is_bordered_boxes_with_arrows():
    out = polish_report(_REPORT)
    tl = out.split("Attack Timeline", 1)[1]
    assert "┌" in tl and "└" in tl and "▼" in tl     # bordered event boxes + arrow
    assert "```text" in tl                            # fenced for monospace
    # the original table pipes for the timeline are gone (replaced by the diagram)
    assert "| Timestamp (UTC) | Event |" not in out
    # every box border line is the same visible width (aligned)
    widths = {len(l) for l in tl.splitlines() if l.startswith(("┌", "│", "└"))}
    assert len(widths) == 1, widths


def test_mitre_table_still_renders_under_box():
    out = polish_report(_REPORT)
    # the MITRE table is preserved (not blockquoted into oblivion)
    assert "| Tactic | Technique | Evidence |" in out


def test_idempotent():
    once = polish_report(_REPORT)
    twice = polish_report(once)
    assert once == twice


def test_malformed_input_returns_original():
    assert polish_report("") == ""
    assert polish_report("no headings at all") == "no headings at all"


def test_duplicate_per_user_sections_collapse_to_one_richer():
    md = """# R

## Per-User Attribution
short summary.
### u1
- pid: 2

## MITRE ATT&CK Mapping

| T | x |
|---|---|
| Execution | F1 |

## Appendix: Per-User Attribution

### User: u1 — VICTIM
**Owned PIDs:** 16 processes (a much longer, richer body than the summary above)
**Forensic Interpretation:** detailed appendix content here.
"""
    out = polish_report(md)
    # exactly one Per-User section, titled canonically, not "Appendix: ..."
    assert out.count("Per-User Attribution") == 1
    assert "Appendix: Per-User Attribution" not in out
    # the RICHER (appendix) body was kept
    assert "richer body" in out and "detailed appendix content" in out


def test_benign_findings_dropped_from_timeline():
    md = """# R
## Attack Timeline

| Timestamp (UTC) | Event | User | Finding ID | Details |
|---|---|---|---|---|
| 2018-08-30T13:52:00 | persistence | s | F033 | real backdoor |
| 2018-09-06T18:28:30 | listener | s | F009 | benign svchost |
| 2018-08-30T16:43:36 | mixed | s | F005, F009 | partly benign |
"""
    out = polish_report(md, benign_fids={"F009"})
    assert "F033" in out and "real backdoor" in out      # real event kept
    assert "benign svchost" not in out                    # all-benign row dropped
    assert "partly benign" in out                         # mixed row kept
