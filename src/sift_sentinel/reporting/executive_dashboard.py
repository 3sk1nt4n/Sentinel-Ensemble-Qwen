"""Deterministic executive dashboard -- the 'At a Glance' block at the top
of report.md.

A reader (customer, judge, junior analyst) gets the whole story in five
lines before any prose: a verdict banner derived from the truth buckets, a
disposition scoreboard, the confirmed-findings strip with severities, and
the evidence-integrity status. Built ONLY from
finding_disposition_buckets + integrity_check -- zero AI prose, so it can
never contradict the structured sections (the AI body is separately
reconciled by confirmed_consistency).

Idempotent (the section replaces itself on re-run), fail-safe (returns the
input unchanged on any error), pure presentation. Kill-switch
SIFT_EXEC_DASHBOARD=0. Universal: bucket counts + hash verdict, no case data.
"""
from __future__ import annotations

import os
import re

_MARK = "## 🧭 At a Glance"
_SECTION_RE = re.compile(
    r"\n## 🧭 At a Glance.*?(?=\n## |\n# |\Z)", re.DOTALL)
_FIRST_H2_RE = re.compile(r"^## ", re.MULTILINE)

_CONFIRMED_CAP = 8

_SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}


def _clean(s: str) -> str:
    try:
        from sift_sentinel.reporting.display_sanitize import clean_display_text
        return clean_display_text(s) or s
    except Exception:
        return s


def _rows(items) -> list[dict]:
    return [f for f in (items or []) if isinstance(f, dict)]


def _verdict(n_confirmed: int, n_review: int, n_inconclusive: int) -> str:
    if n_confirmed:
        return ("🔴 **CONFIRMED MALICIOUS ACTIVITY** — "
                f"{n_confirmed} finding(s) confirmed against tool evidence; "
                "incident response recommended")
    if n_review or n_inconclusive:
        return ("🟡 **SUSPICIOUS ACTIVITY — ANALYST REVIEW REQUIRED** — "
                f"{n_review} finding(s) warrant a closer look before this "
                "system is cleared")
    return ("🟢 **NO CONFIRMED MALICIOUS FINDINGS** — nothing on the examined "
            "evidence survived validation as malicious")


def _integrity_line(integrity) -> str:
    if isinstance(integrity, dict) and integrity.get("match") is True:
        return "✅ **SHA256 MATCH** — evidence unmodified (pre == post)"
    if isinstance(integrity, dict) and integrity.get("match") is False:
        return "🚨 **SPOLIATION ALERT** — evidence hashes changed during the run"
    return "⏳ verification pending — re-checked at Step 15 before delivery"


def insert_executive_dashboard(report_md, buckets, integrity=None):
    """Insert/refresh the At-a-Glance dashboard. Returns (md, n_inserted)."""
    if not isinstance(report_md, str) or not report_md or not isinstance(buckets, dict):
        return report_md, 0
    if os.environ.get("SIFT_EXEC_DASHBOARD", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return report_md, 0
    try:
        confirmed = _rows(buckets.get("confirmed_malicious_atomic"))
        review = _rows(buckets.get("suspicious_needs_review"))
        benign = _rows(buckets.get("benign_or_false_positive"))
        inconclusive = _rows(buckets.get("inconclusive_unresolved"))

        lines = [
            "",
            _MARK,
            "",
            "> " + _verdict(len(confirmed), len(review), len(inconclusive)),
            "",
            "| | |",
            "|---|---|",
            f"| 🔴 Confirmed malicious | **{len(confirmed)}** |",
            f"| 🟡 Needs analyst review | {len(review)} |",
            f"| 🟢 Benign / false-positive (ReAct AI-Cross-Check · SC layer 1) | {len(benign)} |",
            f"| ⚪ Inconclusive (honest unknowns) | {len(inconclusive)} |",
            f"| 🔒 Evidence integrity | {_integrity_line(integrity)} |",
        ]
        if confirmed:
            lines += ["", "**Confirmed findings:**", "",
                      "| ID | Severity | Finding |", "|---|---|---|"]
            for f in confirmed[:_CONFIRMED_CAP]:
                fid = str(f.get("finding_id") or f.get("id") or "?")
                title = _clean(str(f.get("title") or f.get("summary") or ""))[:96]
                sev = str(f.get("severity") or "").upper()
                icon = _SEV_ICON.get(sev, "▪️")
                lines.append(f"| **{fid}** | {icon} {sev or '—'} | {title} |")
            if len(confirmed) > _CONFIRMED_CAP:
                lines.append(
                    f"| | | *…+{len(confirmed) - _CONFIRMED_CAP} more — "
                    "see the Confirmed section below* |")
        lines += [
            "",
            "*Every number above is rendered from the deterministic "
            "disposition buckets — the same source as the structured "
            "sections below. Every finding traces to raw tool output "
            "(`forensic_audit.jsonl`).*",
            "",
        ]
        block = "\n".join(lines)

        # idempotent: refresh in place when present
        if _MARK in report_md:
            return _SECTION_RE.sub(lambda _m: block.rstrip("\n"), report_md, count=1), 1

        m = _FIRST_H2_RE.search(report_md)
        if m:
            i = m.start()
            return report_md[:i] + block.lstrip("\n") + "\n" + report_md[i:], 1
        return report_md.rstrip("\n") + "\n" + block, 1
    except Exception:
        return report_md, 0
