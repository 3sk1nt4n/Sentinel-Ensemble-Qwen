"""Deterministic executive dashboard ('At a Glance') injected at the top of
report.md: verdict banner + disposition scoreboard + confirmed-findings strip
+ evidence-integrity status. Built ONLY from the truth buckets and the
integrity check -- zero AI prose, so it can never contradict the report body
(the body's confirm-claims are separately reconciled by
confirmed_consistency). Idempotent; fail-safe; kill-switch
SIFT_EXEC_DASHBOARD=0. Universal: bucket counts + hash verdict, no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.reporting.executive_dashboard import (  # noqa: E402
    insert_executive_dashboard,
)

MD = "# Forensic Incident Report\n\n**Report Date:** 2026-06-11 (UTC)\n\n---\n\n## 1. Executive Summary\nBody text.\n"


def _buckets(confirmed=2, review=3, benign=1, inconclusive=1):
    def f(i, title="RWX injection in a service process", sev="HIGH"):
        return {"finding_id": f"F{i:03d}", "title": title, "severity": sev}
    return {
        "confirmed_malicious_atomic": [f(i) for i in range(1, confirmed + 1)],
        "suspicious_needs_review": [f(i + 10) for i in range(review)],
        "benign_or_false_positive": [f(i + 30) for i in range(benign)],
        "inconclusive_unresolved": [f(i + 40) for i in range(inconclusive)],
        "synthesis_narrative": [],
    }


def test_dashboard_inserted_with_counts_and_confirmed_rows():
    out, n = insert_executive_dashboard(MD, _buckets(), {"match": True})
    assert n == 1
    assert "At a Glance" in out
    assert out.index("At a Glance") < out.index("## 1. Executive Summary")
    assert "**2**" in out                      # confirmed count bolded
    assert "F001" in out and "F002" in out     # confirmed strip rows
    assert "SHA256 MATCH" in out


def test_verdict_tiers():
    red, _ = insert_executive_dashboard(MD, _buckets(confirmed=2), {"match": True})
    assert "CONFIRMED MALICIOUS ACTIVITY" in red
    yellow, _ = insert_executive_dashboard(MD, _buckets(confirmed=0, review=3), {"match": True})
    assert "REVIEW REQUIRED" in yellow and "CONFIRMED MALICIOUS ACTIVITY" not in yellow
    green, _ = insert_executive_dashboard(
        MD, _buckets(confirmed=0, review=0, inconclusive=0), {"match": True})
    assert "NO CONFIRMED MALICIOUS FINDINGS" in green


def test_integrity_states():
    bad, _ = insert_executive_dashboard(MD, _buckets(), {"match": False})
    assert "SPOLIATION" in bad
    pending, _ = insert_executive_dashboard(MD, _buckets(), None)
    assert "pending" in pending.lower()


def test_idempotent_rerun_replaces_not_duplicates():
    once, _ = insert_executive_dashboard(MD, _buckets(), {"match": True})
    twice, n2 = insert_executive_dashboard(once, _buckets(confirmed=1), {"match": True})
    assert n2 == 1
    assert twice.count("At a Glance") == 1     # replaced, not appended
    assert "**1**" in twice                    # refreshed count wins


def test_confirmed_strip_bounded_with_overflow_note():
    out, _ = insert_executive_dashboard(MD, _buckets(confirmed=12), {"match": True})
    assert "+4 more" in out                    # cap 8 + explicit overflow, never silent


def test_titles_pass_display_sanitizer():
    b = _buckets(confirmed=1)
    b["confirmed_malicious_atomic"][0]["title"] = (
        "path:tmp/sift-onboard-mnt/case-001/windows/prefetch/tool.exe-1a2b3c4d.pf")
    out, _ = insert_executive_dashboard(MD, b, {"match": True})
    assert "sift-onboard-mnt" not in out


def test_confirmed_strip_column_order_severity_before_title():
    # eye gets the color/level before the prose: ID | Severity | Finding
    out, _ = insert_executive_dashboard(MD, _buckets(confirmed=1), {"match": True})
    assert "| ID | Severity | Finding |" in out
    assert "| **F001** | 🔴 HIGH | RWX injection in a service process |" in out


def test_confirmed_cards_get_severity_icons_via_polish():
    from sift_sentinel.reporting.report_polish import polish_report
    body = (MD + "\n## 2. Confirmed Malicious Atomic Findings\n\n"
            "### F001: RWX injection\n\n- **Severity:** HIGH\n- **Confidence:** MEDIUM\n")
    out = polish_report(body, benign_fids=set())
    assert "- **Severity:** 🔴 HIGH" in out
    # idempotent: second pass never double-decorates
    again = polish_report(out, benign_fids=set())
    assert again.count("🔴 🔴") == 0 and "🔴 HIGH" in again


def test_kill_switch_and_fail_safe(monkeypatch):
    monkeypatch.setenv("SIFT_EXEC_DASHBOARD", "0")
    out, n = insert_executive_dashboard(MD, _buckets(), {"match": True})
    assert n == 0 and out == MD
    monkeypatch.delenv("SIFT_EXEC_DASHBOARD")
    out2, n2 = insert_executive_dashboard(None, _buckets(), {"match": True})
    assert n2 == 0 and out2 is None
    out3, n3 = insert_executive_dashboard(MD, None, {"match": True})
    assert n3 == 0 and out3 == MD
