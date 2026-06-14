"""#2 WHO-FIRST: every findings-table row's Details leads with an account/
identity -- a derived user, else the honest service context, else an explicit
'not attributed (disk/host artifact)' -- never a silent blank. Universal,
kill-switch SIFT_WHO_FIRST_ALWAYS=0.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.reporting import customer_findings_table_bucket_faithful as t  # noqa: E402


def _render(finding):
    buckets = {"confirmed_malicious_atomic": [finding],
               "suspicious_needs_review": [], "benign_or_false_positive": []}
    return t.render_findings_terminal(buckets, width=200)


def test_disk_artifact_finding_leads_with_not_attributed():
    f = {"finding_id": "F1", "title": "x",
         "description": "AppCompatCache execution record",
         "source_tools": ["run_appcompatcacheparser"], "claims": []}
    out = _render(f)
    assert "Who: not attributed" in out


def test_service_context_finding_leads_with_context():
    f = {"finding_id": "F2", "title": "x", "description": "svc",
         "execution_context": "SYSTEM/service context",
         "source_tools": ["vol_pstree"], "claims": []}
    out = _render(f)
    assert "Who: SYSTEM/service context" in out


def test_kill_switch_allows_blank(monkeypatch):
    monkeypatch.setenv("SIFT_WHO_FIRST_ALWAYS", "0")
    f = {"finding_id": "F3", "title": "x", "description": "d",
         "source_tools": ["run_appcompatcacheparser"], "claims": []}
    out = _render(f)
    assert "Who: not attributed" not in out
