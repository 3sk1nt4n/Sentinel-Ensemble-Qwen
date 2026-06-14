"""CONFIRMED-first must hold even when the confirmed findings were PROMOTED by
inv3a (and so carry self_corrected=True).

Live Haiku run: all 4 confirmed findings were inv3a-promoted, so the tier map
labelled them SELF-CORRECTED, and the FINDINGS-table sort (which keyed on the
tier == 'CONFIRMED') dropped them out of the top rows -- a needs-review egress
finding led the table instead. The sort must key on actual confirmed-bucket
membership, not the override-prone tier label.

Also: the per-finding 'why it matters' must not mis-key (a data-collection
finding got the 'staging folder' line; a privilege finding got the 'service
install' line).
"""
import re

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)
from sift_sentinel.reporting.finding_significance import plain_significance


def _f(fid, tools, **extra):
    d = {"finding_id": fid, "source_tools": ["t%d" % i for i in range(tools)],
         "title": fid, "severity": "HIGH"}
    d.update(extra)
    return d


def _order(out):
    clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
    seg = clean[clean.find("FINDINGS  ("): clean.find("AI-DETECTED")]
    ids = []
    for m in re.finditer(r"F(\d{3})", seg):
        fid = "F" + m.group(1)
        if fid not in ids:
            ids.append(fid)
    return ids


def test_inv3a_promoted_confirmed_still_leads_table():
    buckets = {
        # confirmed findings promoted by inv3a -> self_corrected True, FEW tools
        "confirmed_malicious_atomic": [
            _f("F011", 4, self_corrected=True),
            _f("F014", 1, self_corrected=True),
        ],
        # a needs-review finding with MANY tools that previously stole row 1
        "suspicious_needs_review": [_f("F049", 12)],
        "benign_or_false_positive": [], "synthesis_narrative": [],
        "inconclusive_unresolved": [],
    }
    order = _order(render_findings_terminal(buckets, width=100))
    assert order[:2] == ["F011", "F014"], order   # confirmed lead despite fewer tools
    assert order.index("F049") >= 2


def test_collection_finding_gets_collection_significance_not_staging():
    s = plain_significance({"title": "Data collection: 'bobby' accessed 995 file "
                            "artifacts co-occurring with an external channel "
                            "(potential staging / exfiltration)"})
    assert "accessed an unusually large number of files" in s
    assert "ran from a temporary or staging folder" not in s


def test_privilege_finding_not_mislabelled_as_service():
    s = plain_significance({"title": "Elevated privilege context: dashost.exe with "
                            "SeImpersonate privilege",
                            "description": "Device Association Service token"})
    assert "powerful Windows privileges" in s
    assert "Windows service was installed" not in s


def test_real_service_install_still_matches():
    s = plain_significance({"title": "Non-standard service install (Event 7045)"})
    assert "Windows service was installed" in s


# ── FP findings explain WHY they are benign (not 'why it matters') ──────────
def test_fp_finding_shows_benign_reason_not_why_it_matters():
    from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
        _details_for_display,
    )
    f = {"finding_id": "F012", "title": "Suspicious network connectivity from X",
         "description": "process connecting to a server",
         "react_conclusion": {"is_false_positive": True,
                              "text": "PID 13224 is benign: legitimate vendor push service",
                              "verdict": "confirmed_benign"}}
    det = _details_for_display(f)
    assert "Assessed benign:" in det
    assert "legitimate vendor push service" in det
    assert "Why it matters" not in det          # the malicious framing is suppressed


def test_real_finding_still_shows_why_it_matters():
    from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
        _details_for_display,
    )
    f = {"finding_id": "F011", "title": "Anti-forensics SDelete execution",
         "description": "sdelete wiped a drive"}
    det = _details_for_display(f)
    assert "Why it matters" in det              # confirmed/needs-review keep significance


def test_inconclusive_react_does_not_fake_a_benign_reason():
    from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
        _details_for_display,
    )
    f = {"finding_id": "F008", "title": "Memory injection RWX",
         "react_conclusion": {"verdict": "inconclusive",
                              "reason": "ReAct reached 5-turn cap without a conclusion"}}
    det = _details_for_display(f)
    assert "Assessed benign:" not in det        # placeholder text is not surfaced


# ── collection finding surfaces the actual files (IOC column) ──────────────
def test_collection_finding_artifact_is_a_list_of_real_paths():
    from sift_sentinel.analysis.user_account_synthesizer import (
        synthesize_collection_findings,
    )
    tf = {"user_account_fact": [{"username": "u", "domain": "D",
                                 "owned_pids": [5], "source_tools": ["run_jlecmd"],
                                 "fact_id": "u0"}],
          "lnk_execution_fact": [{"path": "C:/Users/u/Dropbox/x%d.png" % i}
                                 for i in range(25)],
          "network_connection_fact": [{"pid": 5, "dst_ip": "203.0.113.1"}]}
    f = synthesize_collection_findings(tf)[0]
    assert isinstance(f["artifact"], list)
    assert any("Dropbox" in p for p in f["artifact"])   # real files surfaced, not just the owner
