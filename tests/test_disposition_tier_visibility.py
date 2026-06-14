"""FINDINGS table ordering: CONFIRMED rows sort FIRST, then by descending tool-hit
count. The disposition tier orders the rows but is NOT shown as a tag in Details.
Universal: keyed on the bucket + tool-hit count, no case value.
"""
import re
import sift_sentinel.reporting.customer_findings_table_bucket_faithful as R


def _f(fid, pid, tools):
    return {"finding_id": fid, "title": "t%d" % pid, "source_tools": tools,
            "claims": [{"type": "pid", "pid": pid, "process": "p.exe"}]}


def _buckets():
    return {
        # an INCONCLUSIVE finding with MANY tool hits ...
        "inconclusive_unresolved": [_f("F026", 26, ["a", "b", "c", "d"])],
        # ... must still sort below a CONFIRMED finding with fewer hits.
        "confirmed_malicious_atomic": [_f("F039", 39, ["a", "b"])],
        "suspicious_needs_review": [_f("F020", 20, ["a"])],
    }


def _order(out):
    # the ID column sits after the row-number column: "│ N  │ Fxxx │"
    return re.findall(r"[│|]\s*\d+\s*[│|]\s*(F\d+)", out)


def test_confirmed_sorts_first_regardless_of_tool_hits():
    R._C = R._G = R._B = R._R = R._Y = R._D = R._X = R._M = ""
    out = R.render_findings_terminal(_buckets(), summary={})
    order = _order(out)
    assert order and order[0] == "F039", order  # CONFIRMED first


def test_no_tier_tag_in_details():
    R._C = R._G = R._B = R._R = R._Y = R._D = R._X = R._M = ""
    out = R.render_findings_terminal(_buckets(), summary={})
    for tag in ("CONFIRMED --", "INCONCLUSIVE", "NEEDS-REVIEW", "UNRESOLVED"):
        assert tag not in out, tag


def test_no_data_only_line():
    out = R.render_findings_terminal(
        _buckets(),
        summary={"tool_record_counts": {"vol_handles": 9, "unused_tool": 3}})
    assert "data-only) [" not in out  # the standalone data-only section is removed
