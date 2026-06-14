"""Section layout: AI self-corrected rows live UNDER the main FINDINGS table; the
single remaining table is 'AI-DETECTED FP/Benign (ReAct AI-Cross-Check)' holding
ONLY ReAct-FP + benign rows -- its title no longer names self-correction.
Universal: keys on the react_fp / self_corrected partition, no case data.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def _f(fid, title, pid):
    return {"finding_id": fid, "title": title,
            "claims": [{"type": "pid", "pid": pid, "process": "p%d.exe" % pid}]}


def _buckets():
    fp = _f("F022", "react fp caught", 2); fp["react_conclusion"] = {"is_false_positive": True}
    plain = _f("F030", "plain benign", 3)
    sc = _f("F012", "sc corrected", 4); sc["self_corrected"] = True
    return {
        "confirmed_malicious_atomic": [_f("F001", "real confirmed", 1)],
        "benign_or_false_positive": [fp, plain],
        "inconclusive_unresolved": [sc],
    }


def test_self_corrected_sits_under_findings():
    out = render_findings_terminal(_buckets())
    fp_hdr = out.index("AI-DETECTED FP/Benign")
    # self-corrected now in the FINDINGS table, ABOVE the FP header
    assert out.index("F012") < fp_hdr
    # ReAct-FP + benign rows are BELOW the FP header
    assert out.index("F022") > fp_hdr
    assert out.index("F030") > fp_hdr


def test_fp_section_title_drops_self_corrected():
    out = render_findings_terminal(_buckets())
    assert "AI-DETECTED FP/Benign (ReAct AI-Cross-Check)" in out
    # the title no longer names self-correction
    assert "AI SELF-CORRECTED" not in out


def test_all_rows_present():
    out = render_findings_terminal(_buckets())
    for fid in ("F001", "F012", "F022", "F030"):
        assert fid in out, fid


def test_self_corrected_to_benign_routes_to_fp_section():
    # a self-corrected finding whose disposition is BENIGN (AI corrected it to an
    # FP) belongs with the FPs, NOT in FINDINGS.
    from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
        render_findings_terminal,
    )
    scfp = {"finding_id": "F009", "self_corrected": True,
            "final_disposition": "benign_or_false_positive",
            "react_conclusion": {"is_false_positive": True},
            "title": "", "claims": [{"type": "pid", "pid": 9088, "process": "svchost.exe"}],
            "description": "svchost UDP listener is benign"}
    real = {"finding_id": "F001", "title": "real", "source_tools": ["vol_malfind"],
            "claims": [{"type": "pid", "pid": 1, "process": "p.exe"}]}
    out = render_findings_terminal(
        {"confirmed_malicious_atomic": [real], "benign_or_false_positive": [scfp]},
        summary={})
    fp_hdr = out.index("AI-DETECTED FP/Benign")
    assert out.index("F009") > fp_hdr   # self-corrected-to-FP under the FP section
    assert out.index("F001") < fp_hdr   # the real finding stays in FINDINGS
