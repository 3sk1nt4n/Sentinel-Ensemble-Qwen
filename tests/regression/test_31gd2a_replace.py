"""31G-D2a confirmed-section replace (synthetic + defect/fallback-shaped, inert)."""
from sift_sentinel.analysis.behavior_signature import (
    build_behavior_groups, render_confirmed_md, render_findings_tables_md,
    replace_confirmed_findings_section, confirmed_finding_ids)
def _f(fid,claims,**kw):
    d={"finding_id":fid,"claims":claims}; d.update(kw); return d
def _ttp(*t): return [{"type":"cmd","ttp_tag":x} for x in t]
def _g(F,d): return build_behavior_groups(F,disposition_by_id=d)
def _five():
    F=[_f("F%03d"%i,_ttp("cradle")) for i in range(1,6)]
    return _g(F,{f["finding_id"]:"confirmed_malicious_atomic" for f in F})
LLM_REPORT="""# Forensic Incident Report

## Key Findings

### Confirmed Malicious Atomic Findings (5 Total)
- **F001**: Cradle one
- **F002**: Cradle two
(plus 3 similar variants summarized for brevity)

## Requiring Further Investigation
- nothing
"""
def test_replace_restores_all_dropped_ids():
    g=_five(); new,n=replace_confirmed_findings_section(LLM_REPORT,g); assert n>0
    for fid in ["F001","F002","F003","F004","F005"]: assert fid in new
    assert "(5 total)" in new and "(plus 3 similar" not in new
    assert "## Requiring Further Investigation" in new and "## Key Findings" in new
def test_idempotent_byte_identical():
    g=_five(); once,_=replace_confirmed_findings_section(LLM_REPORT,g)
    twice,_=replace_confirmed_findings_section(once,g); assert once==twice
def test_drift_tolerant_header_no_count():
    g=_five(); rpt=LLM_REPORT.replace("### Confirmed Malicious Atomic Findings (5 Total)","### Confirmed Malicious Findings")
    new,n=replace_confirmed_findings_section(rpt,g); assert n>0 and "F005" in new
def test_fallback_insert_when_no_confirmed_header():
    g=_five(); rpt="# R\n\n## Key Findings\n\nprose\n\n## Requiring Further Investigation\n- x\n"
    new,n=replace_confirmed_findings_section(rpt,g)
    assert n>0 and "Confirmed Malicious Atomic Findings (5 total)" in new
    assert new.index("## Key Findings")<new.index("Confirmed Malicious")<new.index("## Requiring")
def test_does_not_duplicate_bucket_fallback_confirmed_section():
    report="# Sentinel Qwen Ensemble Incident Report\n## Status\nok\n## Confirmed Malicious (atomic)\n- **F001**: old row\n## Requiring Further Investigation\n- x\n"
    g=_five(); new,n=replace_confirmed_findings_section(report,g)
    assert new.count("Confirmed Malicious")==1
    assert "## Confirmed Malicious Atomic Findings" in new
    assert "F005" in new and "## Requiring Further Investigation" in new
def test_preserves_heading_level():
    g=_five()
    n2,_=replace_confirmed_findings_section("## Confirmed Malicious (atomic)\n- old\n\n## Next\n",g)
    assert "## Confirmed Malicious Atomic Findings (5 total)" in n2 and "### Confirmed Malicious Atomic" not in n2
    n3,_=replace_confirmed_findings_section("### Confirmed Malicious Atomic Findings (5 Total)\n- old\n\n## Next\n",g)
    assert "### Confirmed Malicious Atomic Findings (5 total)" in n3
def test_confirmed_finding_ids_covered_by_render():
    g=_five(); block=render_confirmed_md(g)
    for fid in confirmed_finding_ids(g): assert fid in block
    assert confirmed_finding_ids(g)=={"F001","F002","F003","F004","F005"}
def test_combined_render_backward_compatible():
    g=_five(); md=render_findings_tables_md(g)
    assert "Confirmed Malicious Atomic Findings (5 total)" in md
    assert "Benign/False Positive (0)" in md and "Self-Corrections (0)" in md
