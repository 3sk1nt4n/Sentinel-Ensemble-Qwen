"""31G-D1 deterministic findings-table render (synthetic, inert)."""
import re
from sift_sentinel.analysis.behavior_signature import (
    build_behavior_groups, render_findings_tables_md, reportable_finding_ids)
def _f(fid,claims,**kw):
    d={"finding_id":fid,"claims":claims}; d.update(kw); return d
def _ttp(*t): return [{"type":"cmd","ttp_tag":x} for x in t]
def _proc(p): return [{"type":"pid","pid":"1","process":p}]
def _g(F,d): return build_behavior_groups(F,disposition_by_id=d)
def test_collapsible_one_row_enumerates():
    F=[_f("A",_ttp("c"),title="Cradle"),_f("B",_ttp("c"),title="Cradle")]
    md=render_findings_tables_md(_g(F,{"A":"confirmed_malicious_atomic","B":"confirmed_malicious_atomic"}))
    assert "(2 instances): A, B" in md and "(2 total)" in md
def test_entity_per_member_distinct_titles():
    F=[_f("A",_proc("p"),title="Memory injection"),_f("B",_proc("p"),title="Child spawn")]
    md=render_findings_tables_md(_g(F,{"A":"confirmed_malicious_atomic","B":"confirmed_malicious_atomic"}))
    assert "**A**: Memory injection" in md and "**B**: Child spawn" in md
    assert "instances)" not in md.split("Benign")[0]
def test_every_confirmed_id_coverage():
    F=[_f("C%d"%i,_ttp("c")) for i in range(18)]+[_f("X",_proc("p"),title="Inj")]
    g=_g(F,{f["finding_id"]:"confirmed_malicious_atomic" for f in F}); md=render_findings_tables_md(g)
    assert re.search(r"\(19 total\)",md)
    for fid in [f["finding_id"] for f in F]: assert fid in md
    assert reportable_finding_ids(g)==set(f["finding_id"] for f in F)
def test_fp_sc_tables():
    F=[_f("A",_ttp("x"),is_false_positive=True,title="FP row"),_f("B",_ttp("y"),self_corrected=True,title="SC row")]
    md=render_findings_tables_md(_g(F,{"A":"benign_or_false_positive","B":"confirmed_malicious_atomic"}))
    assert "Benign/False Positive (1)" in md and "**A**: FP row" in md
    assert "Self-Corrections (1)" in md and "**B**: SC row" in md
