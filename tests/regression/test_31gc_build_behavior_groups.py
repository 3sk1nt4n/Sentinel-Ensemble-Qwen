"""31G-C build_behavior_groups: freeze schema + collapsible logic (synthetic)."""
from sift_sentinel.analysis.behavior_signature import build_behavior_groups
def _f(fid, claims, **kw):
    d={"finding_id":fid,"claims":claims}; d.update(kw); return d
def _ttp(*t): return [{"type":"cmd","ttp_tag":x} for x in t]
def _proc(p): return [{"type":"pid","pid":"1","process":p}]
def test_ttp_collapsible_entity_not():
    F=[_f("A",_ttp("cradle")),_f("B",_ttp("cradle")),_f("C",_proc("a")),_f("D",_proc("a"))]
    g={tuple(x["member_finding_ids"]):x for x in build_behavior_groups(F)}
    assert g[("A","B")]["collapsible"] is True and g[("A","B")]["group_kind"]=="ttp_defined"
    assert g[("C","D")]["collapsible"] is False and g[("C","D")]["group_kind"]=="entity_defined"
def test_members_complete_titles_preserved():
    F=[_f("A",_proc("a"),title="Memory injection"),_f("B",_proc("a"),title="Child spawn")]
    g=build_behavior_groups(F)[0]
    assert g["member_finding_ids"]==["A","B"]
    assert {m["finding_id"]:m["title"] for m in g["members"]}=={"A":"Memory injection","B":"Child spawn"}
def test_partition_of_input_ids():
    F=[_f("A",_ttp("x")),_f("B",_ttp("x")),_f("C",_proc("p")),_f("D",_ttp("x","y")),_f("E",_proc("q"))]
    ids=[fid for g in build_behavior_groups(F) for fid in g["member_finding_ids"]]
    assert sorted(ids)==["A","B","C","D","E"] and len(ids)==len(set(ids))
def test_fp_sc_disposition_overlay():
    F=[_f("A",_ttp("x"),self_corrected=True),_f("B",_ttp("x"),is_false_positive=True)]
    g=build_behavior_groups(F,disposition_by_id={"A":"confirmed","B":"benign"})[0]
    assert g["self_corrected_member_ids"]==["A"] and g["fp_member_ids"]==["B"]
    assert g["disposition_set"]==["benign","confirmed"]
def test_no_representative_title_field():
    assert "representative_title" not in build_behavior_groups([_f("A",_ttp("x"))])[0]
