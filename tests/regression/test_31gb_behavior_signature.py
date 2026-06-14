"""31G-B behavior_signature: structural grouping (synthetic, dataset-agnostic).

Locks: identical claim-classifications group together; an extra ttp separates;
process findings group by process (case-folded); the grouping is a true
partition (exact, disjoint cover); duplicate input ids rejected; dedup_map
reversible; the partition gate catches the duplicate-and-drop false-safe.
No real-dataset values appear here."""
from sift_sentinel.analysis.behavior_signature import (
    behavior_signature, partition_findings, build_dedup_map, assert_partition,
)


def _f(fid, claims): return {"finding_id": fid, "claims": claims}
def _ttp(*tags): return [{"type": "cmd", "ttp_tag": t} for t in tags]
def _proc(name): return [{"type": "pid", "pid": "1", "process": name}]


def test_identical_classification_groups():
    assert behavior_signature(_f("A", _ttp("tag_x", "tag_y"))) == \
           behavior_signature(_f("B", _ttp("tag_y", "tag_x")))


def test_extra_tag_separates():
    assert behavior_signature(_f("A", _ttp("tag_x", "tag_y"))) != \
           behavior_signature(_f("B", _ttp("tag_x", "tag_y", "tag_z")))


def test_process_groups_by_name_casefolded():
    assert behavior_signature(_f("A", _proc("alpha"))) == \
           behavior_signature(_f("B", _proc("ALPHA")))
    assert behavior_signature(_f("A", _proc("alpha"))) != \
           behavior_signature(_f("C", _proc("beta")))


def test_partition_is_exact_disjoint_cover():
    F = [_f("A", _ttp("x")), _f("B", _ttp("x")), _f("C", _proc("alpha")),
         _f("D", _proc("beta")), _f("E", _ttp("x", "y"))]
    assert_partition(F)
    groups = partition_findings(F)
    members = [x["finding_id"] for g in groups.values() for x in g]
    assert sorted(members) == ["A", "B", "C", "D", "E"]
    assert len(members) == len(set(members))


def test_dedup_map_reversible():
    F = [_f("A", _ttp("x")), _f("B", _ttp("x")), _f("C", _proc("alpha"))]
    m = build_dedup_map(F)
    all_ids = [fid for ids in m["groups"].values() for fid in ids]
    assert sorted(all_ids) == ["A", "B", "C"]
    assert set(m["by_finding"]) == {"A", "B", "C"}
    assert m["by_finding"]["A"] == m["by_finding"]["B"]
    assert m["by_finding"]["A"] != m["by_finding"]["C"]


def test_duplicate_input_id_rejected():
    F = [_f("A", _ttp("x")), _f("A", _ttp("y"))]
    try:
        assert_partition(F); assert False, "should raise on duplicate id"
    except AssertionError:
        pass


def test_partition_catches_drop_and_dup(monkeypatch):
    import sift_sentinel.analysis.behavior_signature as bs
    F = [_f("A", _ttp("x")), _f("B", _ttp("y")), _f("C", _ttp("z"))]
    monkeypatch.setattr(bs, "partition_findings",
                        lambda findings: {("g1",): [F[0], F[0]], ("g2",): [F[1]]})
    try:
        bs.assert_partition(F); assert False, "must reject duplicate-and-drop"
    except AssertionError:
        pass
