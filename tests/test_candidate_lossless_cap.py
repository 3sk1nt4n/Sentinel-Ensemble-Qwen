"""LOSSLESS-CAP: the return cap must never drop a validation-ready candidate.

Live telemetry (acme: '1000(1132) capped returned, 212 validation-ready',
ready_full==ready_returned==212) shows the 1000 cap is lossless TODAY because
ready candidates sort first and number ~200. But the guarantee was positional,
not structural: probed with max_candidates=2 over 5 ready candidates, the slice
dropped 3 validation-ready candidates. On an evidence-rich case with >1000
ready candidates the same silent loss would occur at the default cap.

Fix: the effective cap stretches to the validation-ready count
(max(max_candidates, ready_total)), so the cap only ever drops the non-ready
tail -- baseline noise -- no matter the case size. Raising the constant
(e.g. 1000 -> 1200) would NOT give this guarantee and would only admit more
thin single-source noise into the Inv2 prompt.
"""
import json

from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
)


def _injection_facts(n, start_pid=6000):
    return [{
        "fact_id": "mi%d" % i, "source_tool": "vol_malfind",
        "PID": start_pid + i, "Name": "p%d.exe" % i,
        "raw_excerpt": json.dumps({
            "PID": start_pid + i, "Process": "p%d.exe" % i,
            "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS"}),
    } for i in range(n)]


def _noise_privilege_facts(n, start_pid=1000):
    return [{
        "fact_id": "pv%d" % i, "source_tool": "vol_privileges",
        "raw_excerpt": json.dumps({
            "PID": start_pid + i, "Process": "svc%d.exe" % i,
            "Privilege": "SeDebugPrivilege",
            "Attributes": "Present,Enabled,Default"}),
    } for i in range(n)]


def test_cap_never_drops_validation_ready():
    # 5 validation-ready injection candidates, cap of 2: ALL 5 must return.
    typed = {"memory_injection_fact": _injection_facts(5)}
    res = build_candidate_observations({"typed_facts": typed}, max_candidates=2)
    ceiling = res["validation_ready_ceiling"]
    assert ceiling["validation_ready_total"] == 5
    assert ceiling["returned_validation_ready"] == 5, (
        "the cap dropped validation-ready candidates -- the lossless-cap "
        "guarantee is broken")
    assert sum(1 for c in res["candidates"] if c["validation_ready"]) == 5


def test_cap_still_drops_nonready_noise():
    # 2 ready + 40 non-ready noise, cap 5: all ready kept, noise capped.
    typed = {"memory_injection_fact": _injection_facts(2)}
    typed["privilege_fact"] = _noise_privilege_facts(40)
    res = build_candidate_observations({"typed_facts": typed}, max_candidates=5)
    cands = res["candidates"]
    assert len(cands) == 5                               # cap holds for noise
    assert sum(1 for c in cands if c["validation_ready"]) >= 2
    assert res["total_candidate_count"] > 5              # overflow shown honestly


def test_cap_unchanged_when_ready_below_cap():
    # the live shape (ready << cap): behavior must be byte-identical.
    typed = {"memory_injection_fact": _injection_facts(2)}
    typed["privilege_fact"] = _noise_privilege_facts(10)
    res = build_candidate_observations({"typed_facts": typed},
                                       max_candidates=1000)
    assert len(res["candidates"]) == res["total_candidate_count"]  # no cap hit
