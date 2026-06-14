"""High-value tool candidates must survive the return cap (overflow protection) and the
cap is raised to 1000.

The cap keeps validation_ready candidates first (already guaranteed). This adds a second
priority axis so that NON-ready candidates sourced from the highest-value detectors
(malfind/psxview/ldrmodules/WMI/SSDT/hollow) rank ABOVE ordinary low-value non-ready
candidates -- so a busy box can never let baseline noise push an injection/rootkit
candidate out of the returned set. Universal: keyed on the tool class, no case data.
"""
import json

from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
    _is_high_value_candidate,
)


def test_high_value_predicate():
    assert _is_high_value_candidate({"source_tools": ["vol_psxview"]}) is True
    assert _is_high_value_candidate({"source_tools": ["vol_malfind", "vol_pstree"]}) is True
    assert _is_high_value_candidate({"source_tools": ["parse_wmi_subscription"]}) is True
    assert _is_high_value_candidate({"source_tools": ["vol_pstree"]}) is False
    assert _is_high_value_candidate({"source_tools": []}) is False
    assert _is_high_value_candidate({}) is False


def test_cap_default_raised_to_1000():
    import inspect
    sig = inspect.signature(build_candidate_observations)
    assert sig.parameters["max_candidates"].default == 1000


def test_high_value_candidate_survives_a_tight_cap_over_low_value_noise():
    # one genuine malfind injection candidate + lots of low-value privilege noise.
    typed = {
        "memory_injection_fact": [{
            "fact_id": "mi1", "source_tool": "vol_malfind", "PID": 6666, "Name": "evil.exe",
            "raw_excerpt": json.dumps({"PID": 6666, "Process": "evil.exe",
                                       "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS"}),
        }],
    }
    # filler: many distinct low-value (non-ready) elevated-privilege context candidates
    typed["privilege_fact"] = [{
        "fact_id": "pv%d" % i, "source_tool": "vol_privileges",
        "raw_excerpt": json.dumps({"PID": 1000 + i, "Process": "svc%d.exe" % i,
                                   "Privilege": "SeDebugPrivilege", "Attributes": "Present,Enabled,Default"}),
    } for i in range(40)]

    res = build_candidate_observations({"typed_facts": typed}, max_candidates=3)
    returned = res["candidates"]
    assert len(returned) == 3
    # the malfind injection candidate must be present despite the tight cap
    assert any(_is_high_value_candidate(c) for c in returned), \
        "high-value injection candidate was overflowed out by low-value noise"
