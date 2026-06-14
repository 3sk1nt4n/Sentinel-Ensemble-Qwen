"""vol_callbacks -> kernel_callback_fact compiler (closes the last 31X WARN).

Every live run warned: 'raw tool vol_callbacks produced records but no
compiler is registered in _TOOL_COMPILERS - records silently dropped' --
318 kernel-callback registrations (process/thread/image-load notify routines,
the classic rootkit hook surface) never reached the EvidenceDB.

Structural pass-through like the sibling _c_ssdt: no is_suspicious judgment,
no module name lists. Record schema verified against live Vol3 output:
  Type / Callback (address) / Module / Symbol|None / Detail|None / TreeDepth.
"""
from sift_sentinel.analysis.phase2_extractors import (
    PHASE2_COMPILERS,
    PHASE2_FACT_TYPES,
    _c_callbacks,
)


def _compile(records):
    out, skips = [], []
    for _idx, fact, reason in _c_callbacks(records):
        if fact is not None:
            out.append(fact)
        else:
            skips.append(reason)
    return out, skips


def test_registered_so_the_31x_warn_clears():
    assert PHASE2_COMPILERS.get("vol_callbacks") is _c_callbacks
    assert "kernel_callback_fact" in PHASE2_FACT_TYPES
    # the gate reads the merged _TOOL_COMPILERS -- prove the merge picked it up.
    from sift_sentinel.analysis.evidence_db import _TOOL_COMPILERS
    assert "vol_callbacks" in _TOOL_COMPILERS


def test_live_shape_passthrough():
    # exact live record shape (values are generic OS modules, no case data)
    recs = [
        {"Callback": 272689121941808, "Detail": None, "Module": "WdFilter",
         "Symbol": None, "Type": "PspLoadImageNotifyRoutine", "TreeDepth": 0},
        {"Callback": 272689422002976, "Detail": None, "Module": "ahcache",
         "Symbol": "HalpRMStub", "Type": "PspLoadImageNotifyRoutine",
         "TreeDepth": 0},
    ]
    facts, skips = _compile(recs)
    assert len(facts) == 2 and not skips
    f = facts[0]
    assert f["fact_type"] == "kernel_callback_fact"
    assert f["callback_type"] == "PspLoadImageNotifyRoutine"
    assert f["module"] == "wdfilter"            # normalized lower
    assert f["address"] == 272689121941808
    assert facts[1]["symbol"] == "HalpRMStub"


def test_random_tokens_pass_through_verbatim():
    # metamorphic: the compiler must never key on specific names.
    recs = [{"Callback": 1, "Module": "Zq9xK", "Symbol": "sYm",
             "Type": "TknT", "Detail": "d1"}]
    facts, _ = _compile(recs)
    assert facts[0]["module"] == "zq9xk"
    assert facts[0]["callback_type"] == "TknT"
    assert facts[0]["detail"] == "d1"


def test_empty_and_malformed_input():
    assert _compile([]) == ([], [])
    assert _compile(None) == ([], [])
    facts, skips = _compile(["not-a-dict", {"Callback": 5}])
    assert facts == []
    assert "non_dict_record" in skips and "no_type_or_module" in skips


def test_entity_ids_distinct_per_callback():
    recs = [{"Callback": 100 + i, "Module": "m", "Type": "T"} for i in range(4)]
    facts, _ = _compile(recs)
    assert len({f["entity_id"] for f in facts}) == 4
