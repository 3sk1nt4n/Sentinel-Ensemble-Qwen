"""vol_ldrmodules -> memory_injection_fact for UNBACKED modules (T1055), end to end.

An ldrmodules entry present in the loader/memory view (InLoad/InMem) with NO backing file
on disk (empty MappedPath) is a reflectively-loaded / injected region. This was the last
high-value memory tool with no candidate compiler. It reuses the memory_injection_fact
family (already validated by_pid), so it needs no new validation wiring.

FP discipline (from real base-hosta data): legit unlinked entries (System/smss/csrss meta,
every process's main image with InInit=False) ALL carry a valid System32 MappedPath, so
the empty-path requirement fires ZERO times on a clean image. Synthetic values only.
"""
from sift_sentinel.analysis.evidence_db import _c_ldrmodules, build_typed_evidence_db
from sift_sentinel.analysis.candidate_observations import build_candidate_observations

UNBACKED = {"Pid": 6666, "Process": "evil.exe", "Base": "0x7ff0",
            "InLoad": True, "InInit": True, "InMem": True, "MappedPath": ""}
BACKED = {"Pid": 800, "Process": "svchost.exe", "Base": "0x7ff1",
          "InLoad": True, "InInit": True, "InMem": True,
          "MappedPath": "\\Windows\\System32\\ntdll.dll"}
# real-data legit pattern: System/smss unlinked from every list but BACKED -> must not fire
LEGIT_UNLINKED_BACKED = {"Pid": 4, "Process": "System", "Base": "0x1",
                         "InLoad": False, "InInit": False, "InMem": False,
                         "MappedPath": "\\Windows\\System32\\ntdll.dll"}


def _emit(records):
    return [f for _i, f, _s in _c_ldrmodules(records) if f]


def test_compiler_emits_injection_fact_for_unbacked_module():
    facts = _emit([UNBACKED])
    assert len(facts) == 1
    assert facts[0]["fact_type"] == "memory_injection_fact"
    assert facts[0]["fields"]["characterization"] == "unbacked_executable_module"
    assert facts[0]["fields"]["pid"] == 6666
    assert facts[0]["index"]["by_pid"] == ["6666"]


def test_compiler_skips_backed_module():
    assert _emit([BACKED]) == []


def test_compiler_skips_legit_unlinked_but_backed_no_fp():
    # the exact System/smss pattern from real evidence -> no false positive
    assert _emit([LEGIT_UNLINKED_BACKED]) == []


def test_end_to_end_unbacked_module_reaches_validation_ready():
    db = build_typed_evidence_db({"vol_ldrmodules": {"output": [UNBACKED, BACKED, LEGIT_UNLINKED_BACKED]}})
    # exactly one memory_injection_fact compiled (the unbacked one)
    assert len(db["typed_facts"].get("memory_injection_fact", [])) == 1
    res = build_candidate_observations(db)
    assert any(c.get("validation_ready") for c in res["candidates"])
    assert any("memory_injection" in (c.get("signals") or []) for c in res["candidates"])


def test_end_to_end_clean_box_all_backed_no_candidate():
    db = build_typed_evidence_db({"vol_ldrmodules": {"output": [BACKED, LEGIT_UNLINKED_BACKED]}})
    assert db["typed_facts"].get("memory_injection_fact", []) == []
    res = build_candidate_observations(db)
    assert not any("memory_injection" in (c.get("signals") or []) for c in res["candidates"])
