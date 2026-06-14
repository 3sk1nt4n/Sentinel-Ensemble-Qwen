"""vol_ldrmodules is a cache-only injection corroborator (ReAct reads its raw
unlinked/hidden-DLL output; it is intentionally not compiled to typed facts), so
the 31X-lite coverage gate must NOT flag it as a silent-drop. A genuinely
uncompiled, non-exempt tool with records IS still flagged. Dataset-agnostic."""

from sift_sentinel.analysis.drift_gate import (
    build_evidencedb_coverage_snapshot,
    validate_evidencedb_coverage_snapshot,
)


def _env(n):
    return {"output": [{"i": i} for i in range(n)], "record_count": n}


def test_ldrmodules_cache_only_not_flagged_but_other_uncompiled_is():
    tool_outputs = {
        "vol_ldrmodules": _env(3),           # no compiler, cache-only -> exempt
        "zz_fake_uncompiled_tool": _env(2),  # no compiler, NOT exempt -> flagged
    }
    snap = build_evidencedb_coverage_snapshot({}, tool_outputs)
    dropped = snap["silent_dropped_tools_without_compiler"]
    assert "vol_ldrmodules" not in dropped
    assert "zz_fake_uncompiled_tool" in dropped


def test_validate_emits_no_silent_drop_violation_for_ldrmodules():
    snap = build_evidencedb_coverage_snapshot({}, {"vol_ldrmodules": _env(5)})
    verdicts = validate_evidencedb_coverage_snapshot(snap)
    ldr = [
        v for v in verdicts
        if v.get("kind") == "missing_compiler_for_nonempty_tool"
        and "vol_ldrmodules" in (str(v.get("details")) + str(v.get("message")))
    ]
    assert ldr == []
