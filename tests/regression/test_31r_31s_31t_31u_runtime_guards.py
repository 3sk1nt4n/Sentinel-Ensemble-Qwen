
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_31r_final_tool_health_not_applicable_accepts_failure_mode_status_kind():
    tree = ast.parse(_read("run_pipeline.py"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_is_not_applicable")
    mod = ast.Module(body=[fn], type_ignores=[])
    ast.fix_missing_locations(mod)
    ns = {}
    exec(compile(mod, "<_is_not_applicable>", "exec"), ns)

    f = ns["_is_not_applicable"]
    assert f({"kind": "not_applicable"})
    assert f({"status": "not_applicable"})
    assert f({"failure_mode": "not_applicable", "error": "no_yara_rules_available"})
    assert not f({"failure_mode": "runtime_error"})


def test_31r_mcp_client_does_not_mark_not_applicable_as_failed():
    text = _read("src/sift_sentinel/mcp_client.py")
    assert "31R: not_applicable is capability/coverage absence, not failure" in text
    assert "return result" in text
    assert "health.mark_failure" in text


def test_31s_runtime_heavy_react_tools_cache_only():
    text = _read("src/sift_sentinel/react_discipline.py")
    assert "31S-runtime: heavy ReAct tools are cache-only" in text
    assert re.search(r'"vol_memmap"\s*:\s*0', text)
    assert re.search(r'"vol_dumpfiles"\s*:\s*0', text)


def test_31s_runtime_derived_tools_do_not_fail_on_missing_runtime_outputs():
    text = _read("src/sift_sentinel/coordinator.py")
    assert "31S-runtime: derived-after-raw tools are Step 6C/cache-only during ReAct" in text
    assert "derived_after_raw_cache_only" in text
    assert '"failure_mode": "not_applicable"' in text


def test_31t_live_titles_are_not_hard_truncated_at_50_chars():
    text = _read("run_pipeline.py")
    assert "31T: do not truncate live finding titles" in text
    assert 'f.get("artifact", "")[:50]' not in text


def test_31u_track_b_user_account_defaults_are_set_after_renumber():
    text = _read("run_pipeline.py")
    assert "31U: normalize Track B user-account finding shape" in text
    assert 'finding_type", "compromised_user_account"' in text
    assert '"confidence_level"' in text
    assert '"tool_call_ids"' in text
