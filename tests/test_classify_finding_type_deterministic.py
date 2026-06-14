"""_classify_finding_type must not relabel a deterministic atomic detection as
composite_narrative just because XCORR gave it >=6 corroborating tools.

run_pipeline.py is a top-level script, so the helper is extracted via AST and
exec'd (same pattern as test_f5_atomic_composite_split).
"""
from __future__ import annotations

import ast
from pathlib import Path


def _load():
    src = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()
    tree = ast.parse(src)
    ns = {"_F2_COMPOSITE_TOOL_THRESHOLD": 6,
          "_F2_COMPOSITE_TITLE_MARKERS": ("full attack chain",
                                          "attack chain summary")}
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_classify_finding_type")
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<t>", "exec"), ns)
    return ns["_classify_finding_type"]


_F = _load()


def test_deterministic_semantic_with_many_tools_is_atomic():
    f = {"deterministic_finding": True,
         "malicious_semantic_signals": ["srum_egress_outlier"],
         "source_tools": ["t"] * 16}
    assert _F(f) == "atomic"


def test_model_finding_many_tools_still_composite():
    assert _F({"source_tools": ["t"] * 8, "artifact": "x"}) == "composite_narrative"


def test_model_finding_few_tools_atomic():
    assert _F({"source_tools": ["t"] * 2}) == "atomic"


def test_deterministic_without_semantic_not_exempt():
    f = {"deterministic_finding": True, "malicious_semantic_signals": [],
         "source_tools": ["t"] * 16}
    assert _F(f) == "composite_narrative"
