"""
F2 regression tests: composite vs atomic finding classification.

Dataset-agnostic properties (slot 28):
  - No hardcoded finding IDs
  - No hardcoded tool names from real runs
  - Property-based assertions against the helper function

NOTE: run_pipeline.py is a script -- it calls argparse.parse_args() at
module load. Direct `from run_pipeline import ...` breaks under pytest
because argparse sees pytest's own argv. We use AST-exec (same pattern
as tests/test_pipeline/test_html_report.py) to extract the helper and
its constants without running the top-level script.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest


# ── Module-level extraction so pytest.mark.parametrize can see the markers
# tuple at collection time. AST-only, no script execution.
def _extract_f2_namespace() -> dict:
    src = Path("run_pipeline.py").read_text()
    tree = ast.parse(src)
    wanted = {
        "_classify_finding_type",
        "_F2_COMPOSITE_TITLE_MARKERS",
        "_F2_COMPOSITE_TOOL_THRESHOLD",
    }
    ns: dict = {"__builtins__": __builtins__}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            exec(compile(ast.get_source_segment(src, node), "run_pipeline.py", "exec"), ns)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.target.id in wanted:
            exec(compile(ast.get_source_segment(src, node), "run_pipeline.py", "exec"), ns)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    exec(compile(ast.get_source_segment(src, node), "run_pipeline.py", "exec"), ns)
                    break
    missing = wanted - ns.keys()
    if missing:
        raise RuntimeError(f"F2 names not found in run_pipeline.py: {missing}")
    return ns


_F2 = _extract_f2_namespace()
_classify_finding_type = _F2["_classify_finding_type"]
_F2_COMPOSITE_TITLE_MARKERS = _F2["_F2_COMPOSITE_TITLE_MARKERS"]
_F2_COMPOSITE_TOOL_THRESHOLD = _F2["_F2_COMPOSITE_TOOL_THRESHOLD"]


class TestClassifyByToolCount:
    def test_threshold_triggers_composite(self):
        finding = {
            "source_tools": ["t" + str(i) for i in range(_F2_COMPOSITE_TOOL_THRESHOLD)],
            "artifact": "normal artifact title",
        }
        assert _classify_finding_type(finding) == "composite_narrative"

    def test_below_threshold_is_atomic(self):
        finding = {
            "source_tools": ["t" + str(i) for i in range(_F2_COMPOSITE_TOOL_THRESHOLD - 1)],
            "artifact": "normal artifact title",
        }
        assert _classify_finding_type(finding) == "atomic"

    def test_zero_source_tools_is_atomic(self):
        finding = {"source_tools": [], "artifact": "some event"}
        assert _classify_finding_type(finding) == "atomic"


class TestClassifyByTitle:
    @pytest.mark.parametrize("marker", _F2_COMPOSITE_TITLE_MARKERS)
    def test_each_marker_triggers_composite(self, marker):
        finding = {
            "source_tools": ["t1", "t2"],  # below threshold
            "artifact": f"Incident report: {marker} observed across hosts",
        }
        assert _classify_finding_type(finding) == "composite_narrative"

    def test_marker_is_case_insensitive(self):
        finding = {
            "source_tools": ["t1"],
            "artifact": "FULL ATTACK CHAIN summary of observed activity",
        }
        assert _classify_finding_type(finding) == "composite_narrative"


class TestClassifyTotal:
    def test_every_finding_gets_a_type(self):
        # Property: classification is total -- no finding returns None
        samples = [
            {"source_tools": [], "artifact": ""},
            {"source_tools": ["t1"] * 10, "artifact": ""},
            {"source_tools": [], "artifact": "Full Attack Chain Observed"},
            {},  # degenerate empty dict
        ]
        for s in samples:
            result = _classify_finding_type(s)
            assert result in ("atomic", "composite_narrative")

    def test_missing_keys_default_to_atomic(self):
        # Degenerate finding with no source_tools, no artifact
        assert _classify_finding_type({}) == "atomic"
