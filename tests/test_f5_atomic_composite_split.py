"""
F5 regression tests: atomic/composite display split.

Dataset-agnostic source-level tests because run_pipeline.py is not safely
importable due to argparse/module-load behavior. Helper behavior is
verified by extracting _f5_is_synthesis_finding via AST and exec'ing it
in an isolated namespace.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path


def _src() -> str:
    return Path("run_pipeline.py").read_text()


def _load_helper():
    """Extract _f5_is_synthesis_finding from run_pipeline.py via AST and
    execute it in an isolated namespace. Avoids importing the pipeline."""
    tree = ast.parse(_src())
    func = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_f5_is_synthesis_finding":
            func = node
            break
    assert func is not None, "missing _f5_is_synthesis_finding at module level"
    mod = ast.Module(body=[func], type_ignores=[])
    ast.fix_missing_locations(mod)
    ns: dict = {}
    exec(compile(mod, "<f5_helper>", "exec"), ns)
    return ns["_f5_is_synthesis_finding"]


class TestHelperExists:
    def test_helper_defined_at_module_level(self):
        tree = ast.parse(_src())
        names = [
            n.name for n in tree.body
            if isinstance(n, ast.FunctionDef)
        ]
        assert "_f5_is_synthesis_finding" in names

    def test_helper_callable_via_ast_exec(self):
        h = _load_helper()
        assert callable(h)


class TestHelperBehavior:
    def test_composite_narrative_is_synthesis(self):
        h = _load_helper()
        assert h({"finding_type": "composite_narrative"}) is True

    def test_synthesis_is_synthesis(self):
        h = _load_helper()
        assert h({"finding_type": "synthesis"}) is True

    def test_composite_is_synthesis(self):
        h = _load_helper()
        assert h({"finding_type": "composite"}) is True

    def test_hyphen_form_normalized_to_synthesis(self):
        h = _load_helper()
        assert h({"finding_type": "composite-narrative"}) is True

    def test_case_insensitive_finding_type(self):
        h = _load_helper()
        assert h({"finding_type": "COMPOSITE_NARRATIVE"}) is True
        assert h({"finding_type": "Synthesis"}) is True

    def test_critical_synthesis_marker_fallback_is_synthesis(self):
        h = _load_helper()
        assert h({"artifact": "[CRITICAL-SYNTHESIS] F012 full attack chain"}) is True

    def test_marker_in_title_also_triggers(self):
        h = _load_helper()
        assert h({"title": "[critical-synthesis] kill chain rollup"}) is True

    def test_missing_finding_type_without_marker_defaults_to_atomic(self):
        h = _load_helper()
        assert h({"artifact": "normal missing finding_type"}) is False

    def test_atomic_finding_type_without_marker_is_not_synthesis(self):
        h = _load_helper()
        assert h({"finding_type": "atomic", "artifact": "normal evidence"}) is False

    def test_empty_dict_defaults_to_atomic(self):
        h = _load_helper()
        assert h({}) is False


class TestSeverityCountSplit:
    def test_severity_line_has_atomic_and_synthesis_counts(self):
        src = _src()
        assert "CRITICAL atomic" in src
        assert "CRITICAL synthesis" in src
        assert "_atomic_crit_count" in src
        assert "_synth_crit_count" in src

    def test_old_blended_critical_count_removed(self):
        src = _src()
        assert "[CRITICAL] {_sev_counts['CRITICAL']}" not in src
        assert '[CRITICAL] {_sev_counts["CRITICAL"]}' not in src

    def test_atomic_count_uses_helper_negation(self):
        src = _src()
        pattern = re.compile(
            r"_atomic_crit_count\s*=\s*sum\([\s\S]*?not\s+_f5_is_synthesis_finding\(_f\)",
            re.MULTILINE,
        )
        assert pattern.search(src), (
            "atomic critical count must use `not _f5_is_synthesis_finding(_f)`"
        )

    def test_synth_count_uses_helper(self):
        src = _src()
        pattern = re.compile(
            r"_synth_crit_count\s*=\s*sum\([\s\S]*?(?<!not )_f5_is_synthesis_finding\(_f\)",
            re.MULTILINE,
        )
        assert pattern.search(src), (
            "synthesis critical count must use `_f5_is_synthesis_finding(_f)` (not negated)"
        )

    def test_atomic_and_synth_count_no_longer_reference_composite_narrative_literal(self):
        src = _src()
        atomic_block = re.search(
            r"_atomic_crit_count\s*=\s*sum\([\s\S]*?\)", src
        )
        synth_block = re.search(
            r"_synth_crit_count\s*=\s*sum\([\s\S]*?\)", src
        )
        assert atomic_block and synth_block
        assert "composite_narrative" not in atomic_block.group(0)
        assert "composite_narrative" not in synth_block.group(0)


class TestDetailBlockSplit:
    def test_atomic_and_synthesis_variables_exist(self):
        src = _src()
        assert "_atomic_crits" in src
        assert "_synthesis_crits" in src

    def test_old_blended_header_removed(self):
        src = _src()
        assert "CRITICAL findings ({len(_criticals)})" not in src

    def test_atomic_section_header_exists(self):
        src = _src()
        assert "CRITICAL atomic findings" in src

    def test_synthesis_section_header_exists(self):
        src = _src()
        assert "CRITICAL synthesis narrative" in src

    def test_synthesis_marker_preserves_severity(self):
        src = _src()
        assert "[CRITICAL-SYNTHESIS]" in src


class TestPartitionLogic:
    def test_atomic_partition_uses_helper_negation(self):
        src = _src()
        pattern = re.compile(
            r"_atomic_crits\s*=\s*\[[\s\S]*?not\s+_f5_is_synthesis_finding\(_f\)",
            re.MULTILINE,
        )
        assert pattern.search(src), (
            "atomic detail partition must use `not _f5_is_synthesis_finding(_f)`"
        )

    def test_synthesis_partition_uses_helper(self):
        src = _src()
        pattern = re.compile(
            r"_synthesis_crits\s*=\s*\[[\s\S]*?(?<!not )_f5_is_synthesis_finding\(_f\)",
            re.MULTILINE,
        )
        assert pattern.search(src), (
            "synthesis detail partition must use `_f5_is_synthesis_finding(_f)` (not negated)"
        )

    def test_partitions_no_longer_reference_composite_narrative_literal(self):
        src = _src()
        atomic_block = re.search(
            r"_atomic_crits\s*=\s*\[[\s\S]*?\]", src
        )
        synth_block = re.search(
            r"_synthesis_crits\s*=\s*\[[\s\S]*?\]", src
        )
        assert atomic_block and synth_block
        assert "composite_narrative" not in atomic_block.group(0)
        assert "composite_narrative" not in synth_block.group(0)


class TestOrderingAndConditional:
    def test_atomic_section_before_synthesis_section(self):
        src = _src()
        atomic_idx = src.find("CRITICAL atomic findings")
        synth_idx = src.find("CRITICAL synthesis narrative")
        assert atomic_idx != -1
        assert synth_idx != -1
        assert atomic_idx < synth_idx

    def test_synthesis_section_is_conditional(self):
        src = _src()
        idx = src.find("CRITICAL synthesis narrative")
        assert idx != -1
        context = src[max(0, idx - 500):idx]
        assert "if _synthesis_crits" in context


class TestDisplayInvariant:
    def test_synthesis_not_downgraded_or_hidden(self):
        src = _src()
        assert "CRITICAL synthesis narrative" in src
        assert "[CRITICAL-SYNTHESIS]" in src

    def test_critical_synthesis_marker_preserved_in_output(self):
        src = _src()
        # The marker must be emitted verbatim in the detail loop
        assert re.search(
            r"\[CRITICAL-SYNTHESIS\][\s\S]*?_syn\.get\('finding_id'",
            src,
        ), "[CRITICAL-SYNTHESIS] marker must prefix the synthesis detail rows"
