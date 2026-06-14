"""Tests for CC#15 Gemini output token cap.

Run 7 Gemini Inv2 output was 1,995 tokens while Claude was 4,614 -- the
Gemini backend max_output_tokens was clipping structured findings. These
tests lock the caps in place so future refactors can't silently lower
Inv2/Inv4 below 8192 or raise ReAct above 1024.
"""
from __future__ import annotations

import re
from pathlib import Path

RUN_PIPELINE = Path("run_pipeline.py")


def _source() -> str:
    return RUN_PIPELINE.read_text()


def _load_adapter_helper():
    """Load _adapter_token_cap in isolation without executing run_pipeline
    main (argparse runs at module load and breaks on pytest argv)."""
    import ast
    import types

    src = _source()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_adapter_token_cap":
            mod = types.ModuleType("adapter_helper")
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         "<_adapter_token_cap>", "exec"), mod.__dict__)
            return mod._adapter_token_cap
    raise AssertionError("_adapter_token_cap not found in run_pipeline.py")


class TestAdapterTokenCap:
    def test_adapter_react_token_cap_is_1024(self):
        """ReAct-shape call (max_turns>=2, timeout<=30) -> 1024 tokens."""
        fn = _load_adapter_helper()
        assert fn(timeout=30, max_turns=3) == 1024
        assert fn(timeout=30, max_turns=2) == 1024
        assert fn(timeout=15, max_turns=3) == 1024

    def test_adapter_non_react_token_cap_is_8192(self):
        """Non-ReAct adapter calls (longer timeout) get the full 8192."""
        fn = _load_adapter_helper()
        assert fn(timeout=60, max_turns=5) == 8192
        assert fn(timeout=120, max_turns=1) == 8192
        assert fn(timeout=90, max_turns=7) == 8192


class TestInv2Inv4LiveCallCaps:
    def test_gemini_inv2_token_cap_is_at_least_8192(self):
        """The LIVE Inv2 _live_call passes >= 8192 tokens."""
        src = _source()
        # Find the Inv2 analysis call and extract the max_tokens literal
        match = re.search(
            r'_live_call\(\s*_inv2_live_prompt\s*,\s*(\d+)\s*,\s*"Inv2 \(analysis\)"',
            src,
        )
        assert match, "Could not locate Inv2 _live_call in run_pipeline.py"
        max_tokens = int(match.group(1))
        assert max_tokens >= 8192, (
            f"Inv2 max_tokens={max_tokens} below 8192 -- Gemini will truncate"
        )

    def test_gemini_inv4_token_cap_is_at_least_8192(self):
        """The LIVE Inv4 _live_call passes >= 8192 tokens."""
        src = _source()
        match = re.search(
            r'_live_call\(\s*_inv4_live_prompt\s*,\s*(\d+)\s*,\s*"Inv4 \(report\)"',
            src,
        )
        assert match, "Could not locate Inv4 _live_call in run_pipeline.py"
        max_tokens = int(match.group(1))
        assert max_tokens >= 8192, (
            f"Inv4 max_tokens={max_tokens} below 8192 -- report truncated"
        )

    def test_gemini_inv1_token_cap_is_reasonable(self):
        """Inv1 tool selection JSON is small; 4096 is plenty."""
        src = _source()
        match = re.search(
            r'_live_call\(\s*_inv1_prompt_text\s*,\s*(\d+)\s*,\s*"Inv1',
            src,
        )
        assert match, "Could not locate Inv1 _live_call"
        max_tokens = int(match.group(1))
        assert 1024 <= max_tokens <= 8192


class TestCapsAreDocumented:
    def test_adapter_cap_docstring_mentions_react(self):
        """The cap helper must document its rationale so future changes notice."""
        fn = _load_adapter_helper()
        doc = fn.__doc__ or ""
        assert "ReAct" in doc
        assert "1024" in doc
        assert "8192" in doc
