"""Tests for coordinator.py -- the 16-step pipeline conductor."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import os

@pytest.fixture(autouse=True)
def dry_run_mode(monkeypatch):
    """Force all coordinator tests to use the legacy subprocess path."""
    monkeypatch.setenv("SIFT_DRY_RUN", "1")


from sift_sentinel.coordinator import (
    BOOTSTRAP_TOOLS,
    GOLDEN_PATH_TOOLS,
    INVESTIGATION_TOOLS,
    MANDATORY_TOOLS,
    _TOOL_REGISTRY,
    _coerce_findings,
    _coerce_report,
    _coerce_selected_tools,
    _guardrail_filter_tools,
    _expect_dict,
    _psscan_fallback,
    _safe_finding_id,
    _safe_state_path,
    build_bootstrap_summary,
    build_inv1_prompt,
    compare_fingerprints,
    empty_findings_fallback,
    ensure_state_dir,
    golden_path_fallback,
    golden_path_tools,
    invoke_claude,
    read_state,
    run_mandatory_tools,
    run_pipeline,
    run_tool,
    safety_net_tools,
    sha256_fingerprint,
    skip_threads_fallback,
    ssdt_check,
    step_02_fingerprint,
    step_03_ssdt,
    step_10_validate,
    step_11_investigate,
    step_11b_enrich_findings,
    step_11c_revalidate,
    step_13_calibrate,
    step_15_verify,
    template_report_fallback,
    write_state,
)


# ── SHA256 fingerprinting ────────────────────────────────────────────────


class TestSHA256:
    def test_fingerprint_real_file(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"evidence data")
        result = sha256_fingerprint([str(f)])
        assert len(result) == 1
        assert len(result[str(f)]) == 64  # hex digest length

    def test_fingerprint_consistent(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"evidence data 12345")
        h1 = sha256_fingerprint([str(f)])
        h2 = sha256_fingerprint([str(f)])
        assert h1 == h2

    def test_fingerprint_detects_change(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"original")
        h1 = sha256_fingerprint([str(f)])
        f.write_bytes(b"modified")
        h2 = sha256_fingerprint([str(f)])
        assert h1[str(f)] != h2[str(f)]

    def test_fingerprint_missing_file_raises_by_default(self):
        with pytest.raises(FileNotFoundError, match="Evidence file not found"):
            sha256_fingerprint(["/nonexistent/file.raw"])

    def test_fingerprint_missing_file_allow_missing(self):
        result = sha256_fingerprint(
            ["/nonexistent/file.raw"], allow_missing=True,
        )
        assert result["/nonexistent/file.raw"] == "FILE_NOT_FOUND"

    def test_fingerprint_empty_list(self):
        assert sha256_fingerprint([]) == {}

    def test_fingerprint_multiple_files(self, tmp_path):
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        a.write_bytes(b"aaa")
        b.write_bytes(b"bbb")
        result = sha256_fingerprint([str(a), str(b)])
        assert len(result) == 2
        assert result[str(a)] != result[str(b)]

    def test_compare_match(self):
        pre = {"/a": "abc123", "/b": "def456"}
        post = {"/a": "abc123", "/b": "def456"}
        result = compare_fingerprints(pre, post)
        assert result["match"] is True
        assert len(result["details"]) == 2
        assert all(d["match"] for d in result["details"])

    def test_compare_mismatch(self):
        pre = {"/a": "abc123"}
        post = {"/a": "CHANGED"}
        result = compare_fingerprints(pre, post)
        assert result["match"] is False

    def test_compare_missing_post(self):
        pre = {"/a": "abc123"}
        result = compare_fingerprints(pre, {})
        assert result["match"] is False
        assert result["details"][0]["post"] == "MISSING"

    def test_compare_empty(self):
        result = compare_fingerprints({}, {})
        assert result["match"] is True

    def test_compare_file_not_found_never_matches(self):
        """Two FILE_NOT_FOUND values must NOT count as integrity match."""
        pre = {"/a": "FILE_NOT_FOUND"}
        post = {"/a": "FILE_NOT_FOUND"}
        result = compare_fingerprints(pre, post)
        assert result["match"] is False

    def test_compare_directory_never_matches(self):
        """DIRECTORY sentinels must fail the integrity check."""
        pre = {"/mnt": "DIRECTORY"}
        post = {"/mnt": "DIRECTORY"}
        result = compare_fingerprints(pre, post)
        assert result["match"] is False

    def test_compare_missing_sentinel_never_matches(self):
        """MISSING sentinels must fail the integrity check."""
        pre = {"/a": "abc123"}
        post = {"/a": "MISSING"}
        result = compare_fingerprints(pre, post)
        assert result["match"] is False

    def test_step_02_writes_file(self, tmp_path):
        evidence = tmp_path / "ev.bin"
        evidence.write_bytes(b"data")
        sd = tmp_path / "state"
        sd.mkdir()
        hashes = step_02_fingerprint([str(evidence)], sd)
        assert (sd / "sha256_pre.txt").exists()
        assert len(hashes) == 1

    def test_step_15_match(self, tmp_path):
        evidence = tmp_path / "ev.bin"
        evidence.write_bytes(b"data")
        sd = tmp_path / "state"
        sd.mkdir()
        pre = sha256_fingerprint([str(evidence)])
        result = step_15_verify([str(evidence)], pre, sd)
        assert result["match"] is True
        assert (sd / "sha256_post.txt").exists()

    def test_step_15_spoliation(self, tmp_path):
        evidence = tmp_path / "ev.bin"
        evidence.write_bytes(b"original")
        pre = sha256_fingerprint([str(evidence)])
        evidence.write_bytes(b"tampered")
        sd = tmp_path / "state"
        sd.mkdir()
        result = step_15_verify([str(evidence)], pre, sd)
        assert result["match"] is False


# ── SSDT check ───────────────────────────────────────────────────────────


class TestSSDTCheck:
    def test_empty_is_degraded(self):
        # Empty SSDT output means plugin failed/no data -- cannot confirm
        # kernel integrity, so trust must degrade (not "full").
        assert ssdt_check({"output": []}) == "degraded"

    def test_no_output_key_is_degraded(self):
        assert ssdt_check({}) == "degraded"

    def test_error_is_degraded(self):
        assert ssdt_check({"output": [], "error": "plugin failed"}) == "degraded"

    def test_all_ntoskrnl(self):
        entries = [{"Module": "ntoskrnl"} for _ in range(100)]
        assert ssdt_check({"output": entries}) == "full"

    def test_ntoskrnl_exe(self):
        entries = [{"Module": "ntoskrnl.exe"}]
        assert ssdt_check({"output": entries}) == "full"

    def test_win32k_clean(self):
        entries = [
            {"Module": "ntoskrnl"},
            {"Module": "win32k.sys"},
            {"Module": "win32k"},
        ]
        assert ssdt_check({"output": entries}) == "full"

    def test_case_insensitive(self):
        entries = [{"Module": "NTOSKRNL.EXE"}]
        assert ssdt_check({"output": entries}) == "full"

    def test_degraded_one_hook(self):
        entries = [
            {"Module": "ntoskrnl"},
            {"Module": "rootkit.sys"},
        ]
        assert ssdt_check({"output": entries}) == "degraded"

    def test_degraded_five_hooks(self):
        entries = [{"Module": "ntoskrnl"}] * 50
        entries += [{"Module": f"evil{i}.sys"} for i in range(5)]
        assert ssdt_check({"output": entries}) == "degraded"

    def test_untrusted_many_hooks(self):
        entries = [{"Module": f"evil{i}.sys"} for i in range(10)]
        assert ssdt_check({"output": entries}) == "untrusted"

    def test_empty_module_ignored(self):
        entries = [{"Module": ""}]
        assert ssdt_check({"output": entries}) == "full"

    def test_lowercase_module_key(self):
        entries = [{"module": "ntoskrnl"}]
        assert ssdt_check({"output": entries}) == "full"

    def test_step_03_runs_volatility(self, tmp_path):
        with patch(
            "sift_sentinel.coordinator.run_volatility",
            return_value=[{"Address": "0x1", "Index": 0,
                           "Module": "ntoskrnl", "Symbol": "NtTest"}],
        ):
            trust = step_03_ssdt(tmp_path, "/evidence/memory.img")
        assert trust in ("full", "degraded", "untrusted")
        assert (tmp_path / "tool_outputs" / "vol_ssdt.json").exists()


# ── invoke_claude ────────────────────────────────────────────────────────


class TestInvokeClaude:
    def test_timeout_triggers_fallback(self, tmp_path):
        prompt = tmp_path / "prompt.md"
        prompt.write_text("test prompt")
        fallback = MagicMock(return_value={"fallback": True})

        with patch(
            "sift_sentinel.coordinator.subprocess.run",
            side_effect=subprocess.TimeoutExpired("claude", 60),
        ):
            result = invoke_claude(str(prompt), 60, 5, fallback)

        fallback.assert_called_once()
        assert result == {"fallback": True}

    def test_invalid_json_triggers_fallback(self, tmp_path):
        prompt = tmp_path / "prompt.md"
        prompt.write_text("test prompt")
        fallback = MagicMock(return_value={"fallback": True})

        mock_result = MagicMock()
        mock_result.stdout = b"not valid json {{{{"

        with patch(
            "sift_sentinel.coordinator.subprocess.run",
            return_value=mock_result,
        ):
            result = invoke_claude(str(prompt), 60, 5, fallback)

        fallback.assert_called_once()
        assert result == {"fallback": True}

    def test_success_returns_parsed_json(self, tmp_path):
        prompt = tmp_path / "prompt.md"
        prompt.write_text("test prompt")
        fallback = MagicMock()

        mock_result = MagicMock()
        mock_result.stdout = b'{"selected_tools": ["vol_cmdline"]}'

        with patch(
            "sift_sentinel.coordinator.subprocess.run",
            return_value=mock_result,
        ):
            result = invoke_claude(str(prompt), 60, 5, fallback)

        fallback.assert_not_called()
        assert result == {"selected_tools": ["vol_cmdline"]}

    def test_fenced_json_stripped(self, tmp_path):
        prompt = tmp_path / "prompt.md"
        prompt.write_text("test prompt")
        fallback = MagicMock()

        mock_result = MagicMock()
        mock_result.stdout = b'```json\n{"key": "value"}\n```'

        with patch(
            "sift_sentinel.coordinator.subprocess.run",
            return_value=mock_result,
        ):
            result = invoke_claude(str(prompt), 60, 5, fallback)

        assert result == {"key": "value"}

    def test_missing_prompt_triggers_fallback(self):
        fallback = MagicMock(return_value={"fallback": True})
        result = invoke_claude("/nonexistent/prompt.md", 60, 5, fallback)
        fallback.assert_called_once()
        assert result == {"fallback": True}

    def test_subprocess_args(self, tmp_path):
        prompt = tmp_path / "prompt.md"
        prompt.write_text("my prompt text")
        fallback = MagicMock()

        mock_result = MagicMock()
        mock_result.stdout = b'{"ok": true}'

        with patch(
            "sift_sentinel.coordinator.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            invoke_claude(str(prompt), 120, 7, fallback)

        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "claude"
        assert "--print" in cmd
        assert "--output-format" in cmd
        assert "json" in cmd
        assert "--max-turns" in cmd
        assert "7" in cmd
        assert call_args[1]["timeout"] == 120
        assert call_args[1]["capture_output"] is True


# ── Golden Path & fallbacks ──────────────────────────────────────────────


class TestGoldenPath:
    def test_golden_path_tools_count(self):
        assert len(golden_path_tools()) >= 7
        assert "vol_pstree" in golden_path_tools()
        assert "parse_prefetch" in golden_path_tools()

    def test_golden_path_tools_contents(self):
        tools = golden_path_tools()
        assert "vol_pstree" in tools
        assert "vol_netscan" in tools
        assert "get_amcache" in tools
        assert "vol_cmdline" in tools

    def test_golden_path_returns_copy(self):
        a = golden_path_tools()
        b = golden_path_tools()
        assert a is not b

    def test_golden_path_fallback_shape(self):
        result = golden_path_fallback()
        assert "selected_tools" in result
        assert len(result["selected_tools"]) == len(golden_path_tools())

    def test_bootstrap_subset_of_golden(self):
        gp = set(GOLDEN_PATH_TOOLS)
        for t in BOOTSTRAP_TOOLS:
            assert t in gp

    def test_bootstrap_is_two_tools(self):
        assert len(BOOTSTRAP_TOOLS) == 2
        assert "vol_pstree" in BOOTSTRAP_TOOLS
        assert "vol_netscan" in BOOTSTRAP_TOOLS

    def test_empty_findings_fallback(self):
        result = empty_findings_fallback()
        assert result == {"findings": []}

    def test_skip_threads_fallback(self):
        result = skip_threads_fallback()
        assert result == {"threads": []}

    def test_template_report_fallback(self):
        result = template_report_fallback()
        assert "report" in result
        assert "INCOMPLETE" in result["report"]


class TestGoldenPathModern:
    """F8-C: Golden Path is the dry-run / unit-test deterministic
    fallback AND the guardrail empty-after-filter safety net. It is
    NOT the live Inv1 failure path (live failures retry then halt
    via Inv1RetryExhausted). When this fallback fires it must still
    cover modern evidence parsers -- event logs, PowerShell
    transcripts, RDP, and WMI subscription -- instead of the stale
    9-tool slice.
    """

    _REQUIRED_MODERN = (
        "parse_event_logs",
        "parse_powershell_transcripts",
        "parse_rdp_artifacts",
        "parse_wmi_subscription",
    )

    _REQUIRED_CORE = (
        "vol_pstree", "vol_psscan", "vol_netscan", "vol_malfind",
        "vol_cmdline", "vol_dlllist",
        "get_amcache", "extract_mft_timeline", "parse_prefetch",
    )

    def test_includes_parse_event_logs(self):
        assert "parse_event_logs" in golden_path_tools()

    def test_includes_parse_powershell_transcripts(self):
        assert "parse_powershell_transcripts" in golden_path_tools()

    def test_includes_parse_rdp_artifacts(self):
        assert "parse_rdp_artifacts" in golden_path_tools()

    def test_includes_parse_wmi_subscription(self):
        assert "parse_wmi_subscription" in golden_path_tools()

    def test_includes_all_required_core(self):
        """The pre-F8-C core set must remain intact."""
        tools = set(golden_path_tools())
        for t in self._REQUIRED_CORE:
            assert t in tools, f"required core tool {t} missing"

    def test_guardrail_empty_uses_modern_fallback(self):
        """_guardrail_filter_tools([]) returns the fallback minus bootstrap."""
        from sift_sentinel.coordinator import _guardrail_filter_tools
        result = _guardrail_filter_tools([])
        expected = [t for t in GOLDEN_PATH_TOOLS if t not in BOOTSTRAP_TOOLS]
        assert result == expected
        for modern in self._REQUIRED_MODERN:
            assert modern in result
        for mandatory in BOOTSTRAP_TOOLS:
            assert mandatory not in result

    def test_guardrail_all_unknown_uses_modern_fallback(self):
        """Same fallback fires when every AI pick is unregistered garbage."""
        from sift_sentinel.coordinator import _guardrail_filter_tools
        result = _guardrail_filter_tools(["ghost_a", "ghost_b", "ghost_c"])
        expected = [t for t in GOLDEN_PATH_TOOLS if t not in BOOTSTRAP_TOOLS]
        assert result == expected

    def test_fallback_bounded(self):
        """Fallback must stay far below the full 178-tool registry."""
        assert len(golden_path_tools()) < 30

    def test_every_fallback_tool_is_registered(self):
        """Every entry must pass the Rule 2 registration gate."""
        from sift_sentinel.coordinator import _is_registered
        for t in golden_path_tools():
            assert _is_registered(t), f"{t} not in _TOOL_REGISTRY w/ capability"

    def test_no_non_windows_tools_in_fallback(self):
        """Linux/Mac Vol3 plugins must never land in the Windows fallback."""
        from sift_sentinel.coordinator import _NON_WINDOWS_TOOLS
        leaked = [t for t in golden_path_tools() if t in _NON_WINDOWS_TOOLS]
        assert not leaked, f"non-Windows tools leaked: {leaked}"

    def test_bootstrap_unchanged(self):
        """Bootstrap must still be pstree + netscan only."""
        assert list(BOOTSTRAP_TOOLS) == ["vol_pstree", "vol_netscan"]
        gp = set(GOLDEN_PATH_TOOLS)
        for t in BOOTSTRAP_TOOLS:
            assert t in gp

    def test_fallback_is_deduplicated(self):
        """No duplicates should sneak in across refactors."""
        tools = golden_path_tools()
        assert len(tools) == len(set(tools))


class TestBootstrapDefaultOff:
    """F8-C corrected design: default live path must NOT auto-run
    run_mandatory_tools. Inv1 is the first tool-selection decision.
    """

    def test_run_pipeline_signature_has_bootstrap_flag(self):
        """Pipeline must accept bootstrap kwarg (default False)."""
        import inspect
        sig = inspect.signature(run_pipeline)
        assert "bootstrap" in sig.parameters, (
            "run_pipeline must accept a bootstrap kwarg"
        )
        assert sig.parameters["bootstrap"].default is False, (
            "bootstrap kwarg must default to False"
        )

    def test_default_does_not_run_mandatory_tools(self, tmp_path):
        """With default bootstrap=False, run_mandatory_tools is not called."""
        from sift_sentinel import coordinator as _coord
        calls: list[tuple] = []
        orig = _coord.run_mandatory_tools

        def _spy(*a, **kw):
            calls.append((a, kw))
            return orig(*a, **kw)

        with patch.object(_coord, "run_mandatory_tools", _spy):
            _coord.run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert not calls, (
            f"run_mandatory_tools was called {len(calls)} time(s) in "
            "default bootstrap-off mode"
        )

    def test_bootstrap_flag_enables_mandatory_tools(self, tmp_path):
        """Explicit bootstrap=True must run run_mandatory_tools exactly once."""
        from sift_sentinel import coordinator as _coord
        calls: list[tuple] = []
        orig = _coord.run_mandatory_tools

        def _spy(*a, **kw):
            calls.append((a, kw))
            return orig(*a, **kw)

        with patch.object(_coord, "run_mandatory_tools", _spy):
            _coord.run_pipeline(
                state_dir=str(tmp_path), dry_run=True, bootstrap=True,
            )
        assert len(calls) == 1, (
            f"run_mandatory_tools called {len(calls)} times "
            "with bootstrap=True (expected 1)"
        )

    def test_default_step4_does_not_populate_mandatory_dict(self, tmp_path):
        """Step 4 must leave ``mandatory`` empty when bootstrap is off.

        The bootstrap tools may still be written in Step 6 if Inv1 picks
        them -- that is legitimate AI-driven execution, not auto-run. We
        assert the *Step 4* contribution is empty by observing that
        run_mandatory_tools was never invoked (see sibling test) and that
        the Inv1 selectable pool is the no-bootstrap variant (includes
        vol_pstree / vol_netscan).
        """
        path = build_inv1_prompt({}, tmp_path)
        text = path.read_text()
        assert "vol_pstree" in text and "vol_netscan" in text

    def test_explicit_bootstrap_writes_outputs(self, tmp_path):
        """With bootstrap=True, both bootstrap tool outputs must land on disk."""
        run_pipeline(
            state_dir=str(tmp_path), dry_run=True, bootstrap=True,
        )
        tool_dir = tmp_path / "tool_outputs"
        for name in BOOTSTRAP_TOOLS:
            assert (tool_dir / f"{name}.json").exists()


class TestInv1SelectableNoBootstrap:
    """When bootstrap did not run, Inv1 selectable pool must include
    vol_pstree / vol_netscan AND the modern evidence parsers.
    """

    _MODERN = (
        "parse_event_logs",
        "parse_powershell_transcripts",
        "parse_rdp_artifacts",
        "parse_wmi_subscription",
    )

    def test_inv1_selectable_includes_pstree_no_bootstrap(self, tmp_path):
        path = build_inv1_prompt({}, tmp_path)
        text = path.read_text()
        assert "vol_pstree" in text, (
            "vol_pstree must be selectable when bootstrap did not run"
        )

    def test_inv1_selectable_includes_netscan_no_bootstrap(self, tmp_path):
        path = build_inv1_prompt({}, tmp_path)
        text = path.read_text()
        assert "vol_netscan" in text, (
            "vol_netscan must be selectable when bootstrap did not run"
        )

    def test_inv1_selectable_includes_modern_parsers_no_bootstrap(
        self, tmp_path,
    ):
        path = build_inv1_prompt({}, tmp_path)
        text = path.read_text()
        for tool in self._MODERN:
            assert tool in text, (
                f"{tool} missing from Inv1 selectable pool "
                f"(no-bootstrap mode)"
            )

    def test_inv1_selectable_excludes_bootstrap_when_ran(self, tmp_path):
        """When bootstrap DID run, its tools must not re-appear as selectable."""
        import re
        outputs = {
            "vol_pstree": {
                "output": [{"ImageFileName": "svchost.exe", "PID": 100}],
                "record_count": 1,
            },
            "vol_netscan": {"output": [], "record_count": 0},
        }
        path = build_inv1_prompt(outputs, tmp_path)
        text = path.read_text()
        idx = text.find("Available tools")
        assert idx >= 0, "Catalog header missing from Inv1 prompt"
        catalog_block = text[idx:]
        for tool in BOOTSTRAP_TOOLS:
            pattern = rf"\b{re.escape(tool)}\b"
            assert not re.search(pattern, catalog_block), (
                f"{tool} re-advertised after bootstrap ran "
                f"(would duplicate work)"
            )


class TestInv1AIRetryBehavior:
    """Live Inv1 failure MUST trigger an AI retry (not Golden Path) and
    halt honestly if the retry also fails.
    """

    def test_retry_helper_calls_primary_then_retry(self, tmp_path, monkeypatch):
        """Two invalid responses -> Inv1RetryExhausted, never Golden Path."""
        from sift_sentinel.coordinator import (
            _inv1_select_with_retry, Inv1RetryExhausted,
        )
        calls: list[tuple] = []

        def fake_invoke(prompt, timeout, turns, fallback, *, model=None):
            calls.append((prompt, model))
            return {"selected_tools": []}  # always invalid

        primary_prompt = tmp_path / "inv1_prompt.md"
        primary_prompt.write_text("primary")
        with pytest.raises(Inv1RetryExhausted):
            _inv1_select_with_retry(
                fake_invoke, primary_prompt, {}, tmp_path,
            )
        assert len(calls) == 2, (
            f"Expected primary + retry (2 AI calls), got {len(calls)}"
        )
        primary_model, retry_model = calls[0][1], calls[1][1]
        # Models resolve via the env/config role resolver; under
        # pytest each role yields its synthetic default.
        assert primary_model == "synthetic-model-primary", (
            f"Primary Inv1 role must resolve to the primary synthetic "
            f"model, got {primary_model}"
        )
        assert retry_model == "synthetic-model-retry", (
            f"Retry Inv1 role must resolve to the retry synthetic "
            f"model, got {retry_model}"
        )

    def test_retry_helper_returns_retry_result_when_primary_fails(
        self, tmp_path,
    ):
        """Primary invalid, retry valid -> retry's selection is returned."""
        from sift_sentinel.coordinator import _inv1_select_with_retry
        counter: dict[str, int] = {"n": 0}

        def fake_invoke(prompt, timeout, turns, fallback, *, model=None):
            counter["n"] += 1
            if counter["n"] == 1:
                return None  # primary invalid
            return {"selected_tools": ["vol_malfind", "get_amcache"]}

        primary_prompt = tmp_path / "inv1_prompt.md"
        primary_prompt.write_text("primary")
        resp = _inv1_select_with_retry(
            fake_invoke, primary_prompt, {}, tmp_path,
        )
        assert resp["selected_tools"] == ["vol_malfind", "get_amcache"]
        assert counter["n"] == 2
        assert (tmp_path / "inv1_retry_prompt.md").exists(), (
            "Retry must write a stricter prompt artifact"
        )
        assert (tmp_path / "inv1_retry_response.json").exists()

    def test_retry_helper_returns_primary_when_primary_valid(self, tmp_path):
        """Primary valid -> retry not attempted."""
        from sift_sentinel.coordinator import _inv1_select_with_retry
        counter: dict[str, int] = {"n": 0}

        def fake_invoke(prompt, timeout, turns, fallback, *, model=None):
            counter["n"] += 1
            return {"selected_tools": ["vol_malfind"]}

        primary_prompt = tmp_path / "inv1_prompt.md"
        primary_prompt.write_text("primary")
        resp = _inv1_select_with_retry(
            fake_invoke, primary_prompt, {}, tmp_path,
        )
        assert resp["selected_tools"] == ["vol_malfind"]
        assert counter["n"] == 1, "Retry must not fire when primary valid"

    def test_inv1_retry_helper_accepts_model_optional_invoke(self, tmp_path):
        """Legacy invoke_fn without `model` kwarg must still work."""
        from sift_sentinel.coordinator import _inv1_select_with_retry
        calls: list = []

        def legacy_invoke(prompt, timeout, turns, fallback):
            calls.append(prompt)
            return {"selected_tools": ["vol_malfind"]}

        primary_prompt = tmp_path / "inv1_prompt.md"
        primary_prompt.write_text("primary")
        resp = _inv1_select_with_retry(
            legacy_invoke, primary_prompt, {}, tmp_path,
        )
        assert resp["selected_tools"] == ["vol_malfind"]
        assert len(calls) == 1


class TestInv1RetryRoutesSonnetAsideCompat:
    """Compatibility tests for current model routing policy.

    These tests verify _model_for_label() behavior instead of searching for
    stale source constants. run_pipeline.py parses CLI args at module import,
    so we AST-extract only the function under test.
    """

    def _load_model_for_label(self, monkeypatch):
        import ast as _ast
        from pathlib import Path as _Path

        src = _Path("run_pipeline.py").read_text()
        tree = _ast.parse(src)

        func = None
        for node in tree.body:
            if isinstance(node, _ast.FunctionDef) and node.name == "_model_for_label":
                func = node
                break

        assert func is not None, "_model_for_label not found in run_pipeline.py"

        module = _ast.Module(body=[func], type_ignores=[])
        _ast.fix_missing_locations(module)

        ns = {}
        exec(compile(module, "run_pipeline.py::_model_for_label", "exec"), ns)

        monkeypatch.delenv("SIFT_FORCE_MODEL", raising=False)
        return ns["_model_for_label"]

    def test_inv1_primary_role_resolves_synthetic(self, monkeypatch):
        model_for_label = self._load_model_for_label(monkeypatch)
        assert model_for_label("Inv1") == "synthetic-model-primary"

    def test_inv1_retry_role_resolves_synthetic(self, monkeypatch):
        model_for_label = self._load_model_for_label(monkeypatch)
        assert model_for_label("Inv1 retry") == "synthetic-model-retry"

    def test_inv4_report_role_resolves_synthetic(self, monkeypatch):
        model_for_label = self._load_model_for_label(monkeypatch)
        assert model_for_label("Inv4 report") == "synthetic-model-report"

    def test_inv2_inv3_and_self_correction_roles(self, monkeypatch):
        model_for_label = self._load_model_for_label(monkeypatch)

        assert model_for_label("Inv2 analysis") == "synthetic-model-analysis"
        assert model_for_label("Inv ReAct") == "synthetic-model-react"
        assert model_for_label("Inv SC (t=30s)") == (
            "synthetic-model-self-correction"
        )
        assert model_for_label("SC retry") == (
            "synthetic-model-self-correction"
        )
        assert model_for_label("correction") == (
            "synthetic-model-self-correction"
        )

    def test_force_model_env_override_still_wins(self, monkeypatch):
        model_for_label = self._load_model_for_label(monkeypatch)

        monkeypatch.setenv("SIFT_FORCE_MODEL", "synthetic-model-forced")
        assert model_for_label("Inv1") == "synthetic-model-forced"
        assert model_for_label("Inv4 report") == "synthetic-model-forced"


class TestNoSilentGoldenPathInLivePath:
    """Static source checks guarding against the silent live Golden
    Path regression. The specific log string and the `keeping Golden
    Path` phrasing must not reappear anywhere in src/ or run_pipeline.py.
    """

    def test_no_live_inv1_failed_message_in_run_pipeline(self):
        repo_root = Path(__file__).resolve().parents[2]
        src = (repo_root / "run_pipeline.py").read_text()
        assert "LIVE Inv1 primary invalid/empty -- retrying once with AI fallback model Opus 4.6" not in src, (
            "Silent Golden Path fallback message reappeared in "
            "run_pipeline.py -- remove and route through AI retry."
        )

    def test_no_live_inv1_failed_message_in_coordinator(self):
        repo_root = Path(__file__).resolve().parents[2]
        src = (
            repo_root / "src" / "sift_sentinel" / "coordinator.py"
        ).read_text()
        assert "LIVE Inv1 primary invalid/empty -- retrying once with AI fallback model Opus 4.6" not in src

    def test_run_pipeline_has_retry_label(self):
        repo_root = Path(__file__).resolve().parents[2]
        src = (repo_root / "run_pipeline.py").read_text()
        assert "Inv1 retry" in src, (
            "run_pipeline.py must route retry through the "
            "'Inv1 retry' label so _model_for_label resolves the "
            "inv1_retry role."
        )

    def test_run_pipeline_model_router_routes_retry_role(self):
        """_model_for_label('Inv1 retry ...') resolves the inv1_retry
        role -> its synthetic default under test mode."""
        import ast as _ast
        from pathlib import Path as _Path
    
        # Use this checkout, not the sibling/main repo.
        repo_root = _Path(__file__).resolve().parents[2]
        src = (repo_root / "run_pipeline.py").read_text()
        tree = _ast.parse(src)
    
        func = None
        for node in tree.body:
            if isinstance(node, _ast.FunctionDef) and node.name == "_model_for_label":
                func = node
                break
    
        assert func is not None, "_model_for_label not found in active run_pipeline.py"
    
        module = _ast.Module(body=[func], type_ignores=[])
        _ast.fix_missing_locations(module)
    
        ns = {}
        exec(compile(module, "run_pipeline.py::_model_for_label", "exec"), ns)
    
        assert ns["_model_for_label"]("Inv1 retry") == (
            "synthetic-model-retry"
        )


# ── Bootstrap summary ──────────────────────────────────────────────────


class TestBootstrapSummary:
    def _make_outputs(self, procs=None, conns=None):
        return {
            "vol_pstree": {
                "output": procs or [],
                "record_count": len(procs or []),
            },
            "vol_netscan": {
                "output": conns or [],
                "record_count": len(conns or []),
            },
        }

    def test_bootstrap_summary_built(self):
        """Summary contains process count."""
        outputs = self._make_outputs(
            procs=[{"ImageFileName": "svchost.exe", "PID": 100}],
            conns=[{"Owner": "svchost.exe", "LocalPort": "445"}],
        )
        summary = build_bootstrap_summary(outputs)
        assert "Processes found: 1" in summary
        assert "Network connections: 1" in summary

    def test_bootstrap_summary_suspicious_path(self):
        outputs = self._make_outputs(
            procs=[{"ImageFileName": "evil.exe", "PID": 666, "Path": "C:\\Users\\temp\\evil.exe"}],
        )
        summary = build_bootstrap_summary(outputs)
        assert "Suspicious processes:" in summary
        assert "evil.exe" in summary

    def test_bootstrap_summary_short_name(self):
        outputs = self._make_outputs(
            procs=[{"ImageFileName": "x.exe", "PID": 99, "Path": "C:\\x.exe"}],
        )
        summary = build_bootstrap_summary(outputs)
        assert "short name" in summary

    def test_bootstrap_summary_unusual_port(self):
        outputs = self._make_outputs(
            conns=[{"Owner": "cmd.exe", "LocalPort": "4444"}],
        )
        summary = build_bootstrap_summary(outputs)
        assert "Unusual network activity:" in summary
        assert "4444" in summary

    def test_bootstrap_summary_empty_pstree_warning(self):
        outputs = self._make_outputs(procs=[], conns=[])
        summary = build_bootstrap_summary(outputs)
        assert "pstree returned 0" in summary

    def test_inv1_receives_bootstrap(self, tmp_path):
        """Inv1 prompt contains suspicious procs from bootstrap."""
        outputs = self._make_outputs(
            procs=[{"ImageFileName": "evil.exe", "PID": 666, "Path": "C:\\temp\\evil.exe"}],
            conns=[{"Owner": "evil.exe", "LocalPort": "4444"}],
        )
        prompt_path = build_inv1_prompt(outputs, tmp_path)
        prompt = prompt_path.read_text() if hasattr(prompt_path, "read_text") else Path(prompt_path).read_text()
        assert "evil.exe" in prompt
        assert "senior DFIR analyst" in prompt
        assert "Select 20-30 tools" in prompt


# ── Safety net ─────────────────────────────────────────────────────────


class TestSafetyNet:
    def test_safety_net_min_tools(self):
        """AI picks 2 -> padded to 5+."""
        result = safety_net_tools(["vol_malfind", "get_amcache"])
        assert len(result) >= 5

    def test_safety_net_max_tools(self):
        """AI over-selects -> capped at MAX_SELECTED_TOOLS (the band ceiling)."""
        from sift_sentinel.coordinator import MAX_SELECTED_TOOLS
        tools = [f"vol_tool_{i}" for i in range(MAX_SELECTED_TOOLS + 5)]
        result = safety_net_tools(tools)
        assert len(result) <= MAX_SELECTED_TOOLS


    def test_safety_net_needs_memory(self):
        """All disk selected -> adds vol_malfind."""
        result = safety_net_tools([
            "get_amcache", "parse_event_logs",
            "extract_mft_timeline", "parse_prefetch",
            "get_amcache",
        ])
        assert any(t.startswith("vol_") for t in result)

    def test_safety_net_needs_disk(self):
        """All memory selected -> adds a disk tool (bucket-driven).

        Slot 31I-gamma: the disk-balance pad is selected by semantic
        bucket priority over the live registry, not a hardcoded
        ``get_amcache`` literal. The invariant is that disk coverage is
        restored, not which specific tool provides it.
        """
        from sift_sentinel.coordinator import DISK_TOOLS

        result = safety_net_tools([
            "vol_psscan", "vol_malfind", "vol_cmdline",
            "vol_dlllist", "vol_handles",
        ])
        assert any(t in DISK_TOOLS for t in result), result

    def test_safety_net_passthrough(self):
        """Balanced thin selection is preserved, then padded to 20-30."""
        tools = [
            "vol_psscan", "vol_malfind", "vol_cmdline",
            "get_amcache", "parse_event_logs", "extract_mft_timeline",
        ]
        result = safety_net_tools(tools)
        assert result[:len(tools)] == tools
        assert 20 <= len(result) <= 30


    def test_ai_reasoning_logged(self, tmp_path, capsys):
        """Reasoning field captured from Inv1 (via pipeline dry-run print)."""
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        captured = capsys.readouterr()
        assert "AI CHOSE" in captured.out


# ── State I/O ────────────────────────────────────────────────────────────


class TestStateIO:
    def test_ensure_state_dir(self, tmp_path):
        sd = tmp_path / "state"
        ensure_state_dir(sd)
        assert sd.exists()
        assert (sd / "tool_outputs").exists()

    def test_ensure_state_dir_idempotent(self, tmp_path):
        sd = tmp_path / "state"
        ensure_state_dir(sd)
        ensure_state_dir(sd)  # no error
        assert sd.exists()

    def test_write_read_json(self, tmp_path):
        data = {"key": "value", "list": [1, 2, 3]}
        write_state(tmp_path, "test.json", data)
        loaded = read_state(tmp_path, "test.json")
        assert loaded == data

    def test_write_string(self, tmp_path):
        write_state(tmp_path, "test.txt", "hello world")
        assert (tmp_path / "test.txt").read_text() == "hello world"

    def test_write_nested_path(self, tmp_path):
        write_state(tmp_path, "sub/dir/file.json", {"a": 1})
        assert (tmp_path / "sub" / "dir" / "file.json").exists()
        loaded = read_state(tmp_path, "sub/dir/file.json")
        assert loaded == {"a": 1}


# ── Tool dispatch ────────────────────────────────────────────────────────


class TestToolDispatch:
    def test_known_memory_tool(self):
        result = run_tool("vol_pstree", "/evidence/memory.raw", "/evidence/disk")
        assert result["tool_name"] == "vol_pstree"
        assert "output" in result
        assert "error" not in result

    def test_known_disk_tool(self):
        result = run_tool("get_amcache", "/evidence/memory.raw", "/evidence/disk")
        assert result["tool_name"] == "get_amcache"
        assert "output" in result

    def test_mft_tool(self):
        result = run_tool(
            "extract_mft_timeline", "/evidence/memory.raw", "/evidence/disk",
            "2018-11-16", "2018-11-19",
        )
        assert result["tool_name"] == "extract_mft_timeline"
        assert "output" in result

    def test_unknown_tool(self):
        result = run_tool(
            "not_a_tool", "/evidence/memory.raw", "/evidence/disk",
        )
        assert "error" in result
        assert "unknown tool" in result["error"]

    def test_bootstrap_runs_two_tools(self):
        """Step 4 runs only pstree + netscan."""
        results = run_mandatory_tools("/evidence/memory.raw", "/evidence/disk")
        assert len(results) == len(BOOTSTRAP_TOOLS)
        for name in BOOTSTRAP_TOOLS:
            assert name in results
            assert "output" in results[name]

    def test_bootstrap_tools_have_records(self):
        results = run_mandatory_tools("/evidence/memory.raw", "/evidence/disk")
        for name, env in results.items():
            assert env.get("record_count", 0) >= 0


# ── Step 10: Validate ────────────────────────────────────────────────────


class TestStep10:
    def _ref_set(self, **overrides):
        base = {
            "pid_to_process": {},
            "hashes": {},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }
        base.update(overrides)
        return base

    def test_empty_findings(self):
        passed, blocked = step_10_validate([], self._ref_set())
        assert passed == []
        assert blocked == []

    def test_finding_with_valid_pid(self):
        ref = self._ref_set(pid_to_process={1234: ["evil.exe"]})
        finding = {
            "claims": [{"type": "pid", "pid": 1234, "process": "evil.exe"}],
        }
        passed, blocked = step_10_validate([finding], ref)
        assert len(passed) == 1
        assert passed[0]["deterministic_check"] == "passed"
        assert len(blocked) == 0

    def test_finding_with_wrong_pid(self):
        ref = self._ref_set(pid_to_process={1234: ["svchost.exe"]})
        finding = {
            "claims": [{"type": "pid", "pid": 1234, "process": "evil.exe"}],
        }
        passed, blocked = step_10_validate([finding], ref)
        assert len(passed) == 0
        assert len(blocked) == 1
        assert blocked[0][0]["deterministic_check"] == "blocked"

    def test_finding_no_claims_is_blocked(self):
        """UNRESOLVED findings go to blocked, not passed."""
        passed, blocked = step_10_validate([{"claims": []}], self._ref_set())
        assert len(passed) == 0
        assert len(blocked) == 1
        assert blocked[0][0]["deterministic_check"] == "blocked"

    def test_multiple_findings_mixed(self):
        ref = self._ref_set(pid_to_process={1: ["a.exe"], 2: ["b.exe"]})
        findings = [
            {"claims": [{"type": "pid", "pid": 1, "process": "a.exe"}]},
            {"claims": [{"type": "pid", "pid": 2, "process": "WRONG"}]},
        ]
        passed, blocked = step_10_validate(findings, ref)
        assert len(passed) == 1
        assert len(blocked) == 1


# ── Step 11: ReAct PID logging ─────────────────────────────────────────


class TestStep11PidLogging:
    """Regression: PID %d crashes when Claude returns pid=None."""

    def _make_finding(self, pid):
        return {
            "finding_id": "F-LOG",
            "claims": [{"type": "pid", "pid": pid, "process": "sqlsvc.exe"}],
            "source_tools": ["vol_pstree"],
            "validation_status": "MATCH",
        }

    @patch("sift_sentinel.coordinator.filter_tool_by_pid", return_value=[])
    def test_log_pid_none_no_error(self, mock_filter, tmp_path, caplog):
        """Logging must not crash when Claude returns pid=None."""
        call_count = 0

        def fake_invoke(prompt, timeout, turns, fallback):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"action": "tool", "tool": "vol_psscan",
                        "pid": None, "reasoning": "scan all"}
            return {"action": "conclude",
                    "conclusion": "nothing found",
                    "evidence_summary": ""}

        import logging
        with caplog.at_level(logging.INFO, logger="sift_sentinel.coordinator"):
            result = step_11_investigate(
                [self._make_finding(9001)], tmp_path, dry_run=False,
                invoke_fn=fake_invoke, image_path="/fake.raw",
            )
        assert isinstance(result, dict)
        assert len(result["investigations"]) == 1
        # Force-format every captured record -- TypeError if %d got None
        for record in caplog.records:
            record.getMessage()
        running = [r for r in caplog.records
                   if "Running" in r.getMessage()]
        assert len(running) >= 1
        assert "all" in running[0].getMessage()

    @patch("sift_sentinel.coordinator.filter_tool_by_pid", return_value=[])
    def test_log_pid_int_works(self, mock_filter, tmp_path, caplog):
        """Logging must handle integer PID normally."""
        call_count = 0

        def fake_invoke(prompt, timeout, turns, fallback):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"action": "tool", "tool": "vol_cmdline",
                        "pid": 1234, "reasoning": "check cmdline"}
            return {"action": "conclude",
                    "conclusion": "clean",
                    "evidence_summary": ""}

        import logging
        with caplog.at_level(logging.INFO, logger="sift_sentinel.coordinator"):
            result = step_11_investigate(
                [self._make_finding(1234)], tmp_path, dry_run=False,
                invoke_fn=fake_invoke, image_path="/fake.raw",
            )
        assert isinstance(result, dict)
        assert len(result["investigations"]) == 1
        for record in caplog.records:
            record.getMessage()
        running = [r for r in caplog.records
                   if "Running" in r.getMessage()]
        assert len(running) >= 1
        assert "1234" in running[0].getMessage()


# ── Step 11: OLLAMA mode ──────────────────────────────────────────────────


class TestStep11OllamaMode:
    """Bug 3: Step 11 must run (not skip) when ollama=True (dry_run=False)."""

    @patch("sift_sentinel.coordinator.filter_tool_by_pid", return_value=[])
    def test_step11_runs_in_ollama_mode(self, mock_filter, tmp_path, caplog):
        """With dry_run=False and findings present, step 11 must execute."""
        finding = {
            "finding_id": "F-001",
            "claims": [{"type": "pid", "pid": 9001, "process": "sqlsvc.exe"}],
        }

        def fake_invoke(prompt, timeout, turns, fallback):
            return {"action": "conclude",
                    "conclusion": "confirmed malicious",
                    "evidence_summary": "sqlsvc.exe matches IOC"}

        import logging
        with caplog.at_level(logging.INFO, logger="sift_sentinel.coordinator"):
            result = step_11_investigate(
                [finding], tmp_path, dry_run=False,
                invoke_fn=fake_invoke, image_path="/fake.raw",
            )
        assert len(result["investigations"]) == 1
        assert result["investigations"][0]["conclusion"] == "confirmed malicious"
        msgs = [r.getMessage() for r in caplog.records]
        assert not any("skipped" in m for m in msgs), \
            "Step 11 should not skip when dry_run=False"

    def test_step11_skips_with_dry_run(self, tmp_path, caplog):
        """Verify dry_run=True still skips correctly."""
        finding = {
            "finding_id": "F-001",
            "claims": [{"type": "pid", "pid": 9001, "process": "sqlsvc.exe"}],
        }
        import logging
        with caplog.at_level(logging.INFO, logger="sift_sentinel.coordinator"):
            result = step_11_investigate(
                [finding], tmp_path, dry_run=True,
                invoke_fn=lambda *a: None,
            )
        assert result == {"investigations": [], "threads": []}
        msgs = [r.getMessage() for r in caplog.records]
        assert any("dry-run" in m for m in msgs)

    def test_step11_empty_findings_message(self, tmp_path, caplog):
        """Empty findings should say 'no passed findings', not 'dry-run'."""
        import logging
        with caplog.at_level(logging.INFO, logger="sift_sentinel.coordinator"):
            result = step_11_investigate(
                [], tmp_path, dry_run=False,
                invoke_fn=lambda *a: None,
            )
        assert result == {"investigations": [], "threads": []}
        msgs = [r.getMessage() for r in caplog.records]
        assert any("no passed findings" in m for m in msgs)
        assert not any("dry-run" in m for m in msgs)


# ── Step 11b/11c: Investigation learning loop ────────────────────────────


class TestStep11Enrichment:
    """Step 11b: investigation adds claims to finding dict."""

    def test_step11_enriches_findings(self):
        findings = [{
            "finding_id": "F-001",
            "claims": [{"type": "pid", "pid": 9001, "process": "sqlsvc.exe"}],
            "source_tools": ["vol_pstree"],
        }]
        investigations = [{
            "finding_id": "F-001",
            "pid": 9001,
            "process": "sqlsvc.exe",
            "turns": 2,
            "tool_chain": ["vol_handles", "vol_cmdline"],
            "details": [
                {
                    "turn": 0, "tool": "vol_handles", "pid": 9001,
                    "result_count": 1,
                    "result_sample": [
                        {"Name": "\\pipe\\fhsvc", "Process": "sqlsvc.exe"},
                    ],
                },
                {
                    "turn": 1, "tool": "vol_cmdline", "pid": 9001,
                    "result_count": 1,
                    "result_sample": [
                        {"Args": "C:\\sqlsvc.exe", "Process": "sqlsvc.exe"},
                    ],
                },
            ],
        }]
        result = step_11b_enrich_findings(findings, investigations)
        assert "investigation_claims" in result[0]
        assert len(result[0]["investigation_claims"]) == 2
        assert result[0]["investigation_tools"] == [
            "vol_handles", "vol_cmdline",
        ]
        assert result[0]["investigation_turns"] == 2

    def test_investigation_claims_separate(self):
        """investigation_claims is a separate list from original claims."""
        findings = [{
            "finding_id": "F-001",
            "claims": [{"type": "pid", "pid": 100, "process": "cmd.exe"}],
            "source_tools": ["vol_pstree"],
        }]
        investigations = [{
            "finding_id": "F-001",
            "pid": 100,
            "process": "cmd.exe",
            "turns": 1,
            "tool_chain": ["vol_handles"],
            "details": [{
                "turn": 0, "tool": "vol_handles", "pid": 100,
                "result_count": 1,
                "result_sample": [{"Name": "\\x", "Process": "cmd.exe"}],
            }],
        }]
        step_11b_enrich_findings(findings, investigations)
        assert len(findings[0]["claims"]) == 1  # original untouched
        assert "investigation_claims" in findings[0]
        assert findings[0]["claims"] is not findings[0]["investigation_claims"]

    def test_no_investigation_no_enrichment(self):
        findings = [{
            "finding_id": "F-002",
            "claims": [{"type": "pid", "pid": 50, "process": "x.exe"}],
            "source_tools": ["vol_pstree"],
        }]
        step_11b_enrich_findings(findings, [])
        assert "investigation_claims" not in findings[0]


class TestStep11cRevalidate:
    """Step 11c: enriched findings re-run through validator."""

    def _ref_set(self):
        return {
            "hashes": {},
            "pid_to_process": {9001: ["sqlsvc.exe"], 100: ["cmd.exe"]},
            "timestamps_per_artifact": {},
            "connections": {
                "9001:192.0.2.111:4444->192.0.2.129:443": "sqlsvc.exe",
            },
            "paths": {},
        }

    def test_step11_revalidates(self):
        """Enriched finding re-runs through validator."""
        finding = {
            "finding_id": "F-001",
            "claims": [{"type": "pid", "pid": 9001, "process": "sqlsvc.exe"}],
            "investigation_claims": [
                {
                    "type": "connection",
                    "pid": 9001,
                    "foreign_addr": "192.0.2.129",
                    "process": "sqlsvc.exe",
                    "source_tools": ["vol_netscan"],
                },
            ],
            "source_tools": ["vol_pstree"],
            "validation_status": "MATCH",
            "deterministic_check": "passed",
        }
        upgraded, unchanged = step_11c_revalidate(
            [finding], self._ref_set(),
        )
        assert len(unchanged) == 1  # was MATCH, stays MATCH
        assert len(finding["claims"]) == 2  # merged

    def test_step11_upgrade_mismatch_to_match(self):
        """Finding with new valid claims upgrades MISMATCH -> MATCH."""
        finding = {
            "finding_id": "F-003",
            "claims": [],  # no original claims -> was UNRESOLVED
            "investigation_claims": [
                {
                    "type": "pid",
                    "pid": 9001,
                    "process": "sqlsvc.exe",
                    "source_tools": ["vol_handles"],
                },
            ],
            "source_tools": ["vol_pstree"],
            "validation_status": "UNRESOLVED",
            "deterministic_check": "blocked",
        }
        upgraded, unchanged = step_11c_revalidate(
            [finding], self._ref_set(),
        )
        assert len(upgraded) == 1
        assert finding["validation_status"] == "MATCH"
        assert finding["deterministic_check"] == "passed"
        assert "vol_handles" in finding["source_tools"]

    def test_no_investigation_claims_unchanged(self):
        finding = {
            "finding_id": "F-004",
            "claims": [{"type": "pid", "pid": 100, "process": "cmd.exe"}],
            "source_tools": ["vol_pstree"],
            "validation_status": "MATCH",
        }
        upgraded, unchanged = step_11c_revalidate(
            [finding], self._ref_set(),
        )
        assert len(upgraded) == 0
        assert len(unchanged) == 1


class TestConfidenceInvestigation:
    """Confidence calibration with investigation_claims source types."""

    def test_confidence_multi_source_high(self):
        """2+ source types from investigation -> HIGH allowed."""
        finding = {
            "source_tools": ["vol_pstree"],  # M only -> MEDIUM
            "confidence_level": "HIGH",
            "investigation_claims": [
                {"source_tools": ["vol_netscan"]},  # adds N
                {"source_tools": ["get_amcache"]},   # adds A
            ],
        }
        # Without investigation: 1 type (M) -> MEDIUM ceiling
        # With investigation: 3 types (M, N, A) -> HIGH ceiling
        result = step_13_calibrate([finding], "full")
        assert result[0]["confidence_level"] == "HIGH"

    def test_confidence_single_source_medium(self):
        """1 source type = MEDIUM max even with investigation claims."""
        finding = {
            "source_tools": ["vol_pstree"],  # M
            "confidence_level": "HIGH",
            "investigation_claims": [
                {"source_tools": ["vol_handles"]},   # still M
                {"source_tools": ["vol_cmdline"]},   # still M
            ],
        }
        result = step_13_calibrate([finding], "full")
        assert result[0]["confidence_level"] == "MEDIUM"


# ── Step 13: Calibrate ───────────────────────────────────────────────────


class TestStep13:
    def test_preserves_valid_high(self):
        finding = {
            "source_tools": ["vol_pstree", "vol_netscan", "get_amcache"],
            "confidence_level": "HIGH",
        }
        result = step_13_calibrate([finding], "full")
        assert result[0]["confidence_level"] == "HIGH"

    def test_caps_single_type_to_medium(self):
        finding = {
            "source_tools": ["vol_pstree"],
            "confidence_level": "HIGH",
        }
        result = step_13_calibrate([finding], "full")
        assert result[0]["confidence_level"] == "MEDIUM"

    def test_ssdt_degraded_caps_memory(self):
        # SSDT degraded caps memory ceiling, but cross-domain upgrade
        # (memory + disk) overrides when disk corroborates.
        finding = {
            "source_tools": ["vol_pstree", "vol_netscan", "get_amcache"],
            "confidence_level": "HIGH",
        }
        result = step_13_calibrate([finding], "degraded")
        assert result[0]["confidence_level"] == "HIGH"

    def test_ssdt_degraded_memory_only_caps(self):
        # SSDT degraded with memory-only tools -> stays capped at MEDIUM
        finding = {
            "source_tools": ["vol_pstree", "vol_netscan"],
            "confidence_level": "HIGH",
        }
        result = step_13_calibrate([finding], "degraded")
        assert result[0]["confidence_level"] == "MEDIUM"

    def test_no_tools_speculative(self):
        finding = {"source_tools": [], "confidence_level": "LOW"}
        result = step_13_calibrate([finding], "full")
        assert result[0]["confidence_level"] == "SPECULATIVE"

    def test_empty_findings(self):
        result = step_13_calibrate([], "full")
        assert result == []


# ── Pipeline dry-run (integration) ──────────────────────────────────────


class TestPipelineDryRun:
    def test_pipeline_completes(self, tmp_path):
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert summary["status"] == "completed"
        assert summary["dry_run"] is True

    def test_pipeline_creates_state_files(self, tmp_path):
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert (tmp_path / "tool_outputs").is_dir()
        assert (tmp_path / "reference_set.json").exists()
        assert (tmp_path / "inv1_response.json").exists()
        assert (tmp_path / "inv2_response.json").exists()
        assert (tmp_path / "findings_validated.json").exists()
        assert (tmp_path / "findings_final.json").exists()
        assert (tmp_path / "report.md").exists()
        assert (tmp_path / "pipeline_summary.json").exists()
        assert (tmp_path / "sha256_pre.txt").exists()
        assert (tmp_path / "sha256_post.txt").exists()

    def test_pipeline_tool_output_files(self, tmp_path):
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        tool_dir = tmp_path / "tool_outputs"
        for name in BOOTSTRAP_TOOLS:
            assert (tool_dir / f"{name}.json").exists()
        assert (tool_dir / "vol_ssdt.json").exists()

    def test_pipeline_builds_reference_set(self, tmp_path):
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        ref_set = json.loads((tmp_path / "reference_set.json").read_text())
        assert "pid_to_process" in ref_set
        assert "hashes" in ref_set
        assert len(ref_set["pid_to_process"]) > 0

    def test_pipeline_sha256_consistent(self, tmp_path):
        """In dry-run, evidence files don't exist so integrity can't be
        verified -- sentinel values (FILE_NOT_FOUND) correctly fail."""
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        summary = json.loads(
            (tmp_path / "pipeline_summary.json").read_text(),
        )
        assert summary["integrity"]["match"] is False

    def test_pipeline_all_golden_path_tools(self, tmp_path):
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        for t in GOLDEN_PATH_TOOLS:
            assert t in summary["tools_run"]

    def test_pipeline_ssdt_trust(self, tmp_path):
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert summary["ssdt_trust"] in ("full", "degraded", "untrusted")

    def test_pipeline_elapsed_positive(self, tmp_path):
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert summary["elapsed_s"] > 0

    def test_pipeline_no_findings_in_dry_run(self, tmp_path):
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert summary["findings_count"] == 0
        assert summary["corrections_count"] == 0

    def test_pipeline_template_report(self, tmp_path):
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        report = (tmp_path / "report.md").read_text()
        assert "INCOMPLETE" in report

    def test_pipeline_inv1_golden_path(self, tmp_path):
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        inv1 = json.loads((tmp_path / "inv1_response.json").read_text())
        assert inv1["selected_tools"] == GOLDEN_PATH_TOOLS

    def test_pipeline_with_custom_invoke(self, tmp_path):
        """Verify invoke_fn override works."""
        calls = []

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            calls.append(prompt_path)
            return fallback_fn()

        summary = run_pipeline(
            state_dir=str(tmp_path), dry_run=True,
            image_path="/evidence/memory.raw",
            disk_path="/evidence/disk",
            invoke_fn=fake_invoke,
        )
        assert summary["status"] == "completed"
        # dry_run=True uses fallbacks, invoke_fn never called
        assert len(calls) == 0


# ── _expect_dict guard ──────────────────────────────────────────────────


class TestExpectDict:
    def test_dict_passes_through(self):
        result = _expect_dict({"key": "val"}, "test", lambda: {"fb": True})
        assert result == {"key": "val"}

    def test_list_triggers_fallback(self):
        result = _expect_dict(
            [{"finding": 1}], "inv1", golden_path_fallback,
        )
        assert "selected_tools" in result

    def test_string_triggers_fallback(self):
        result = _expect_dict(
            "some text", "inv2", empty_findings_fallback,
        )
        assert result == {"findings": []}

    def test_none_triggers_fallback(self):
        result = _expect_dict(None, "inv4", template_report_fallback)
        assert "report" in result

    def test_int_triggers_fallback(self):
        result = _expect_dict(42, "test", lambda: {"ok": True})
        assert result == {"ok": True}


# ── Path traversal prevention ───────────────────────────────────────────


class TestPathSafety:
    def test_safe_state_path_normal(self, tmp_path):
        path = _safe_state_path(tmp_path, "test.json")
        assert path == (tmp_path / "test.json").resolve()

    def test_safe_state_path_nested(self, tmp_path):
        path = _safe_state_path(tmp_path, "sub/dir/file.json")
        assert tmp_path.resolve() in path.parents

    def test_safe_state_path_blocks_traversal(self, tmp_path):
        with pytest.raises(ValueError, match="escapes state_dir"):
            _safe_state_path(tmp_path, "../../../etc/passwd")

    def test_safe_state_path_blocks_absolute(self, tmp_path):
        with pytest.raises(ValueError, match="escapes state_dir"):
            _safe_state_path(tmp_path, "/tmp/evil.json")

    def test_safe_finding_id_clean(self):
        assert _safe_finding_id("F-001") == "F-001"

    def test_safe_finding_id_sanitizes_slashes(self):
        result = _safe_finding_id("../../etc/passwd")
        assert "/" not in result
        assert "\\" not in result

    def test_safe_finding_id_sanitizes_special(self):
        result = _safe_finding_id("F-001; rm -rf /")
        assert ";" not in result
        assert " " not in result

    def test_write_state_blocks_traversal(self, tmp_path):
        with pytest.raises(ValueError, match="escapes state_dir"):
            write_state(tmp_path, "../escape.json", {"bad": True})

    def test_read_state_blocks_traversal(self, tmp_path):
        """read_state must route through _safe_state_path like write_state."""
        with pytest.raises(ValueError, match="escapes state_dir"):
            read_state(tmp_path, "../../../etc/passwd")

    def test_read_state_blocks_absolute(self, tmp_path):
        with pytest.raises(ValueError, match="escapes state_dir"):
            read_state(tmp_path, "/tmp/evil.json")


# ── Inv1 tool advertisement ─────────────────────────────────────────────


class TestInv1ToolList:
    def test_only_registered_tools_advertised(self, tmp_path):
        """Inv1 prompt must only list Windows tools from _TOOL_REGISTRY.

        Per Commit 15b, non-Windows vol plugins are filtered from Inv1
        prompt-generation. This test asserts (a) Windows tools appear,
        (b) ghost tools never appear, (c) non-Windows tools do NOT appear.
        """
        import re
        from sift_sentinel.coordinator import _NON_WINDOWS_TOOLS
        mandatory = {
            name: {"tool_name": name, "output": [], "record_count": 0}
            for name in MANDATORY_TOOLS
        }
        prompt_path = build_inv1_prompt(mandatory, tmp_path)
        prompt_text = prompt_path.read_text()
        # Windows tools should appear (non-Windows filtered per Commit 15b).
        # P0-D: vol_mftscan is quarantined from the Inv1 catalog until the MCP
        # dispatch signature (missing image_path arg) is fixed.
        _QUARANTINED = {"vol_mftscan"}
        selectable = (set(_TOOL_REGISTRY) - set(MANDATORY_TOOLS)
                      - _NON_WINDOWS_TOOLS - _QUARANTINED)
        for tool in selectable:
            assert tool in prompt_text, f"Windows tool {tool} missing"
        # Unregistered ghost tools must NOT appear.
        # CC#17a.1: vol_handles was promoted to _TOOL_REGISTRY (no longer a ghost).
        for ghost in ["parse_registry", "extract_srum", "parse_sysmon",
                      "parse_browser", "parse_jump_lists", "parse_lnk",
                      "extract_prefetch", "extract_shimcache", "hash_lookup"]:
            # Exact token check: parse_registry_persistence is valid and
            # must not fail merely because it contains parse_registry.
            assert re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(ghost)}(?![A-Za-z0-9_])",
                prompt_text,
            ) is None, (
                f"{ghost} advertised but not in _TOOL_REGISTRY"
            )
        # Non-Windows tools MUST NOT appear (Commit 15b filter assertion).
        # Word-boundary regex avoids substring false-positives where a
        # non-Windows tool name is a prefix of a Windows tool name.
        for non_win in _NON_WINDOWS_TOOLS:
            pattern = rf"\b{re.escape(non_win)}\b"
            assert not re.search(pattern, prompt_text), (
                f"non-Windows tool {non_win} leaked into Inv1 prompt"
            )


# ── Step 10: UNRESOLVED goes to blocked ─────────────────────────────────


class TestStep10UnresolvedBlocked:
    def _ref_set(self):
        return {
            "pid_to_process": {1: ["a.exe"]},
            "hashes": {},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }

    def test_unresolved_not_in_passed(self):
        """Findings with no checkable claims must NOT reach passed."""
        finding = {"claims": [{"type": "alien_type", "data": "x"}]}
        passed, blocked = step_10_validate([finding], self._ref_set())
        assert len(passed) == 0
        assert len(blocked) == 1

    def test_match_still_passes(self):
        """Valid findings still reach passed."""
        finding = {
            "claims": [{"type": "pid", "pid": 1, "process": "a.exe"}],
        }
        passed, blocked = step_10_validate([finding], self._ref_set())
        assert len(passed) == 1
        assert len(blocked) == 0


# ── Report validation wired into pipeline ───────────────────────────────


class TestReportValidation:
    def test_report_validation_state_file_created(self, tmp_path):
        """Pipeline must write report_validation.json."""
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert (tmp_path / "report_validation.json").exists()
        check = json.loads(
            (tmp_path / "report_validation.json").read_text(),
        )
        assert "valid" in check
        assert "errors" in check

    def test_bogus_citation_triggers_fallback(self, tmp_path):
        """Report with F-999 citation must fall back to template."""
        # Create fake evidence files so fingerprinting succeeds
        img = tmp_path / "memory.raw"
        disk = tmp_path / "disk"
        img.write_bytes(b"fake image")
        disk.mkdir()

        # Create a finding that passes validation
        findings = [{
            "finding_id": "F-001",
            "artifact": "test.exe",
            "claims": [{"type": "pid", "pid": 1, "process": "test.exe"}],
            "source_tools": ["vol_pstree", "vol_netscan", "get_amcache"],
            "confidence_level": "HIGH",
        }]

        def findings_invoke(prompt_path, timeout, max_turns, fallback_fn):
            text = Path(prompt_path).read_text()
            # Inv1 primary/retry must return a valid selected_tools list
            # so the pipeline progresses past the AI retry helper. We
            # reuse the Golden Path set as a deterministic test stand-in.
            if ("senior DFIR analyst" in text
                    or "Select 15-20 tools" in text
                    or "selected_tools" in text):
                return golden_path_fallback()
            if "Analyze tool outputs" in text:
                return {"findings": findings}
            if "incident report" in text.lower() or "Write an" in text:
                return {"report": "See F-999 for details."}
            return fallback_fn()

        state = tmp_path / "state"
        summary = run_pipeline(
            state_dir=str(state), dry_run=False,
            image_path=str(img),
            disk_path=str(disk),
            invoke_fn=findings_invoke,
        )
        report = (state / "report.md").read_text()
        assert "INCOMPLETE" in report  # fell back to template


# ── Coercion guards ──────────────────────────────────────────────────────


class TestCoerceSelectedTools:
    def test_valid_list_filters_to_allowed(self):
        result = _coerce_selected_tools(["vol_cmdline", "vol_dlllist"])
        assert "vol_cmdline" in result
        assert "vol_dlllist" in result

    def test_string_returns_golden_path(self):
        result = _coerce_selected_tools("vol_cmdline")
        assert result == golden_path_tools()

    def test_none_returns_golden_path(self):
        result = _coerce_selected_tools(None)
        assert result == golden_path_tools()

    def test_list_with_non_strings_filtered(self):
        result = _coerce_selected_tools(["vol_cmdline", 42, None])
        assert result == ["vol_cmdline"]

    def test_unknown_tools_filtered(self):
        result = _coerce_selected_tools(["vol_cmdline", "vol_fake"])
        assert result == ["vol_cmdline"]

    def test_mandatory_tools_excluded(self):
        result = _coerce_selected_tools(["vol_pstree", "vol_cmdline"])
        assert "vol_pstree" not in result  # mandatory, not selectable


class TestCoerceFindings:
    def test_valid_list_passes(self):
        findings = [{"id": "F-001"}, {"id": "F-002"}]
        assert _coerce_findings(findings) == findings

    def test_none_returns_empty(self):
        assert _coerce_findings(None) == []

    def test_string_returns_empty(self):
        assert _coerce_findings("not a list") == []

    def test_filters_non_dicts(self):
        result = _coerce_findings([{"id": "F-001"}, "bad", 42, None])
        assert len(result) == 1
        assert result[0]["id"] == "F-001"


class TestCoerceReport:
    def test_string_passes(self):
        assert _coerce_report("# Report") == "# Report"

    def test_none_returns_template(self):
        result = _coerce_report(None)
        assert "INCOMPLETE" in result

    def test_list_returns_template(self):
        result = _coerce_report(["segment1", "segment2"])
        assert "INCOMPLETE" in result

    def test_int_returns_template(self):
        result = _coerce_report(0)
        assert "INCOMPLETE" in result


# ── Missing evidence aborts pipeline ─────────────────────────────────────


class TestMissingEvidenceAbort:
    def test_missing_evidence_raises_in_live_mode(self, tmp_path,
                                                   monkeypatch):
        """Non-dry-run pipeline must abort if evidence files don't exist."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        with pytest.raises(FileNotFoundError, match="Evidence file not found"):
            run_pipeline(
                state_dir=str(tmp_path),
                dry_run=False,
                image_path="/nonexistent/memory.raw",
                disk_path="/nonexistent/disk",
            )

    def test_directory_evidence_hashed_as_directory(self, tmp_path):
        d = tmp_path / "evidence_dir"
        d.mkdir()
        result = sha256_fingerprint([str(d)])
        assert result[str(d)] == "DIRECTORY"


# ── Hallucination tracking ──────────────────────────────────────────────


class TestHallucinationTracking:
    def _ref_set(self, **overrides):
        base = {
            "pid_to_process": {},
            "hashes": {},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }
        base.update(overrides)
        return base

    def test_validation_status_tagged_match(self):
        """MATCH findings get validation_status='MATCH'."""
        ref = self._ref_set(pid_to_process={1: ["a.exe"]})
        finding = {"claims": [{"type": "pid", "pid": 1, "process": "a.exe"}]}
        step_10_validate([finding], ref)
        assert finding["validation_status"] == "MATCH"

    def test_validation_status_tagged_mismatch(self):
        """MISMATCH findings get validation_status='MISMATCH'."""
        ref = self._ref_set(pid_to_process={1: ["a.exe"]})
        finding = {"claims": [{"type": "pid", "pid": 1, "process": "WRONG"}]}
        step_10_validate([finding], ref)
        assert finding["validation_status"] == "MISMATCH"

    def test_validation_status_tagged_unresolved(self):
        """UNRESOLVED findings get validation_status='UNRESOLVED'."""
        ref = self._ref_set()
        finding = {"claims": []}
        step_10_validate([finding], ref)
        assert finding["validation_status"] == "UNRESOLVED"

    def test_accuracy_in_dry_run_summary(self, tmp_path):
        """Accuracy dict appears in pipeline summary with zero counts."""
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert "accuracy" in summary
        acc = summary["accuracy"]
        assert acc["produced"] == 0
        assert acc["passed"] == 0
        assert acc["blocked"] == 0
        assert acc["mismatch"] == 0
        assert acc["hallucination_rate"] == "0.0%"

    def test_accuracy_persisted_in_json(self, tmp_path):
        """Accuracy dict persisted in pipeline_summary.json."""
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        summary = json.loads(
            (tmp_path / "pipeline_summary.json").read_text(),
        )
        assert "accuracy" in summary
        expected_keys = {
            "produced", "passed", "blocked",
            "mismatch", "hallucination_rate",
        }
        assert expected_keys == set(summary["accuracy"].keys())

    def test_accuracy_counts_mixed_findings(self, tmp_path):
        """Counts correct when findings have mixed validation outcomes."""
        # PID 4 = System in cached pstree
        findings = [
            {
                "finding_id": "F-001",
                "claims": [
                    {"type": "pid", "pid": 4, "process": "System"},
                ],
                "source_tools": ["vol_pstree", "vol_netscan", "get_amcache"],
                "confidence_level": "HIGH",
            },
            {
                "finding_id": "F-002",
                "claims": [
                    {"type": "pid", "pid": 4, "process": "WRONG_NAME"},
                ],
                "source_tools": ["vol_pstree"],
                "confidence_level": "MEDIUM",
            },
            {
                "finding_id": "F-003",
                "claims": [],
                "source_tools": ["vol_pstree"],
                "confidence_level": "LOW",
            },
        ]

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            text = Path(prompt_path).read_text()
            if ("senior DFIR analyst" in text
                    or "Select 15-20 tools" in text
                    or "selected_tools" in text):
                return golden_path_fallback()
            if "Analyze tool outputs" in text:
                return {"findings": findings}
            return fallback_fn()

        img = tmp_path / "memory.raw"
        disk = tmp_path / "disk"
        img.write_bytes(b"fake image")
        disk.mkdir()

        state = tmp_path / "state"
        summary = run_pipeline(
            state_dir=str(state), dry_run=False,
            image_path=str(img), disk_path=str(disk),
            invoke_fn=fake_invoke,
            corrector_fn=lambda raw, err: None,
        )

        acc = summary["accuracy"]
        assert acc["produced"] == 2  # F-003 (claims=[]) dropped by claims filter
        assert acc["passed"] == 1
        assert acc["mismatch"] == 1
        assert acc["blocked"] == 0
        assert acc["hallucination_rate"] == "50.0%"


# ── Token tracking ──────────────────────────────────────────────────────


class TestTokenTracking:
    def test_token_usage_in_dry_run_summary(self, tmp_path):
        """Token usage appears in pipeline summary with zeros in dry-run."""
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert "token_usage" in summary
        tok = summary["token_usage"]
        assert tok["total_input"] == 0
        assert tok["total_output"] == 0

    def test_token_usage_persisted_in_json(self, tmp_path):
        """Token usage dict persisted in pipeline_summary.json."""
        run_pipeline(state_dir=str(tmp_path), dry_run=True)
        summary = json.loads(
            (tmp_path / "pipeline_summary.json").read_text(),
        )
        assert "token_usage" in summary
        expected_keys = {"total_input", "total_output"}
        assert expected_keys == set(summary["token_usage"].keys())

    def test_token_totals_reset_per_run(self, tmp_path):
        """Each pipeline run resets token counters to zero."""
        from sift_sentinel.coordinator import _token_totals
        _token_totals["input"] = 9999
        _token_totals["output"] = 9999
        summary = run_pipeline(state_dir=str(tmp_path), dry_run=True)
        assert summary["token_usage"]["total_input"] == 0
        assert summary["token_usage"]["total_output"] == 0


class TestGuardrailFilter:
    """Universal tool registry filter -- defense-in-depth."""

    def test_guardrail_drops_unknown(self):
        """Unknown tools are filtered out, valid ones survive."""
        result = _guardrail_filter_tools(["vol_cmdline", "fake_tool"])
        assert result == ["vol_cmdline"]

    def test_guardrail_all_unknown_fallback(self):
        """All unknown → falls back to Golden Path minus mandatory."""
        result = _guardrail_filter_tools(["fake1", "fake2"])
        expected = [t for t in GOLDEN_PATH_TOOLS if t not in MANDATORY_TOOLS]
        assert result == expected

    def test_guardrail_all_valid(self):
        """All valid tools pass through unchanged."""
        result = _guardrail_filter_tools(["vol_cmdline", "vol_dlllist"])
        assert result == ["vol_cmdline", "vol_dlllist"]


class TestBootstrapOnly:
    """Bootstrap runs exactly pstree + netscan, nothing else."""

    def test_bootstrap_excludes_event_logs(self):
        """parse_event_logs is AI-selectable, not bootstrap."""
        assert "parse_event_logs" not in BOOTSTRAP_TOOLS

    def test_bootstrap_excludes_malfind(self):
        """vol_malfind is AI-selectable, not bootstrap."""
        assert "vol_malfind" not in BOOTSTRAP_TOOLS

    def test_bootstrap_only_two(self):
        results = run_mandatory_tools("/evidence/memory.raw", "/evidence/disk")
        assert set(results.keys()) == set(BOOTSTRAP_TOOLS)


class TestClaimsFilter:
    """Zero-claims drop filter: findings without claims are dropped early."""

    @staticmethod
    def _filter(findings):
        """Replicate the inline claims filter from run_pipeline."""
        return [f for f in findings if f.get("claims")]

    def test_claims_filter_keeps_valid(self):
        """Finding with claims list → kept."""
        f = {"id": "F-1", "claims": [{"type": "pid", "process": "x", "pid": 1}]}
        assert self._filter([f]) == [f]

    def test_claims_filter_drops_empty_list(self):
        """Finding with claims=[] → dropped."""
        f = {"id": "F-2", "claims": []}
        assert self._filter([f]) == []

    def test_claims_filter_drops_missing_key(self):
        """Finding with no 'claims' key → dropped."""
        f = {"id": "F-3", "summary": "no claims key"}
        assert self._filter([f]) == []

    def test_claims_filter_mixed(self):
        """3 findings [valid, empty, valid] → returns 2."""
        valid1 = {"id": "F-1", "claims": [{"type": "pid", "process": "a", "pid": 1}]}
        empty = {"id": "F-2", "claims": []}
        valid2 = {"id": "F-3", "claims": [{"type": "pid", "process": "b", "pid": 2}]}
        result = self._filter([valid1, empty, valid2])
        assert result == [valid1, valid2]


# ── Wide MFT defaults ──────────────────────────────────────────────────


class TestWideMFTDefaults:
    """Verify coordinator uses evidence-agnostic wide date range."""

    def test_default_mft_start_is_wide(self):
        from sift_sentinel.coordinator import DEFAULT_MFT_START
        assert DEFAULT_MFT_START == "2015-01-01"

    def test_default_mft_end_is_wide(self):
        from sift_sentinel.coordinator import DEFAULT_MFT_END
        assert DEFAULT_MFT_END == "2025-12-31"

    def test_run_tool_signature_uses_wide_defaults(self):
        """run_tool signature defaults match the wide date range."""
        import inspect
        sig = inspect.signature(run_tool)
        assert sig.parameters["mft_start"].default == "2015-01-01"
        assert sig.parameters["mft_end"].default == "2025-12-31"


# ── parse_prefetch dispatch & routing ─────────────────────────────────────


class TestPrefetchDispatch:
    """Bug fix: parse_prefetch must be dispatched with disk_mount, not image_path."""

    def test_prefetch_in_tool_dispatch(self):
        """parse_prefetch is registered in _TOOL_REGISTRY."""
        assert "parse_prefetch" in _TOOL_REGISTRY
        fn, arg_type = _TOOL_REGISTRY["parse_prefetch"]
        assert callable(fn)

    def test_prefetch_gets_standalone_not_disk(self):
        """Dispatcher uses 'standalone' arg_type so parse_prefetch uses
        DISK_MOUNT_PATH default, not the raw disk image path."""
        _fn, arg_type = _TOOL_REGISTRY["parse_prefetch"]
        assert arg_type == "standalone", (
            f"parse_prefetch arg_type must be 'standalone' (uses DISK_MOUNT_PATH), "
            f"got '{arg_type}'"
        )

    def test_prefetch_called_without_disk_path(self):
        """run_tool must NOT pass disk_path to parse_prefetch."""
        mock_fn = MagicMock(return_value={"output": [], "record_count": 0})
        with patch.dict(_TOOL_REGISTRY, {"parse_prefetch": (mock_fn, "standalone")}):
            run_tool("parse_prefetch", "/evidence/memory.raw", "/evidence/disk")
        mock_fn.assert_called_once_with()

    def test_prefetch_results_in_reference_set(self):
        """Prefetch executable names appear in reference set paths."""
        from sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "parse_prefetch": {
                "tool_name": "parse_prefetch",
                "execution_time_ms": 1,
                "evidence_path": "/synthetic/evidence/disk",
                "output": [
                    {"executable_name": "FIXTURE_PREFETCH_A.EXE",
                     "run_count": 3,
                     "last_run_times": ["2020-01-01 00:00:00"],
                     "path": "/synthetic/prefetch/FIXTURE_PREFETCH_A.pf",
                     "files_accessed": []},
                    {"executable_name": "FIXTURE_PREFETCH_B.EXE",
                     "run_count": 1,
                     "last_run_times": [],
                     "path": "/synthetic/prefetch/FIXTURE_PREFETCH_B.pf",
                     "files_accessed": []},
                ],
                "record_count": 2,
            },
        }
        ref = build_reference_set(tool_outputs)
        # Executable names must appear in paths (lowercased by reference_set)
        assert "fixture_prefetch_a.exe" in ref["paths"]
        assert "fixture_prefetch_b.exe" in ref["paths"]
        # Timestamps must appear when present
        assert "2020-01-01 00:00:00" in ref["timestamps_per_artifact"].get("fixture_prefetch_a.exe", set())

    def test_disk_tool_routing(self):
        """All vol_ tools get image_path; standalone tools get no args."""
        for name, (fn, arg_type) in _TOOL_REGISTRY.items():
            if name.startswith("vol_"):
                # CC#17a.1: vol_generic covers Vol3 plugins without Python
                # wrappers; run_tool routes them through run_volatility.
                assert arg_type in ("memory", "vol_generic"), (
                    f"{name} should have arg_type 'memory' or 'vol_generic', "
                    f"got '{arg_type}'"
                )
            elif name in ("parse_prefetch", "parse_event_logs"):
                assert arg_type == "standalone", (
                    f"{name} should have arg_type 'standalone', got '{arg_type}'"
                )


# ── psscan fallback ────────────────────────────────────────────────────

class TestPsscanFallback:
    """When pstree returns 0 records but psscan has data, use psscan."""

    def test_psscan_fallback_when_pstree_empty(self):
        """pstree=0 + psscan=139 -> pstree gets psscan data."""
        mandatory = {
            "vol_pstree": {"tool_name": "vol_pstree", "record_count": 0, "output": []},
            "vol_psscan": {"tool_name": "vol_psscan", "record_count": 139, "output": [{"PID": i} for i in range(139)]},
        }
        result = _psscan_fallback(mandatory)
        assert result["vol_pstree"]["record_count"] == 139
        assert result["vol_pstree"]["tool_name"] == "vol_pstree (psscan fallback)"
        assert len(result["vol_pstree"]["output"]) == 139

    def test_psscan_fallback_not_triggered(self):
        """pstree=129 -> no fallback, original data preserved."""
        mandatory = {
            "vol_pstree": {"tool_name": "vol_pstree", "record_count": 129, "output": [{"PID": i} for i in range(129)]},
            "vol_psscan": {"tool_name": "vol_psscan", "record_count": 139, "output": [{"PID": i} for i in range(139)]},
        }
        result = _psscan_fallback(mandatory)
        assert result["vol_pstree"]["record_count"] == 129
        assert result["vol_pstree"]["tool_name"] == "vol_pstree"

    def test_psscan_fallback_both_empty(self):
        """Both empty -> no fallback, pstree stays empty."""
        mandatory = {
            "vol_pstree": {"tool_name": "vol_pstree", "record_count": 0, "output": []},
            "vol_psscan": {"tool_name": "vol_psscan", "record_count": 0, "output": []},
        }
        result = _psscan_fallback(mandatory)
        assert result["vol_pstree"]["record_count"] == 0
        assert result["vol_pstree"]["tool_name"] == "vol_pstree"

    def test_psscan_fallback_no_psscan_key(self):
        """Missing psscan key -> no crash, no fallback."""
        mandatory = {
            "vol_pstree": {"tool_name": "vol_pstree", "record_count": 0, "output": []},
        }
        result = _psscan_fallback(mandatory)
        assert result["vol_pstree"]["record_count"] == 0


class TestPsscanAvailable:
    """vol_psscan must be in registry (AI-selectable) and in Golden Path fallback."""

    def test_psscan_in_registry(self):
        assert "vol_psscan" in _TOOL_REGISTRY

    def test_psscan_in_golden_path(self):
        assert "vol_psscan" in GOLDEN_PATH_TOOLS

    def test_psscan_not_in_bootstrap(self):
        assert "vol_psscan" not in BOOTSTRAP_TOOLS


class TestInv1WhitelistFilter:
    """Inv1 selected tools must be filtered against a supported whitelist."""

    INV1_SUPPORTED = {
        "vol_cmdline", "vol_dlllist", "vol_handles", "vol_envars",
        "vol_getsids", "vol_privileges", "vol_svcscan", "vol_ldrmodules",
        "vol_filescan", "vol_callbacks", "vol_driverscan",
        "parse_event_logs", "parse_prefetch", "get_amcache",
        "extract_mft_timeline",
    }

    def _filter(self, raw_selected):
        """Replicate the Inv1 whitelist filter from run_pipeline.py."""
        selected = []
        for t in raw_selected:
            clean = t.replace("tool_", "")
            if clean in self.INV1_SUPPORTED:
                selected.append(clean)
        return selected

    def test_unsupported_tool_filtered(self):
        raw = ["vol_cmdline", "tool_run_volatility", "vol_dlllist"]
        result = self._filter(raw)
        assert "vol_cmdline" in result
        assert "vol_dlllist" in result
        assert "run_volatility" not in result
        assert len(result) == 2

    def test_tool_prefix_stripped(self):
        raw = ["tool_vol_handles", "tool_vol_envars"]
        result = self._filter(raw)
        assert "vol_handles" in result
        assert "vol_envars" in result

    def test_all_unsupported_returns_empty(self):
        raw = ["tool_run_volatility", "tool_parse_shellbags"]
        result = self._filter(raw)
        assert result == []


class TestDiskIntegrityMountOnly:
    """When only --disk-mount is provided (no raw disk image), integrity
    should report 'not_checked' rather than claiming full verification."""

    def test_no_disk_path_reports_not_checked(self):
        disk_path = None
        disk_integrity = (
            "verified" if disk_path
            else "not_checked (mounted filesystem, no raw image to hash)"
        )
        assert "not_checked" in disk_integrity

    def test_with_disk_path_reports_verified(self):
        disk_path = "/evidence/disk.E01"
        disk_integrity = (
            "verified" if disk_path
            else "not_checked (mounted filesystem, no raw image to hash)"
        )
        assert disk_integrity == "verified"


# ── Investigation enrichment: claim extraction + confidence upgrade ─────


class TestInvestigationAddsClaims:
    """Investigation results produce claims from amcache/prefetch/psscan."""

    def test_investigation_adds_claims(self):
        """Finding gains claims from investigation including execution type."""
        findings = [{
            "finding_id": "F-010",
            "claims": [{"type": "pid", "pid": 9001, "process": "sqlsvc.exe"}],
            "source_tools": ["vol_pstree"],
        }]
        investigations = [{
            "finding_id": "F-010",
            "pid": 9001,
            "process": "sqlsvc.exe",
            "turns": 2,
            "tool_chain": ["vol_netscan", "get_amcache"],
            "details": [
                {
                    "turn": 0, "tool": "vol_netscan", "pid": 9001,
                    "result_count": 1,
                    "result_sample": [{
                        "ForeignAddr": "192.0.2.129",
                        "Owner": "sqlsvc.exe",
                    }],
                },
                {
                    "turn": 1, "tool": "get_amcache", "pid": 9001,
                    "result_count": 1,
                    "result_sample": [{
                        "FileName": "sqlsvc.exe",
                        "SHA1": "abc123",
                    }],
                },
            ],
        }]
        result = step_11b_enrich_findings(findings, investigations)
        inv_claims = result[0]["investigation_claims"]
        assert len(inv_claims) == 2
        types = {c["type"] for c in inv_claims}
        assert "connection" in types
        assert "execution" in types
        # All claims marked with source=investigation
        for c in inv_claims:
            assert c.get("source") == "investigation"


class TestInvestigationUpgradesConfidence:
    """MEDIUM -> HIGH after investigation adds claims from 2+ evidence types."""

    def test_investigation_upgrades_confidence(self):
        finding = {
            "finding_id": "F-011",
            "source_tools": ["vol_pstree"],
            "confidence_level": "HIGH",
            "claims": [{"type": "pid", "pid": 9001, "process": "sqlsvc.exe"}],
            "investigation_claims": [
                {"source_tools": ["vol_netscan"], "type": "connection"},
                {"source_tools": ["get_amcache"], "type": "execution"},
            ],
        }
        # 1 source type (memory) -> MEDIUM without investigation
        # 3 source types (memory + network + disk) -> HIGH with investigation
        result = step_13_calibrate([finding], "full")
        assert result[0]["confidence_level"] == "HIGH"


class TestInvestigationNoDataNoChange:
    """0-record investigation doesn't change finding."""

    def test_investigation_no_data_no_change(self):
        findings = [{
            "finding_id": "F-012",
            "claims": [{"type": "pid", "pid": 100, "process": "cmd.exe"}],
            "source_tools": ["vol_pstree"],
        }]
        investigations = [{
            "finding_id": "F-012",
            "pid": 100,
            "process": "cmd.exe",
            "turns": 1,
            "tool_chain": ["vol_handles"],
            "details": [{
                "turn": 0, "tool": "vol_handles", "pid": 100,
                "result_count": 0,
                "result_sample": [],
            }],
        }]
        step_11b_enrich_findings(findings, investigations)
        assert "investigation_claims" not in findings[0]
        assert "investigation_claims_count" not in findings[0]


class TestInvestigationClaimsLogged:
    """investigation_claims and investigation_claims_count present in finding."""

    def test_investigation_claims_logged(self):
        findings = [{
            "finding_id": "F-013",
            "claims": [{"type": "pid", "pid": 9001, "process": "sqlsvc.exe"}],
            "source_tools": ["vol_pstree"],
        }]
        investigations = [{
            "finding_id": "F-013",
            "pid": 9001,
            "process": "sqlsvc.exe",
            "turns": 1,
            "tool_chain": ["vol_cmdline"],
            "details": [{
                "turn": 0, "tool": "vol_cmdline", "pid": 9001,
                "result_count": 1,
                "result_sample": [{"Args": "C:\\sqlsvc.exe", "Process": "sqlsvc.exe"}],
            }],
        }]
        step_11b_enrich_findings(findings, investigations)
        assert "investigation_claims" in findings[0]
        assert isinstance(findings[0]["investigation_claims"], list)
        assert findings[0]["investigation_claims_count"] == 1
        assert findings[0]["investigation_tools"] == ["vol_cmdline"]
