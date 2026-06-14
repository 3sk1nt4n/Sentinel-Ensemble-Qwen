"""Phase A Step 2 dispatcher tests.

Enforces the typed-tool integration contract -- rules 1, 2, 6 (see ARCHITECTURE.md):
  * Rule 1: startup counts are computed from registry state.
  * Rule 2: every registered tool has a capability declaration.
  * Rule 6: no dataset observations / case-specific strings in source.

Also covers the new sleuthkit dispatch branch (binary-missing handling
and runtime-error containment), the circular-safe capability import,
and the unified _is_registered guardrail.
"""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


# ── Rule 2: capability coverage ────────────────────────────────────────

class TestRule2CapabilityCoverage:
    def test_every_registered_tool_has_capability_declaration(self):
        """Every _TOOL_REGISTRY entry must have a capability dict."""
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        from sift_sentinel.tools.capabilities import get_capability

        missing = [t for t in _TOOL_REGISTRY if get_capability(t) is None]
        assert not missing, (
            f"Rule 2 violation -- tools without capability declarations: "
            f"{missing}"
        )

    def test_capability_schema_has_five_required_fields(self):
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        from sift_sentinel.tools.capabilities import (
            REQUIRED_FIELDS, get_capability,
        )
        for tool in _TOOL_REGISTRY:
            cap = get_capability(tool)
            assert cap is not None, tool
            missing = REQUIRED_FIELDS - set(cap.keys())
            assert not missing, f"{tool} missing fields: {sorted(missing)}"

    def test_runtime_class_values_valid(self):
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        from sift_sentinel.tools.capabilities import (
            VALID_RUNTIME_CLASSES, get_capability,
        )
        for tool in _TOOL_REGISTRY:
            cap = get_capability(tool)
            assert cap["runtime_class"] in VALID_RUNTIME_CLASSES, (
                f"{tool}: runtime_class={cap['runtime_class']!r} invalid"
            )

    def test_produces_list_nonempty(self):
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        from sift_sentinel.tools.capabilities import get_capability
        for tool in _TOOL_REGISTRY:
            cap = get_capability(tool)
            assert isinstance(cap["produces"], list) and cap["produces"], (
                f"{tool}: produces must be a non-empty list"
            )


# ── Rule 6: no case-specific strings in source ────────────────────────

class TestRule6NoCaseSpecificArtifacts:
    def test_no_case_specific_artifacts_in_source(self):
        """Rule 6: no case-specific dataset strings in src/ or pipeline.

        Capabilities, prompts, and dispatch code must stay generic.
        Case-specific observations belong in reports/ and reference-data
        files, not in production source.
        """
        forbidden = [
            "9001", "9002", "9003", "2876",
            "192.0.2.129", "192.0.2.140", "192.0.2.151", "192.0.2.175",
            "CRIMSON", "OSPREY",
            "PWDumpX", "PSEXESVC", "perfmon\\\\",
        ]
        pattern = "|".join(forbidden)
        result = subprocess.run(
            [
                "grep", "-rEn", pattern,
                "src/", "run_pipeline.py",
                "--include=*.py",
            ],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        assert result.returncode == 1, (
            f"Rule 6 violation -- case-specific strings in source:\n"
            f"{result.stdout}"
        )

    def test_no_hardcoded_finding_counts(self):
        """Rule 6: no hardcoded expected finding counts in source."""
        result = subprocess.run(
            [
                "grep", "-rEn", r"findings.*==\s*(10|11|12)\b",
                "src/", "run_pipeline.py", "--include=*.py",
            ],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        assert result.returncode == 1, (
            f"Rule 6 violation -- hardcoded finding counts:\n{result.stdout}"
        )


# ── Registry floor + dynamic-or-fallback integrity ─────────────────────

class TestRegistryIntegrity:
    def test_registry_minimum_floor(self):
        """Floor: 23 original + 3 sleuthkit = 26 (fallback path)."""
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        assert len(_TOOL_REGISTRY) >= 26, (
            f"Registry size {len(_TOOL_REGISTRY)} below Phase A floor (26)"
        )

    def test_dynamic_vol_discovery_or_explicit_fallback(self, caplog):
        """Silent failure is not allowed: either dynamic discovery added
        enough plugins, or the fallback log explicitly fired."""
        import sift_sentinel.tools.common as common_mod
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        from sift_sentinel.tools.common import _VOL_CANONICAL_ALIASES

        vol_entries = [k for k in _TOOL_REGISTRY if k.startswith("vol_")]
        dynamic_added = len(vol_entries) - len(_VOL_CANONICAL_ALIASES)

        if dynamic_added < 30:
            with caplog.at_level(
                "INFO", logger="sift_sentinel.tools.common",
            ):
                importlib.reload(common_mod)
            fallback_logged = any(
                "fallback" in rec.message.lower()
                or "hardcoded" in rec.message.lower()
                for rec in caplog.records
            )
            assert fallback_logged, (
                f"Silent failure: dynamic_added={dynamic_added} but no "
                "fallback log recorded. Rule 1 violation."
            )

    def test_hardcoded_vol_fallback_defined(self):
        from sift_sentinel.tools.common import _VOL_CANONICAL_ALIASES
        assert isinstance(_VOL_CANONICAL_ALIASES, dict)
        assert len(_VOL_CANONICAL_ALIASES) >= 21
        assert _VOL_CANONICAL_ALIASES["vol_pstree"] == "windows.pstree.PsTree"


# ── Unified guardrail + circular import safety ─────────────────────────

class TestGuardrailAndImports:
    def test_is_registered_uses_real_capability_module(self):
        """Guard against circular import causing a lambda fallback."""
        from sift_sentinel.coordinator import get_capability
        assert getattr(get_capability, "__name__", "") != "<lambda>", (
            "Circular import fallback active -- capabilities module unreachable"
        )
        cap = get_capability("vol_pstree")
        assert cap is not None

    def test_is_registered_true_for_known_tool(self):
        from sift_sentinel.coordinator import _is_registered
        assert _is_registered("vol_pstree") is True
        assert _is_registered("sleuthkit_fls") is True

    def test_is_registered_false_for_unknown_tool(self):
        from sift_sentinel.coordinator import _is_registered
        assert _is_registered("nonexistent_tool") is False

    def test_guardrail_filter_drops_unknown(self):
        from sift_sentinel.coordinator import _guardrail_filter_tools
        filtered = _guardrail_filter_tools(
            ["vol_pstree", "nonexistent_tool", "sleuthkit_fls"],
        )
        assert "vol_pstree" in filtered
        assert "sleuthkit_fls" in filtered
        assert "nonexistent_tool" not in filtered


# ── Sleuthkit registration + dispatch ─────────────────────────────────

class TestSleuthkitIntegration:
    @pytest.mark.parametrize(
        "tool_name", ["sleuthkit_fls", "sleuthkit_mmls", "sleuthkit_fsstat"],
    )
    def test_sleuthkit_registered(self, tool_name):
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        from sift_sentinel.tools.capabilities import get_capability
        assert tool_name in _TOOL_REGISTRY
        entry = _TOOL_REGISTRY[tool_name]
        assert entry[1] == "sleuthkit"
        assert get_capability(tool_name) is not None

    def test_sleuthkit_dispatch_handles_missing_binary(self, monkeypatch):
        """Sleuthkit branch must return structured error, not crash."""
        from sift_sentinel import coordinator
        monkeypatch.setattr("shutil.which", lambda _: None)
        result = coordinator.run_tool(
            "sleuthkit_fls",
            image_path="/tmp/fake-image",
            disk_path="/tmp/fake-disk",
        )
        assert "error" in result
        assert result.get("failure_mode") == "binary_missing"
        assert result.get("tool_name") == "sleuthkit_fls"

    def test_sleuthkit_dispatch_captures_runtime_error(self, monkeypatch):
        """A raising run_sleuthkit call must be wrapped as failure_mode."""
        from sift_sentinel import coordinator
        import sift_sentinel.tools.generic as generic_mod

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/fls")

        def _blow_up(cmd, image):
            raise RuntimeError("sleuthkit exploded")

        monkeypatch.setattr(generic_mod, "run_sleuthkit", _blow_up)

        result = coordinator.run_tool(
            "sleuthkit_fls",
            image_path="/tmp/fake-image",
            disk_path="/tmp/fake-disk",
        )
        assert "error" in result
        assert result.get("failure_mode") == "runtime_error"


# ── auto_capability factory ────────────────────────────────────────────

class TestAutoCapability:
    def test_windows_default_applicability(self):
        from sift_sentinel.tools.capabilities import auto_capability
        cap = auto_capability("vol_unknown", os_family="windows")
        # INTENTIONAL CHANGE (disk-only live-run fix): Vol3 dynamic plugins
        # are memory-required -- memory_evidence tag added.
        assert cap["applicable_when"] == ["windows_evidence", "memory_evidence"]
        # Commit 5: mac branch added -- exclusion list now includes mac_evidence
        assert cap["not_applicable_when"] == ["linux_evidence", "mac_evidence"]
        assert cap["runtime_class"] == "medium"

    def test_linux_os_family(self):
        from sift_sentinel.tools.capabilities import auto_capability
        cap = auto_capability("linux_tool", os_family="linux")
        # INTENTIONAL CHANGE (disk-only live-run fix): see windows case above.
        assert cap["applicable_when"] == ["linux_evidence", "memory_evidence"]
        # Commit 5: mac branch added -- exclusion list now includes mac_evidence
        assert cap["not_applicable_when"] == ["windows_evidence", "mac_evidence"]

    def test_any_os_family(self):
        from sift_sentinel.tools.capabilities import auto_capability
        cap = auto_capability("neutral", os_family="any")
        # INTENTIONAL CHANGE (disk-only live-run fix): even OS-neutral Vol3
        # plugins still require a memory image to run at all.
        assert cap["applicable_when"] == ["memory_evidence"]
        assert cap["not_applicable_when"] == []

    def test_invalid_os_family_raises(self):
        from sift_sentinel.tools.capabilities import auto_capability
        with pytest.raises(ValueError, match="os_family"):
            auto_capability("x", os_family="solaris")

    def test_register_capability_requires_all_fields(self):
        from sift_sentinel.tools.capabilities import register_capability
        with pytest.raises(ValueError, match="missing fields"):
            register_capability("bad", {"produces": ["x"]})

    def test_register_capability_rejects_bad_runtime_class(self):
        from sift_sentinel.tools.capabilities import register_capability
        bad = {
            "produces": ["x"],
            "applicable_when": [],
            "not_applicable_when": [],
            "failure_modes": [],
            "runtime_class": "lightning",
        }
        with pytest.raises(ValueError, match="runtime_class"):
            register_capability("bad", bad)


# ── Capability content sanity (without leaking dataset observations) ───

class TestCapabilityContentSanity:
    def test_vol_pstree_windows_applicable(self):
        from sift_sentinel.tools.capabilities import get_capability
        cap = get_capability("vol_pstree")
        assert "windows_evidence" in cap["applicable_when"]
        assert "linux_evidence" in cap["not_applicable_when"]

    def test_sleuthkit_fls_disk_applicable(self):
        from sift_sentinel.tools.capabilities import get_capability
        cap = get_capability("sleuthkit_fls")
        assert "disk_evidence" in cap["applicable_when"]
        assert "binary_missing" in cap["failure_modes"]

    def test_hollowprocesses_failure_mode_is_generic(self):
        """Rule 6 fix: failure_modes must not reference observed profiles."""
        from sift_sentinel.tools.capabilities import get_capability
        cap = get_capability("vol_hollowprocesses")
        for mode in cap["failure_modes"]:
            lowered = mode.lower()
            assert "observed" not in lowered, mode
            # token assembled so this test source carries no contiguous
            # dataset literal while still scanning for the real token.
            assert ("rd" "-01") not in lowered, mode
            assert "dataset" not in lowered, mode
