"""Commit 25: Regression guards for pycryptodome environment dependency
and the 3 credential-extraction Vol3 plugins it enables.

Property tests + structural guards. All dataset-agnostic (synthetic
fixtures, no hardcoded finding IDs, no cached artifact values).

Assertions:
  L25-1 Crypto module is importable (pycryptodome installed)
  L25-2 vol_cachedump, vol_hashdump, vol_lsadump are in _TOOL_REGISTRY
  L25-3 All 3 are categorized as registry_analysis (registry-hive extractors)
  L25-4 _TOOL_REGISTRY size has floor of 175 (forward-compatible)
  L25-5 ENVIRONMENT.md exists and documents pycryptodome
  L25-6 Windows selectable pool arithmetic correct (175 - 2 - 47 = 126)
"""
from __future__ import annotations

from pathlib import Path


def test_L25_1_crypto_module_importable():
    """Regression guard: pycryptodome must be installed. Without it,
    Vol3 partially fails to load plugin registry, causing multiple
    plugins to produce empty stdout and crash mcp_client json.loads."""
    try:
        from Crypto.Cipher import ARC4, AES  # noqa: F401
    except ImportError as exc:
        import pytest
        pytest.fail(
            f"pycryptodome is not installed: {exc}. "
            f"Install with: pip install pycryptodome --break-system-packages. "
            f"See ENVIRONMENT.md for details."
        )


def test_L25_2_credential_extraction_tools_registered():
    """Property: the 3 credential-extraction Vol3 plugins must be in
    _TOOL_REGISTRY. Their presence depends on pycryptodome enabling
    the Vol3 registry subsystem to load cleanly."""
    from sift_sentinel.coordinator import _TOOL_REGISTRY
    expected = {"vol_cachedump", "vol_hashdump", "vol_lsadump"}
    missing = expected - set(_TOOL_REGISTRY.keys())
    assert not missing, (
        f"Credential-extraction tools missing from registry: {missing}. "
        f"Check pycryptodome installation per ENVIRONMENT.md."
    )


def test_L25_3_credential_extraction_tools_categorized_as_registry_analysis():
    """Property: the 3 credential-extraction tools are categorized as
    registry_analysis.

    Semantic rationale: these tools EXTRACT credential data from
    SAM/SECURITY/CACHE registry hives, fitting the registry_analysis
    pattern (vol_printkey, vol_reg_hivelist, vol_getservicesids,
    run_recmd). They do not DETECT attack techniques (which is what
    malware_detection tools like vol_malfind, vol_hollowprocesses do).
    """
    from sift_sentinel.coordinator import _TOOL_CATEGORY
    for tool in ("vol_cachedump", "vol_hashdump", "vol_lsadump"):
        assert _TOOL_CATEGORY.get(tool) == "registry_analysis", (
            f"{tool} should be categorized as registry_analysis, "
            f"got {_TOOL_CATEGORY.get(tool)!r}"
        )


def test_L25_4_registry_size_floor_175():
    """Property: _TOOL_REGISTRY has at least 175 tools post-Commit-25.

    Floor (not exact): allows future commits to add tools without
    breaking this guard, while catching regressions if pycryptodome
    is uninstalled or plugins are removed (which would drop registry
    below 175)."""
    from sift_sentinel.coordinator import _TOOL_REGISTRY
    assert len(_TOOL_REGISTRY) >= 175, (
        f"Registry size regressed below floor: {len(_TOOL_REGISTRY)} < 175. "
        f"Check pycryptodome installation per ENVIRONMENT.md."
    )


def test_L25_5_environment_md_exists_and_documents_pycryptodome():
    """Structural: ENVIRONMENT.md must exist at repo root and reference
    both pycryptodome and Commit 25 for traceability."""
    env_path = Path(__file__).resolve().parent.parent / "ENVIRONMENT.md"
    assert env_path.exists(), "ENVIRONMENT.md must exist at repo root"
    content = env_path.read_text()
    assert "pycryptodome" in content, (
        "ENVIRONMENT.md must mention pycryptodome dependency"
    )
    assert "Commit 25" in content, (
        "ENVIRONMENT.md must reference Commit 25 for traceability"
    )


def test_L25_6_selectable_pool_arithmetic_correct():
    """Property: post-F8-B Windows selectable pool is 129.

    Arithmetic: 178 total - 2 bootstrap - 47 non-Windows = 129.
    Recomputed from registry state to catch any miscalculation."""
    from sift_sentinel.coordinator import (
        _TOOL_REGISTRY, BOOTSTRAP_TOOLS, _NON_WINDOWS_TOOLS
    )
    selectable = (set(_TOOL_REGISTRY) - set(BOOTSTRAP_TOOLS)
                  - _NON_WINDOWS_TOOLS)
    assert len(selectable) == 129, (
        f"Windows selectable pool arithmetic wrong: "
        f"expected 129 (178-2-47), got {len(selectable)}"
    )
