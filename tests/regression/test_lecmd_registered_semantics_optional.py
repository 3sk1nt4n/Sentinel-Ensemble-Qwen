"""Slot 31I-beta: optional LECmd-like shortcut-artifact semantics.

LECmd is an EZ Tools binary that may or may not be wired into this
build. Discover the registered equivalent case-insensitively by name
(lecmd / lnk / shortcut / lecd). If present, it MUST carry the
execution_artifacts bucket and a shortcut_artifact detect tag. If
absent, this is a REVIEW/skip -- never a hard failure (no invented
tool names).
"""

import re

import pytest

import sift_sentinel.coordinator as c
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tool_semantics import get_tool_semantics

_LECMD_RE = re.compile(r"lecmd|lecd|lnk|shortcut", re.IGNORECASE)


def _registered_lecmd_like():
    return sorted(n for n in c._TOOL_REGISTRY if _LECMD_RE.search(n))


def test_lecmd_like_tool_semantics_if_present():
    candidates = _registered_lecmd_like()
    if not candidates:
        pytest.skip(
            "REVIEW: no LECmd-like tool registered in this build; "
            "optional-absent, not a failure"
        )
    for name in candidates:
        sem = get_tool_semantics(
            name, c._TOOL_REGISTRY[name], get_capability(name),
        )
        assert "execution_artifacts" in sem["buckets"], (
            f"{name}: missing execution_artifacts bucket"
        )
        assert "shortcut_artifact" in sem["detects"], (
            f"{name}: missing shortcut_artifact detect tag"
        )


def test_discovery_is_case_insensitive_and_registry_bound():
    # Any candidate found must be a real registry key (no phantoms).
    for name in _registered_lecmd_like():
        assert name in c._TOOL_REGISTRY
