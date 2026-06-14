"""Regression: the Step-6 high-value resolver must tolerate an EIO/corrupt
directory under ``Users`` when probing for ``.rdp`` profiles.

Root cause of the live "future raised: OSError [Errno 5]" crash: the resolver
``_resolve_rdp_artifacts`` probed ``users_dir.rglob("*.rdp")`` -- a lazy
generator that propagates the EIO raised by ``scandir`` on a corrupt directory
of a force-mounted NTFS image. The resolver runs inside a Step-6 worker thread,
*outside* the MCP client's try/except, so the escaping OSError surfaced as a
tool error and zeroed the entire RDP family (the tool itself never ran).

These tests assert *properties* (EIO tolerance, applicability via the EVTX
sub-source, no crash) -- never dataset-specific values.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def _hv():
    import sift_sentinel.runtime.high_value_tool_args as hv

    return importlib.reload(hv)


def test_has_file_with_suffix_positive_and_negative_on_real_tree(
    tmp_path: Path,
) -> None:
    hv = _hv()
    root = tmp_path / "Users"
    (root / "alice" / "Documents").mkdir(parents=True)
    (root / "alice" / "Documents" / "server.rdp").write_text("full address:s:host")
    (root / "bob").mkdir(parents=True)

    assert hv._has_file_with_suffix(root, ".rdp") is True
    # Case-insensitive on the suffix.
    assert hv._has_file_with_suffix(root, ".RDP") is True
    # Absent suffix -> False, having traversed the whole tree without error.
    assert hv._has_file_with_suffix(root, ".nonexistent_suffix") is False


def _walk_yielding_then_raising(match_name: str | None):
    """Return a fake ``os.walk`` that yields one directory tuple (optionally
    containing *match_name*) and then raises OSError mid-iteration -- the
    real failure mode (EIO surfacing from the walk generator under concurrent
    mount access), not a raise-at-call.
    """

    def _fake_walk(_top, onerror=None):  # noqa: ANN001
        def _gen():
            yield ("/synthetic/a", ["sub"], [match_name] if match_name else ["readme.txt"])
            raise OSError(5, "Input/output error")

        return _gen()

    return _fake_walk


def test_has_file_with_suffix_tolerates_oserror_after_a_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hv = _hv()
    import os

    monkeypatch.setattr(os, "walk", _walk_yielding_then_raising("profile.rdp"))
    # Match is yielded before the mid-iteration OSError -> True, no propagation.
    assert hv._has_file_with_suffix(Path("/synthetic"), ".rdp") is True


def test_has_file_with_suffix_swallows_midwalk_oserror_returns_bool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hv = _hv()
    import os

    monkeypatch.setattr(os, "walk", _walk_yielding_then_raising(None))
    # No match before the OSError -> graceful False, never a propagated OSError.
    result = hv._has_file_with_suffix(Path("/synthetic"), ".rdp")
    assert result is False


def test_resolve_rdp_artifacts_applicable_despite_corrupt_users_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The headline regression: a corrupt directory under Users must not crash
    the resolver. With TerminalServices EVTX present, the tool stays applicable.
    """
    hv = _hv()
    mount = tmp_path / "ntfs"
    logs = mount / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx").write_bytes(b"EVTX")
    (mount / "Users" / "bobby").mkdir(parents=True)

    # Simulate the EIO surfacing mid-iteration during the .rdp probe.
    import os

    monkeypatch.setattr(os, "walk", _walk_yielding_then_raising(None))

    result = hv._resolve_rdp_artifacts(mount)  # must not raise
    assert result["kind"] == "mcp_call"
    assert result["tool_name"] == "parse_rdp_artifacts"
    assert "mount_path" in result["args"]
