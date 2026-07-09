from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Iterable

# SIFT_VOLATILITY_ARG_CONTRACT_V1
#
# Universal contract:
# - Every vol_* tool requires a memory image path.
# - Missing path is a pipeline/tool-routing bug, not a forensic zero.
# - This resolver may recover the memory path from explicit args, locals, env,
#   or process argv, but it never invents a path.
# - Disk images such as .E01/.AFF/.VHD are intentionally not accepted as
#   memory images for Volatility.
# - Bad pseudo-values ("None", "null", "unknown") are rejected.

_BAD_VALUES = {"", "none", "null", "nil", "unknown", "n/a", "na", "-", "--"}
_MEMORY_SUFFIXES = {
    ".img", ".mem", ".raw", ".vmem", ".lime", ".dmp", ".dump",
    ".bin", ".hiberfil", ".hibr", ".snapshot",
}
_DISK_SUFFIXES = {
    ".e01", ".ex01", ".aff", ".aff4", ".vhd", ".vhdx", ".vmdk",
    ".qcow", ".qcow2", ".iso",
}
_MEMORY_HINTS = ("memory", "mem", "vmem", "ram", "dump", "hiberfil")


def _clean_path_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Path):
        value = str(value)
    if not isinstance(value, str):
        return None
    s = value.strip().strip("'\"")
    if s.lower() in _BAD_VALUES:
        return None
    if not s:
        return None
    return s


def _looks_like_memory_image(path: str, *, flagged_memory_arg: bool = False) -> bool:
    cleaned = _clean_path_value(path)
    if not cleaned:
        return False

    p = Path(cleaned)
    name = p.name.lower()
    suffix = p.suffix.lower()

    if suffix in _DISK_SUFFIXES:
        return False

    # A --memory value is authoritative enough to allow extensionless memory
    # images, but still must not be a directory.
    if flagged_memory_arg:
        return not p.exists() or p.is_file()

    if suffix in _MEMORY_SUFFIXES:
        return not p.exists() or p.is_file()

    if any(hint in name for hint in _MEMORY_HINTS):
        return not p.exists() or p.is_file()

    return False


def _iter_mapping_values(mapping: Any) -> Iterable[str]:
    if not isinstance(mapping, dict):
        return
    preferred_keys = (
        "memory_path", "memory_image", "mem_path", "mem_image",
        "image_path", "image", "input_path", "path", "file", "f",
    )
    for key in preferred_keys:
        if key in mapping:
            v = _clean_path_value(mapping.get(key))
            if v:
                yield v

    # Secondary scan for nested/plain values that clearly look like memory paths.
    for value in mapping.values():
        if isinstance(value, str):
            v = _clean_path_value(value)
            if v:
                yield v
        elif isinstance(value, (list, tuple)):
            for item in value:
                v = _clean_path_value(item)
                if v:
                    yield v


def _iter_env_values(env: dict[str, str] | None = None) -> Iterable[str]:
    env = env or os.environ
    keys = (
        "SIFT_MEMORY_IMAGE",
        "SIFT_MEMORY_PATH",
        "SIFT_ACTIVE_MEMORY_PATH",
        "SIFT_ACTIVE_MEMORY_IMAGE",
        "SIFT_ACTIVE_VOLATILITY_IMAGE",
        "SIFT_EVIDENCE_MEMORY",
        "SIFT_IMAGE_PATH",
        "MEMORY_IMAGE",
        "MEMORY_PATH",
        "VOLATILITY_IMAGE",
        "VOL_IMAGE",
    )
    for key in keys:
        v = _clean_path_value(env.get(key))
        if v:
            yield v


def _iter_sys_argv_values(argv: list[str] | None = None) -> Iterable[tuple[str, bool]]:
    argv = list(sys.argv if argv is None else argv)
    memory_flags = {
        "--memory", "--memory-path", "--memory_image", "--memory-image",
        "--mem", "--mem-path", "--image", "--image-path",
    }

    for i, token in enumerate(argv):
        if token in memory_flags and i + 1 < len(argv):
            v = _clean_path_value(argv[i + 1])
            if v:
                yield v, True
        for flag in memory_flags:
            prefix = flag + "="
            if token.startswith(prefix):
                v = _clean_path_value(token[len(prefix):])
                if v:
                    yield v, True

    for token in argv:
        v = _clean_path_value(token)
        if v:
            yield v, False
        if "=" in token:
            rhs = _clean_path_value(token.split("=", 1)[1])
            if rhs:
                yield rhs, False


def resolve_volatility_image_path(
    positional_mapping: Any = None,
    *,
    tool_name: str = "",
    plugin_name: str = "",
    explicit_path: Any = None,
    locals_map: dict[str, Any] | None = None,
    kwargs: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    argv: list[str] | None = None,
) -> str | None:
    """Return the best available memory image path for a vol_* tool.

    This function is deliberately conservative. It only returns a candidate
    that looks like a memory image, and it rejects disk image extensions.
    """

    # SIFT_VOLATILITY_RESOLVER_POSITIONAL_COMPAT_V1C
    if positional_mapping is not None:
        if kwargs is None and isinstance(positional_mapping, dict):
            kwargs = positional_mapping
        elif explicit_path is None:
            explicit_path = positional_mapping

    candidates: list[tuple[str, bool, str]] = []

    explicit = _clean_path_value(explicit_path)
    if explicit:
        candidates.append((explicit, False, "explicit"))

    for source_name, mapping in (("kwargs", kwargs), ("locals", locals_map)):
        for v in _iter_mapping_values(mapping):
            candidates.append((v, False, source_name))

    for v in _iter_env_values(env):
        candidates.append((v, False, "env"))

    for v, flagged in _iter_sys_argv_values(argv):
        candidates.append((v, flagged, "argv"))

    seen: set[str] = set()
    for value, flagged, source in candidates:
        if value in seen:
            continue
        seen.add(value)

        if not _looks_like_memory_image(value, flagged_memory_arg=flagged):
            continue

        p = Path(value)
        # Existing file wins immediately. Non-existing path is allowed only
        # for explicit/flagged cases because some tests and remote wrappers
        # may not have the file locally mounted.
        if p.exists() and p.is_file():
            return str(p)

        if source in {"explicit", "env"} or flagged:
            return value

    return None


def structured_missing_image_result(
    *,
    tool_name: str,
    plugin_name: str = "",
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "tool": tool_name,
        "plugin": plugin_name,
        "status": "tool_error",
        "records": [],
        "record_count": 0,
        "error": reason or f"{tool_name}: missing memory image path for Volatility",
        "reason": reason or "missing memory image path for Volatility",
        "coverage_only": True,
        "finding_capable": False,
        "sift_contract": "SIFT_VOLATILITY_ARG_CONTRACT_V1",
    }


def normalize_volatility_call_kwargs(
    *,
    tool_name: str,
    plugin_name: str = "",
    kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return kwargs with memory/image path fields populated when possible."""

    new_kwargs = dict(kwargs or {})
    resolved = resolve_volatility_image_path(
        tool_name=tool_name,
        plugin_name=plugin_name,
        explicit_path=new_kwargs.get("image_path")
        or new_kwargs.get("memory_path")
        or new_kwargs.get("file")
        or new_kwargs.get("f"),
        kwargs=new_kwargs,
    )
    if resolved:
        for key in ("image_path", "memory_path", "file", "f"):
            new_kwargs.setdefault(key, resolved)
    return new_kwargs
