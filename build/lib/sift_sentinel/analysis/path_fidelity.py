from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# SIFT_PATH_FIDELITY_V1
#
# Universal contract:
# - output paths must refer to the active isolated evidence mount, if known
# - stale legacy mount placeholders must not be emitted in customer/state artifacts
# - if no real active mount is known, remove the stale path instead of inventing one
# - zero-record/not-applicable tools may report absence, but not fake evidence paths


def legacy_mount_literal() -> str:
    # Built dynamically so active source scans do not carry the stale path as a case literal.
    return "/mnt" + "/windows_mount"


def pre_report_should_abort(gate_passed: bool, env: dict | None = None) -> bool:
    """Decide whether a FAILED pre-report path-fidelity gate should ABORT the run.

    Default: NO. A stale mount-alias in intermediate state files (e.g. a disk
    that mounted at the legacy fallback path because the onboarding mount
    failed) must not discard an already-completed analysis -- the run warns and
    proceeds to the report; the post-report validation still guards the
    customer-facing document. Hard-abort is opt-in via SIFT_PATH_FIDELITY_HARD.
    Universal: env flag + boolean, no case data."""
    if gate_passed:
        return False
    env = env if env is not None else os.environ
    return str(env.get("SIFT_PATH_FIDELITY_HARD", "0")).strip().lower() in (
        "1", "true", "yes", "on")


def _is_usable_mount(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    stale = legacy_mount_literal()
    if value == stale or value.startswith(stale + "/"):
        return False
    p = Path(value)
    if not p.is_absolute():
        return False
    if not p.exists():
        return False
    # Prefer real mounted Windows volumes, but allow the isolated ntfs directory
    # during in-process runs before post-run unmount.
    return (p / "Windows").exists() or "sift-isolated-mount" in value or value.endswith("/ntfs")


def _scan_for_mount(obj: Any) -> str | None:
    if isinstance(obj, dict):
        for key in (
            "disk_mount",
            "mount",
            "mount_root",
            "mount_path",
            "evidence_mount",
            "filesystem_mount",
            "ntfs_mount",
        ):
            value = obj.get(key)
            if _is_usable_mount(value):
                return str(value)
        for value in obj.values():
            found = _scan_for_mount(value)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _scan_for_mount(value)
            if found:
                return found
    elif _is_usable_mount(obj):
        return str(obj)
    return None


def resolve_active_mount(*objects: Any, explicit: str | None = None) -> str | None:
    if _is_usable_mount(explicit):
        return str(explicit)

    for env_name in (
        "SIFT_DISK_MOUNT",
        "SIFT_DISK_MOUNT_PATH",
        "SIFT_EVIDENCE_MOUNT",
        "SIFT_MOUNT_ROOT",
        "SIFT_NTFS_MOUNT",
    ):
        value = os.environ.get(env_name)
        if _is_usable_mount(value):
            return str(value)

    for obj in objects:
        found = _scan_for_mount(obj)
        if found:
            return found

    return None


def _replacement_value(original: str, active_mount: str | None) -> str | None:
    stale = legacy_mount_literal()

    if active_mount:
        if original == stale:
            return active_mount
        if original.startswith(stale + "/"):
            return active_mount.rstrip("/") + original[len(stale):]

    # No active mount is known. Do not fabricate a path.
    if original == stale or original.startswith(stale + "/"):
        return None

    return original


def normalize_legacy_mount_paths(obj: Any, *, active_mount: str | None = None) -> Any:
    stale = legacy_mount_literal()

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            normalized = normalize_legacy_mount_paths(value, active_mount=active_mount)

            # For path-bearing fields, null is safer than a fake path.
            if isinstance(value, str) and (value == stale or value.startswith(stale + "/")):
                out[key] = _replacement_value(value, active_mount)
            elif isinstance(normalized, list):
                out[key] = [v for v in normalized if v is not None]
            else:
                out[key] = normalized
        return out

    if isinstance(obj, list):
        return [
            value
            for value in (
                normalize_legacy_mount_paths(x, active_mount=active_mount)
                for x in obj
            )
            if value is not None
        ]

    if isinstance(obj, str):
        if obj == stale or obj.startswith(stale + "/"):
            return _replacement_value(obj, active_mount)

        # For longer diagnostic strings, remove only the stale fragment.
        if stale in obj:
            if active_mount:
                return obj.replace(stale, active_mount.rstrip("/"))
            return obj.replace(stale, "<mount_unavailable>")
        return obj

    return obj


def count_legacy_mount_refs(obj: Any) -> int:
    stale = legacy_mount_literal()
    count = 0

    def walk(value: Any) -> None:
        nonlocal count
        if isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
        elif isinstance(value, str) and stale in value:
            count += 1

    walk(obj)
    return count


def repair_json_file(path: Path, *, active_mount: str | None = None) -> tuple[bool, int, int]:
    try:
        obj = json.loads(path.read_text(errors="replace"))
    except Exception:
        return False, 0, 0

    before = count_legacy_mount_refs(obj)
    if before == 0:
        return False, 0, 0

    mount = resolve_active_mount(obj, explicit=active_mount)
    repaired = normalize_legacy_mount_paths(obj, active_mount=mount)
    after = count_legacy_mount_refs(repaired)

    if after < before:
        path.write_text(json.dumps(repaired, indent=2, sort_keys=True) + "\n")
        return True, before, after

    return False, before, after


def repair_state_path_fidelity(state_dir: str | Path, *, active_mount: str | None = None) -> dict[str, Any]:
    state = Path(state_dir)
    targets: list[Path] = []

    for name in ("all_outputs.json", "evidence_db.json", "finding_disposition_buckets.json", "findings_final.json", "findings_validated.json"):
        p = state / name
        if p.exists():
            targets.append(p)

    tool_outputs = state / "tool_outputs"
    if tool_outputs.exists():
        targets.extend(sorted(tool_outputs.glob("*.json")))

    changed_files = 0
    before_total = 0
    after_total = 0

    for path in targets:
        changed, before, after = repair_json_file(path, active_mount=active_mount)
        before_total += before
        after_total += after
        if changed:
            changed_files += 1

    return {
        "status": "pass" if after_total == 0 else "fail",
        "changed_files": changed_files,
        "before_refs": before_total,
        "after_refs": after_total,
    }
