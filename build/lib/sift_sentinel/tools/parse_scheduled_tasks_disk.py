"""Read-only parser for Windows scheduled task XML files on disk."""

from __future__ import annotations


def _env_int(name: str, default: int) -> int:
    """Read a non-negative integer cap from env; fall back safely."""
    raw = __import__("os").environ.get(name)
    if raw in (None, ""):
        return int(default)
    try:
        return max(0, int(raw))
    except ValueError:
        return int(default)


import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as DET
from defusedxml.common import DefusedXmlException

from sift_sentinel.config import DISK_MOUNT_PATH


TOOL_NAME = "parse_scheduled_tasks_disk"
EVIDENCE_TYPE = "scheduled_task_xml"

MAX_XML_BYTES = 1024 * 1024
RAW_EXCERPT_CHARS = 4096
SETTINGS_EXCERPT_CHARS = 2048
ERROR_CHARS = 300
TEXT_CHARS = 2000


def _bounded(value: str | None, limit: int = TEXT_CHARS) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


def _bool_text(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _snake(name: str) -> str:
    out: list[str] = []
    for idx, char in enumerate(name):
        if char.isupper() and idx and not name[idx - 1].isupper():
            out.append("_")
        out.append(char.lower())
    return "".join(out)


def _children(element: Any | None, name: str | None = None) -> list[Any]:
    if element is None:
        return []
    result = []
    for child in list(element):
        child_name = _local_name(str(child.tag))
        if name is None or child_name == name:
            result.append(child)
    return result


def _first_child(element: Any | None, name: str) -> Any | None:
    matches = _children(element, name)
    return matches[0] if matches else None


def _find_path(element: Any | None, *parts: str) -> Any | None:
    current = element
    for part in parts:
        current = _first_child(current, part)
        if current is None:
            return None
    return current


def _text_at(element: Any | None, *parts: str) -> str | None:
    target = _find_path(element, *parts)
    return _bounded(target.text if target is not None else None)


def _bool_at(element: Any | None, *parts: str) -> bool | None:
    return _bool_text(_text_at(element, *parts))


def _merge_value(target: dict[str, Any], key: str, value: Any) -> None:
    if key not in target:
        target[key] = value
        return
    existing = target[key]
    if isinstance(existing, list):
        existing.append(value)
    else:
        target[key] = [existing, value]


def _element_mapping(element: Any | None, depth: int = 0) -> Any:
    if element is None:
        return None
    if depth >= 4:
        return _bounded("".join(element.itertext()))
    children = _children(element)
    if not children:
        return _bounded(element.text)
    result: dict[str, Any] = {}
    text = _bounded(element.text)
    if text:
        result["text"] = text
    for child in children:
        _merge_value(
            result,
            _snake(_local_name(str(child.tag))),
            _element_mapping(child, depth + 1),
        )
    return result


def _task_name(task_path: str, root: Any) -> str:
    uri = _text_at(root, "RegistrationInfo", "URI")
    if uri:
        stripped = uri.strip("\\/")
        if stripped:
            return stripped.replace("\\", "/").split("/")[-1]
    return Path(task_path).name


def _extract_triggers(root: Any) -> list[dict[str, Any]]:
    triggers_parent = _find_path(root, "Triggers")
    triggers: list[dict[str, Any]] = []
    for trigger in _children(triggers_parent):
        item: dict[str, Any] = {"type": _local_name(str(trigger.tag))}
        enabled = _bool_at(trigger, "Enabled")
        if enabled is not None:
            item["enabled"] = enabled
        for child in _children(trigger):
            key = _snake(_local_name(str(child.tag)))
            if key == "enabled":
                continue
            _merge_value(item, key, _element_mapping(child))
        triggers.append(item)
    return triggers


def _extract_actions(root: Any) -> list[dict[str, Any]]:
    actions_parent = _find_path(root, "Actions")
    actions: list[dict[str, Any]] = []
    for action in _children(actions_parent):
        action_type = _local_name(str(action.tag))
        item: dict[str, Any] = {
            "type": action_type,
            "execute": None,
            "arguments": None,
            "working_directory": None,
        }
        if action_type == "Exec":
            item["execute"] = _text_at(action, "Command")
            item["arguments"] = _text_at(action, "Arguments")
            item["working_directory"] = _text_at(action, "WorkingDirectory")
        else:
            for child in _children(action):
                _merge_value(
                    item,
                    _snake(_local_name(str(child.tag))),
                    _element_mapping(child),
                )
        actions.append(item)
    return actions


def _settings_excerpt(root: Any) -> str | None:
    settings = _find_path(root, "Settings")
    if settings is None:
        return None
    text = DET.tostring(settings, encoding="unicode")
    return _bounded(text, SETTINGS_EXCERPT_CHARS)


def _read_task_bytes(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_XML_BYTES:
        raise ValueError(
            f"scheduled task XML exceeds {MAX_XML_BYTES} byte read cap"
        )
    return path.read_bytes()


def _file_modified(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(
            path.stat().st_mtime, timezone.utc,
        ).isoformat()
    except OSError:
        return None


def _relative_task_path(path: Path, tasks_dir: Path) -> str:
    try:
        return path.relative_to(tasks_dir).as_posix()
    except ValueError:
        return path.name


def _parse_task_file(path: Path, tasks_dir: Path) -> dict[str, Any]:
    raw = _read_task_bytes(path)
    root = DET.fromstring(raw)
    task_path = _relative_task_path(path, tasks_dir)
    principal = _find_path(root, "Principals", "Principal")

    return {
        "tool": TOOL_NAME,
        "source_path": str(path),
        "task_path": task_path,
        "task_name": _task_name(task_path, root),
        "author": _text_at(root, "RegistrationInfo", "Author"),
        "user_id": _text_at(principal, "UserId"),
        "description": _text_at(root, "RegistrationInfo", "Description"),
        "enabled": _bool_at(root, "Settings", "Enabled"),
        "hidden": _bool_at(root, "Settings", "Hidden"),
        "run_level": _text_at(principal, "RunLevel"),
        "logon_type": _text_at(principal, "LogonType"),
        "triggers": _extract_triggers(root),
        "actions": _extract_actions(root),
        "created": _text_at(root, "RegistrationInfo", "Date"),
        "modified": _file_modified(path),
        "settings_xml_excerpt": _settings_excerpt(root),
        "raw_excerpt": _bounded(
            raw.decode("utf-8", errors="replace"), RAW_EXCERPT_CHARS,
        ),
        "evidence_type": EVIDENCE_TYPE,
    }


def _error_for(path: Path, tasks_dir: Path, exc: Exception) -> dict[str, str]:
    return {
        "source_path": str(path),
        "task_path": _relative_task_path(path, tasks_dir),
        "error_type": type(exc).__name__,
        "error": _bounded(str(exc).replace("\n", " "), ERROR_CHARS) or "",
    }


def _envelope(
    status: str,
    records: list[dict[str, Any]],
    searched_paths: list[str],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "tool_name": TOOL_NAME,
        "status": status,
        "record_count": len(records),
        "records": records,
        "searched_paths": searched_paths,
        "errors": errors,
    }


def _tasks_dir(
    mount_path: str | None,
    tasks_root: str | None,
) -> Path:
    if tasks_root is not None:
        return Path(tasks_root)
    mount = mount_path if mount_path is not None else DISK_MOUNT_PATH
    from sift_sentinel.tools.common import resolve_path_ci as _ci  # SIFT_CI_PATH
    return _ci(mount, "Windows", "System32", "Tasks")


def _walk_depth(root: Path, current: Path) -> int:
    try:
        return len(current.relative_to(root).parts)
    except ValueError:
        return 0


def parse_scheduled_tasks_disk(
    mount_path: str | None = None,
    tasks_root: str | None = None,
    max_files: int | None = None,
    max_records: int | None = None,
    max_depth: int = 8,
) -> dict:
    """Parse Windows scheduled task XML files from a mounted disk.

    The parser is read-only and treats task XML as attacker-controlled
    evidence. It uses defusedxml, never resolves external entities, and
    never executes task actions.
    """
    root = _tasks_dir(mount_path, tasks_root)
    records: list[dict[str, Any]] = []
    searched_paths: list[str] = [str(root)]
    errors: list[dict[str, str]] = []

    if not root.is_dir():
        return _envelope("not_found", records, searched_paths, errors)

    if max_files is None:
        max_files = _env_int("SIFT_SCHEDULED_TASKS_MAX_FILES", 50000)
    if max_records is None:
        max_records = _env_int("SIFT_SCHEDULED_TASKS_MAX_RECORDS", 50000)
    max_files = max(0, int(max_files))
    max_records = max(0, int(max_records))
    max_depth = max(0, int(max_depth))
    if max_files == 0 or max_records == 0:
        return _envelope("capped", records, searched_paths, errors)

    files_seen = 0
    capped = False

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False,
    ):
        current_dir = Path(dirpath)
        if str(current_dir) not in searched_paths:
            searched_paths.append(str(current_dir))

        dirnames.sort(key=str.lower)
        filenames.sort(key=str.lower)
        if _walk_depth(root, current_dir) >= max_depth:
            dirnames[:] = []

        for filename in filenames:
            if files_seen >= max_files or len(records) >= max_records:
                capped = True
                break

            path = current_dir / filename
            if not path.is_file():
                continue
            files_seen += 1

            try:
                records.append(_parse_task_file(path, root))
            except (
                OSError,
                UnicodeError,
                ValueError,
                SyntaxError,
                DefusedXmlException,
            ) as exc:
                errors.append(_error_for(path, root, exc))

        if capped:
            break

    if capped or files_seen >= max_files or len(records) >= max_records:
        status = "capped"
    elif errors and not records:
        status = "parse_error"
    else:
        status = "ok"
    return _envelope(status, records, searched_paths, errors)
