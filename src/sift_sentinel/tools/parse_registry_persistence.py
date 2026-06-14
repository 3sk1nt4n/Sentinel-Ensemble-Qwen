"""Read-only parser for Windows registry persistence artifacts.

Runtime parsing uses the optional ``python-registry`` library when it is
available. The project does not add that dependency here; when it is
missing, the parser reports a structured ``parse_error`` for existing hive
files. Unit tests exercise the parser with synthetic pre-parsed hive/key/
value objects at the normalization layer, and the VM side probe verifies
real mounted-hive discovery and honest dependency handling.
"""

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


import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sift_sentinel.config import DISK_MOUNT_PATH


TOOL_NAME = "parse_registry_persistence"
EVIDENCE_TYPE = "registry_persistence"

VALUE_TEXT_CHARS = 4096
RAW_EXCERPT_CHARS = 1000
ERROR_CHARS = 300
BINARY_BYTES = 256
MAX_MULTI_SZ_ITEMS = 128

PERSISTENCE_TYPES = frozenset({
    "run_key",
    "service",
    "winlogon",
    "safeboot",
    "appinit",
    "ifeo",
    "lsa",
    "task_cache",
    "other",
})

_REG_TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

_RUN_KEY_PATHS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)

_WINLOGON_PATH = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
_APPINIT_PATH = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
_IFEO_PATH = (
    r"Software\Microsoft\Windows NT\CurrentVersion"
    r"\Image File Execution Options"
)
_TASKCACHE_PATH = (
    r"Software\Microsoft\Windows NT\CurrentVersion"
    r"\Schedule\TaskCache\Tasks"
)


class _RegistryUnavailable(RuntimeError):
    """Raised when python-registry is not importable."""


class _Collector:
    def __init__(self, max_records: int) -> None:
        self.max_records = max(0, int(max_records))
        self.records: list[dict[str, Any]] = []
        self.capped = self.max_records == 0

    def add(self, record: dict[str, Any]) -> bool:
        if len(self.records) >= self.max_records:
            self.capped = True
            return False
        self.records.append(record)
        return True


def _bounded_text(value: Any, limit: int = VALUE_TEXT_CHARS) -> tuple[str, bool]:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text, False
    return text[:limit] + "...[truncated]", True


def _bounded_json(data: dict[str, Any], limit: int = RAW_EXCERPT_CHARS) -> str:
    text = json.dumps(data, sort_keys=True, default=str)
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


def _error_for(path: Path, exc: BaseException) -> dict[str, str]:
    msg = str(exc)
    if len(msg) > ERROR_CHARS:
        msg = msg[:ERROR_CHARS] + "...[truncated]"
    return {
        "path": str(path),
        "error_type": exc.__class__.__name__,
        "error": msg,
    }


def _iso_utc(value: Any) -> str | None:
    if value is None or not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat()


def _hive_type(path: Path) -> str:
    name = path.name.upper()
    if name in {"SYSTEM", "SOFTWARE"}:
        return name
    if name == "NTUSER.DAT":
        return "NTUSER"
    if name == "USRCLASS.DAT":
        return "USRCLASS"
    return "UNKNOWN"


def _user_profile(path: Path, hive_type: str) -> str | None:
    if hive_type == "NTUSER":
        return path.parent.name
    if hive_type == "USRCLASS":
        parts = list(path.parts)
        lowered = [p.lower() for p in parts]
        if "users" in lowered:
            idx = lowered.index("users")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None


def _value_name(value: Any) -> str:
    name_attr = getattr(value, "name", None)
    name = name_attr() if callable(name_attr) else name_attr
    if name is None:
        return ""
    text = str(name)
    if text.lower() in {"(default)", "default"}:
        return ""
    return text


def _type_name(value: Any) -> str:
    type_attr = getattr(value, "value_type", None)
    raw_type = type_attr() if callable(type_attr) else type_attr
    if isinstance(raw_type, str):
        return raw_type.upper()
    if isinstance(raw_type, int):
        return _REG_TYPE_NAMES.get(raw_type, f"REG_TYPE_{raw_type}")
    return "UNKNOWN"


def _value_data(value: Any) -> Any:
    value_attr = getattr(value, "value", None)
    return value_attr() if callable(value_attr) else value_attr


def _raw_value_bytes(value: Any, data: Any) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    raw_attr = getattr(value, "raw_data", None)
    raw = raw_attr() if callable(raw_attr) else raw_attr
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, bytearray):
        return bytes(raw)
    if isinstance(raw, memoryview):
        return raw.tobytes()
    try:
        return bytes(data)
    except (TypeError, ValueError):
        return str(data).encode("utf-8", errors="replace")


def _normalize_data(value: Any) -> tuple[Any, str, bool]:
    value_type = _type_name(value)
    data = _value_data(value)

    if value_type == "REG_BINARY":
        raw = _raw_value_bytes(value, data)
        truncated = len(raw) > BINARY_BYTES
        return "0x" + raw[:BINARY_BYTES].hex(), value_type, truncated

    if value_type == "REG_MULTI_SZ":
        if data is None:
            return [], value_type, False
        if isinstance(data, (list, tuple)):
            items = [str(item) for item in data]
        else:
            items = [str(data)]
        truncated = len(items) > MAX_MULTI_SZ_ITEMS
        out: list[str] = []
        for item in items[:MAX_MULTI_SZ_ITEMS]:
            bounded, was_truncated = _bounded_text(item)
            truncated = truncated or was_truncated
            out.append(bounded)
        return out, value_type, truncated

    if isinstance(data, str):
        bounded, truncated = _bounded_text(data)
        return bounded, value_type, truncated
    if data is None:
        return None, value_type, False
    if isinstance(data, (int, float, bool)):
        return data, value_type, False
    bounded, truncated = _bounded_text(data)
    return bounded, value_type, truncated


def _key_name(key: Any) -> str:
    name_attr = getattr(key, "name", None)
    name = name_attr() if callable(name_attr) else name_attr
    return "" if name is None else str(name)


def _key_values(key: Any) -> list[Any]:
    values_attr = getattr(key, "values", None)
    values = values_attr() if callable(values_attr) else values_attr
    if values is None:
        return []
    return list(values)


def _subkeys(key: Any) -> list[Any]:
    subkeys_attr = getattr(key, "subkeys", None)
    subkeys = subkeys_attr() if callable(subkeys_attr) else subkeys_attr
    if subkeys is None:
        return []
    return list(subkeys)


def _key_timestamp(key: Any) -> str | None:
    ts_attr = getattr(key, "timestamp", None)
    ts = ts_attr() if callable(ts_attr) else ts_attr
    return _iso_utc(ts)


def _is_missing_key(exc: BaseException) -> bool:
    if isinstance(exc, KeyError):
        return True
    name = exc.__class__.__name__.lower()
    text = str(exc).lower()
    return "notfound" in name or "not_found" in name or "not found" in text


def _open_key(hive: Any, path: str) -> Any | None:
    try:
        return hive.open(path)
    except Exception as exc:  # noqa: BLE001 - library-specific missing-key types
        if _is_missing_key(exc):
            return None
        raise


def _find_value(key: Any, wanted_name: str) -> Any | None:
    wanted = wanted_name.lower()
    for value in _key_values(key):
        if _value_name(value).lower() == wanted:
            return value
    return None


def _make_record(
    *,
    source_hive: Path,
    hive_type: str,
    registry_path: str,
    value: Any,
    persistence_type: str,
    control_set: str | None = None,
    is_active_controlset: bool | None = None,
    user_profile: str | None = None,
    key: Any | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value_name = _value_name(value)
    value_data, value_type, truncated = _normalize_data(value)
    record: dict[str, Any] = {
        "tool": TOOL_NAME,
        "source_hive": str(source_hive),
        "hive_type": hive_type,
        "registry_path": registry_path,
        "value_name": value_name,
        "value_data": value_data,
        "value_type": value_type,
        "value_data_truncated": truncated,
        "is_default": value_name == "",
        "persistence_type": (
            persistence_type if persistence_type in PERSISTENCE_TYPES else "other"
        ),
        "control_set": control_set,
        "is_active_controlset": is_active_controlset,
        "user_profile": user_profile,
        "last_write_time": _key_timestamp(key),
        "evidence_type": EVIDENCE_TYPE,
    }
    if extra:
        record.update(extra)
    record["raw_excerpt"] = _bounded_json({
        "registry_path": registry_path,
        "value_name": value_name,
        "value_type": value_type,
        "value_data": value_data,
    })
    return record


def _software_hive_path(registry_path: str) -> str:
    prefix = "Software\\"
    if registry_path.lower().startswith(prefix.lower()):
        return registry_path[len(prefix):]
    return registry_path


def _logical_path(root_name: str, registry_path: str) -> str:
    return root_name + "\\" + registry_path


def _emit_values(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    open_path: str,
    logical_path: str,
    persistence_type: str,
    collector: _Collector,
    value_names: Iterable[str] | None = None,
    control_set: str | None = None,
    is_active_controlset: bool | None = None,
    user_profile: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    key = _open_key(hive, open_path)
    if key is None or collector.capped:
        return

    if value_names is None:
        values = _key_values(key)
    else:
        values = []
        for name in value_names:
            value = _find_value(key, name)
            if value is not None:
                values.append(value)

    for value in values:
        if not collector.add(_make_record(
            source_hive=source_hive,
            hive_type=hive_type,
            registry_path=logical_path,
            value=value,
            persistence_type=persistence_type,
            control_set=control_set,
            is_active_controlset=is_active_controlset,
            user_profile=user_profile,
            key=key,
            extra=extra,
        )):
            return


def _parse_run_keys(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    root_name: str,
    collector: _Collector,
    user_profile: str | None,
    software_hive: bool = False,
) -> None:
    for rel_path in _RUN_KEY_PATHS:
        _emit_values(
            hive=hive,
            source_hive=source_hive,
            hive_type=hive_type,
            open_path=(
                _software_hive_path(rel_path) if software_hive else rel_path
            ),
            logical_path=_logical_path(root_name, rel_path),
            persistence_type="run_key",
            collector=collector,
            user_profile=user_profile,
        )
        if collector.capped:
            return


def _parse_winlogon(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    root_name: str,
    collector: _Collector,
    user_profile: str | None,
    software_hive: bool = False,
) -> None:
    _emit_values(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        open_path=(
            _software_hive_path(_WINLOGON_PATH)
            if software_hive else _WINLOGON_PATH
        ),
        logical_path=_logical_path(root_name, _WINLOGON_PATH),
        persistence_type="winlogon",
        collector=collector,
        value_names=("Shell", "Userinit"),
        user_profile=user_profile,
    )


def _parse_appinit(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    collector: _Collector,
) -> None:
    _emit_values(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        open_path=_software_hive_path(_APPINIT_PATH),
        logical_path=_logical_path("HKLM", _APPINIT_PATH),
        persistence_type="appinit",
        collector=collector,
        value_names=(
            "AppInit_DLLs",
            "LoadAppInit_DLLs",
            "RequireSignedAppInit_DLLs",
        ),
    )


def _parse_ifeo(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    collector: _Collector,
) -> None:
    key = _open_key(hive, _software_hive_path(_IFEO_PATH))
    if key is None:
        return
    for image_key in _subkeys(key):
        if collector.capped:
            return
        debugger = _find_value(image_key, "Debugger")
        if debugger is None:
            continue
        image_name = _key_name(image_key)
        collector.add(_make_record(
            source_hive=source_hive,
            hive_type=hive_type,
            registry_path=_logical_path("HKLM", _IFEO_PATH) + "\\" + image_name,
            value=debugger,
            persistence_type="ifeo",
            key=image_key,
            extra={"image_name": image_name},
        ))


def _parse_task_cache(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    collector: _Collector,
) -> None:
    key = _open_key(hive, _software_hive_path(_TASKCACHE_PATH))
    if key is None:
        return
    for task_key in _subkeys(key):
        if collector.capped:
            return
        task_id = _key_name(task_key)
        for value in _key_values(task_key):
            if not collector.add(_make_record(
                source_hive=source_hive,
                hive_type=hive_type,
                registry_path=(
                    _logical_path("HKLM", _TASKCACHE_PATH) + "\\" + task_id
                ),
                value=value,
                persistence_type="task_cache",
                key=task_key,
                extra={"task_cache_id": task_id},
            )):
                return


def _read_select_current(hive: Any) -> int | None:
    key = _open_key(hive, "Select")
    if key is None:
        return None
    value = _find_value(key, "Current")
    if value is None:
        return None
    data = _value_data(value)
    try:
        return int(data)
    except (TypeError, ValueError):
        return None


def _control_sets(hive: Any) -> list[str]:
    root_attr = getattr(hive, "root", None)
    if not callable(root_attr):
        return []
    root = root_attr()
    names = []
    for subkey in _subkeys(root):
        name = _key_name(subkey)
        if (
            len(name) == len("ControlSet001")
            and name.startswith("ControlSet")
            and name[-3:].isdigit()
        ):
            names.append(name)
    return sorted(names)


def _active_flag(control_set: str, current: int | None) -> bool | None:
    if current is None:
        return None
    return control_set == f"ControlSet{current:03d}"


def _parse_services(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    control_set: str,
    is_active_controlset: bool | None,
    collector: _Collector,
) -> None:
    services_path = control_set + r"\Services"
    services_key = _open_key(hive, services_path)
    if services_key is None:
        return
    for service_key in _subkeys(services_key):
        if collector.capped:
            return
        service_name = _key_name(service_key)
        for value_name in ("ImagePath", "DisplayName", "Start", "Type"):
            value = _find_value(service_key, value_name)
            if value is None:
                continue
            if not collector.add(_make_record(
                source_hive=source_hive,
                hive_type=hive_type,
                registry_path=(
                    r"HKLM\SYSTEM" + "\\" + services_path + "\\" + service_name
                ),
                value=value,
                persistence_type="service",
                control_set=control_set,
                is_active_controlset=is_active_controlset,
                key=service_key,
                extra={"service_name": service_name},
            )):
                return


def _parse_safeboot(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    control_set: str,
    is_active_controlset: bool | None,
    collector: _Collector,
) -> None:
    base_path = control_set + r"\Control\SafeBoot"
    _emit_values(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        open_path=base_path,
        logical_path=r"HKLM\SYSTEM" + "\\" + base_path,
        persistence_type="safeboot",
        collector=collector,
        value_names=("AlternateShell",),
        control_set=control_set,
        is_active_controlset=is_active_controlset,
    )
    _emit_values(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        open_path=base_path + r"\AlternateShell",
        logical_path=r"HKLM\SYSTEM" + "\\" + base_path + r"\AlternateShell",
        persistence_type="safeboot",
        collector=collector,
        control_set=control_set,
        is_active_controlset=is_active_controlset,
    )


def _parse_lsa(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    control_set: str,
    is_active_controlset: bool | None,
    collector: _Collector,
) -> None:
    lsa_path = control_set + r"\Control\Lsa"
    _emit_values(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        open_path=lsa_path,
        logical_path=r"HKLM\SYSTEM" + "\\" + lsa_path,
        persistence_type="lsa",
        collector=collector,
        value_names=(
            "Authentication Packages",
            "Security Packages",
            "Notification Packages",
        ),
        control_set=control_set,
        is_active_controlset=is_active_controlset,
    )


def _parse_system_hive(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    collector: _Collector,
) -> None:
    current = _read_select_current(hive)
    for control_set in _control_sets(hive):
        active = _active_flag(control_set, current)
        _parse_services(
            hive=hive,
            source_hive=source_hive,
            hive_type=hive_type,
            control_set=control_set,
            is_active_controlset=active,
            collector=collector,
        )
        if collector.capped:
            return
        _parse_safeboot(
            hive=hive,
            source_hive=source_hive,
            hive_type=hive_type,
            control_set=control_set,
            is_active_controlset=active,
            collector=collector,
        )
        if collector.capped:
            return
        _parse_lsa(
            hive=hive,
            source_hive=source_hive,
            hive_type=hive_type,
            control_set=control_set,
            is_active_controlset=active,
            collector=collector,
        )
        if collector.capped:
            return


def _parse_software_hive(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    collector: _Collector,
) -> None:
    _parse_run_keys(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        root_name="HKLM",
        collector=collector,
        user_profile=None,
        software_hive=True,
    )
    if collector.capped:
        return
    _parse_winlogon(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        root_name="HKLM",
        collector=collector,
        user_profile=None,
        software_hive=True,
    )
    if collector.capped:
        return
    _parse_appinit(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        collector=collector,
    )
    if collector.capped:
        return
    _parse_ifeo(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        collector=collector,
    )
    if collector.capped:
        return
    _parse_task_cache(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        collector=collector,
    )


def _parse_user_hive(
    *,
    hive: Any,
    source_hive: Path,
    hive_type: str,
    collector: _Collector,
) -> None:
    profile = _user_profile(source_hive, hive_type)
    _parse_run_keys(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        root_name="HKCU",
        collector=collector,
        user_profile=profile,
    )
    if collector.capped:
        return
    _parse_winlogon(
        hive=hive,
        source_hive=source_hive,
        hive_type=hive_type,
        root_name="HKCU",
        collector=collector,
        user_profile=profile,
    )


def _parse_hive(path: Path, hive: Any, collector: _Collector) -> None:
    hive_type = _hive_type(path)
    if hive_type == "SYSTEM":
        _parse_system_hive(
            hive=hive,
            source_hive=path,
            hive_type=hive_type,
            collector=collector,
        )
    elif hive_type == "SOFTWARE":
        _parse_software_hive(
            hive=hive,
            source_hive=path,
            hive_type=hive_type,
            collector=collector,
        )
    elif hive_type in {"NTUSER", "USRCLASS"}:
        _parse_user_hive(
            hive=hive,
            source_hive=path,
            hive_type=hive_type,
            collector=collector,
        )


def _open_registry_hive(path: Path) -> Any:
    try:
        from Registry import Registry  # type: ignore[import-not-found]
    except ImportError as exc:
        raise _RegistryUnavailable(
            "python-registry library unavailable"
        ) from exc
    return Registry.Registry(str(path))


def _default_hive_candidates(mount_path: str | None) -> list[Path]:
    mount = Path(mount_path if mount_path is not None else DISK_MOUNT_PATH)
    candidates = [
        mount / "Windows" / "System32" / "config" / "SYSTEM",
        mount / "Windows" / "System32" / "config" / "SOFTWARE",
    ]
    users = mount / "Users"
    if users.is_dir():
        candidates.extend(sorted(
            users.glob("*/NTUSER.DAT"),
            key=lambda p: str(p).lower(),
        ))
        candidates.extend(sorted(
            users.glob("*/AppData/Local/Microsoft/Windows/UsrClass.dat"),
            key=lambda p: str(p).lower(),
        ))
    return candidates


def _hive_candidates(
    mount_path: str | None,
    hive_paths: list[str] | None,
) -> list[Path]:
    if hive_paths is not None:
        return [Path(p) for p in hive_paths]
    return _default_hive_candidates(mount_path)


def _envelope(
    status: str,
    collector: _Collector,
    searched_paths: list[str],
    errors: list[dict[str, str]],
) -> dict:
    return {
        "tool": TOOL_NAME,
        "tool_name": TOOL_NAME,
        "status": status,
        "record_count": len(collector.records),
        "records": collector.records,
        "searched_paths": searched_paths,
        "errors": errors,
    }


def parse_registry_persistence(
    mount_path: str | None = None,
    hive_paths: list[str] | None = None,
    max_hives: int = 50,
    max_records: int | None = None,
) -> dict:
    """Parse Windows registry autorun and persistence evidence.

    The parser reads mounted hive files only. It does not access a live
    registry, execute commands, expand environment variables, classify
    maliciousness, or write to the evidence mount.
    """
    if max_records is None:
        max_records = _env_int("SIFT_REGISTRY_PERSISTENCE_MAX", 50000)
    collector = _Collector(max_records)
    errors: list[dict[str, str]] = []
    candidates = _hive_candidates(mount_path, hive_paths)
    searched_paths = [str(p) for p in candidates]

    max_hives = max(0, int(max_hives))
    if collector.capped or max_hives == 0:
        return _envelope("capped", collector, searched_paths, errors)

    existing = [p for p in candidates if p.is_file()]
    if not existing:
        return _envelope("not_found", collector, searched_paths, errors)

    hive_capped = len(existing) > max_hives
    for path in existing[:max_hives]:
        if collector.capped:
            break
        try:
            hive = _open_registry_hive(path)
            _parse_hive(path, hive, collector)
        except Exception as exc:  # noqa: BLE001 - keep parsing other hives
            errors.append(_error_for(path, exc))

    if hive_capped or collector.capped:
        status = "capped"
    elif collector.records:
        status = "ok"
    elif errors:
        status = "parse_error"
    else:
        status = "ok"
    return _envelope(status, collector, searched_paths, errors)
