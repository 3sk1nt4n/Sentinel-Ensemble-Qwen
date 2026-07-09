from __future__ import annotations

import os
import subprocess
from typing import Any

# SIFT_SSDT_RUNTIME_GUARD_V2
#
# Universal policy:
# - windows.ssdt.SSDT is useful when it completes.
# - windows.ssdt.SSDT is not allowed to stall the whole investigation.
# - timeout / page fault / nonzero exit is health=unknown, not clean, not malicious.
# - this guard is command-shape based, not dataset-specific.

_ORIGINAL_RUN = subprocess.run


def _as_text_cmd(cmd: Any) -> str:
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(x) for x in cmd)
    return str(cmd)


def _is_ssdt_command(cmd: Any) -> bool:
    text = _as_text_cmd(cmd).lower()
    return "windows.ssdt.ssdt" in text or "vol_ssdt" in text


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _timeout_seconds() -> float:
    raw = os.environ.get("SIFT_SSDT_TIMEOUT_S", "45")
    try:
        val = float(raw)
    except Exception:
        val = 45.0
    if val < 5:
        val = 5.0
    if val > 300:
        val = 300.0
    return val


def guarded_subprocess_run(*popenargs: Any, **kwargs: Any) -> subprocess.CompletedProcess:
    cmd = kwargs.get("args", popenargs[0] if popenargs else None)

    if not _is_ssdt_command(cmd):
        return _ORIGINAL_RUN(*popenargs, **kwargs)

    timeout_s = _timeout_seconds()
    existing_timeout = kwargs.get("timeout")
    if existing_timeout is None:
        kwargs["timeout"] = timeout_s
    else:
        try:
            kwargs["timeout"] = min(float(existing_timeout), timeout_s)
        except Exception:
            kwargs["timeout"] = timeout_s

    try:
        return _ORIGINAL_RUN(*popenargs, **kwargs)
    except subprocess.TimeoutExpired as exc:
        stdout = _to_text(getattr(exc, "stdout", ""))
        stderr = _to_text(getattr(exc, "stderr", ""))
        stderr = (
            stderr
            + "\nSIFT_SSDT_RUNTIME_GUARD timeout "
            + f"timeout_s={timeout_s} health_status=unknown can_support_finding=false"
        )
        return subprocess.CompletedProcess(
            args=getattr(exc, "cmd", cmd),
            returncode=124,
            stdout=stdout,
            stderr=stderr,
        )


def install() -> bool:
    current = subprocess.run
    if getattr(current, "_sift_ssdt_runtime_guard_v2", False):
        return False

    guarded_subprocess_run._sift_ssdt_runtime_guard_v2 = True  # type: ignore[attr-defined]
    subprocess.run = guarded_subprocess_run
    return True
