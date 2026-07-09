"""Deterministic JIT/.NET RWX false-positive discriminator (DOWNGRADE-ONLY).

malfind flags PAGE_EXECUTE_READWRITE memory; managed/JIT runtimes (.NET CLR,
Chakra/JScript9, Electron V8) legitimately allocate RWX to JIT-compile code, so a
clean JIT host produces an "injection" false positive. This module decides, purely
from technique + structure, whether such a finding should be DOWNGRADED to
benign-JIT -- never deleted, so a real compromise loses confidence but always
stays in the report.

Three rails (all must hold to suppress), per the agreed design:
  1. NO real payload in any RWX region. We key on the malfind compiler's own
     characterization (evidence_db: injection_corroborated = private && char in
     {mz_pe, shellcode}). If ANY region carries a PE header or shellcode
     signature we never suppress. This inspects RWX CONTENT, so it closes the
     module-less-shellcode blind spot a module-list (ldrmodules) check would miss.
  2. The process is a managed/JIT host: it loads a JIT runtime DLL, OR runs from
     a UWP package path-shape.
  3. No OTHER injection corroborator: no unlinked DLL (ldrmodules), no external
     egress tied to the PID, no process-ancestry violation.

Universal / dataset-agnostic: a runtime-DLL vocabulary + UWP path-shape +
structural payload characterization. No process-name allowlist, no case path.
"""
from __future__ import annotations

import re

# JIT / managed runtimes that allocate RWX as normal behaviour. Universal DLL
# names defined by Microsoft, not a case list.
_JIT_RUNTIME_DLLS = (
    "clr.dll", "coreclr.dll", "clrjit.dll", "mscoree.dll", "mscorlib",
    "jscript9.dll", "chakra.dll", "chakracore.dll", "mrt100",
)

# UWP / packaged-app path shape (WindowsApps / SystemApps / Microsoft.<pkg>_...).
_UWP_PATH_RE = re.compile(r"(windowsapps|systemapps|/microsoft\.[^/]+_)", re.IGNORECASE)

# Electron / Squirrel host shape: an app installed under a user profile that runs
# from a versioned '.../current/<app>.exe' (Teams/Slack/Discord/VS Code-style),
# or that ships node/electron next to the exe. Electron embeds a V8 JIT, so it
# allocates RWX like a managed runtime. A structural SHAPE, not an app-name list;
# gated (SIFT_JIT_RWX_V2) because it is broader than the UWP rail.
_ELECTRON_PATH_RE = re.compile(
    r"/appdata/(?:local|roaming)/[^/]+/[^/]+/current/[^/]+\.exe$"
    r"|/(?:electron|squirrel)[^/]*\.exe$",
    re.IGNORECASE,
)

# RWX content that PROVES a real payload -- never suppress when present.
_PAYLOAD_CHARS = frozenset({"mz_pe", "pe", "shellcode"})


def _basename(name: str) -> str:
    return str(name or "").lower().replace("\\", "/").rsplit("/", 1)[-1]


def is_managed_jit_host(dll_names=(), process_path: str = "", *,
                        electron: bool = False) -> bool:
    """True iff the process loads a JIT runtime DLL or runs from a UWP path
    (always), or matches the Electron/Squirrel host shape (only when
    ``electron`` is enabled -- a broader, gated rail)."""
    names = {_basename(d) for d in (dll_names or [])}
    if any(any(j in n for j in _JIT_RUNTIME_DLLS) for n in names):
        return True
    path = str(process_path or "").replace("\\", "/")
    if _UWP_PATH_RE.search(path):
        return True
    return bool(electron and _ELECTRON_PATH_RE.search(path))


def classify_benign_jit_rwx(
    injection_facts,
    dll_names=(),
    process_path: str = "",
    has_unlinked_dll: bool = False,
    has_external_egress: bool = False,
    has_ancestry_violation: bool = False,
    *,
    electron: bool = False,
) -> tuple[bool, str]:
    """Return ``(suppress, reason)`` for a malfind-RWX finding.

    ``suppress=True`` means the caller should DOWNGRADE the finding to benign-JIT
    (lower tier / needs-review-eligible) -- never delete it. Suppress only when
    all three rails hold; otherwise return the first failing rail's reason.
    """
    facts = [f for f in (injection_facts or []) if isinstance(f, dict)]
    if not facts:
        return False, "no_injection_facts"

    # Rail 1: no real payload signature in any RWX region.
    if any(f.get("injection_corroborated") for f in facts):
        return False, "payload_corroborated"
    if any(str(f.get("characterization", "")).strip().lower() in _PAYLOAD_CHARS
           for f in facts):
        return False, "payload_signature_present"

    # Rail 2: managed / JIT host.
    if not is_managed_jit_host(dll_names, process_path, electron=electron):
        return False, "not_a_managed_jit_host"

    # Rail 3: no other injection corroborator.
    if has_unlinked_dll:
        return False, "unlinked_dll_present"
    if has_external_egress:
        return False, "external_egress_present"
    if has_ancestry_violation:
        return False, "ancestry_violation_present"

    return True, "benign_jit_rwx"
