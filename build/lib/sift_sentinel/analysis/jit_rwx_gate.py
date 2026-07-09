"""JIT/UWP benign-RWX downgrade gate (env-gated SIFT_JIT_RWX) -- pre-routing.

malfind flags PAGE_EXECUTE_READWRITE memory; managed/JIT runtimes (.NET CLR,
Chakra/JScript, UWP packaged apps) legitimately allocate RWX to JIT-compile code,
so a clean JIT host produces an "injection" false positive (a prior live run
showed ~6 such FPs on SearchApp/LockApp/RuntimeBroker/Smartscreen/DllHost). This
gate downgrades those -- and ONLY those -- by delegating to the verified universal
``classify_benign_jit_rwx`` (three structural rails, no process/AV name list):

  Rail 1  no real payload in any RWX region (no mz_pe / shellcode characterization)
  Rail 2  managed/JIT host (loads a JIT-runtime DLL, or a UWP path-shape)
  Rail 3  no other injection corroborator (unlinked DLL / external egress / bad ancestry)

DOWNGRADE-ONLY: a finding it flags routes to benign, never deleted. Rail 1 makes it
safe on a real-injection box (rd01): a genuine reflective/PE/shellcode injection is
``injection_corroborated`` -> Rail 1 blocks -> never downgraded, regardless of host.

Universal / dataset-agnostic: every input is read STRUCTURALLY from the typed
evidence DB by pid (injection characterization, loaded-DLL names, image path,
external-egress connections); no tool/case/AV-name literal. NO signed-AV name list
(that would be an answer key) -- a signed AV product's no-payload RWX stays
INCONCLUSIVE, the honest universal disposition.
"""
from __future__ import annotations

import os
import re

from sift_sentinel.analysis.injection_fp_filter import classify_benign_jit_rwx

_PID = re.compile(r"\bpid[:=]?\s*(\d{1,7})\b", re.I)
_RFC1918 = re.compile(r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)")


def _tdb(evidence_db):
    if hasattr(evidence_db, "facts_by_index"):
        return evidence_db
    from sift_sentinel.validation.typed_validator import TypedEvidenceDB
    return TypedEvidenceDB(evidence_db if isinstance(evidence_db, dict) else {})


def _pid_of(finding: dict):
    for c in finding.get("claims") or []:
        if isinstance(c, dict) and c.get("pid") not in (None, ""):
            return str(c.get("pid")).strip()
    blob = " ".join(str(finding.get(k) or "") for k in ("title", "description", "raw_excerpt"))
    m = _PID.search(blob)
    return m.group(1) if m else None


def _by_pid(tdb, pid, ft):
    return tdb.facts_by_index("by_pid", str(pid), ft) if pid is not None else []


def _best_process_path(procs) -> str:
    """The richest process path across ALL process_fact entries + path fields.

    Volatility emits the truncated ImageFileName ('SearchApp.exe') on one fact
    and the full image path ('c:/windows/systemapps/.../searchapp.exe') on
    another. Rail 2's UWP/JIT detection needs the FULL path, so prefer the
    longest value that carries a directory separator; fall back to any value."""
    best = ""
    fallback = ""
    for p in procs or []:
        if not isinstance(p, dict):
            continue
        fields = p.get("fields") if isinstance(p.get("fields"), dict) else {}
        for k in ("path", "process_path", "image_path", "image_name", "process"):
            v = str(p.get(k) or fields.get(k) or "").strip()
            if not v:
                continue
            if "/" in v.replace("\\", "/") and len(v) > len(best):
                best = v
            elif len(v) > len(fallback):
                fallback = v
    return best or fallback


def jit_rwx_downgrade(finding: dict, evidence_db) -> tuple[bool, str]:
    """(downgrade, reason) for one finding. True only when all three universal
    rails hold; False (with the first failing rail's reason) otherwise."""
    if not isinstance(finding, dict):
        return False, "not_a_dict"
    tdb = _tdb(evidence_db)
    pid = _pid_of(finding)
    if pid is None:
        return False, "no_pid"
    inj = _by_pid(tdb, pid, "memory_injection_fact")
    if not inj:
        return False, "no_injection_facts"

    dlls = []
    for f in _by_pid(tdb, pid, "dll_load_fact"):
        dlls.append(str(f.get("dll_name") or f.get("dll_path") or ""))
    ppath = _best_process_path(_by_pid(tdb, pid, "process_fact"))

    has_egress = False
    for f in _by_pid(tdb, pid, "network_connection_fact"):
        ip = str(f.get("remote_ip") or f.get("foreign_addr") or f.get("ip") or "").strip()
        if ip and not _RFC1918.match(ip) and not ip.startswith(("127.", "0.", "::1")):
            has_egress = True
            break
    has_unlinked = bool(_by_pid(tdb, pid, "ldrmodules_unlinked_fact"))
    _dr = " ".join(str(x) for x in (finding.get("disposition_reasons") or [])).lower()
    has_ancestry = bool(finding.get("react_entity_conflict")) or "ancestry_violation" in _dr

    # Electron/V8 host recognition is broader than the UWP rail and can suppress
    # a real injection into an Electron app, so it is gated (SIFT_JIT_RWX_V2,
    # default OFF) -- validate on a known-compromised image before enabling.
    _electron = os.environ.get("SIFT_JIT_RWX_V2", "0").strip().lower() not in (
        "0", "false", "no", "off", "")
    return classify_benign_jit_rwx(
        inj, dll_names=dlls, process_path=ppath,
        has_unlinked_dll=has_unlinked, has_external_egress=has_egress,
        has_ancestry_violation=has_ancestry, electron=_electron)


def apply_jit_rwx_downgrade(findings, evidence_db) -> int:
    """In-place: flag benign-JIT-RWX findings with ``_jit_rwx_downgrade`` (honored
    by derive_final_disposition). Returns the count flagged."""
    n = 0
    for f in findings or []:
        if not isinstance(f, dict) or f.get("_jit_rwx_downgrade"):
            continue
        down, reason = jit_rwx_downgrade(f, evidence_db)
        if down:
            f["_jit_rwx_downgrade"] = True
            f["_jit_rwx_reason"] = reason
            n += 1
    return n


__all__ = ["jit_rwx_downgrade", "apply_jit_rwx_downgrade"]
