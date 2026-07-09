"""Baseline-artifact precision gate (lever 3 / C2 + C1).

On a low-signal box the pipeline over-confirmed baseline Windows artifacts: system
binaries (cmd.exe, rundll32.exe, powershell.exe ...) that merely *appear* in
AppCompatCache/Amcache/MFT reached the `confirmed_malicious_atomic` bucket. But
ShimCache presence is not execution, and system LOLBINs are present on every
Windows host -- confirming them is a false positive that costs C2 hard.

The discriminator is universal and structural, NOT a binary name list:

  * the finding's evidence is only execution-HISTORY / existence tools
    (AppCompatCache / Amcache / ShimCache / MFT-timeline / Prefetch / registry),
    i.e. nothing behavioral (malfind, netscan, handles, ldrmodules, injection), AND
  * its path(s) sit under \\System32\\ or \\SysWOW64\\ (the OS baseline dirs), AND
  * there is no corroborating signal (injection, network IOC, anti-forensics,
    temp/staging execution, suspicious arguments).

Such a finding is DEMOTED confirmed -> needs-review (never deleted). The same tool
staged in a Temp/Perfmon directory has a non-system path, so it is NOT demoted --
that is the line between baseline noise and a real staged tool.
"""
from __future__ import annotations

import re

CONFIRMED = "confirmed_malicious_atomic"
NEEDS_REVIEW = "suspicious_needs_review"

# Execution-history / existence artifacts -- presence here is not behavior.
_HISTORY_TOOL_RE = re.compile(
    r"appcompatcache|shimcache|amcache|mft|timeline|prefetch|registry", re.IGNORECASE)
# Behavioral evidence -- if any of these produced the finding it is NOT mere baseline.
_BEHAVIORAL_TOOL_RE = re.compile(
    r"malfind|netscan|netstat|handles|ldrmodules|dlllist|vadyarascan|vadregexscan|"
    r"malware|injection|yarascan|svcscan|cmdline", re.IGNORECASE)
# OS baseline directories (retained for context; no longer a demotion REQUIREMENT).
_SYSTEM_DIR_RE = re.compile(r"(?:^|[\\/])(?:system32|syswow64)[\\/]", re.IGNORECASE)
# Malicious corroboration that justifies KEEPING a history-only confirm. NOTE:
# temp/staging is the WEAK signal (installers stage to temp constantly), so it is
# deliberately NOT here -- a bare execution-from-temp must not count as its own
# corroboration. Real tools self-identify (credential/anti-forensics/injection/C2/
# persistence/reflection), and those survive.
_CORROBORATION_RE = re.compile(
    r"inject|shellcode|rwx|page_execute|\bc2\b|beacon|egress|exfil|anti.?forensic|"
    r"\bwipe\b|sdelete|credential|mimikatz|lsass|encoded|reflection|persistence|"
    r"\bhollow|known.?malware|yara", re.IGNORECASE)


def is_baseline_history_only_confirm(f) -> bool:
    """True iff this confirmed finding is known ONLY from execution history
    (ShimCache/Amcache/MFT) with no behavioral corroboration -- i.e. not confirm-grade.

    ShimCache/Amcache 'Executed' is not reliable execution and mere presence is not
    malice, so this holds REGARDLESS of path: a System32 baseline binary (cmd.exe,
    rundll32.exe) AND an installer staged in Temp (isbew64.exe, setup.exe, vcredist)
    are equally non-confirmable from execution history alone. A finding survives only
    if an independent malicious signal corroborates it -- read from STRUCTURAL fields
    (disposition_reasons + detected malicious_semantic_signals + claim types), NEVER the
    AI free-text description. That distinction matters: an LLM routinely writes "rundll32
    is commonly used for lateral movement and persistence" as boilerplate, which must NOT
    count as evidence. A real anti-forensics burst, registry-persistence signal, or
    injection signal is structural and DOES corroborate; a bare ShimCache LOLBin/installer
    with only an admin_or_lolbin / temp-execution signal does not."""
    if not isinstance(f, dict):
        return False
    tools = [str(t) for t in (f.get("source_tools") or []) if t]
    if not tools:
        return False
    # every contributing tool must be a history/existence tool, none behavioral
    if any(_BEHAVIORAL_TOOL_RE.search(t) for t in tools):
        return False
    if not all(_HISTORY_TOOL_RE.search(t) for t in tools):
        return False
    # corroboration from STRUCTURAL fields ONLY -- never the AI description/title, whose
    # generic "commonly abused for persistence/lateral movement" prose would false-positive.
    # NOTE: the inv3a/ReAct verdict reason text IS read here on purpose -- it carries real
    # malice signals like "credential dumping" / "injection" that legitimately corroborate
    # a staged attacker tool (credential-dump/remote-exec style). An earlier attempt to exclude it demoted
    # those genuine confirms to 0 on a full-APT box; the cost of also keeping the odd
    # generic-LOLBIN aggregate (a single borderline MEDIUM) is far smaller. See revert.
    blob = " ".join(
        [str(x) for x in (f.get("disposition_reasons") or [])]
        + [str(x) for x in (f.get("malicious_semantic_signals") or [])]
        + [str(c.get("type") or "") for c in (f.get("claims") or []) if isinstance(c, dict)]
    )
    if _CORROBORATION_RE.search(blob):
        return False
    if f.get("injection_corroborated") or f.get("_jit_rwx_downgrade"):
        return False
    return True


def demote_baseline_confirms(buckets):
    """Demote baseline system-binary confirms to needs-review. Returns
    ``(new_buckets, ledger)``; no-op shallow-copy when nothing qualifies."""
    if not isinstance(buckets, dict):
        return buckets, []
    confirmed = [f for f in (buckets.get(CONFIRMED) or []) if isinstance(f, dict)]
    demote = [f for f in confirmed if is_baseline_history_only_confirm(f)]
    if not demote:
        return {k: list(v) if isinstance(v, list) else v for k, v in buckets.items()}, []
    demote_ids = {id(f) for f in demote}
    new_buckets = {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}
    new_buckets[CONFIRMED] = [f for f in confirmed if id(f) not in demote_ids]
    ledger = []
    moved = []
    for f in demote:
        f = dict(f)
        f["_baseline_demoted_from"] = CONFIRMED
        rs = list(f.get("disposition_reasons") or [])
        rs.append("baseline_gate:system_binary_history_only[confirmed->needs_review]")
        f["disposition_reasons"] = rs
        moved.append(f)
        ledger.append({"finding_id": str(f.get("finding_id") or f.get("id") or "-"),
                       "from": CONFIRMED, "to": NEEDS_REVIEW,
                       "reason": "system-binary known only from execution history; not behavior"})
    new_buckets[NEEDS_REVIEW] = list(new_buckets.get(NEEDS_REVIEW) or []) + moved
    return new_buckets, ledger
