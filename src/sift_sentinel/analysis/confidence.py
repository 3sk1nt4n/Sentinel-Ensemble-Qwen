"""
SIFT Sentinel -- Confidence calibration (Pipeline Step 13).
Deterministic Python. Evidence-based, not feeling-based.

Rules (deterministic, model-agnostic confidence calibration; see ARCHITECTURE.md):
  3+ independent artifact types -> HIGH allowed
  1-2 artifact types -> MEDIUM max
  0 artifact types -> SPECULATIVE
  SSDT degraded/untrusted -> memory-based ceiling capped at MEDIUM
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

# Cross-domain source classification for memory+disk upgrade rule
MEMORY_TOOLS: set[str] = {
    "vol_pstree", "vol_netscan", "vol_malfind", "vol_cmdline",
    "vol_dlllist", "vol_psscan", "vol_handles", "vol_envars",
    "vol_svcscan",
}
DISK_TOOLS: set[str] = {
    "get_amcache", "extract_mft_timeline", "parse_event_logs",
    "parse_prefetch", "parse_shellbags", "parse_powershell_transcripts",
    "parse_rdp_artifacts", "parse_wmi_subscription",
}

# Artifact types (ARCHITECTURE.md confidence calibration):
#   M = Memory (Volatility plugins except netscan)
#   N = Network (netscan -- part of memory but independent data class)
#   A = AmCache / Prefetch / ShimCache (execution artifacts)
#   T = MFT (timestamp/metadata)
#   E = Event Log (Sysmon, Security, PowerShell)
#   R = Registry
#   D = Disk (filesystem, browser, LNK, jump lists)
TOOL_TO_ARTIFACT_TYPE: dict[str, str] = {
    "vol_pstree": "M",
    "vol_malfind": "M",
    "vol_cmdline": "M",
    "vol_dlllist": "M",
    "vol_handles": "M",
    "vol_psscan": "M",
    "vol_ssdt": "M",
    "vol_netscan": "N",
    "get_amcache": "A",
    "extract_mft_timeline": "T",
    "parse_event_logs": "E",
    "parse_powershell_transcripts": "E",
    "parse_rdp_artifacts": "E",
    "parse_wmi_subscription": "E",
    "parse_registry": "R",
    "extract_srum": "D",
    "run_srumecmd": "D",  # 31K-SRUM-SURFACE-RESOLVER-A3
    "parse_sysmon": "E",
    "parse_browser": "D",
    "parse_jump_lists": "D",
    "parse_lnk": "D",
    "hash_lookup": "D",
    "extract_prefetch": "A",
    "extract_shimcache": "A",
    # Map completion: every EvidenceDB compiler tool whose artifact domain is
    # unambiguous. An unmapped tool is silently discarded by
    # count_artifact_types, so its corroboration never counts toward the
    # 3-type HIGH ceiling -- e.g. 'parse_registry_persistence' (the registered
    # tool name; 'parse_registry' above is a legacy alias) was invisible.
    # Letters classify the ARTIFACT, not the acquisition channel (precedent:
    # vol_netscan = N). Deliberately UNMAPPED multi-domain/derived tools
    # (run_yara, run_bulk_extractor, decode_base64_strings,
    # extract_network_iocs): they re-read other domains' content, so counting
    # them would double-count their input domain.
    "parse_registry_persistence": "R",
    "vol_filescan": "M",
    "run_strings": "M",
    "vol_ldrmodules": "M",
    "vol_psxview": "M",
    "vol_envars": "M",
    "vol_getsids": "M",
    "vol_privileges": "M",
    "vol_sessions": "M",
    "vol_svcscan": "M",
    "run_memprocfs": "M",
    "vol_reg_hivelist": "R",
    "vol_userassist": "R",
    "parse_userassist": "R",
    "parse_usb_devices": "R",
    "vol_amcache": "A",
    "parse_prefetch": "A",
    "run_appcompatcacheparser": "A",
    "run_mftecmd": "T",
    "sleuthkit_fls": "T",
    "sleuthkit_mactime": "T",
    "sleuthkit_tsk_recover": "T",
    "parse_scheduled_tasks_disk": "D",
    "run_jlecmd": "D",
    "run_lecmd": "D",
}

_RANK = {
    "UNRESOLVED": 0,
    "SPECULATIVE": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
}


def count_artifact_types(source_tools: list[str]) -> int:
    """Count distinct artifact types covered by source_tools."""
    types = {TOOL_TO_ARTIFACT_TYPE.get(t) for t in source_tools}
    types.discard(None)
    return len(types)


# Independent memory-evidence LENSES. The artifact-type map above collapses every
# Volatility process plugin to one type "M", so a memory-ONLY run (no disk to cross-
# corroborate) caps even a textbook injection at MEDIUM. But several memory plugins are
# INDEPENDENT forensic methods that, when they agree, are strong corroboration (an RWX
# region + an unbacked module + a thread starting in the injected region). Grouped so
# genuinely-independent methods are distinct lenses while CORRELATED views of the same
# structure share one (malfind/vadinfo/vadyarascan all examine the VAD region -> one
# 'vad' lens; ldrmodules/dlllist are both module-integrity -> one 'mod'). Used ONLY for
# a single-artifact memory run; paired runs are untouched. Universal: keyed on forensic
# method, no case data.
MEMORY_LENS: dict[str, str] = {
    "vol_malfind": "vad", "vol_vadinfo": "vad", "vol_vadyarascan": "vad", "vol_vadwalk": "vad",
    "vol_ldrmodules": "mod", "vol_dlllist": "mod",
    "vol_suspiciousthreads": "thread", "vol_threads": "thread",
    "vol_handles": "handle",
    "vol_pstree": "proc", "vol_psscan": "proc", "vol_psxview": "proc", "vol_pslist": "proc",
    "vol_privileges": "priv", "vol_getsids": "priv",
    "vol_svcscan": "svc",
    "vol_ssdt": "kernel",
    "vol_netscan": "net",
    "vol_cmdline": "cmd", "vol_envars": "cmd",
}


def count_memory_lenses(source_tools: list[str]) -> int:
    """Distinct INDEPENDENT memory forensic methods among ``source_tools`` (correlated
    views of the same structure share a lens, so they cannot fake independence)."""
    lenses = {MEMORY_LENS.get(t) for t in source_tools}
    lenses.discard(None)
    return len(lenses)


def _extract_claim_tools(finding: dict) -> list[str]:
    """Return deduped tool names from ``finding['claims'][i]``.

    Inv2 emits per-claim provenance in two shapes depending on the model:
      - ``{"source_tool": "vol_cmdline"}`` (singular, common from Claude/GPT)
      - ``{"source_tools": ["vol_cmdline", "vol_pstree"]}`` (plural, Gemini)
    Both are accepted. Investigation claims (Step 11b) follow the plural
    shape and are also included so cross-domain corroboration carries
    through to the confidence ceiling.

    Prior to CC#15 these fields were ignored, so every finding had
    ``claim_tools=[]`` and no finding could reach HIGH via the 3+ unique
    tools + memory+disk rule.
    """
    out: list[str] = []
    for c in (finding.get("claims") or []):
        if not isinstance(c, dict):
            continue
        single = c.get("source_tool")
        if isinstance(single, str) and single:
            out.append(single)
        for t in (c.get("source_tools") or []):
            if isinstance(t, str) and t:
                out.append(t)
    for c in (finding.get("investigation_claims") or []):
        if not isinstance(c, dict):
            continue
        for t in (c.get("source_tools") or []):
            if isinstance(t, str) and t:
                out.append(t)
    # dedupe preserving order
    seen: set[str] = set()
    return [t for t in out if not (t in seen or seen.add(t))]


def _is_false_positive(finding: dict) -> bool:
    """True when current-run evidence marks the finding false positive.

    Only explicit current-run signals may force LOW:
      - ``is_false_positive`` set directly by the finding pipeline
      - ``react_conclusion.is_false_positive`` set by Step 11 ReAct

    Optional local process context (``known_good``) is display/context
    only and does not lower confidence by itself.
    """
    if finding.get("is_false_positive"):
        return True
    react = finding.get("react_conclusion") or {}
    return bool(react.get("is_false_positive"))


def calibrate_confidence(
    finding: dict,
    ssdt_trust: str = "full",
    tool_records: dict[str, int] | None = None,
    run_domain: str | None = None,
) -> str:
    """Calibrate a finding's confidence based on artifact types and SSDT trust.

    Returns the calibrated ConfidenceLevel string.
    AI-stated confidence cannot exceed the ceiling from artifact type count.

    Confidence rules (CC#15 update):
      HIGH    cross-domain corroboration (memory + disk in the combined
              set of source_tools + claim_tools), OR 3+ artifact types.
      MEDIUM  1-2 artifact types, single domain.
      LOW     false-positive marker from current-run FP/ReAct evidence.

    B5 FIX: when tool_records is provided, source_tools is filtered to
    tools that returned records > 0. Tools cited in source_tools that
    produced 0 records -- or that are absent from tool_records entirely
    -- are phantom citations, not corroboration, and must not contribute
    to artifact-type counting or cross-domain upgrade. Default 0 on
    missing key: unverifiable = phantom. Legacy behavior preserved when
    tool_records is None.
    """
    source_tools = list(finding.get("source_tools", []))
    claim_tools = _extract_claim_tools(finding)
    # Persist claim_tools on the finding so callers/reports can see the
    # per-claim provenance (was silently empty before CC#15).
    finding["claim_tools"] = claim_tools
    # Claim-level tools corroborate finding-level source_tools for ceiling
    # computation -- previously only finding.source_tools + investigation
    # were counted, so well-cited findings still capped at MEDIUM.
    for t in claim_tools:
        if t not in source_tools:
            source_tools.append(t)
    # B5 FIX: filter source_tools to tools that actually produced records.
    # Default 0 on missing key: if a tool (e.g. added by ReAct post-collection)
    # is absent from tool_records, treat as 0 -- unmeasured = phantom.
    # tool_records=None preserves pre-fix behavior for direct callers.
    if tool_records is not None:
        source_tools = [t for t in source_tools if tool_records.get(t, 0) > 0]
    n_types = count_artifact_types(source_tools)
    current = str(finding.get("confidence_level", "LOW")).upper()

    # False-positive marker forces LOW regardless of corroboration.
    if _is_false_positive(finding):
        react = finding.get("react_conclusion") or {}
        if react.get("is_false_positive"):
            logger.info(
                "  %s: FORCED LOW by ReAct (AI Cross-Check) FP conclusion: %s",
                finding.get("finding_id", "?"),
                (react.get("text", "") or "")[:120],
            )
        else:
            logger.info(
                "  %s: false_positive marker -> LOW",
                finding.get("finding_id", "?"),
            )
        return "LOW"

    # Ceiling from artifact type count (see ARCHITECTURE.md)
    # 1 model, 1-2 artifact types = MEDIUM max
    # 3+ artifact types, 1 model = HIGH allowed
    if n_types >= 3:
        ceiling = "HIGH"
    elif n_types >= 1:
        ceiling = "MEDIUM"
    else:
        ceiling = "SPECULATIVE"

    if run_domain is None:
        run_domain = os.environ.get("SIFT_RUN_DOMAIN")

    # SSDT degradation: cap memory-dependent findings.
    # Commit 22: when the cap actually fires, attach a
    # confidence_cap_reason policy string to the finding so the
    # Inv4 report, self-assessment, HTML report, and any reviewer
    # reading raw findings JSON can see WHY confidence was limited.
    # Policy text is a constant; dataset-agnostic.
    if ssdt_trust != "full":
        has_memory = any(
            TOOL_TO_ARTIFACT_TYPE.get(t) == "M" for t in source_tools
        )
        if has_memory and _RANK.get(ceiling, 0) > _RANK["MEDIUM"]:
            ceiling = "MEDIUM"
            finding["confidence_cap_reason"] = (
                f"Memory-dependent evidence capped at MEDIUM: SSDT trust is "
                f"'{ssdt_trust}' (Volatility3 plugin failure and kernel "
                f"hooks produce the same signal; conservative policy caps "
                f"when trust is not 'full'). Disk, network, and Prefetch "
                f"corroboration unaffected."
            )

    # Apply ceiling: AI confidence cannot exceed it
    if _RANK.get(current, 0) > _RANK.get(ceiling, 0):
        calibrated = ceiling
    else:
        calibrated = current

    # Cross-domain upgrade: memory + disk sources -> HIGH.
    # CC#15: the domain set now includes claim_tools. Previously a finding
    # citing ["vol_pstree", "vol_cmdline"] at finding-level with a
    # {"source_tool": "get_amcache"} claim capped at MEDIUM because the
    # claim-level tool was never read.
    domains: set[str] = set()
    for tool in source_tools:
        if tool in MEMORY_TOOLS:
            domains.add("memory")
        if tool in DISK_TOOLS:
            domains.add("disk")

    logger.info(
        "  %s: source_tools=%s, claim_tools=%s",
        finding.get("finding_id", "?"),
        finding.get("source_tools", []),
        claim_tools,
    )

    if len(domains) >= 2 and calibrated != "HIGH":
        calibrated = "HIGH"
        logger.info(
            "  %s: upgraded to HIGH (confirmed across %s -- cross-domain confirmation)",
            finding.get("finding_id", "?"),
            " AND ".join(sorted(domains)),
        )

    # Single-artifact MEMORY run: there is no disk to cross-corroborate, and all memory
    # plugins collapse to one artifact type, so even a textbook injection would cap at
    # MEDIUM. 3+ INDEPENDENT memory lenses (RWX region + unbacked module + injected
    # thread ...) is the within-domain equivalent of cross-domain confirmation -> upgrade
    # to HIGH, exactly like the rule above. Requires SSDT trust 'full' (an untrusted
    # kernel could fake the very memory signals this relies on). Gated to a memory-only
    # run so paired / disk-only runs are byte-identical. Universal: method-independence.
    if (run_domain == "memory" and calibrated != "HIGH" and ssdt_trust == "full"
            and count_memory_lenses(source_tools) >= 3):
        calibrated = "HIGH"
        finding["confidence_basis"] = "memory_only_independent_lenses"
        logger.info(
            "  %s: upgraded to HIGH (memory-only: %d independent memory lenses)",
            finding.get("finding_id", "?"), count_memory_lenses(source_tools))

    return calibrated


# ── Severity descriptions (parenthetical labels) ────────────────────
SEVERITY_DESC: dict[str, str] = {
    "CRITICAL": "attacker can steal credentials or move laterally",
    "HIGH": "active attack technique detected",
    "MEDIUM": "suspicious activity worth investigating",
    "LOW": "informational anomaly",
}

# Term lists for severity classification.
# MITRE ATT&CK + SANS-standard forensic vocabulary. These are
# credential-access and lateral-movement technique keywords that
# appear in evidence from any credential-focused attack, not
# scenario-specific terms. Equivalent to medical diagnostic
# vocabulary — do NOT remove for agnosticity enforcement.
_CRITICAL_TERMS: list[str] = [
    "pwdump", "mimikatz", "procdump", "lsass",
    "credential", "psexec", "wmiexec", "smbexec",
    "lateral movement", "pass-the-hash", "kerberoast",
    "dcsync", "ntds.dit", "sam dump", "hashdump",
]

_HIGH_PATTERNS: list[str] = [
    r"wmi.*powershell", r"powershell.*encoded",
    "whoami", "ipconfig", "net user", "systeminfo",
    "netstat", "discovery", "reconnaissance",
    "scheduled task", "registry run", "service creat",
    "malfind", "injected", "hollowed", "beacon",
]

_MEDIUM_TERMS: list[str] = [
    "listening", "established", "suspicious",
    "unusual", "unknown service", r"temp\\", "tmp/",
]


# RUN17_P0_CREDENTIAL_DUMPING_SEVERITY
#
# Dataset-agnostic credential-dumping severity guard.
# Covers PWDump/PWDumpX-style family prefixes, including truncated evidence
# strings such as "pwdum..." observed in tool output or fixtures. No case
# paths, hashes, IPs, or PIDs are embedded here.
_CREDENTIAL_DUMPING_FAMILY_RE = re.compile(
    r"\bpwdum[pA-Za-z0-9_.-]*\b|\bpwdum[A-Za-z0-9_.-]*\b",
    re.IGNORECASE,
)

def assign_severity(finding: dict) -> str:
    """Rate finding severity based on artifact content.

    Returns one of: CRITICAL, HIGH, MEDIUM, LOW.
    """
    artifact = str(finding.get("artifact", "")).lower()
    description = str(finding.get("description", "")).lower()
    text = artifact + " " + description

    if _CREDENTIAL_DUMPING_FAMILY_RE.search(text):
        return "CRITICAL"

    if any(t in text for t in _CRITICAL_TERMS):
        return "CRITICAL"

    if any(re.search(p, text) for p in _HIGH_PATTERNS):
        return "HIGH"

    if any(t in text for t in _MEDIUM_TERMS):
        return "MEDIUM"

    return "LOW"


# -- Severity clamp: reconcile keyword severity with evidence confidence --
# assign_severity() classifies by ATT&CK keyword ("how bad the technique
# is"); calibrate_confidence() measures evidentiary support. Displayed
# Severity must honour both: no CRITICAL on SPECULATIVE/LOW confidence, and
# no HIGH-confidence finding buried at LOW for lack of a keyword. Pure +
# deterministic; keys only on the severity/confidence enums (no case-
# specific terms) -> dataset-agnostic.
_SEV_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_CONF_SEV_CEILING = {
    "UNRESOLVED": "LOW", "SPECULATIVE": "LOW", "LOW": "LOW",
    "MEDIUM": "MEDIUM", "HIGH": "CRITICAL",
}
_CONF_SEV_FLOOR = {"MEDIUM": "MEDIUM", "HIGH": "HIGH"}


def clamp_severity_to_confidence(
    keyword_severity: str, confidence_level: str,
) -> str:
    """Clamp keyword severity to what the confidence ladder supports.

    Caps promotion (no CRITICAL on LOW/SPECULATIVE confidence) and lifts
    demotion (>=HIGH confidence reaches at least HIGH). Returns one of
    CRITICAL/HIGH/MEDIUM/LOW. Idempotent. Unknown confidence -> LOW
    ceiling (conservative); unknown severity -> treated as LOW.
    """
    kw = (keyword_severity or "LOW").upper()
    conf = (confidence_level or "LOW").upper()
    if kw not in _SEV_ORDER:
        kw = "LOW"
    out = kw
    ceiling = _CONF_SEV_CEILING.get(conf, "LOW")
    floor = _CONF_SEV_FLOOR.get(conf)
    if _SEV_ORDER.index(out) > _SEV_ORDER.index(ceiling):
        out = ceiling
    if floor and _SEV_ORDER.index(out) < _SEV_ORDER.index(floor):
        out = floor
    return out

# SIFT_TOOL_HIT_INTEGRITY_MODULE_WRAPPERS_V1
try:
    from sift_sentinel.analysis.tool_hit_integrity import install_module_wrappers as _sift_install_tool_hit_integrity_wrappers
    _sift_install_tool_hit_integrity_wrappers(globals())
except Exception:
    pass
