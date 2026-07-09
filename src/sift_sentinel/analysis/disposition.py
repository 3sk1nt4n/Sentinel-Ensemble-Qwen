"""Sentinel Qwen Ensemble - Final disposition truth buckets (Slot 31E-DB.3).

A deterministic, dataset-agnostic truth layer that runs *after* Step 13

confidence calibration and *before* Step 14 report rendering.

It does NOT rewrite Inv4 / report prompt input. It only produces a
canonical, validator-ready partition of the calibrated findings so a
later slot (31E-DB.4) can consume buckets without re-deriving truth.

Problem this layer fixes
------------------------
The validator can now use typed EvidenceDB facts, but *final
disposition* could still misrepresent truth:

  * ReAct-benign / likely false-positive findings appearing in a
    confirmed-malicious bucket.
  * CRITICAL/HIGH severity findings carried at LOW confidence treated
    as confirmed malicious.
  * One-claim findings surviving as confirmed malicious without enough
    independent typed support.
  * Synthesis / attack-chain narrative findings inflating the count of
    atomic confirmed findings.
  * Heterogeneous finding shapes making ReAct verdict extraction
    brittle.

Every routing decision here is mechanical: no AI call, no live tool
run, no network. Conservative by default -- when truth cannot be
proven, a finding is routed *out* of the confirmed bucket, never into
it.

Reverting Slot 31E-DB.3 deletes this module and its Step-13.5 call
site, restoring pre-31E-DB.3 raw finding disposition behavior with no
EvidenceDB schema migration, state-dir filename dependency, Inv4 prompt
contract change, or downstream contract change required.
"""

from __future__ import annotations

import copy
import os
import re

from sift_sentinel.analysis.malicious_semantics import (
    _clear_view_cache,
    CONCLUSIVE_STRUCTURAL_SIGNALS,
    ENVIRONMENT_CONTEXT_SIGNALS,
    LEGITIMATE_NULL_CMDLINE_PROCESSES,
    MALICIOUS_SEMANTIC_SIGNALS,
    c2_corroboration_axes,
    environment_context_signals,
    has_malicious_semantic,
    resolve_semantic_signal_support,
)

# ── Slot 31E-DB.5a-alpha gate names ──────────────────────────────────────
# Probed by side gates / tests; the disposition module is the single
# import surface for routing-truth gate identifiers.
GATE_EXPLICIT_FACT_ID_IN_CLAIMS = "EXPLICIT_FACT_ID_IN_CLAIMS_GATE"
GATE_CLAIM_FACT_REFERENCE = "CLAIM_FACT_REFERENCE_GATE"
GATE_SEMANTIC_SIGNAL_PROVENANCE = "SEMANTIC_SIGNAL_PROVENANCE_GATE"
GATE_MALICIOUS_SEMANTIC_PROVENANCE = "MALICIOUS_SEMANTIC_PROVENANCE_GATE"
GATE_NO_PID_ONLY_CONFIRMED = "NO_PID_ONLY_CONFIRMED_GATE"
# Slot 31E-DB.5d B5: a finding whose entity has contradictory ReAct
# verdicts is routed out of confirmed_malicious_atomic (fail-closed).
GATE_REACT_ENTITY_CONFLICT = "REACT_ENTITY_CONFLICT_CONFIRMED_GATE"
GATE_SYNTHESIS_SOURCE_DISPOSITION = "SYNTHESIS_SOURCE_DISPOSITION_GATE"

GATE_RWX_REQUIRES_CORROBORATION = "RWX_REQUIRES_CORROBORATION_GATE"
GATE_C2_REQUIRES_CORROBORATION = "C2_REQUIRES_CORROBORATION_GATE"
# Semantic signals that, ALONE (even combined with each other), are insufficient
# for confirmed_malicious_atomic. Both are high-false-positive indicators: private
# RWX memory is allocated legitimately by JIT/.NET/browser/Electron runtimes, and a
# null/empty command line is a common artifact of legitimate system processes and of
# memory-acquisition gaps. Either -- or both together -- must be corroborated by an
# INDEPENDENT malicious signal (hollowing, lolbin lineage, persistence, staging/temp
# execution, C2, hidden module) to enter the confirmed bucket. Dataset-agnostic; no
# case-specific names.
_WEAK_ALONE_SEMANTIC_SIGNALS = frozenset({
    "rwx_memory_region_with_unusual_protection",
    "null_or_empty_cmdline_on_executable",
    "sensitive_privilege_enabled_on_non_baseline",
    # SIFT_TEMP_EXEC_WEAK_V1: temp/staging execution is ubiquitous among legitimate
    # installers / updaters / runtimes, and is context-free from ShimCache/AmCache;
    # suspicious only when corroborated by an independent malicious signal. Universal.
    "executes_from_temp_path",
    # 31-LATERAL-EVENTS: explicit-credential / RunAs logon (4648) is noisy alone
    # (legit admin RunAs) -> corroborating only; surfaces when paired with another
    # signal on the same account/host, never standalone.
    "explicit_credential_logon",
})

# Disk-execution HISTORY signals. ShimCache/AppCompatCache, LNK and JumpList record that a
# binary EXECUTED FROM DISK at some past time -- not the LIVE process's in-memory state, so
# they cannot corroborate a memory-injection (RWX) claim. (executes_from_temp_path is
# deliberately NOT here: it reflects the live image's location, a same-domain corroborator.)
# Structural taxonomy only -- no paths/PIDs/process names.
_DISK_HISTORY_SEMANTIC_SIGNALS = frozenset({
    "appcompatcache_execution_from_staging",
    "lnk_execution_from_staging",
    "jumplist_access_to_staging",
})

# SIFT_REACT_BENIGN_VS_ANOMALY_V1: deterministic, self-relative / structural
# BEHAVIORAL-anomaly semantics. Each describes ANOMALOUS ACTIVITY -- egress volume
# vs the image's OWN baseline, data archived into a transient/staging path, or
# system-recovery sabotage -- NOT binary identity. A ReAct "the program is
# legitimate software" benign verdict therefore does NOT refute them: legitimacy of
# the binary is irrelevant to whether the activity is anomalous. Such a finding is
# held for human review, never silently buried as benign. Registry-known names only;
# structural taxonomy, no host/IP/path/process literal.
_BEHAVIORAL_ANOMALY_SEMANTIC_SIGNALS = frozenset({
    "srum_egress_outlier",
    "archive_in_staging_path",
    "inhibit_system_recovery",
    "anti_forensics_execution",
    "mass_encryption_burst",
    "service_account_interactive_execution",
    "admin_share_access",
    "privileged_group_modification",
})

# CONCLUSIVE structural persistence primitives -- malicious by registry-key SHAPE
# (an IFEO <exe>\Debugger value; a non-default SafeBoot AlternateShell), and only
# rarely legitimate. A ReAct binary-legitimacy benign verdict cannot refute these:
# the key is the malicious primitive regardless of which process ReAct examined.
# Universal: keyed on the registered structural matcher names, never a case value.
_CONCLUSIVE_PERSISTENCE_SIGNALS = frozenset({
    "ifeo_debugger_hijack",
    "safeboot_alternateshell_persistence",
})


_RWX_SIGNAL = "rwx_memory_region_with_unusual_protection"

# Tools whose presence on a finding means a real network observation backs it.
_NETWORK_TOOLS = frozenset({
    "vol_netscan", "extract_network_iocs", "vol_handles", "run_srumecmd",
})
_PUBLIC_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _ipv4_is_public(ip: str) -> bool:
    """True for a routable public IPv4 -- excludes RFC1918 / loopback / link-local
    / multicast / reserved. Octet-shape only, never a specific address."""
    try:
        o = [int(x) for x in str(ip).split(".")]
    except (ValueError, TypeError):
        return False
    if len(o) != 4 or any(not 0 <= x <= 255 for x in o):
        return False
    a, b = o[0], o[1]
    if a in (0, 10, 127):
        return False                       # this-net / RFC1918-10 / loopback
    if a == 192 and b == 168:
        return False                       # RFC1918-192
    if a == 172 and 16 <= b <= 31:
        return False                       # RFC1918-172
    if a == 169 and b == 254:
        return False                       # link-local
    if a >= 224:
        return False                       # multicast / reserved
    if o[3] == 0:
        return False                       # network base address / fragment
    return True


def _claim_foreign_addrs(finding) -> list:
    out = []
    for c in (finding.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for k in ("foreign_addr", "foreign_ip", "remote_addr", "remote_ip",
                  "value"):
            v = c.get(k)
            if isinstance(v, str) and v:
                out.append(v)
    return out


def _has_external_network_corroborator(finding) -> bool:
    """True iff the finding evidences a connection to an EXTERNAL (public) host --
    a strong independent corroborator for an otherwise in-memory signal (injected
    code that beacons out). Requires BOTH a public IPv4 AND a real network context
    (a connection claim or a network tool) so a public-looking version string in
    an unrelated field never counts. Universal: public-IP octet shape, no case
    data."""
    if not isinstance(finding, dict):
        return False
    tools = {str(t).strip().lower() for t in (finding.get("source_tools") or [])}
    has_conn_claim = any(
        isinstance(c, dict) and str(c.get("type")) == "connection"
        for c in (finding.get("claims") or []))
    if not (has_conn_claim or (tools & _NETWORK_TOOLS)):
        return False
    # public IP in a connection claim field, or in the finding's own text.
    for v in _claim_foreign_addrs(finding):
        for m in _PUBLIC_IPV4_RE.finditer(v):
            if _ipv4_is_public(m.group(1)):
                return True
    blob = " ".join(str(finding.get(k) or "")
                    for k in ("title", "description", "artifact", "raw_excerpt"))
    for m in _PUBLIC_IPV4_RE.finditer(blob):
        if _ipv4_is_public(m.group(1)):
            return True
    return False


def _has_concrete_signal_provenance(finding) -> bool:
    """True iff any ``semantic_signal_support`` ledger entry cites INDEPENDENT,
    concrete provenance for its signal: a real forensic ``supporting_tool`` (not
    the anonymous ``evidence_db`` index fallback) AND a concrete
    ``supporting_fact_refs`` id (not the ``<type>:matched`` fallback). This is the
    paired-reference-set discipline: a weak-alone signal corroborated by a fact
    that is attributable to a named tool and a citable id is independent evidence;
    an anonymous DB self-match of the model's own claim is not. Universal --
    provenance completeness, no case data. (See malicious_semantics._tool_for /
    _refs_for for the fallbacks this rejects.)"""
    if not isinstance(finding, dict):
        return False
    for entry in (finding.get("semantic_signal_support") or []):
        if not isinstance(entry, dict):
            continue
        tool = str(entry.get("supporting_tool") or "").strip().lower()
        if not tool or tool == "evidence_db":
            continue                       # anonymous index fallback, not a tool
        refs = entry.get("supporting_fact_refs") or []
        if not isinstance(refs, (list, tuple)):
            refs = [refs]
        concrete_ref = any(
            str(r).strip() and not str(r).strip().endswith(":matched")
            for r in refs)
        if concrete_ref:
            return True
    return False


# A4: execution-history tools whose record IS execution evidence (not mere
# presence): AppCompatCache 'Executed' flag, Amcache, Prefetch. Tool-class only.
_EXECUTION_HISTORY_TOOLS = frozenset({
    "run_appcompatcacheparser", "get_amcache", "parse_prefetch",
})
# md5 (32) / sha1 (40) / sha256 (64) hex, word-bounded.
_HASH_TOKEN_RE = re.compile(r"\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?(?:[a-fA-F0-9]{24})?\b")


def _finding_has_hash(finding) -> bool:
    """A file hash anywhere in the finding's claims / iocs / description."""
    for c in (finding.get("claims") or []):
        if not isinstance(c, dict):
            continue
        for hk in ("sha1", "sha256", "md5", "hash"):
            v = c.get(hk)
            if isinstance(v, str) and _HASH_TOKEN_RE.fullmatch(v.strip()):
                return True
        for vk in ("value", "artifact", "ioc"):
            v = c.get(vk)
            if isinstance(v, str) and _HASH_TOKEN_RE.search(v):
                return True
    blob = " ".join(str(x) for x in (finding.get("iocs") or []))
    blob += " " + str(finding.get("description") or "")
    return bool(_HASH_TOKEN_RE.search(blob))


def _execution_confirmed_with_hash(finding) -> bool:
    """A4: an execution-history record (AppCompatCache Executed / Amcache /
    Prefetch) PLUS a file hash = concrete execution + identity, two independent
    disk facts agreeing -> corroboration, not 'purely historical'. Both are
    required (a hash alone, or an execution tool alone, is not this axis).
    Kill-switch SIFT_FLOOR_EXEC_HASH_CORROB=0. Universal: tool-class + hash-shape."""
    if os.environ.get("SIFT_FLOOR_EXEC_HASH_CORROB", "1").strip().lower() \
            in ("0", "false", "no", "off"):
        return False
    tools = {str(t).strip().lower() for t in (finding.get("source_tools") or []) if t}
    if not (tools & _EXECUTION_HISTORY_TOOLS):
        return False
    return _finding_has_hash(finding)


def _confirmable_corroborator_present(finding, sem_signals) -> bool:
    """True iff the finding has an INDEPENDENT axis that justifies confirmation
    beyond weak-alone / disk-history signals: a non-weak semantic signal, an
    external public connection, >=2 distinct injection-capable memory tools, a
    conclusive structural primitive, strong typed support (>=2 distinct typed
    facts), or a per-signal evidence ledger with concrete independent provenance.
    Universal -- signal class + tool set + public IP shape + provenance
    completeness, no case data."""
    fired = {str(s) for s in (sem_signals or [])}
    if fired & CONCLUSIVE_STRUCTURAL_SIGNALS:
        return True
    if fired - _WEAK_ALONE_SEMANTIC_SIGNALS - _DISK_HISTORY_SEMANTIC_SIGNALS:
        return True                        # a real (non-weak) semantic signal
    if _has_external_network_corroborator(finding):
        return True
    tools = {str(t).strip().lower()
             for t in (finding.get("source_tools") or []) if t}
    if len(tools & _INJECTION_MEMORY_TOOLS) >= 2:
        return True
    # independent evidence the existing confirm contract already honours:
    # strong typed support (>=2 distinct typed facts), or a per-signal ledger
    # entry with concrete tool+id provenance. F010's anonymous evidence_db
    # self-match satisfies neither.
    if has_strong_typed_support(finding)[0]:
        return True
    if _has_concrete_signal_provenance(finding):
        return True
    if _execution_confirmed_with_hash(finding):   # A4: Executed-flag + hash
        return True
    return False


def weak_alone_only_uncorroborated(finding, sem_signals) -> bool:
    """True iff the finding's malicious meaning rests ENTIRELY on weak-alone /
    disk-history signals (e.g. executes_from_temp_path -- an installer staged in
    Temp; private RWX; null cmdline) with NO independent corroborator -> NOT
    confirm-eligible. This is the same corroboration discipline the normal
    disposition path applies, lifted into the single eligibility gate so an
    inv3a-promoted confirm cannot bypass it. Kill-switch
    SIFT_CONFIRM_CORROBORATION_FLOOR=0. Returns False when there is no weak-alone
    signal at all (not this gate's job)."""
    import os
    if os.environ.get("SIFT_CONFIRM_CORROBORATION_FLOOR", "1").strip().lower() \
            in ("0", "false", "no", "off"):
        return False
    fired = {str(s) for s in (sem_signals or [])}
    if not fired:
        return False
    weak = fired.issubset(
        _WEAK_ALONE_SEMANTIC_SIGNALS | _DISK_HISTORY_SEMANTIC_SIGNALS)
    if not weak:
        return False
    return not _confirmable_corroborator_present(finding, sem_signals)


def _rwx_uncorroborated(has_sem: bool, sem_signals) -> bool:
    """True iff a memory-injection finding lacks an INDEPENDENT, same-domain corroborator
    -> route it out of confirmed_malicious_atomic.

    Weak-alone in-memory signals (private RWX, null/empty cmdline) never confirm alone.
    Disk-execution HISTORY (ShimCache/AppCompatCache, LNK, JumpList) attests PAST on-disk
    execution, not the live process's in-memory state, so it cannot corroborate an injection
    claim either. A live execution-from-temp and memory/process/live-network signals
    (hollowing, injected thread, that process's own C2) DO corroborate. Scoped to
    memory-injection-flavoured findings (an RWX region signal fired); pure disk-execution
    findings (no RWX signal) are untouched."""
    fired = {str(s) for s in (sem_signals or [])}
    if not (has_sem and fired):
        return False
    if fired.issubset(_WEAK_ALONE_SEMANTIC_SIGNALS):
        return True
    if "rwx_memory_region_with_unusual_protection" in fired:
        corroborators = (
            fired
            - _WEAK_ALONE_SEMANTIC_SIGNALS
            - _DISK_HISTORY_SEMANTIC_SIGNALS
        )
        return not corroborators
    return False


# Memory methods that can independently evidence injection. The unbacked-module
# signal (vol_ldrmodules) and the RWX-VAD signal (vol_malfind) are DIFFERENT
# methods, so two distinct tools here = genuine cross-method corroboration.
_INJECTION_MEMORY_TOOLS = frozenset({
    "vol_malfind", "vol_ldrmodules", "vol_psxview", "vol_handles",
    "vol_vadinfo", "vol_vadyarascan", "vol_threads", "vol_hollowprocesses",
})
_UNBACKED_MODULE_SIGNAL = "injected_pe_image_in_executable_memory"


def rwx_uncorroborated_for_finding(finding, has_sem: bool, sem_signals) -> bool:
    """Provenance-aware wrapper around _rwx_uncorroborated (P1).

    SIFT_PROVENANCE_RWX default OFF -> returns the existing signal-only verdict
    unchanged. When ON: the unbacked-module signal corroborates an RWX claim
    only with INDEPENDENT provenance. If it is the SOLE corroborator and the
    finding cites a single injection-capable memory tool, the RWX VAD and the
    unbacked module are one observation counted twice -> uncorroborated. A
    second injection-capable memory method, or any other independent
    corroborator, keeps the finding corroborated. Only this self-corroboration
    case is scoped; every other finding is untouched. The single gate that can
    suppress a true positive, hence OFF by default until validated on clean
    pairs."""
    base = _rwx_uncorroborated(has_sem, sem_signals)
    # PROMOTE (SIFT_CONFIRM_CORROBORATION_FLOOR, default ON): an RWX-injection
    # finding that ALSO carries an INDEPENDENT corroborator -- an external public
    # C2 connection, or >=2 distinct injection-capable memory tools -- is NOT
    # uncorroborated (e.g. lsass.exe with RWX + beacon to a public IP). The
    # signal-only _rwx_uncorroborated cannot see these axes; this restores them.
    # Universal: public-IP shape + injection-tool set, no case data.
    if base and os.environ.get(
            "SIFT_CONFIRM_CORROBORATION_FLOOR", "1").strip().lower() \
            not in ("0", "false", "no", "off"):
        if (_has_external_network_corroborator(finding)
                or len({str(t).strip().lower()
                        for t in (finding.get("source_tools") or [])}
                       & _INJECTION_MEMORY_TOOLS) >= 2):
            return False
    if base or os.environ.get("SIFT_PROVENANCE_RWX", "0") != "1":
        return base
    fired = {str(s) for s in (sem_signals or [])}
    if "rwx_memory_region_with_unusual_protection" not in fired:
        return False
    corroborators = (fired - _WEAK_ALONE_SEMANTIC_SIGNALS
                     - _DISK_HISTORY_SEMANTIC_SIGNALS)
    if corroborators != {_UNBACKED_MODULE_SIGNAL}:
        return False                      # an independent corroborator exists
    tools = {str(t).strip().lower()
             for t in (finding.get("source_tools") or []) if t}
    independent = tools & _INJECTION_MEMORY_TOOLS
    return len(independent) < 2           # single-tool -> self-corroboration


def _c2_uncorroborated(finding, has_sem: bool, sem_signals, evidence_db=None) -> bool:
    """True iff a C2/staging-domain finding has fewer than 2 INDEPENDENT structural
    axes pointing at the host -> route it out of confirmed (to needs-review).

    A non-vendor domain fetched in a download cradle is a high-prior heuristic, not
    proof: a benign DevOps `iwr github` cradle fires it too. It becomes a defensible
    C2 confirm only when >= 2 independent structural axes converge on the SAME host
    (cradle + obfuscation / injection / DGA-shape) -- the 3+-signals model. Scoped to
    c2_staging_domain / dga_domain findings; every other finding is untouched."""
    fired = {str(s).lower() for s in (sem_signals or [])}
    if not (has_sem and (fired & {"c2_staging_domain", "dga_domain"})):
        return False  # not a C2/domain finding
    probe = dict(finding) if isinstance(finding, dict) else {}
    probe["malicious_semantic_signals"] = sorted(fired)
    return len(c2_corroboration_axes(probe, evidence_db)) < 2

# Claim types that identify an entity but do NOT, by themselves, prove
# malicious behaviour. A confirmed finding needs at least one claim
# beyond pure PID / process existence (Slot 31E-DB.5a-alpha TASK 3).
_PID_IDENTITY_CLAIM_TYPES = frozenset({"pid", "process_exists", ""})

# Re-exported so callers and side gates can probe the registry through
# the disposition module (the single import surface for routing truth).
__all__ = [
    "ENVIRONMENT_CONTEXT_SIGNALS",
    "LEGITIMATE_NULL_CMDLINE_PROCESSES",
    "MALICIOUS_SEMANTIC_SIGNALS",
    "has_malicious_semantic",
    "evaluate_confirmed_bucket_eligibility",
    "evaluate_confirmed_bucket_eligibility_cached",
    "make_eligibility_cache",
    "derive_final_disposition",
    "route_findings_for_report",
    "validate_disposition_buckets",
    "assert_buckets_partition_findings",
    "extract_react_verdict",
    "is_synthesis_finding",
    "has_strong_typed_support",
    "durable_fact_refs",
    "has_behavioral_malicious_claim",
    "GATE_EXPLICIT_FACT_ID_IN_CLAIMS",
    "GATE_CLAIM_FACT_REFERENCE",
    "GATE_SEMANTIC_SIGNAL_PROVENANCE",
    "GATE_MALICIOUS_SEMANTIC_PROVENANCE",
    "GATE_NO_PID_ONLY_CONFIRMED",
    "GATE_REACT_ENTITY_CONFLICT",
    "GATE_RWX_REQUIRES_CORROBORATION",
    "GATE_C2_REQUIRES_CORROBORATION",
    "GATE_SYNTHESIS_SOURCE_DISPOSITION",
    "render_synthesis_source_components",
    "synthesis_source_disposition_gate",
]

# ── Canonical bucket names ───────────────────────────────────────────────
BUCKET_CONFIRMED = "confirmed_malicious_atomic"
BUCKET_SUSPICIOUS = "suspicious_needs_review"
BUCKET_BENIGN = "benign_or_false_positive"
BUCKET_INCONCLUSIVE = "inconclusive_unresolved"
BUCKET_SYNTHESIS = "synthesis_narrative"

REQUIRED_BUCKETS = (
    BUCKET_CONFIRMED,
    BUCKET_SUSPICIOUS,
    BUCKET_BENIGN,
    BUCKET_INCONCLUSIVE,
    BUCKET_SYNTHESIS,
)

# Normalized verdict vocabulary returned by extract_react_verdict.
_V_MALICIOUS = "confirmed_malicious"
_V_BENIGN = "confirmed_benign"
_V_LIKELY_FP = "likely_fp"
_V_INCONCLUSIVE = "inconclusive"
_V_UNKNOWN = "unknown"

# Canonical free-text phrases the step-5 fallback is allowed to scan for.
# Scanned ONLY in finding["conclusion"] / finding["investigation_conclusion"]
# -- never the whole serialized finding, which would false-positive on
# any description that merely mentions a word like "benign".
_FALLBACK_PHRASES = (
    ("confirmed_malicious", _V_MALICIOUS),
    ("confirmed_benign", _V_BENIGN),
    ("likely_fp", _V_LIKELY_FP),
    ("false_positive", _V_LIKELY_FP),
    ("inconclusive", _V_INCONCLUSIVE),
    ("cannot be confirmed", _V_INCONCLUSIVE),
    ("cannot confirm", _V_INCONCLUSIVE),
    ("insufficient evidence", _V_INCONCLUSIVE),
)

# finding_type / evidence_type values that are themselves a strong
# synthesis signal. "composite_narrative" is the runtime label emitted
# by run_pipeline._classify_finding_type for attack-chain narratives;
# it is included so calibrated synthesis output is never miscounted as
# atomic confirmed malicious.
_SYNTHESIS_FINDING_TYPES = frozenset({
    "synthesis", "narrative", "attack_chain_summary", "composite_narrative",
})
_SYNTHESIS_EVIDENCE_TYPES = frozenset({"synthesis", "narrative"})

# Tokens in validation_status / deterministic_check / self_verification
# that disqualify a finding from the confirmed bucket. "mismatch" is
# included because a typed/reference refutation is, by definition, not
# confirmed malicious.
_BLOCKED_TOKENS = ("blocked", "error", "fail", "failed", "mismatch")


def _norm(s) -> str:
    return str(s).strip().lower() if s is not None else ""


def _normalize_verdict(raw) -> str | None:
    """Map a raw verdict string onto the canonical vocabulary.

    Returns one of confirmed_malicious / confirmed_benign / likely_fp /
    inconclusive / unknown, or None when the value carries no verdict
    signal.
    """
    v = _norm(raw)
    if not v:
        return None
    if v in (_V_MALICIOUS, "malicious"):
        return _V_MALICIOUS
    if v in (_V_BENIGN, "benign", "confirmed_false_positive"):
        return _V_BENIGN
    if v in (_V_LIKELY_FP, "likely_false_positive",
             "false_positive", "false positive", "probable_fp"):
        return _V_LIKELY_FP
    if v in (_V_INCONCLUSIVE, "cannot be confirmed", "cannot confirm",
             "insufficient evidence", "indeterminate", "ambiguous"):
        return _V_INCONCLUSIVE
    if v == _V_UNKNOWN:
        return _V_UNKNOWN
    return None


def _verdict_from_container(obj) -> tuple[str | None, bool]:
    """Pull (normalized_verdict, is_false_positive) from a structured
    verdict container (finding["investigation"], finding["react_conclusion"],
    or an investigations[*] entry)."""
    if not isinstance(obj, dict):
        return None, False
    verdict = _normalize_verdict(obj.get("verdict"))
    is_fp = bool(obj.get("is_false_positive"))
    return verdict, is_fp


def extract_react_verdict(
    finding: dict,
    investigations: dict | list | None,
) -> tuple[str | None, dict]:
    """Extract the ReAct verdict for a finding.

    Returns ``(verdict, metadata)`` where ``verdict`` is one of
    ``confirmed_malicious`` / ``confirmed_benign`` / ``likely_fp`` /
    ``inconclusive`` / ``unknown`` / ``None``.

    Extraction precedence (first concrete match wins):

      1. ``finding["react_verdict"]``
      2. ``finding["investigation"]["verdict"]``
      3. ``finding["react_conclusion"]["verdict"]`` (runtime ReAct shape;
         a regex-fallback ``inconclusive`` carrying
         ``is_false_positive=True`` is reported as ``likely_fp`` so a
         benign-flagged finding is never treated as confirmed malicious)
      4. ``investigations[finding_id]["verdict"]`` when ``investigations``
         is a dict
      5. matching entry in an ``investigations`` list
      6. fallback: canonical-phrase scan of ``finding["conclusion"]`` and
         ``finding["investigation_conclusion"]`` ONLY

    The serialized finding is never scanned wholesale -- doing so would
    false-route on any description that merely mentions a word such as
    "benign". ``metadata`` records the extraction path.
    """
    fid = finding.get("finding_id")

    # 1. Explicit react_verdict on the finding.
    v = _normalize_verdict(finding.get("react_verdict"))
    if v is not None:
        return v, {"source": "finding.react_verdict"}

    # 2. Structured investigation block on the finding.
    v, _ = _verdict_from_container(finding.get("investigation"))
    if v is not None:
        return v, {"source": "finding.investigation"}

    # 3. Runtime ReAct conclusion block (coordinator Step 11 shape).
    rc = finding.get("react_conclusion")
    v, is_fp = _verdict_from_container(rc)
    if v is not None:
        if v == _V_INCONCLUSIVE and is_fp:
            return _V_LIKELY_FP, {
                "source": "finding.react_conclusion",
                "note": "inconclusive+is_false_positive -> likely_fp",
            }
        return v, {"source": "finding.react_conclusion"}
    if isinstance(rc, dict) and is_fp:
        return _V_LIKELY_FP, {
            "source": "finding.react_conclusion",
            "note": "is_false_positive flag",
        }

    # 4 & 5. External investigations argument, keyed dict or list.
    if isinstance(investigations, dict):
        entry = investigations.get(fid)
        if isinstance(entry, dict):
            v, ev_fp = _verdict_from_container(entry)
            if v is not None:
                return v, {"source": "investigations[finding_id]"}
            ec = entry.get("react_conclusion")
            v, c_fp = _verdict_from_container(ec)
            if v is not None:
                return v, {"source": "investigations[finding_id]"}
            if (isinstance(ec, dict) and c_fp) or ev_fp:
                return _V_LIKELY_FP, {
                    "source": "investigations[finding_id]",
                    "note": "is_false_positive flag",
                }
        else:
            v = _normalize_verdict(entry)
            if v is not None:
                return v, {"source": "investigations[finding_id]"}
    elif isinstance(investigations, list):
        for entry in investigations:
            if not isinstance(entry, dict):
                continue
            if entry.get("finding_id") != fid:
                continue
            v, ev_fp = _verdict_from_container(entry)
            if v is not None:
                return v, {"source": "investigations[list]"}
            ec = entry.get("react_conclusion")
            v, c_fp = _verdict_from_container(ec)
            if v is not None:
                return v, {"source": "investigations[list]"}
            if (isinstance(ec, dict) and c_fp) or ev_fp:
                return _V_LIKELY_FP, {
                    "source": "investigations[list]",
                    "note": "is_false_positive flag",
                }
            break

    # 6. Narrow free-text fallback. Conclusion fields ONLY.
    text = " ".join(
        str(finding.get(k) or "")
        for k in ("conclusion", "investigation_conclusion")
    ).lower()
    if text.strip():
        for phrase, verdict in _FALLBACK_PHRASES:
            if phrase in text:
                return verdict, {
                    "source": "conclusion_text",
                    "phrase": phrase,
                }

    return None, {"source": "none"}


def _fact_type_of(ref) -> str | None:
    """Pull a fact_type token from a typed_fact_refs element, which may
    be a dict ({"fact_type": ...}) or a "fact_type:fact_id" string."""
    if isinstance(ref, dict):
        ft = ref.get("fact_type") or ref.get("type")
        return str(ft) if ft else None
    if isinstance(ref, str) and ref:
        return ref.split(":", 1)[0] if ":" in ref else ref
    return None


def has_strong_typed_support(
    finding: dict,
    evidence_db: dict | None = None,
) -> tuple[bool, list[str]]:
    """Decide whether a finding has strong independent typed support.

    Returns ``(is_strong, reasons)``. ``True`` iff EITHER:

      * ``validator_metadata.typed_fact_refs`` spans >= 2 distinct
        ``fact_type`` values, OR
      * ``validator_metadata.source_tools`` spans >= 2 distinct tool
        names AND typed fact refs are present.

    Conservative by default: when ``validator_metadata`` is absent the
    answer is ``(False, ["no_validator_metadata"])``. ``evidence_db`` is
    accepted for forward-compatibility but strong support is proven from
    the finding's own validator metadata, not by re-querying the DB.
    """
    vm = finding.get("validator_metadata")
    if not isinstance(vm, dict):
        return False, ["no_validator_metadata"]

    typed_refs = vm.get("typed_fact_refs") or []
    if not isinstance(typed_refs, (list, tuple)):
        typed_refs = []
    fact_types = sorted({
        ft for ft in (_fact_type_of(r) for r in typed_refs) if ft
    })

    source_tools = vm.get("source_tools") or []
    if not isinstance(source_tools, (list, tuple)):
        source_tools = []
    tools = sorted({str(t) for t in source_tools if t})

    reasons: list[str] = []
    if len(fact_types) >= 2:
        reasons.append("typed_fact_types={%s}" % ",".join(fact_types))
        return True, reasons

    if len(tools) >= 2 and len(typed_refs) > 0:
        reasons.append("source_tools={%s}" % ",".join(tools))
        reasons.append("typed_fact_refs_present")
        return True, reasons

    if not typed_refs:
        reasons.append("typed_fact_refs_missing")
    if fact_types:
        reasons.append("typed_fact_types={%s}" % ",".join(fact_types))
    if tools:
        reasons.append("source_tools={%s}" % ",".join(tools))
    if not reasons:
        reasons.append("insufficient_typed_support")
    return False, reasons


def _claim_pids(finding: dict) -> set[int]:
    pids: set[int] = set()
    for c in finding.get("claims") or []:
        if not isinstance(c, dict):
            continue
        for key in ("pid", "parent_pid", "child_pid"):
            val = c.get(key)
            if isinstance(val, bool):
                continue
            if isinstance(val, int):
                pids.add(val)
            elif isinstance(val, str) and val.strip().lstrip("-").isdigit():
                pids.add(int(val.strip()))
    return pids


def _claim_process_entities(finding: dict) -> set[str]:
    """Distinct process-identity entities referenced by claims. Only
    process-name fields count -- hashes/paths/filenames are NOT primary
    process entities, so a single atomic file-staging finding citing one
    PID plus two hashes is not mistaken for an attack-chain narrative."""
    ents: set[str] = set()
    for c in finding.get("claims") or []:
        if not isinstance(c, dict):
            continue
        for key in ("process", "image_name", "child_process",
                    "parent_process"):
            v = c.get(key)
            if isinstance(v, str) and v.strip():
                ents.add(v.strip().lower())
    return ents


def _arrow_count(text: str) -> int:
    return text.count("→") + text.count("->")


def is_synthesis_finding(finding: dict) -> tuple[bool, list[str]]:
    """Classify a finding as synthesis / attack-chain narrative.

    Strong signals -- any one triggers synthesis routing:

      * ``finding_type`` in the synthesis type set
      * ``evidence_type`` in {synthesis, narrative}
      * ``is_synthesis`` is True
      * claims reference >= 3 distinct primary *process* entities

    Weak signals -- 2 or more required to trigger:

      * title starts with "full attack chain" / "attack chain summary"
      * description contains "multi-stage intrusion" / "full attack chain"
      * claims reference >= 3 distinct PIDs
      * title contains 2+ arrow tokens ("->", "→")

    A single arrow in title/description is NOT enough: a normal
    process-tree context such as "WmiPrvSE.exe -> powershell.exe" must
    not be misrouted as synthesis.
    """
    signals: list[str] = []

    # A deterministic atomic detection (emitted by candidate_findings with a
    # registered malicious_semantic) is atomic by construction and must never
    # route to synthesis -- even when XCORR enriched it with many corroborating
    # source tools, which the >=6-tools heuristic would otherwise relabel
    # composite_narrative. Without this, a real behavioural-anomaly finding
    # (e.g. an SRUM egress outlier) is demoted out of the confirmed bucket.
    if (finding.get("deterministic_finding") is True
            and _nonempty_list(finding.get("malicious_semantic_signals"))):
        return False, ["atomic:deterministic_semantic_detection"]

    ftype = _norm(finding.get("finding_type"))
    if ftype in _SYNTHESIS_FINDING_TYPES:
        signals.append("strong:finding_type=%s" % ftype)
    etype = _norm(finding.get("evidence_type"))
    if etype in _SYNTHESIS_EVIDENCE_TYPES:
        signals.append("strong:evidence_type=%s" % etype)
    if finding.get("is_synthesis") is True:
        signals.append("strong:is_synthesis_flag")

    procs = _claim_process_entities(finding)
    if len(procs) >= 3:
        signals.append("strong:distinct_process_entities=%d" % len(procs))

    if signals:  # any strong signal already present
        return True, signals

    # Weak signals -- need 2+.
    weak: list[str] = []
    title = _norm(finding.get("title") or finding.get("artifact"))
    desc = _norm(finding.get("description"))

    if title.startswith("full attack chain") or title.startswith(
            "attack chain summary"):
        weak.append("weak:title_attack_chain_prefix")
    if "multi-stage intrusion" in desc or "full attack chain" in desc:
        weak.append("weak:description_attack_chain_phrase")
    pids = _claim_pids(finding)
    if len(pids) >= 3:
        weak.append("weak:distinct_pids=%d" % len(pids))
    if _arrow_count(title) >= 2:
        weak.append("weak:title_multi_arrow")

    if len(weak) >= 2:
        return True, weak
    return False, weak


def _confidence_of(finding: dict) -> str:
    return _norm(
        finding.get("confidence_level")
        if finding.get("confidence_level") is not None
        else finding.get("confidence")
    ).upper()


def _severity_of(finding: dict) -> str:
    return _norm(finding.get("severity")).upper()


def _is_crit_high_low(finding: dict) -> bool:
    return (
        _severity_of(finding) in ("CRITICAL", "HIGH")
        and _confidence_of(finding) == "LOW"
    )


def _is_blocked(finding: dict) -> bool:
    val = _norm(finding.get("validation_status"))
    det = _norm(finding.get("deterministic_check"))
    blob = f"{val} {det}"
    if any(tok in blob for tok in _BLOCKED_TOKENS):
        return True
    if finding.get("self_verification_passed") is False:
        return True
    return False


_SPECULATIVE = "SPECULATIVE"
_REACT_DISQUALIFYING = (_V_BENIGN, _V_LIKELY_FP, _V_INCONCLUSIVE)


def _nonempty_list(value) -> list:
    if isinstance(value, (list, tuple)):
        return [v for v in value if v not in (None, "")]
    return []


def _effective_attribution(finding: dict) -> tuple[list, list]:
    """Source attribution honouring self-correction.

    When a finding was self-corrected (``post_sc`` truthy or
    ``corrected_claims`` present) the *corrected* source attribution is
    canonical -- stale original ``source_tools`` / ``tool_call_ids`` must
    not be allowed to vouch for a finding whose claims were rewritten.
    """
    post_sc = bool(
        finding.get("post_sc")
        or finding.get("self_corrected")
        or finding.get("corrected_claims")
    )
    if post_sc:
        st = _nonempty_list(
            finding.get("corrected_source_tools")
            or finding.get("post_sc_source_tools")
        )
        tc = _nonempty_list(
            finding.get("corrected_tool_call_ids")
            or finding.get("post_sc_tool_call_ids")
        )
        if st or tc:
            return st, tc
    st = _nonempty_list(finding.get("source_tools"))
    tc = _nonempty_list(finding.get("tool_call_ids"))
    if not st:
        vm = finding.get("validator_metadata")
        if isinstance(vm, dict):
            st = _nonempty_list(vm.get("source_tools"))
    return st, tc


def _has_typed_or_validated_support(
    finding: dict, evidence_db: dict | None,
) -> bool:
    strong, _ = has_strong_typed_support(finding, evidence_db)
    if strong:
        return True
    if _nonempty_list(finding.get("typed_fact_refs")):
        return True
    vm = finding.get("validator_metadata")
    if isinstance(vm, dict) and (
        vm.get("typed_fact_refs")
        or vm.get("reference_set_matches")
        or vm.get("reference_fallback")
    ):
        return True
    if _norm(finding.get("validation_status")) in ("match", "verified"):
        return True
    if _norm(finding.get("deterministic_check")) == "passed":
        return True
    return False


def durable_fact_refs(finding: dict) -> list:
    """Collect durable, validator-attached fact references.

    Slot 31E-DB.5a-alpha TASK 1: a confirmed finding must carry
    *durable* references resolving its claims to typed facts. The
    references are attached by the validator (not invented by Inv2) and
    may live at the top level or under ``validator_metadata``. Accepted
    keys: ``validator_fact_refs`` / ``typed_fact_refs`` /
    ``claim_evidence_refs``. Returns the flattened non-empty list.
    """
    if not isinstance(finding, dict):
        return []
    refs: list = []
    keys = ("validator_fact_refs", "typed_fact_refs", "claim_evidence_refs")
    for k in keys:
        refs.extend(_nonempty_list(finding.get(k)))
    vm = finding.get("validator_metadata")
    if isinstance(vm, dict):
        for k in keys:
            refs.extend(_nonempty_list(vm.get(k)))
    return refs


def _behavioral_claims(finding: dict) -> list[dict]:
    """Claims that assert malicious *behaviour*, not mere entity
    existence. A bare ``pid`` / ``process_exists`` claim only identifies
    an entity; a path execution, child-process / relationship,
    connection, timestamp-on-artifact, registry/scheduled-task
    persistence, hash, memory-injection or raw-with-detail claim asserts
    behaviour."""
    out: list[dict] = []
    _behavioral_fields = (
        "child_process", "parent_process", "child_pid", "parent_pid",
        "foreign_addr", "registry_path", "value_data", "path",
        "image_path", "protection", "action", "scheduled_task",
        "command_line", "cmd", "sha1", "sha256", "md5", "filename",
        "artifact",
    )
    for c in finding.get("claims") or []:
        if not isinstance(c, dict):
            continue
        ctype = _norm(c.get("type"))
        if ctype not in _PID_IDENTITY_CLAIM_TYPES:
            out.append(c)
            continue
        # A pid/process_exists claim that also carries a behavioural
        # field (e.g. an attributed suspicious connection) still counts.
        if any(
            str(c.get(f)).strip() for f in _behavioral_fields
            if c.get(f) not in (None, "", [], {})
        ):
            out.append(c)
    return out


def has_behavioral_malicious_claim(
    finding: dict, semantic_support: list | None = None,
) -> bool:
    """True iff the finding has at least one behavioural malicious claim
    beyond PID / process existence.

    Slot 31E-DB.5a-alpha TASK 3/4: behavioural evidence must be a
    *claim*, not merely a semantic signal's provenance. A PID-only
    observation that also carries an ``executes_from_temp_path``
    provenance block is still PID-only as far as confirmed routing is
    concerned -- otherwise a temp-payload-looking process with only a
    PID claim could be promoted. ``semantic_support`` is accepted for
    signature stability and intentionally not used as a behavioural
    substitute.
    """
    del semantic_support  # not a behavioural substitute (TASK 3/4)
    return bool(_behavioral_claims(finding))


# ── Slot 31D-STEP135-ELIGIBILITY-CACHE ────────────────────────────────
# Eligibility cache is valid only within one Step 13A pass. It assumes
# the finding object used for eligibility is not semantically mutated
# between repeated eligibility checks. Cached values are deep-copied on
# store/return; real-data bucket parity tests guard against routing
# drift. Evidence-backed (evidence_db provided) and evidence-less calls
# are stored under different keys so no evidence-backed result is ever
# reused for an evidence_db=None validation call.

def make_eligibility_cache() -> dict:
    """Return a fresh, in-run eligibility cache with stats slots.

    The shape is intentionally a plain dict so callers can serialize the
    stats block for telemetry. The ``store`` is keyed by
    ``(finding_id_or_fallback, bool(evidence_db))`` and holds deep copies
    of eligibility results; mutating a returned value never mutates the
    cached one.
    """
    return {
        "store": {},
        "hits": 0,
        "misses": 0,
        "stores": 0,
    }


def _eligibility_cache_key(
    finding: dict,
    evidence_db: dict | None,
) -> tuple[str, bool]:
    if not isinstance(finding, dict):
        return ("obj:%d" % id(finding), bool(evidence_db))
    fid = finding.get("finding_id") or finding.get("id")
    if fid:
        return ("id:%s" % str(fid), bool(evidence_db))
    # No stable id: fall back to object identity. Two distinct findings
    # without an id are still cached as two distinct entries (never
    # collapsed) -- correctness over hit-rate.
    return ("obj:%d" % id(finding), bool(evidence_db))


def evaluate_confirmed_bucket_eligibility_cached(
    finding: dict,
    evidence_db: dict | None = None,
    eligibility_cache: dict | None = None,
) -> dict:
    """Cache-aware wrapper around evaluate_confirmed_bucket_eligibility.

    Behaviourally equivalent to the underlying evaluator. When
    ``eligibility_cache`` is ``None`` the wrapper just delegates. When a
    cache is provided, repeated calls for the same finding identity and
    same evidence-mode (evidence-backed vs evidence-less) reuse a
    deep-copied result; the underlying evaluator is invoked at most once
    per (identity, mode) pair within a Step 13A pass.
    """
    if eligibility_cache is None:
        return evaluate_confirmed_bucket_eligibility(finding, evidence_db)

    store = eligibility_cache.setdefault("store", {})
    key = _eligibility_cache_key(finding, evidence_db)
    cached = store.get(key)
    if cached is not None:
        eligibility_cache["hits"] = int(
            eligibility_cache.get("hits", 0)) + 1
        return copy.deepcopy(cached)

    eligibility_cache["misses"] = int(
        eligibility_cache.get("misses", 0)) + 1
    result = evaluate_confirmed_bucket_eligibility(finding, evidence_db)
    store[key] = copy.deepcopy(result)
    eligibility_cache["stores"] = int(
        eligibility_cache.get("stores", 0)) + 1
    return copy.deepcopy(result)


def evaluate_confirmed_bucket_eligibility(
    finding: dict,
    evidence_db: dict | None = None,
) -> dict:
    """Decide whether one finding may enter ``confirmed_malicious_atomic``.

    Deterministic, dataset-agnostic, conservative-by-default. A finding
    is eligible only when every gate passes; any failure routes it out
    of the confirmed bucket. Never special-cases an observed case id.

    Return shape::

        {
          "eligible": bool,
          "blocking_reasons": list[str],
          "malicious_semantic_signals": list[str],
          "environment_context_signals": list[str],
          "gates": {
              "CONFIRMED_BUCKET_EVIDENCE_GATE": "PASS"|"FAIL",
              "NO_SPECULATIVE_CONFIRMED_GATE": "PASS"|"FAIL",
              "NO_EMPTY_SOURCE_CONFIRMED_GATE": "PASS"|"FAIL",
              "MISSING_RAW_EVIDENCE_CONFIRMED_GATE": "PASS"|"FAIL",
              "MALICIOUS_SEMANTIC_GATE": "PASS"|"FAIL",
          },
        }
    """
    reasons: list[str] = []
    gates = {
        "CONFIRMED_BUCKET_EVIDENCE_GATE": "PASS",
        "NO_SPECULATIVE_CONFIRMED_GATE": "PASS",
        "NO_EMPTY_SOURCE_CONFIRMED_GATE": "PASS",
        "MISSING_RAW_EVIDENCE_CONFIRMED_GATE": "PASS",
        "MALICIOUS_SEMANTIC_GATE": "PASS",
        GATE_EXPLICIT_FACT_ID_IN_CLAIMS: "PASS",
        GATE_CLAIM_FACT_REFERENCE: "PASS",
        GATE_SEMANTIC_SIGNAL_PROVENANCE: "PASS",
        GATE_MALICIOUS_SEMANTIC_PROVENANCE: "PASS",
        GATE_NO_PID_ONLY_CONFIRMED: "PASS",
        GATE_REACT_ENTITY_CONFLICT: "PASS",
        GATE_RWX_REQUIRES_CORROBORATION: "PASS",
        GATE_C2_REQUIRES_CORROBORATION: "PASS",
    }

    if not isinstance(finding, dict):
        return {
            "eligible": False,
            "blocking_reasons": ["finding_not_a_dict"],
            "malicious_semantic_signals": [],
            "environment_context_signals": [],
            "gates": {k: "FAIL" for k in gates},
        }

    def _fail(gate: str, reason: str) -> None:
        gates[gate] = "FAIL"
        if reason not in reasons:
            reasons.append(reason)

    # ── Core schema completeness ───────────────────────────────────
    for field in ("finding_id", "title", "severity"):
        val = finding.get(field)
        if field == "title":
            val = finding.get("title") or finding.get("artifact")
        if val in (None, "", []):
            _fail("CONFIRMED_BUCKET_EVIDENCE_GATE",
                  "missing_core_field:%s" % field)

    # ── Confidence: present and not SPECULATIVE ────────────────────
    conf = _confidence_of(finding)
    if not conf:
        _fail("NO_SPECULATIVE_CONFIRMED_GATE", "confidence_missing")
    elif conf == _SPECULATIVE:
        _fail("NO_SPECULATIVE_CONFIRMED_GATE", "confidence_speculative")

    # ── Source attribution (self-correction aware) ─────────────────
    src_tools, tool_call_ids = _effective_attribution(finding)
    if not src_tools:
        _fail("NO_EMPTY_SOURCE_CONFIRMED_GATE", "empty_source_tools")
    if not tool_call_ids:
        _fail("MISSING_RAW_EVIDENCE_CONFIRMED_GATE",
              "missing_tool_call_ids")
    raw_excerpt = finding.get("raw_excerpt")
    if not (isinstance(raw_excerpt, str) and raw_excerpt.strip()):
        _fail("MISSING_RAW_EVIDENCE_CONFIRMED_GATE", "missing_raw_excerpt")

    # ── Checkable claims present ───────────────────────────────────
    claims = [c for c in (finding.get("claims") or []) if isinstance(c, dict)]
    if not claims:
        _fail("CONFIRMED_BUCKET_EVIDENCE_GATE", "no_checkable_claims")

    # ── Typed-fact OR validated-claim support ──────────────────────
    if not _has_typed_or_validated_support(finding, evidence_db):
        _fail("CONFIRMED_BUCKET_EVIDENCE_GATE",
              "no_typed_or_validated_support")

    # ── B5: contradicted ReAct entity is fail-closed out of confirmed ─
    # The coordinator tags a finding whose process/file/network entity
    # carries conflicting ReAct verdicts. Such a finding can never be
    # confirmed_malicious_atomic -- it is needs-review until an
    # entity-level tiebreaker resolves the contradiction.
    if finding.get("react_entity_conflict"):
        _fail(GATE_REACT_ENTITY_CONFLICT, "react_entity_verdict_conflict")

    # ── Slot 31C2-FIX-A: severity-ledger route-out is fail-closed ──
    # The post-Step-13 severity ledger tags a finding as ineligible
    # for confirmed_malicious_atomic when it is self-corrected and
    # backed by a single restricted network/listener/service tool
    # without strong malicious-semantic support. Honour the tag here
    # so the confirmed-bucket eligibility check fails closed even
    # when other fields look strong.
    if finding.get("severity_ledger_route_out"):
        _fail(
            "CONFIRMED_BUCKET_EVIDENCE_GATE",
            "severity_ledger_route_out:%s" % str(
                finding.get("severity_ledger_route_out_reason")
                or "self_corrected_single_tool"
            ),
        )

    # ── No benign / false-positive / inconclusive ReAct verdict ────
    verdict, _ = extract_react_verdict(finding, None)
    if verdict in _REACT_DISQUALIFYING:
        _fail("CONFIRMED_BUCKET_EVIDENCE_GATE",
              "react_verdict_benign_or_false_positive:%s" % verdict)

    # ── Malicious semantic meaning required ────────────────────────
    has_sem, sem_signals = has_malicious_semantic(finding, evidence_db)
    env_signals = environment_context_signals(finding)
    if not has_sem:
        _fail("MALICIOUS_SEMANTIC_GATE", "no_malicious_semantic_signal")
        if env_signals:
            _fail("MALICIOUS_SEMANTIC_GATE", "environment_context_only")
    # RWX-alone is a high-FP signal; require an independent malicious corroborator.
    if rwx_uncorroborated_for_finding(finding, has_sem, sem_signals):
        _fail(GATE_RWX_REQUIRES_CORROBORATION, "rwx_memory_region_uncorroborated")
    # WEAK-ALONE CORROBORATION FLOOR (the weak-alone/FP inversion fix): a finding whose
    # malicious meaning rests ENTIRELY on weak-alone / disk-history signals
    # (executes_from_temp_path -- an installer staged in Temp; private RWX; null
    # cmdline) with NO independent corroborator is not confirm-eligible. This is
    # the same discipline the normal disposition path applies, lifted into the
    # single eligibility gate so an inv3a-promoted confirm cannot bypass it -- a
    # clean-provenance benign installer must not out-rank a corroborated real
    # finding. Kill-switch SIFT_CONFIRM_CORROBORATION_FLOOR=0.
    if has_sem and weak_alone_only_uncorroborated(finding, sem_signals):
        _fail("MALICIOUS_SEMANTIC_GATE", "weak_alone_signal_uncorroborated")
    # A non-vendor cradle domain alone is a high-prior heuristic, not proof; require
    # >= 2 independent structural axes (cradle + obfuscation / injection / DGA-shape).
    if _c2_uncorroborated(finding, has_sem, sem_signals, evidence_db):
        _fail(GATE_C2_REQUIRES_CORROBORATION, "c2_staging_domain_uncorroborated")

    # ── TASK 1: durable validator-attached fact references ─────────
    fact_refs = durable_fact_refs(finding)
    if not fact_refs:
        _fail(GATE_CLAIM_FACT_REFERENCE, "no_durable_fact_refs")
        _fail(GATE_EXPLICIT_FACT_ID_IN_CLAIMS, "no_explicit_fact_id_in_claims")

    # ── TASK 2: malicious semantic signal provenance ───────────────
    sem_support, sem_problems = resolve_semantic_signal_support(
        finding, evidence_db)
    if has_sem:
        if not sem_support:
            _fail(GATE_SEMANTIC_SIGNAL_PROVENANCE,
                  "no_semantic_signal_provenance")
            _fail(GATE_MALICIOUS_SEMANTIC_PROVENANCE,
                  "malicious_semantic_provenance_missing")
        for _p in sem_problems:
            _fail(GATE_SEMANTIC_SIGNAL_PROVENANCE, "sem_support:%s" % _p)
            _fail(GATE_MALICIOUS_SEMANTIC_PROVENANCE,
                  "sem_support:%s" % _p)

    # ── TASK 3: at least one behavioural malicious claim ───────────
    if not has_behavioral_malicious_claim(finding, sem_support):
        _fail(GATE_NO_PID_ONLY_CONFIRMED, "pid_or_process_existence_only")

    eligible = all(v == "PASS" for v in gates.values()) and not reasons
    return {
        "eligible": eligible,
        "blocking_reasons": reasons,
        "malicious_semantic_signals": sem_signals,
        "environment_context_signals": env_signals,
        "semantic_signal_support": sem_support,
        "validator_fact_refs": fact_refs,
        "gates": gates,
    }


def derive_final_disposition(
    finding: dict,
    investigation: dict | None = None,
    evidence_db: dict | None = None,
    eligibility_cache: dict | None = None,
) -> tuple[str, list[str]]:
    """Route one finding to a canonical bucket.

    Returns ``(bucket_name, reasons)``. Composes the three primitives --
    ``extract_react_verdict``, ``is_synthesis_finding`` and
    ``has_strong_typed_support`` -- rather than re-deriving their logic.

    Precedence: benign/FP override -> inconclusive override -> synthesis
    -> CRITICAL|HIGH+LOW truth gate -> unsupported one-claim gate ->
    blocked/error gate -> confirmed_malicious_atomic.
    """
    reasons: list[str] = []

    # 0. B5: contradicted ReAct entity -> needs review, never confirmed.
    if isinstance(finding, dict) and finding.get("react_entity_conflict"):
        reasons.append("override:react_entity_conflict")
        return BUCKET_SUSPICIOUS, reasons

    # 0c. FP-routing pass (env-gated upstream, analysis.fp_routing): a finding
    # flagged benign -- loopback-only behind a benign verdict, or per-entity
    # benign propagation -- routes to benign. Inert unless the flag was set, so
    # default routing is unchanged.
    if isinstance(finding, dict) and finding.get("_fp_routing_benign"):
        reasons.append("override:fp_routing_benign[%s]"
                       % str(finding.get("_fp_routing_reason") or ""))
        return BUCKET_BENIGN, reasons

    # 0d. JIT/UWP benign-RWX gate (env-gated upstream, analysis.jit_rwx_gate): a
    # malfind-RWX finding on a managed/JIT host with no payload and no corroborator
    # is a benign JIT allocation -> benign (downgrade-only, never deleted). Inert
    # unless the flag was set.
    if isinstance(finding, dict) and finding.get("_jit_rwx_downgrade"):
        reasons.append("override:benign_jit_rwx[%s]"
                       % str(finding.get("_jit_rwx_reason") or ""))
        return BUCKET_BENIGN, reasons

    # 0d2. Tool-status-noise gate (analysis.tool_status_noise): a finding that only
    # narrates a tool timeout / empty-result is collection metadata (already in
    # TOOL HEALTH), not a forensic finding -> benign (downgrade-only). Inert unless
    # flagged; the matcher already excluded anything with real path/hash/pid.
    if isinstance(finding, dict) and finding.get("_tool_status_noise"):
        reasons.append("override:tool_status_noise[%s]"
                       % str(finding.get("_tool_status_reason") or ""))
        return BUCKET_BENIGN, reasons

    # 0b. Slot 31C2-FIX-A: a self-corrected finding whose only source is
    # a restricted network/listener/service tool has been tagged by the
    # post-Step-13 severity ledger as ineligible for the confirmed
    # bucket (unless a known malicious_semantic_signal supports it, in
    # which case the tag is not set). Route out, never confirmed.
    if isinstance(finding, dict) and finding.get("severity_ledger_route_out"):
        reasons.append(
            "override:severity_ledger_route_out[%s]"
            % str(
                finding.get("severity_ledger_route_out_reason")
                or "self_corrected_single_tool"
            )
        )
        return BUCKET_SUSPICIOUS, reasons

    verdict, vmeta = extract_react_verdict(finding, investigation)
    reasons.append("react_verdict=%s(%s)" % (
        verdict, vmeta.get("source", "?")))

    # 1. Benign / likely false-positive override.
    if verdict in (_V_BENIGN, _V_LIKELY_FP):
        # SIFT_REACT_BENIGN_VS_ANOMALY_V1: a ReAct binary-legitimacy benign
        # verdict cannot refute a deterministic behavioral-anomaly signal
        # (egress outlier / archive-staging / recovery-inhibition) -- those are
        # about ACTIVITY vs the image's own baseline, not the binary's identity.
        # Hold such a finding for human review; never silently bury it as benign.
        _has_anom, _anom_sigs = has_malicious_semantic(finding, evidence_db)
        _anom = set(_anom_sigs) & _BEHAVIORAL_ANOMALY_SEMANTIC_SIGNALS
        if _has_anom and _anom:
            reasons.append(
                "override:react_benign_vs_behavioral_anomaly[%s]"
                % ",".join(sorted(_anom)))
            return BUCKET_SUSPICIOUS, reasons
        # SIFT_REACT_BENIGN_VS_PERSISTENCE_V1: a ReAct benign verdict cannot refute a
        # CONCLUSIVE structural persistence primitive (IFEO Debugger / non-default
        # SafeBoot) -- the registry-key SHAPE is malicious, not the process identity.
        # Hold for review, never bury as benign.
        _persist = set(_anom_sigs) & _CONCLUSIVE_PERSISTENCE_SIGNALS
        if _persist:
            reasons.append(
                "override:react_benign_vs_persistence[%s]"
                % ",".join(sorted(_persist)))
            return BUCKET_SUSPICIOUS, reasons
        reasons.append("override:benign_or_fp")
        return BUCKET_BENIGN, reasons

    # 2. Inconclusive override.
    if verdict == _V_INCONCLUSIVE:
        reasons.append("override:inconclusive")
        return BUCKET_INCONCLUSIVE, reasons

    # 2b. Conclusive-structural auto-confirm (SIFT_CONCLUSIVE_CONFIRM, default
    # OFF). A signal that is forensically conclusive on its OWN -- malicious by
    # STRUCTURE with no benign explanation (e.g. a kernel driver loaded from
    # outside the System32 driver store) -- does not need a corroboration count
    # to confirm. The predicate is the SIGNAL TYPE, never the count: a
    # non-conclusive finding with the same tools is unaffected. A ReAct benign /
    # FP verdict (handled above) is never overridden, and the finding must still
    # pass the full confirmed-bucket evidence gate. Keyed on the registered
    # conclusive-signal set -- no case / product / hash / PID literal.
    if os.environ.get("SIFT_CONCLUSIVE_CONFIRM", "0").strip().lower() in (
            "1", "true", "yes", "on"):
        _hc, _csigs = has_malicious_semantic(finding, evidence_db)
        _conclusive = set(_csigs) & CONCLUSIVE_STRUCTURAL_SIGNALS
        if _conclusive and not _is_blocked(finding):
            _elig = evaluate_confirmed_bucket_eligibility_cached(
                finding, evidence_db, eligibility_cache)
            if _elig["eligible"]:
                reasons.append("confirm:conclusive_structural[%s]"
                               % ",".join(sorted(_conclusive)))
                return BUCKET_CONFIRMED, reasons
            reasons.append("conclusive_structural_ineligible[%s]"
                           % ",".join(_elig.get("blocking_reasons") or []))

    # 3. Synthesis / attack-chain narrative routing.
    is_syn, syn_signals = is_synthesis_finding(finding)
    if is_syn:
        reasons.append("synthesis[%s]" % ",".join(syn_signals))
        return BUCKET_SYNTHESIS, reasons

    # 4. CRITICAL/HIGH severity carried at LOW confidence.
    if _is_crit_high_low(finding):
        reasons.append("gate:severity_%s+confidence_LOW" % _severity_of(
            finding))
        return BUCKET_SUSPICIOUS, reasons

    # 4b. Environment-context-only routing. A finding whose only
    #     declared semantic content is environment context (an MSI
    #     installer event, a listening port, "process exists") with no
    #     malicious semantic signal is never confirmed malicious -- it
    #     is routed to needs-review regardless of claim count.
    _env_sigs = environment_context_signals(finding)
    if _env_sigs:
        _has_sem, _ = has_malicious_semantic(finding, evidence_db)
        if not _has_sem:
            reasons.append(
                "gate:environment_context_only[%s]"
                % ",".join(_env_sigs)
            )
            return BUCKET_SUSPICIOUS, reasons

    # 5. One-claim protection (needs strong independent typed support).
    claims = finding.get("claims") or []
    strong, strong_reasons = has_strong_typed_support(finding, evidence_db)
    if len(claims) < 2 and not strong:
        reasons.append("gate:one_claim_unsupported[%s]" % ",".join(
            strong_reasons))
        # SIFT_CORROBORATION_FLOOR_ONECLAIM_V1 -- one-claim finding whose only malicious signal
        # is weak-alone / disk-history (or none) with no malicious verdict => benign/FP, not
        # inconclusive (which renders as a Finding). Same dataset-agnostic condition as step-7.
        _has_sem1, _sem1 = has_malicious_semantic(finding, evidence_db)
        _weak1 = (not _sem1) or set(_sem1).issubset(
            _WEAK_ALONE_SEMANTIC_SIGNALS | _DISK_HISTORY_SEMANTIC_SIGNALS)
        if verdict != _V_MALICIOUS and _weak1:
            # SIFT_NO_BENIGN_FOR_NONLOW_SEVERITY_V1: a single-claim finding the
            # validator could not bind is UNVERIFIED, not benign. Bury it as a
            # false positive ONLY when it is genuinely low-signal (LOW /
            # SPECULATIVE severity). A MEDIUM/HIGH/CRITICAL single-claim finding
            # (e.g. a single-source reflective loader, credential-dumping tool,
            # or persistence key) routes to INCONCLUSIVE -- visible for review,
            # never silently dropped as an FP. Universal: severity rank only, no
            # case data; ReAct-confirmed-benign (handled earlier) is unchanged.
            if _severity_of(finding) in ("LOW", _SPECULATIVE, ""):
                reasons.append('benign:one_claim_weak_or_history_only')
                return BUCKET_BENIGN, reasons
            reasons.append(
                'inconclusive:one_claim_unbound_nonlow_severity[%s]'
                % _severity_of(finding))
            return BUCKET_INCONCLUSIVE, reasons
        if verdict == _V_MALICIOUS:
            return BUCKET_SUSPICIOUS, reasons
        # (B) SIFT_DETERMINISTIC_PROVENANCE_V1 -- a DETERMINISTICALLY-emitted finding
        # carrying a registered NON-weak semantic WITH provenance is grounded by
        # construction (like the ancestry deterministic findings): claim-count is
        # the wrong proxy for it. Route to needs-review, not inconclusive. Scoped
        # strictly to deterministic_finding so it never widens model single-claim
        # findings. Review-only -- never confirms.
        if (finding.get("deterministic_finding")
                and _has_sem1 and not _weak1
                and finding.get("malicious_semantic_provenance")):
            reasons.append(
                "override:deterministic_provenance_backed[%s]"
                % ",".join(sorted(_sem1)))
            return BUCKET_SUSPICIOUS, reasons
        return BUCKET_INCONCLUSIVE, reasons

    # 6. Validation / self-verification / deterministic block.
    if _is_blocked(finding):
        reasons.append("gate:validation_blocked")
        return BUCKET_SUSPICIOUS, reasons

    # 7. Confirmed-bucket evidence / semantic eligibility gate.
    #    No path reaches confirmed_malicious_atomic without passing
    #    evaluate_confirmed_bucket_eligibility first (Slot 31E-DB.5.2).
    elig = evaluate_confirmed_bucket_eligibility_cached(
        finding, evidence_db, eligibility_cache)
    if not elig["eligible"]:
        reasons.append(
            "gate:confirmed_ineligible[%s]"
            % ",".join(elig["blocking_reasons"])
        )
        for _gk, _gv in elig["gates"].items():
            if _gv != "PASS":
                reasons.append("%s=FAIL" % _gk)
        # SIFT_CORROBORATION_FLOOR_BENIGN_V1 -- universal corroboration-floor (dataset-agnostic, relabel-only).
        # Malicious signals ONLY weak-alone (RWX / null-cmdline) or disk-history (ShimCache/LNK/JumpList),
        # or none at all, with no independent corroboration and no malicious verdict => benign/FP,
        # not a needs-review finding. Confirmed findings never reach here (they exit eligible below).
        _floor_sem = set(elig.get('malicious_semantic_signals') or [])
        _floor_weak_only = (not _floor_sem) or _floor_sem.issubset(
            _WEAK_ALONE_SEMANTIC_SIGNALS | _DISK_HISTORY_SEMANTIC_SIGNALS)
        if verdict != _V_MALICIOUS and not strong and _floor_weak_only:
            reasons.append('benign:uncorroborated_weak_or_history_only')
            return BUCKET_BENIGN, reasons
        # Speculative / environment-context / benign findings are
        # routed out of confirmed, never suppressed.
        return BUCKET_SUSPICIOUS, reasons
    if elig["malicious_semantic_signals"]:
        reasons.append(
            "malicious_semantic[%s]"
            % ",".join(elig["malicious_semantic_signals"])
        )

    # 8. Confirmed malicious atomic -- all gates cleared.
    if strong:
        reasons.append("strong_typed_support[%s]" % ",".join(strong_reasons))
    reasons.append("confirmed:all_gates_cleared")
    return BUCKET_CONFIRMED, reasons


def reconcile_benign_misroutes(buckets, *, enabled: bool | None = None) -> int:
    """Backstop: a finding in ``suspicious_needs_review`` / ``inconclusive_unresolved``
    whose FINAL state the canonical router scores BENIGN belongs in the benign bucket.

    Why this exists: some benign signals are finalized by passes that run AFTER
    ``route_findings_for_report`` builds the buckets -- the ReAct
    ``react_conclusion`` benign verdict and the ``_fp_routing_benign`` entity-
    propagation flag. The initial routing never saw the final state, so a finding
    the system itself assessed benign stayed mislabeled as needs-review.

    This re-evaluates each such finding with the SAME ``derive_final_disposition``
    and moves it only when that returns ``benign_or_false_positive``. Properties:
      * Universal / dataset-agnostic -- re-uses the router, which keys only on
        structural verdict fields + override flags (no case names, hashes, IPs).
      * Respects override precedence -- ``react_entity_conflict`` /
        ``severity_ledger_route_out`` re-derive to suspicious, so a CONTESTED
        finding is never moved.
      * Downgrade-direction only -- the ``confirmed`` and ``synthesis`` buckets
        are never read or touched; a proven finding can never be demoted here.
      * Idempotent (a moved finding is no longer in the scanned buckets).
      * Kill-switch ``SIFT_BENIGN_RECONCILE=0`` (default ON).
    Returns the number of findings moved.
    """
    if enabled is None:
        enabled = os.environ.get("SIFT_BENIGN_RECONCILE", "1").strip().lower() \
            not in ("0", "false", "no", "off")
    if not enabled or not isinstance(buckets, dict):
        return 0

    def _explicit_benign(f: dict) -> bool:
        # Contested findings forced to suspicious by a HIGHER-priority override
        # are never reconciled (preserve derive_final_disposition precedence).
        if f.get("react_entity_conflict") or f.get("severity_ledger_route_out"):
            return False
        # Explicit benign override FLAGS (the same ones derive honors at the top
        # of routing) -- structural, set by deterministic passes.
        if (f.get("_fp_routing_benign") or f.get("_jit_rwx_downgrade")
                or f.get("_tool_status_noise")):
            return True
        # The finding's OWN ReAct / investigation benign verdict (no external
        # investigations arg -- only the finding's own confirmed_benign /
        # is_false_positive / likely_fp). A weak finding with NO verdict is NOT
        # benign here, so plain needs-review items are left untouched.
        verdict, _ = extract_react_verdict(f, None)
        return verdict in (_V_BENIGN, _V_LIKELY_FP)

    moved = 0
    benign = buckets.setdefault(BUCKET_BENIGN, [])
    for src in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE):
        kept = []
        for f in buckets.get(src, []) or []:
            if isinstance(f, dict) and _explicit_benign(f):
                f["final_disposition"] = BUCKET_BENIGN
                rs = f.get("disposition_reasons")
                if isinstance(rs, list):
                    rs.append("reconcile:late_benign_signal")
                else:
                    f["disposition_reasons"] = ["reconcile:late_benign_signal"]
                benign.append(f)
                moved += 1
            else:
                kept.append(f)
        buckets[src] = kept
    return moved


def route_findings_for_report(
    findings: list[dict],
    investigations: dict | list | None = None,
    evidence_db: dict | None = None,
    eligibility_cache: dict | None = None,
) -> dict:
    """Partition findings into the canonical disposition buckets.

    Every required bucket key is always present (possibly empty). Each
    routed finding is a shallow copy annotated with ``final_disposition``
    and ``disposition_reasons``; the input list is not mutated.

    ``eligibility_cache`` is optional and one-run-only. When supplied,
    repeated eligibility evaluations for the same finding identity +
    evidence mode are served from the cache; bucket membership and
    annotation values are byte-equivalent with or without the cache.
    """
    _clear_view_cache()
    buckets: dict[str, list[dict]] = {b: [] for b in REQUIRED_BUCKETS}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        bucket, reasons = derive_final_disposition(
            finding, investigations, evidence_db, eligibility_cache)
        annotated = dict(finding)
        annotated["final_disposition"] = bucket
        annotated["disposition_reasons"] = reasons
        if bucket == BUCKET_CONFIRMED:
            # Persist the malicious semantic signals that were resolved
            # for THIS run (declared + matcher-derived from the run's
            # evidence_db). Without this, an evidence_db-less re-
            # validation of the routed bucket could not see signals that
            # were genuinely derived during routing, falsely flagging an
            # otherwise-eligible confirmed finding. Provenance, not
            # fabrication: the signals were really matched here.
            _elig = evaluate_confirmed_bucket_eligibility_cached(
                finding, evidence_db, eligibility_cache)
            _resolved = sorted(set(
                list(annotated.get("malicious_semantic_signals") or [])
                + list(_elig.get("malicious_semantic_signals") or [])
            ))
            if _resolved:
                annotated["malicious_semantic_signals"] = _resolved
            # Persist the provenance + fact refs resolved for THIS run so
            # an evidence_db-less re-validation of the routed bucket sees
            # matcher-synthesized support / validator refs (provenance,
            # not fabrication: these were really resolved here).
            _sup = _elig.get("semantic_signal_support") or []
            if _sup and not annotated.get("semantic_signal_support"):
                annotated["semantic_signal_support"] = _sup
            _fr = _elig.get("validator_fact_refs") or []
            if _fr and not durable_fact_refs(annotated):
                annotated["validator_fact_refs"] = _fr
        buckets.setdefault(bucket, []).append(annotated)
    return buckets


def validate_disposition_buckets(
    buckets: dict,
    eligibility_cache: dict | None = None,
) -> list[str]:
    """Mechanically verify bucket integrity.

    Returns a list of explicit violation strings; an empty list means
    PASS. Re-derives truth from each finding's own embedded fields so it
    also catches manual / downstream bucket corruption.

    ``eligibility_cache`` is optional. Validation always calls the
    underlying eligibility evaluator in evidence-less mode
    (``evidence_db=None``); when a cache is supplied those evidence-less
    results may be reused across calls. Evidence-backed eligibility
    results from routing are stored under a different cache key and are
    never reused here -- see ``_eligibility_cache_key``.
    """
    violations: list[str] = []

    if not isinstance(buckets, dict):
        return ["buckets_not_a_dict"]

    for required in REQUIRED_BUCKETS:
        if required not in buckets:
            violations.append("missing_bucket:%s" % required)

    confirmed = buckets.get(BUCKET_CONFIRMED) or []
    for f in confirmed:
        if not isinstance(f, dict):
            violations.append("confirmed:non_dict_entry")
            continue
        fid = f.get("finding_id", "?")

        if f.get("final_disposition") != BUCKET_CONFIRMED:
            violations.append("%s:final_disposition_mismatch" % fid)

        verdict, _ = extract_react_verdict(f, None)
        if verdict in (_V_BENIGN, _V_LIKELY_FP):
            violations.append("%s:benign_or_fp_in_confirmed" % fid)
        if verdict == _V_INCONCLUSIVE:
            violations.append("%s:inconclusive_in_confirmed" % fid)

        is_syn, _ = is_synthesis_finding(f)
        if is_syn:
            violations.append("%s:synthesis_in_confirmed" % fid)

        if _is_crit_high_low(f):
            violations.append(
                "%s:critical_high_low_confidence_in_confirmed" % fid)

        claims = f.get("claims") or []
        strong, _ = has_strong_typed_support(f)
        if len(claims) < 2 and not strong:
            violations.append("%s:unsupported_one_claim_in_confirmed" % fid)

        elig = evaluate_confirmed_bucket_eligibility_cached(
            f, None, eligibility_cache)
        if not elig["eligible"]:
            violations.append(
                "%s:confirmed_bucket_ineligible[%s]"
                % (fid, ",".join(elig["blocking_reasons"]))
            )

    return violations


def _bucket_index(buckets: dict) -> dict[str, str]:
    """finding_id -> bucket name, across all canonical buckets."""
    idx: dict[str, str] = {}
    if not isinstance(buckets, dict):
        return idx
    for name in REQUIRED_BUCKETS:
        for f in buckets.get(name) or []:
            if isinstance(f, dict):
                fid = f.get("finding_id")
                if fid:
                    idx[str(fid)] = name
    return idx


_SYNTHESIS_REF_KEYS = (
    "source_finding_refs", "source_finding_ids", "linked_findings",
    "component_finding_ids", "component_ids", "linked_finding_ids",
)


def render_synthesis_source_components(
    synthesis_finding: dict, buckets: dict,
) -> list[dict]:
    """Resolve every component a synthesis narrative references to its
    actual disposition.

    Slot 31E-DB.5a-alpha TASK 5: a synthesis narrative may summarize
    confirmed items, but a referenced suspicious / inconclusive / benign
    component must be rendered *labeled by its real bucket*
    (``"<bucket>: <title>"``) and must NOT be promoted as a standalone
    confirmed attack-chain fact.

    Returns a list of ``{finding_id, bucket, title, render, promoted}``
    entries (one per resolvable reference).
    """
    idx = _bucket_index(buckets)
    title_idx: dict[str, str] = {}
    for name in REQUIRED_BUCKETS:
        for f in (buckets.get(name) or []) if isinstance(buckets, dict) else []:
            if isinstance(f, dict) and f.get("finding_id"):
                title_idx[str(f["finding_id"])] = str(
                    f.get("title") or f.get("artifact") or f["finding_id"])

    refs: list[str] = []
    for k in _SYNTHESIS_REF_KEYS:
        for r in _nonempty_list(synthesis_finding.get(k)):
            rid = r.get("finding_id") if isinstance(r, dict) else r
            if rid is not None and str(rid) not in refs:
                refs.append(str(rid))

    out: list[dict] = []
    for rid in refs:
        bucket = idx.get(rid, BUCKET_INCONCLUSIVE)
        title = title_idx.get(rid, rid)
        if bucket == BUCKET_CONFIRMED:
            out.append({
                "finding_id": rid, "bucket": bucket, "title": title,
                "render": title, "promoted": True,
            })
        else:
            out.append({
                "finding_id": rid, "bucket": bucket, "title": title,
                "render": "%s: %s" % (bucket, title), "promoted": False,
            })
    return out


def synthesis_source_disposition_gate(
    buckets: dict,
) -> tuple[str, list[str]]:
    """Mechanically verify every synthesis narrative labels its
    non-confirmed referenced components by their real disposition.

    Returns ``(status, violations)`` -- status is
    ``SYNTHESIS_SOURCE_DISPOSITION_GATE=PASS`` when ``violations`` is
    empty. A violation means a non-confirmed component would render as a
    bare confirmed attack-chain fact.
    """
    violations: list[str] = []
    if not isinstance(buckets, dict):
        return "FAIL", ["buckets_not_a_dict"]
    for syn in buckets.get(BUCKET_SYNTHESIS) or []:
        if not isinstance(syn, dict):
            continue
        sid = syn.get("finding_id", "?")
        for comp in render_synthesis_source_components(syn, buckets):
            if comp["bucket"] != BUCKET_CONFIRMED and comp["promoted"]:
                violations.append(
                    "%s:promoted_non_confirmed[%s:%s]"
                    % (sid, comp["bucket"], comp["finding_id"])
                )
            if comp["bucket"] != BUCKET_CONFIRMED and not comp[
                "render"
            ].startswith(comp["bucket"]):
                violations.append(
                    "%s:unlabeled_component[%s]"
                    % (sid, comp["finding_id"])
                )
    return ("PASS" if not violations else "FAIL"), violations


def _finding_identity(finding: dict) -> str:
    """Stable identity for partition accounting.

    ``finding_id`` is the primary key. When absent or duplicated across
    findings, fall back to object identity so two distinct findings that
    both lack an id are still counted as two members, never collapsed.
    """
    fid = finding.get("finding_id")
    if fid:
        return "id:%s" % fid
    return "obj:%d" % id(finding)


def assert_buckets_partition_findings(
    buckets: dict,
    findings_final: list,
) -> list[str]:
    """Return violations proving the buckets partition ``findings_final``.

    Returns an explicit list of violation strings; an empty list means
    the disposition buckets form a clean partition of the calibrated
    findings. Asserts, mechanically:

      * every finding in ``findings_final`` appears in exactly one
        disposition bucket
      * no finding appears in more than one bucket
      * total bucket item count == ``len(findings_final)``
      * every bucket name is one of the five canonical bucket names

    The check is identity-based (``finding_id``, falling back to object
    identity) so it also catches a finding silently dropped, duplicated,
    or moved between buckets downstream of Step 13A.
    """
    violations: list[str] = []

    if not isinstance(buckets, dict):
        return ["buckets_not_a_dict"]
    if not isinstance(findings_final, list):
        return ["findings_final_not_a_list"]

    # 1. Every bucket name must be canonical.
    for name in buckets:
        if name not in REQUIRED_BUCKETS:
            violations.append("unknown_bucket:%s" % name)

    # 2. Every required bucket must be present.
    for required in REQUIRED_BUCKETS:
        if required not in buckets:
            violations.append("missing_bucket:%s" % required)

    # 3. Build identity -> [bucket, ...] occupancy across canonical
    #    buckets only (unknown buckets already flagged above).
    occupancy: dict[str, list[str]] = {}
    total_items = 0
    for name in REQUIRED_BUCKETS:
        entries = buckets.get(name) or []
        if not isinstance(entries, (list, tuple)):
            violations.append("bucket_not_a_list:%s" % name)
            continue
        for entry in entries:
            total_items += 1
            if not isinstance(entry, dict):
                violations.append("%s:non_dict_entry" % name)
                continue
            ident = _finding_identity(entry)
            occupancy.setdefault(ident, []).append(name)

    # 4. Count parity.
    if total_items != len(findings_final):
        violations.append(
            "count_mismatch:bucket_total=%d findings_final=%d"
            % (total_items, len(findings_final))
        )

    # 5. Every finding present exactly once; none duplicated.
    for finding in findings_final:
        if not isinstance(finding, dict):
            violations.append("findings_final:non_dict_entry")
            continue
        ident = _finding_identity(finding)
        seen_in = occupancy.get(ident, [])
        fid = finding.get("finding_id", "?")
        if not seen_in:
            violations.append("%s:absent_from_all_buckets" % fid)
        elif len(seen_in) > 1:
            violations.append(
                "%s:in_multiple_buckets[%s]" % (fid, ",".join(seen_in))
            )

    # 6. Any bucketed identity not traceable back to findings_final is a
    #    duplicate / injected entry.
    final_idents = {
        _finding_identity(f) for f in findings_final if isinstance(f, dict)
    }
    for ident, places in occupancy.items():
        if ident not in final_idents:
            violations.append(
                "orphan_in_buckets:%s[%s]" % (ident, ",".join(places))
            )
        elif len(places) > 1:
            # Already reported per-finding above when the finding is in
            # findings_final; keep a bucket-side record for completeness.
            violations.append(
                "duplicate_identity:%s[%s]" % (ident, ",".join(places))
            )

    # De-dup while preserving order (multiple paths can flag the same
    # underlying problem).
    seen: set[str] = set()
    ordered: list[str] = []
    for v in violations:
        if v not in seen:
            seen.add(v)
            ordered.append(v)
    return ordered
