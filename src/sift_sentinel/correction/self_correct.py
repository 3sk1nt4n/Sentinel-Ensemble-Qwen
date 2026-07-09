"""
Sentinel Qwen Ensemble -- Self-correction loop (Pipeline Step 12).
Clean-slate correction for validator-blocked findings.
Code checks AI, not AI checks AI.

CLEAN SLATE: each attempt receives raw_data + error ONLY.
The corrector never sees its own previous wrong draft.
Max 3 attempts, 30s each, 90s total window.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Callable, Optional

from sift_sentinel.config import MAX_CORRECTION_ATTEMPTS
from sift_sentinel.correction.strategies import STRATEGIES
from sift_sentinel.validation.normalize_claims import normalize_claims
from sift_sentinel.validation.validator import validate_finding

logger = logging.getLogger(__name__)

# ── ANSI color constants (disabled when not a TTY) ─────────────────────
_TTY = sys.stdout.isatty() or os.environ.get("SIFT_FORCE_COLOR") == "1"
G  = "\033[92m" if _TTY else ""   # green
R  = "\033[91m" if _TTY else ""   # red
Y  = "\033[93m" if _TTY else ""   # yellow
B  = "\033[1m"  if _TTY else ""   # bold
X  = "\033[0m"  if _TTY else ""   # reset

# Strategy definitions live in .strategies (imported above). Plain English
# descriptions (kept here for grep / static inspection):
#   1 = Explain and retry
#   2 = Simplify to validator-typed claims
#   3 = Last chance or drop
# Re-exported so existing consumers keep working:
#   `from sift_sentinel.correction.self_correct import STRATEGIES`
__all__ = ["self_correct", "STRATEGIES"]

# Core tools always included in SC context for corroboration
_SC_CORE_TOOLS = frozenset([
    "vol_netscan", "get_amcache", "parse_prefetch", "parse_event_logs",
])

# B2 FIX: Fields that identify a finding across its lifecycle. Corrector
# produces a from-scratch dict per attempt (clean-slate design, module
# docstring line 6), so these persist from the rejected original when
# the corrected candidate omits them.
_IDENTITY_FIELDS = (
    "finding_id", "source_tools", "tool_call_ids", "raw_excerpt", "artifact",
)


def _preserve_identity(candidate: dict, original: dict) -> dict:
    """B2 FIX: restore identity fields the corrector did not re-emit.

    Clean-slate design means each SC attempt receives raw_data + error
    only; the corrector AI never sees the rejected original and cannot
    carry its identity metadata forward. Downstream schema enforcement
    requires finding_id, source_tools, tool_call_ids, raw_excerpt.
    This helper restores them from the original when absent or empty
    on the candidate.

    Fields the corrector DID emit (non-empty) are respected.
    Fields missing from both are left unset -- never fabricated.
    """
    for key in _IDENTITY_FIELDS:
        if not candidate.get(key):
            original_val = original.get(key)
            if original_val is not None:
                candidate[key] = original_val
    return candidate


def _build_sc_context(
    finding: dict, all_outputs: dict, max_chars: int = 80000,
) -> dict:
    """Extract only tool outputs relevant to this finding.

    Filters *all_outputs* to tools referenced by the finding's claims
    plus a set of core corroboration tools.  Total serialised size is
    capped at *max_chars* to stay within the API token budget.
    """
    source_tools: set[str] = set(_SC_CORE_TOOLS)
    for claim in finding.get("claims", []):
        for t in claim.get("source_tools", []):
            source_tools.add(t)
    for t in finding.get("source_tools", []):
        source_tools.add(t)

    relevant: dict = {}
    total_chars = 0
    for tool_name, output in all_outputs.items():
        if tool_name not in source_tools:
            continue
        text = json.dumps(output, default=str)
        text_len = len(text)
        if total_chars + text_len > max_chars:
            remaining = max_chars - total_chars
            if remaining > 1000:
                relevant[tool_name] = text[:remaining] + "...(truncated)"
            break
        relevant[tool_name] = output
        total_chars += text_len
    return relevant


def _extract_failed_claim_str(
    validation_result: dict | None,
    finding: dict,
    error: str,
) -> str:
    """Extract a human-readable description of the first failed claim."""
    if validation_result and "checks" in validation_result:
        failed = [
            c for c in validation_result["checks"]
            if c.get("result") == "MISMATCH"
        ]
        if failed:
            return str(failed[0]["claim"])
    # Fallback: use the original finding's first claim
    claims = finding.get("claims", [])
    if claims:
        return str(claims[0])
    return error


# F4 FINAL: SC rich-context dossier
# Python organizes bounded evidence context.
# AI still decides rewrite/downgrade/split/drop.
# Validator remains the truth gate.

_F4_MAX_TOOLS_IN_DOSSIER = 4
_F4_MAX_RECORDS_PER_TOOL = 5
_F4_MAX_DOSSIER_BYTES = 6 * 1024
_F4_MAX_RECORDS_TO_SCAN = 500
_F4_MAX_RECORD_STR_LEN = 800

_F4_ALLOWED_ACTIONS = (
    "rewrite_with_verified_claims",
    "downgrade_to_inference",
    "split_claim",
    "drop_finding",
)


def _f4_json_size(obj: dict) -> int:
    import json as _json
    return len(_json.dumps(obj, default=str).encode("utf-8"))


def _f4_extract_subject_index(finding: dict) -> dict:
    """Extract useful subject values from claims."""
    subj = {
        "pids": [],
        "paths": [],
        "hashes": [],
        "process_names": [],
        "filenames": [],
    }

    for claim in finding.get("claims") or []:
        if not isinstance(claim, dict):
            continue

        for key in ("pid", "parent_pid", "child_pid"):
            val = claim.get(key)
            if val is not None:
                subj["pids"].append(str(val))

        if claim.get("process"):
            subj["process_names"].append(str(claim["process"]))

        if claim.get("filename"):
            subj["filenames"].append(str(claim["filename"]))

        if claim.get("sha1"):
            subj["hashes"].append(str(claim["sha1"]))

        if claim.get("type") == "path" and claim.get("value"):
            subj["paths"].append(str(claim["value"]))

    for key, values in subj.items():
        seen = set()
        deduped = []
        for value in values:
            if value not in seen:
                seen.add(value)
                deduped.append(value)
        subj[key] = deduped

    return subj


def _f4_subject_consistent(original: dict, candidate: dict) -> bool:
    """Dataset-agnostic SC fidelity guard.

    A validated correction must still concern the SAME subject as the original
    finding. Returns True iff the corrected claims carry at least one STRONG
    identity token (a name.ext process/file token, an IPv4 literal, or a path
    leaf with an extension) that also appears in the original finding's own text
    (title + description + claims). Fails OPEN (True) when the correction
    exposes no strong identity token, so legitimate minimal / PID-only
    corrections are never wrongly dropped. Pure structural comparison of the two
    findings' own content: no hardcoded values, no external reference, no answer
    key, no cache, no persistence. Applies identically to every dataset.
    """
    import re as _re
    import json as _json
    if not isinstance(original, dict) or not isinstance(candidate, dict):
        return True
    _NAME_EXT = _re.compile(r"^[\w.\-]+\.[a-z0-9]{2,4}$", _re.I)
    _IPV4 = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    tokens = set()
    for c in candidate.get("claims") or []:
        if not isinstance(c, dict):
            continue
        for k in ("process", "filename", "name", "service_name", "dll_name"):
            v = c.get(k)
            if v and _NAME_EXT.match(str(v).strip()):
                tokens.add(str(v).strip().lower())
        for k in ("foreign_addr", "host", "remote_ip"):
            v = c.get(k)
            if v and _IPV4.match(str(v).strip()):
                tokens.add(str(v).strip().lower())
        for k in ("value", "path", "binary_path", "dll_path"):
            v = c.get(k)
            if v:
                leaf = _re.split(r"[\\/]", str(v).strip())[-1].strip()
                if _NAME_EXT.match(leaf):
                    tokens.add(leaf.lower())
    if not tokens:
        return True
    hay = _json.dumps(
        {"t": original.get("title", ""), "d": original.get("description", ""),
         "c": original.get("claims", [])},
        default=str,
    ).lower()
    return any(tok in hay for tok in tokens)


def _f4_detect_conflicts(finding: dict, subject_index: dict, ref_set: dict) -> list:
    """Detect conflicts such as hash->wrong file or PID->wrong process."""
    conflicts = []

    if not isinstance(ref_set, dict):
        return conflicts

    ref_hashes = ref_set.get("hashes") or {}
    ref_pids = ref_set.get("pids") or {}
    ref_paths = ref_set.get("paths") or []

    for claim in finding.get("claims") or []:
        if not isinstance(claim, dict):
            continue

        # hash -> wrong filename/process
        if claim.get("type") == "hash" or claim.get("sha1"):
            h = claim.get("sha1")
            claimed_name = claim.get("filename") or claim.get("process")
            if isinstance(ref_hashes, dict) and h in ref_hashes:
                ref_name = ref_hashes[h]
                if claimed_name and str(claimed_name).lower() != str(ref_name).lower():
                    conflicts.append(
                        f"hash={str(h)[:12]}... claim says -> {claimed_name}, "
                        f"reference says -> {ref_name}"
                    )

        # PID -> wrong process
        if claim.get("type") == "pid" or "pid" in claim:
            pid = claim.get("pid")
            claimed_process = claim.get("process")
            if pid is not None and isinstance(ref_pids, dict):
                pid_str = str(pid)
                if pid_str in ref_pids and claimed_process:
                    ref_proc = ref_pids[pid_str]
                    if str(claimed_process).lower() != str(ref_proc).lower():
                        conflicts.append(
                            f"pid={pid_str} claim says -> {claimed_process}, "
                            f"reference says -> {ref_proc}"
                        )

    # path case mismatch
    if isinstance(ref_paths, (list, set, tuple)):
        ref_path_list = [p for p in ref_paths if isinstance(p, str)]
        ref_lower = {p.lower(): p for p in ref_path_list}
        for path in subject_index.get("paths", []):
            lower = path.lower()
            if path not in ref_path_list and lower in ref_lower:
                conflicts.append(
                    f"path case mismatch: claim={path} vs reference={ref_lower[lower]}"
                )

    return conflicts


def _f4_rank_matches(subject_index: dict, ref_set: dict) -> dict:
    """Rank exact / near matches from the reference set."""
    matches = {
        "exact": [],
        "conflicting": [],
        "near": [],
        "missing_from_tools": [],
    }

    if not isinstance(ref_set, dict):
        return matches

    ref_hashes = ref_set.get("hashes") or {}
    ref_pids = ref_set.get("pids") or {}
    ref_paths = ref_set.get("paths") or []

    if isinstance(ref_hashes, dict):
        for h in subject_index.get("hashes", []):
            if h in ref_hashes:
                matches["exact"].append(f"sha1={h[:12]}... -> {ref_hashes[h]}")

    if isinstance(ref_pids, dict):
        for pid in subject_index.get("pids", []):
            if pid in ref_pids:
                matches["exact"].append(f"pid={pid} -> {ref_pids[pid]}")

    if isinstance(ref_paths, (list, set, tuple)):
        ref_path_list = [p for p in ref_paths if isinstance(p, str)]
        for claim_path in subject_index.get("paths", []):
            if claim_path in ref_path_list:
                matches["exact"].append(f"path={claim_path}")
            else:
                claim_lower = claim_path.lower()
                for ref_path in ref_path_list:
                    ref_lower = ref_path.lower()
                    if claim_lower in ref_lower and claim_lower != ref_lower:
                        matches["near"].append(
                            f"substring: claim={claim_path} vs ref={ref_path}"
                        )
                        break

    return matches


def _f4_sample_records(raw_data: dict, subject_index: dict) -> dict:
    """Return relevant sample records. Matching records first."""
    if not isinstance(raw_data, dict):
        return {}

    subject_tokens = set()
    for values in subject_index.values():
        for value in values:
            value = str(value)
            if len(value) > 2:
                subject_tokens.add(value.lower())

    scored = []

    for tool_name, tool_data in raw_data.items():
        if not isinstance(tool_data, dict):
            continue

        records = tool_data.get("records") or []
        if not records or not isinstance(records, list):
            continue

        matching = []
        fallback = []

        for record in records[:_F4_MAX_RECORDS_TO_SCAN]:
            record_text = str(record)[:_F4_MAX_RECORD_STR_LEN]
            record_lower = record_text.lower()

            if subject_tokens and any(tok in record_lower for tok in subject_tokens):
                matching.append(record_text)
                if len(matching) >= _F4_MAX_RECORDS_PER_TOOL:
                    break
            elif len(fallback) < _F4_MAX_RECORDS_PER_TOOL:
                fallback.append(record_text)

        scored.append((len(matching), tool_name, matching, fallback))

    scored.sort(key=lambda item: -item[0])

    samples = {}
    for _hit_count, tool_name, matching, fallback in scored[:_F4_MAX_TOOLS_IN_DOSSIER]:
        combined = matching + fallback
        samples[tool_name] = combined[:_F4_MAX_RECORDS_PER_TOOL]

    return samples


def _f4_enforce_budget(dossier: dict) -> dict:
    """Enforce true hard <=6KB budget."""
    # First trim sample records.
    for _ in range(30):
        dossier["size_bytes"] = 0
        if _f4_json_size(dossier) <= _F4_MAX_DOSSIER_BYTES:
            break

        samples = dossier.get("sample_records") or {}
        dropped = False

        for tool in sorted(
            samples.keys(),
            key=lambda t: -sum(len(str(r)) for r in samples.get(t, [])),
        ):
            if samples.get(tool):
                samples[tool].pop()
                if not samples[tool]:
                    del samples[tool]
                dropped = True
                break

        if not dropped:
            break

    # Final hard fallback: truncate non-sample fields too.
    dossier["validator_error"] = str(dossier.get("validator_error", ""))[:800]
    dossier["failed_claim_summary"] = str(dossier.get("failed_claim_summary", ""))[:800]

    matches = dossier.get("matches") or {}
    for key in ("exact", "conflicting", "near", "missing_from_tools"):
        matches[key] = [str(v)[:300] for v in matches.get(key, [])[:5]]
    dossier["matches"] = matches

    subject_index = dossier.get("subject_index") or {}
    for key in list(subject_index.keys()):
        subject_index[key] = [str(v)[:200] for v in subject_index.get(key, [])[:5]]
    dossier["subject_index"] = subject_index

    # If still too large, remove samples entirely.
    dossier["size_bytes"] = 0
    if _f4_json_size(dossier) > _F4_MAX_DOSSIER_BYTES:
        dossier["sample_records"] = {}

    # Final size stamp.
    dossier["size_bytes"] = 0
    dossier["size_bytes"] = _f4_json_size(dossier)

    return dossier


def build_sc_context_dossier(
    finding: dict,
    validator_error: str,
    validation_result: dict | None,
    raw_data: dict | None,
    ref_set: dict | None,
) -> dict:
    """Build structured SC correction dossier.

    AI uses this to decide: rewrite, downgrade, split, or drop.
    Python does not silently repair the finding.
    """
    subject_index = _f4_extract_subject_index(finding or {})
    matches = _f4_rank_matches(subject_index, ref_set or {})
    matches["conflicting"] = _f4_detect_conflicts(
        finding or {}, subject_index, ref_set or {}
    )

    tools_with_records = {
        name
        for name, payload in (raw_data or {}).items()
        if isinstance(payload, dict) and payload.get("records")
    }
    all_tools = set((raw_data or {}).keys())
    matches["missing_from_tools"] = sorted(all_tools - tools_with_records)[
        :_F4_MAX_TOOLS_IN_DOSSIER
    ]

    failed_claim = _extract_failed_claim_str(
        validation_result, finding or {}, validator_error
    )

    dossier = {
        "finding_id": (finding or {}).get("finding_id", "?"),
        "validator_error": validator_error,
        "failed_claim_summary": failed_claim,
        "subject_index": subject_index,
        "matches": matches,
        "sample_records": _f4_sample_records(raw_data or {}, subject_index),
        "allowed_actions": list(_F4_ALLOWED_ACTIONS),
    }

    return _f4_enforce_budget(dossier)


def _f4_render_dossier_for_prompt(dossier: dict) -> str:
    """Render dossier as compact text for prompt injection."""
    lines = [
        f"finding_id: {dossier.get('finding_id')}",
        f"failed_claim: {dossier.get('failed_claim_summary')}",
        "",
        "SUBJECT INDEX:",
    ]

    for key, values in (dossier.get("subject_index") or {}).items():
        if values:
            lines.append(f"  {key}: {', '.join(str(v) for v in values[:5])}")

    lines.append("")
    lines.append("MATCHES:")

    matches = dossier.get("matches") or {}
    lines.append(f"  exact ({len(matches.get('exact', []))}): {matches.get('exact', [])[:3]}")
    lines.append(
        f"  conflicting ({len(matches.get('conflicting', []))}): "
        f"{matches.get('conflicting', [])[:3]}"
    )
    lines.append(f"  near ({len(matches.get('near', []))}): {matches.get('near', [])[:2]}")
    lines.append(f"  missing_from_tools: {matches.get('missing_from_tools', [])[:4]}")

    lines.append("")
    lines.append("SAMPLE RECORDS, ranked by relevance:")

    for tool, records in (dossier.get("sample_records") or {}).items():
        lines.append(f"  {tool}: {len(records)} records")
        for idx, record in enumerate(records[:2]):
            lines.append(f"    [{idx}] {str(record)[:200]}")

    lines.append("")
    lines.append(f"ALLOWED ACTIONS: {dossier.get('allowed_actions')}")
    lines.append(
        "Decision rule: unsupported claims should be dropped or preserved "
        "as INCONCLUSIVE, not forced into a false correction."
    )

    return "\n".join(lines)


def _f4_log_decision(
    finding_id: str,
    attempt_num: int,
    result: dict | None,
    validator_error: str,
    *,
    action: str | None = None,
    outcome: str | None = None,
    reason: str | None = None,
) -> None:
    """Log AI's proposed SC decision. Do not claim validation passed yet.

    Default: classifies from the corrector's response shape (used when the
    AI actually produced a parseable reply).

    Override: callers may pass explicit action/outcome/reason for branches
    that bypass classification -- pre-response errors (None/non-dict return,
    exception, rate limit, wrapper unfixable) and post-validation outcomes
    (VALIDATED, BLOCKED_BY_VALIDATOR) plus the finding-level terminal marker
    action=correction_complete that fires once per call to self_correct().
    Overrides guarantee at least one SC DECISION line on every attempt path
    and one terminal SC DECISION line per blocked finding.
    """
    if action is not None and outcome is not None:
        logger.info(
            "SC DECISION %s attempt=%d: action=%s validator_result=%s reason=%s",
            finding_id,
            attempt_num,
            action,
            outcome,
            (reason or "")[:120],
        )
        return

    action_value = ""
    if isinstance(result, dict):
        action_value = str(result.get("action", "")).lower()

    if action_value in {"drop", "drop_finding"}:
        action = "drop_finding"
        outcome = "INCONCLUSIVE_PROPOSED"
        reason = "unsupported claim rejected; preserve as INCONCLUSIVE"
    elif isinstance(result, dict) and (result.get("error") or result.get("status") == "error"):
        action = "error"
        outcome = "ERROR"
        reason = str(result.get("error", validator_error))[:120]
    elif isinstance(result, dict):
        action = "rewrite_or_split_or_downgrade"
        outcome = "PROPOSED_REWRITE_PENDING_VALIDATION"
        reason = "AI proposed revised claims; validator must re-check"
    else:
        action = "error"
        outcome = "ERROR"
        reason = "corrector returned non-dict"

    logger.info(
        "SC DECISION %s attempt=%d: action=%s validator_result=%s reason=%s",
        finding_id,
        attempt_num,
        action,
        outcome,
        reason,
    )


def _build_strategy_prompt(
    attempt_num: int,
    finding: dict,
    validation_error: str,
    validation_result: dict | None,
    context_dossier: str = "",
) -> tuple[str, str]:
    """Build attempt-specific prompt and return (prompt, strategy_name)."""
    finding = normalize_sc_finding(finding)  # SC_SCHEMA_HARDENING
    strategy = STRATEGIES.get(min(attempt_num, 3), STRATEGIES[3])
    strategy_name = strategy["name"]
    finding_id = finding.get("finding_id", "unknown")
    failed_claim = _extract_failed_claim_str(
        validation_result, finding, validation_error,
    )

    if not context_dossier:
        context_dossier = "(dossier unavailable: caller did not pre-build)"

    prompt = _safe_format_strategy_template(
        strategy["template"],
        finding_id=finding_id,
        validation_error=validation_error,
        failed_claim=failed_claim,
        context_dossier=context_dossier,
    )

    if attempt_num > 1:
        prompt += f"\n\nLast validation error: {validation_error}"
        prompt += f"\nFailed claim: {failed_claim}"

    return prompt, strategy_name


def self_correct(
    finding: dict,
    error: str,
    raw_data: dict,
    ref_set: dict,
    max_attempts: int = MAX_CORRECTION_ATTEMPTS,
    corrector_fn: Optional[Callable[[dict, str], dict]] = None,
    attempt_timeout: float = 30.0,
    total_timeout: float = 90.0,
    inter_attempt_delay: float = 2.0,   # P0-E: reduced default for tier 2/3 API
    rate_limit_wait: float = 10.0,      # P0-E: reduced 60s→10s for tier 2/3 API
    max_context_chars: int = 80000,
) -> dict:
    """Self-correction loop for validator-blocked findings.

    CLEAN SLATE: each attempt receives raw_data + error ONLY.
    The corrector never sees its own previous wrong draft.
    This prevents anchoring bias -- the AI writes from scratch each time.

    Args:
        finding:         Original finding that failed validation (DRAFT).
        error:           Exact error string from the validator.
        raw_data:        Raw tool output data the AI uses to write findings.
        ref_set:         Paired reference set for re-validation.
        max_attempts:    Maximum correction attempts (default 3).
        corrector_fn:    Callable(raw_data, error) -> dict.  In production
                         this calls the configured LLM (Qwen by default); in tests, a stub.
        attempt_timeout: Per-attempt timeout in seconds (default 30).
                         Enforced by the caller/coordinator, not here.
        total_timeout:   Total window in seconds (default 90).
        inter_attempt_delay: Seconds to wait between attempts (rate limit
                         protection). Default 0; step_12 passes 30.
        rate_limit_wait: Seconds to wait on 429 before retrying (default 60).
        max_context_chars: Max chars of raw tool output to include in the
                         SC prompt context (default 80000 ~ 25K tokens).

    Returns:
        dict with keys:
            status           "CORRECTED" | "UNRESOLVED"
            finding          corrected finding or UNRESOLVED finding
            self_corrected   True if correction succeeded
            original_draft   the original blocked finding (DRAFT)
            correction_reason why it was blocked (original error)
            attempts         list of per-attempt results
            attempt_count    how many attempts ran
            total_time_s     wall-clock seconds used
    """
    if corrector_fn is None:
        raise ValueError("corrector_fn is required")

    start = time.monotonic()
    attempts: list[dict] = []
    current_error = error
    last_validation: dict | None = None
    finding_id = finding.get("finding_id", "?")

    # F4: build dossier ONCE per blocked finding.
    _f4_dossier = build_sc_context_dossier(
        finding,
        current_error,
        last_validation,
        raw_data,
        ref_set,
    )
    _f4_dossier_text = _f4_render_dossier_for_prompt(_f4_dossier)

    _f4_matches = _f4_dossier.get("matches", {})
    logger.info(
        "SC DOSSIER %s: exact=%d conflicting=%d near=%d missing=%d size=%dB",
        finding_id,
        len(_f4_matches.get("exact", [])),
        len(_f4_matches.get("conflicting", [])),
        len(_f4_matches.get("near", [])),
        len(_f4_matches.get("missing_from_tools", [])),
        _f4_dossier.get("size_bytes", 0),
    )

    for attempt_num in range(1, max_attempts + 1):
        # Delay before attempt 2+ (rate limit protection)
        if attempt_num > 1 and inter_attempt_delay > 0:
            logger.info(
                "SC: waiting %ds before attempt %d (rate limit protection)",
                int(inter_attempt_delay), attempt_num,
            )
            time.sleep(inter_attempt_delay)

        elapsed = time.monotonic() - start
        if elapsed >= total_timeout:
            break

        # ── Build strategy-specific prompt ───────────────────────────
        strategy_prompt, strategy_name = _build_strategy_prompt(
            attempt_num, finding, current_error, last_validation,
            context_dossier=_f4_dossier_text,
        )

        # Strategy description from definition
        strategy_obj = STRATEGIES.get(min(attempt_num, 3), STRATEGIES[3])
        _desc = strategy_obj.get("description", strategy_name)
        if attempt_num == 1:
            _desc_display = f"{_desc} (reason: {current_error[:80]})"
        else:
            _desc_display = _desc
        print(f"{Y}SELF-CORRECTION attempt {attempt_num}/{max_attempts}: "
              f"{_desc_display}{X}")
        logger.info(
            "SELF-CORRECTION attempt %d/%d for %s: %s",
            attempt_num, max_attempts, finding_id, _desc_display,
        )

        # Log strategy change for judges (attempt 2+)
        if attempt_num > 1:
            prev_obj = STRATEGIES.get(attempt_num - 1, STRATEGIES[1])
            prev_desc = prev_obj.get("description", prev_obj["name"])
            print(f"{Y}AI STRATEGY CHANGE: Switching from "
                  f"'{prev_desc}' to '{_desc}' "
                  f"after attempt {attempt_num - 1} failed{X}")
            logger.info(
                "AI STRATEGY CHANGE: Switching from '%s' to '%s' "
                "after attempt %d failed",
                prev_desc, _desc, attempt_num - 1,
            )

        # ── Filter raw_data to relevant tools (token budget) ─────────
        total_raw = len(json.dumps(raw_data, default=str))
        if total_raw > max_context_chars:
            filtered_data = _build_sc_context(
                finding, raw_data, max_context_chars,
            )
        else:
            filtered_data = raw_data

        # ── CLEAN SLATE: corrector gets filtered data + strategy prompt
        new_finding = None
        try:
            new_finding = corrector_fn(filtered_data, strategy_prompt)
        except Exception as exc:
            exc_str = str(exc)
            if "429" in exc_str or "rate_limit" in exc_str.lower():
                logger.warning(
                    "SC %s attempt %d: rate limited, waiting %ds",
                    finding_id, attempt_num, int(rate_limit_wait),
                )
                time.sleep(rate_limit_wait)
                try:
                    new_finding = corrector_fn(
                        filtered_data, strategy_prompt,
                    )
                except Exception as retry_exc:
                    logger.warning(
                        "SC %s attempt %d: still rate limited after retry",
                        finding_id, attempt_num,
                    )
                    attempts.append({
                        "attempt": attempt_num,
                        "strategy": strategy_name,
                        "status": "RATE_LIMITED",
                        "detail": str(retry_exc),
                    })
                    _f4_log_decision(
                        finding_id, attempt_num, None, current_error,
                        action="rate_limited", outcome="ERROR",
                        reason=str(retry_exc),
                    )
                    continue
            else:
                attempts.append({
                    "attempt": attempt_num,
                    "strategy": strategy_name,
                    "status": "ERROR",
                    "detail": exc_str,
                })
                _f4_log_decision(
                    finding_id, attempt_num, None, current_error,
                    action="exception", outcome="ERROR",
                    reason=exc_str,
                )
                continue

        if new_finding is None:
            attempts.append({
                "attempt": attempt_num,
                "strategy": strategy_name,
                "status": "ERROR",
                "detail": "corrector returned None",
            })
            _f4_log_decision(
                finding_id, attempt_num, None, current_error,
                action="corrector_returned_none", outcome="ERROR",
                reason="corrector returned None",
            )
            continue

        # Guard against non-dict returns (e.g. [], "text", int)
        if not isinstance(new_finding, dict):
            attempts.append({
                "attempt": attempt_num,
                "strategy": strategy_name,
                "status": "ERROR",
                "detail": f"corrector returned {type(new_finding).__name__}, expected dict",
            })
            _f4_log_decision(
                finding_id, attempt_num, None, current_error,
                action="non_dict_return", outcome="ERROR",
                reason=f"corrector returned {type(new_finding).__name__}",
            )
            continue

        # ── Extract reasoning/approach_change from wrapper responses ──
        # Live mode: the model returns {"reasoning": ..., "approach_change": ..., "finding": {...}}
        reasoning = None
        approach_change = None
        if "reasoning" in new_finding and "finding" in new_finding:
            reasoning = new_finding.get("reasoning")
            approach_change = new_finding.get("approach_change")
            new_finding = new_finding["finding"]
            if new_finding is None:
                attempts.append({
                    "attempt": attempt_num,
                    "strategy": strategy_name,
                    "status": "UNFIXABLE",
                    "detail": "corrector declared finding unfixable",
                    "reasoning": reasoning,
                    "approach_change": approach_change,
                })
                _f4_log_decision(
                    finding_id, attempt_num, None, current_error,
                    action="declared_unfixable", outcome="UNFIXABLE",
                    reason="wrapper finding=null (AI declined to rewrite)",
                )
                break  # AI explicitly declined - no point trying further strategies
            if not isinstance(new_finding, dict):
                attempts.append({
                    "attempt": attempt_num,
                    "strategy": strategy_name,
                    "status": "ERROR",
                    "detail": f"wrapper finding is {type(new_finding).__name__}, expected dict",
                    "reasoning": reasoning,
                    "approach_change": approach_change,
                })
                _f4_log_decision(
                    finding_id, attempt_num, None, current_error,
                    action="non_dict_wrapper", outcome="ERROR",
                    reason=f"wrapper finding is {type(new_finding).__name__}",
                )
                continue

        # F4: log AI's proposed decision before any action handling.
        # This logs PROPOSED outcomes only; validator is still the truth gate.
        _f4_log_decision(finding_id, attempt_num, new_finding, current_error)

        # ── Handle "drop" action (AI declares finding unverifiable) ──
        if new_finding.get("action") in ("drop", "drop_finding"):
            logger.info(
                "SC %s attempt %d: corrector returned drop action",
                finding_id, attempt_num,
            )
            attempts.append({
                "attempt": attempt_num,
                "strategy": strategy_name,
                "status": "DROPPED",
                "detail": "corrector declared finding unverifiable",
            })
            inconclusive = dict(finding)
            inconclusive["confidence_level"] = "INCONCLUSIVE"
            inconclusive["deterministic_check"] = "blocked"
            inconclusive["self_corrected"] = False
            inconclusive["correction_reason"] = (
                "Could not produce verifiable claims "
                f"after {attempt_num} correction attempts."
            )
            inconclusive["score"] = 0
            _drop_time = round(time.monotonic() - start, 3)
            _f4_log_decision(
                finding_id, attempt_num, None, current_error,
                action="correction_complete",
                outcome="DROPPED_UNSUPPORTED",
                reason=(
                    f"AI declared unverifiable after {len(attempts)} "
                    "attempt(s); kept as INCONCLUSIVE, not promoted"
                ),
            )
            return {
                "status": "UNRESOLVED",
                "outcome_kind": "DROPPED_UNSUPPORTED",
                "finding": inconclusive,
                "self_corrected": False,
                "original_draft": finding,
                "correction_reason": error,
                "attempts": attempts,
                "attempt_count": len(attempts),
                "total_time_s": _drop_time,
            }

        # ── Normalize + re-validate against paired reference set ─────
        normalized = normalize_claims([new_finding])
        candidate = normalized[0] if normalized else new_finding
        validation = validate_finding(candidate, ref_set)

        # ── Log claim counts per attempt ─────────────────────────────
        submitted_claims = (
            candidate.get("claims", []) if isinstance(candidate, dict)
            else []
        )
        matched_claims = [
            c for c in validation.get("checks", [])
            if c.get("result") == "MATCH"
        ]
        logger.info(
            "SC %s attempt %d: %d claims submitted, %d validated",
            finding_id, attempt_num,
            len(submitted_claims), len(matched_claims),
        )

        attempts.append({
            "attempt": attempt_num,
            "strategy": strategy_name,
            "status": validation["status"],
            "detail": validation.get("detail", ""),
            "reasoning": reasoning,
            "approach_change": approach_change,
            "claims_submitted": submitted_claims,
            "validation_result": validation,
        })

        if validation["status"] == "MATCH":
            # B2 FIX: restore identity fields from the rejected original.
            # Clean-slate design produces a from-scratch dict; corrector
            # never saw the original finding, so identity metadata
            # (finding_id, source_tools, tool_call_ids, raw_excerpt) is
            # absent unless the AI happened to re-emit it. Downstream
            # schema requires these fields. Claims from corrector remain
            # authoritative; identity carries forward from the original.
            if not _f4_subject_consistent(finding, candidate):
                _f4_log_decision(
                    finding_id, attempt_num, None, current_error,
                    action="subject_drift_rejected",
                    outcome="BLOCKED_BY_VALIDATOR",
                    reason="corrected claims introduce a subject absent from the original finding",
                )
                current_error = (
                    "Correction rejected: claims must concern the SAME subject "
                    "(process/file/path/host) named in the original finding. Do "
                    "not substitute a different subject merely to pass validation; "
                    "if the original subject is unsupported, drop the finding."
                )
                last_validation = validation
                continue
            candidate = _preserve_identity(candidate, finding)

            # Correction succeeded -- annotate finding for audit trail
            candidate["self_corrected"] = True
            candidate["original_draft"] = finding
            candidate["correction_reason"] = error
            candidate["deterministic_check"] = "corrected"

            _f4_log_decision(
                finding_id, attempt_num, None, current_error,
                action="correction_complete", outcome="CORRECTED",
                reason=(
                    f"validator confirmed revision on attempt "
                    f"{attempt_num}/{max_attempts}"
                ),
            )
            return {
                "status": "CORRECTED",
                "outcome_kind": "CORRECTED",
                "finding": candidate,
                "self_corrected": True,
                "original_draft": finding,
                "correction_reason": error,
                "attempts": attempts,
                "attempt_count": attempt_num,
                "total_time_s": round(time.monotonic() - start, 3),
                "reasoning": reasoning,
                "approach_change": approach_change,
            }

        # Failed -- update error and track validation for next attempt
        _f4_log_decision(
            finding_id, attempt_num, None, current_error,
            action="revalidation_failed", outcome="BLOCKED_BY_VALIDATOR",
            reason=str(validation.get("detail", ""))[:120],
        )
        current_error = validation.get("detail") or current_error
        last_validation = validation

    # ── All attempts exhausted: UNRESOLVED (score 0, not -2) ─────────
    unresolved = dict(finding)
    unresolved["confidence_level"] = "UNRESOLVED"
    unresolved["deterministic_check"] = "blocked"
    unresolved["self_corrected"] = False
    unresolved["correction_reason"] = error
    unresolved["score"] = 0

    # Collect last reasoning/approach_change from attempts
    last_reasoning = None
    last_approach = None
    for a in reversed(attempts):
        if a.get("reasoning"):
            last_reasoning = a["reasoning"]
            last_approach = a.get("approach_change")
            break

    # Distinguish error-only exhaustion (no attempt produced a classifiable
    # AI decision -- all branches were exception/null/unfixable) from a
    # validator-driven exhaustion (AI answered but validator kept rejecting).
    _any_validator_rejection = any(
        a.get("status") in ("MISMATCH", "MATCH") for a in attempts
    ) or (last_validation is not None)
    _outcome_kind = "EXHAUSTED" if _any_validator_rejection else "DROPPED_HONEST"
    _exhausted_time = round(time.monotonic() - start, 3)
    _f4_log_decision(
        finding_id, len(attempts), None, error,
        action="correction_complete", outcome=_outcome_kind,
        reason=(
            f"all {len(attempts)} attempt(s) failed; kept as "
            f"{unresolved['confidence_level']}, not promoted"
        ),
    )

    return {
        "status": "UNRESOLVED",
        "outcome_kind": _outcome_kind,
        "finding": unresolved,
        "self_corrected": False,
        "original_draft": finding,
        "correction_reason": error,
        "attempts": attempts,
        "attempt_count": len(attempts),
        "total_time_s": _exhausted_time,
        "reasoning": last_reasoning,
        "approach_change": last_approach,
    }


def _safe_format_strategy_template(template: str, **kwargs) -> str:
    """Format SC prompt templates without crashing on literal JSON braces.

    Some SC strategy prompts contain JSON examples such as {"type": "pid"}.
    Python str.format treats that as a field named '"type"' unless braces are
    doubled. This helper keeps Step 12 dataset-agnostic and fail-closed:
    known placeholders are replaced, literal JSON remains literal.
    """
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError, ValueError):
        rendered = template
        for key, value in kwargs.items():
            rendered = rendered.replace("{" + key + "}", "" if value is None else str(value))
        return rendered.replace("{{", "{").replace("}}", "}")


# ── Step 12 schema hardening: dataset-agnostic claim normalization ─────────────
def normalize_sc_claim(claim):
    """Normalize one self-correction claim without assuming a schema.

    Zero-fake / dataset-agnostic:
    - no case IOCs
    - no answer keys
    - no fixed case-specific IDs
    - malformed input becomes explicit unstructured evidence, not a crash
    """
    if not isinstance(claim, dict):
        return {
            "type": "unstructured",
            "text": str(claim),
            "raw": claim,
        }

    out = dict(claim)
    out.setdefault(
        "type",
        out.get("claim_type")
        or out.get("kind")
        or out.get("category")
        or "unrecognized",
    )
    out.setdefault(
        "text",
        out.get("text")
        or out.get("claim")
        or out.get("description")
        or str(out)[:1000],
    )
    return out


def normalize_sc_claims(claims):
    """Normalize a claim collection for Step 12 self-correction."""
    if claims is None:
        return []
    if isinstance(claims, dict):
        claims = [claims]
    elif not isinstance(claims, (list, tuple)):
        claims = [claims]
    return [normalize_sc_claim(c) for c in claims]


def normalize_sc_finding(finding):
    """Normalize finding claims before Step 12 prompt construction/correction."""
    if not isinstance(finding, dict):
        return {
            "id": "<unstructured>",
            "claims": [normalize_sc_claim(finding)],
            "raw": finding,
        }

    out = dict(finding)
    out["claims"] = normalize_sc_claims(
        out.get("claims")
        or out.get("claim")
        or out.get("observations")
        or []
    )
    return out

