"""Compact live-console rendering for final findings.

This module is display-only. It does not create, delete, validate, promote,
or suppress findings. Verbose reports and run artifacts remain persisted by
the pipeline; this renderer only controls what is visible in the live terminal.
"""

from __future__ import annotations

import re as _re
import sys as _sys

from collections.abc import Mapping, Sequence
from textwrap import wrap
from typing import Any


BUCKET_LABELS = {
    "confirmed_malicious_atomic": "confirmed malicious atomic",
    "suspicious_needs_review": "suspicious needs review",
    "benign_or_false_positive": "benign or false positive",
    "inconclusive_unresolved": "inconclusive unresolved",
    "synthesis_narrative": "synthesis narrative",
}


# 31R: ANSI palette + helpers for compact-table colorization.
_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")

_ANSI_PALETTE = {
    "R":           "\033[0m",
    "B":           "\033[1m",
    "DIM":         "\033[2m",
    "CRIT":        "\033[1;97;41m",
    "HIGH":        "\033[1;31m",
    "MED":         "\033[1;33m",
    "LOW":         "\033[34m",
    "SPECULATIVE": "\033[2;37m",
    "CONFIRMED":   "\033[1;32m",
    "FP":          "\033[2;37m",
    "REVIEW":      "\033[1;33m",
    "UNRESOLVED":  "\033[2;37m",
    "OBSERVATION": "\033[1;36m",
    "SC":          "\033[1;92m",  # 31AJ-T: bright green (was dim cyan)
}

_STATUS_MAP = {
    "confirmed malicious atomic": ("CONFIRMED",      "CONFIRMED"),
    "benign or false positive":   ("FALSE POSITIVE", "FP"),
    "suspicious needs review":    ("NEEDS REVIEW",   "REVIEW"),
    "inconclusive unresolved":    ("UNRESOLVED",     "UNRESOLVED"),
    "synthesis narrative":        ("OBSERVATION",    "OBSERVATION"),
}

_SEV_COLOR = {
    "CRITICAL":    "CRIT",
    "HIGH":        "HIGH",
    "MEDIUM":      "MED",
    "LOW":         "LOW",
    "SPECULATIVE": "SPECULATIVE",
}

_CONF_COLOR = {
    "HIGH":        "CONFIRMED",
    "MEDIUM":      "MED",
    "LOW":         "DIM",
    "SPECULATIVE": "DIM",
}


def _ansi_enabled() -> bool:
    """Whether to emit ANSI escape codes (only when stdout is a TTY)."""
    try:
        return _sys.stdout.isatty()
    except Exception:
        return False


def _colorize(text: str, color_key) -> str:
    """Wrap text in ANSI color codes when stdout is a TTY; plain otherwise."""
    if not _ansi_enabled() or not color_key:
        return text
    code = _ANSI_PALETTE.get(color_key, "")
    if not code:
        return text
    return f"{code}{text}{_ANSI_PALETTE['R']}"


def _visible_len(s: str) -> int:
    """Length of s ignoring ANSI escape sequences (for width math)."""
    return len(_ANSI_RE.sub("", s))


def _was_self_corrected(f: Any) -> bool:
    """Detect whether a finding came from the self-correction loop."""
    if not isinstance(f, Mapping):
        return False
    if f.get("self_corrected"):
        return True
    sc = f.get("self_correction")
    if isinstance(sc, Mapping) and sc.get("applied"):
        return True
    validation = str(f.get("validation_status") or "").lower()
    if validation in ("corrected", "self_corrected"):
        return True
    return False


def _status_cell(routed: str) -> str:
    """Map disposition string -> colored status label."""
    key = (routed or "").lower().strip()
    fallback = ((routed or "?").upper(), "DIM")
    label, color_key = _STATUS_MAP.get(key, fallback)
    return _colorize(label, color_key)


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else []


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    return text or default


def _finding_id(finding: Mapping[str, Any], fallback: int) -> str:
    return _text(finding.get("finding_id") or finding.get("id"), f"F{fallback:03d}")


def _finding_name(finding: Mapping[str, Any]) -> str:
    return _text(
        finding.get("title")
        or finding.get("artifact")
        or finding.get("name")
        or finding.get("description"),
        "(untitled finding)",
    )


def _severity(finding: Mapping[str, Any]) -> str:
    sev = _text(finding.get("severity"), "?").upper()
    color_key = _SEV_COLOR.get(sev)
    return _colorize(sev, color_key) if color_key else sev


def _confidence(finding: Mapping[str, Any]) -> str:
    conf = _text(
        finding.get("confidence_level")
        or finding.get("confidence")
        or finding.get("confidence_score"),
        "?",
    ).upper()
    color_key = _CONF_COLOR.get(conf)
    return _colorize(conf, color_key) if color_key else conf


def _source_tools(finding: Mapping[str, Any]) -> list[str]:
    for key in ("source_tools", "claim_tools", "tool_call_ids"):
        tools = [_text(t) for t in _as_list(finding.get(key)) if _text(t)]
        if tools:
            return list(dict.fromkeys(tools))
    return []


def _bucket_map(disposition_buckets: Mapping[str, Any] | None) -> dict[str, str]:
    mapped: dict[str, str] = {}
    if not isinstance(disposition_buckets, Mapping):
        return mapped

    for bucket, items in disposition_buckets.items():
        label = BUCKET_LABELS.get(str(bucket), str(bucket).replace("_", " "))
        if isinstance(items, Mapping):
            items = items.get("findings") or items.get("items") or []
        for item in _as_list(items):
            if isinstance(item, Mapping):
                fid = _text(item.get("finding_id") or item.get("id"))
            else:
                fid = _text(item)
            if fid:
                mapped[fid] = label
    return mapped


def _disposition(finding: Mapping[str, Any], bucket_lookup: Mapping[str, str]) -> str:
    fid = _text(finding.get("finding_id") or finding.get("id"))
    return _text(
        finding.get("final_disposition")
        or finding.get("disposition")
        or bucket_lookup.get(fid),
        "validator-backed",
    ).replace("_", " ")


def _typed_ref_count(finding: Mapping[str, Any]) -> int:
    refs = finding.get("validator_fact_refs") or finding.get("typed_fact_refs")
    if isinstance(refs, list):
        return len(refs)
    meta = finding.get("validator_metadata")
    if isinstance(meta, Mapping):
        refs = meta.get("typed_fact_refs") or meta.get("validator_fact_refs")
        if isinstance(refs, list):
            return len(refs)
    telemetry = finding.get("_validation_telemetry")
    if isinstance(telemetry, Mapping):
        try:
            return int(telemetry.get("typed_fact_matches", 0) or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def _details(finding: Mapping[str, Any], routed: str) -> str:
    """Plain-English Details column.

    Reads as: <disposition narrative>. <claims> verified, <tools> tool(s)
    used, <refs> evidence pieces<, evidence type><, self-correct marker>.
    Junior-analyst friendly; technical jargon is dropped.
    """
    claims = len(_as_list(finding.get("claims")))
    tools = len(_source_tools(finding))
    refs = _typed_ref_count(finding)
    evidence_type = _text(finding.get("evidence_type"))

    norm = (routed or "").lower().strip()
    prefix = {
        "confirmed malicious atomic": "Verified malicious.",
        "benign or false positive":   "Not malicious.",
        "suspicious needs review":    "Suggests malicious.",
        "inconclusive unresolved":    "Could not confirm.",
        "synthesis narrative":        "Context observation.",
    }.get(norm, "")

    parts = []
    if claims:
        parts.append(f"{claims} AI claim{'s' if claims != 1 else ''} verified")
    if tools:
        parts.append(f"{tools} forensic tool{'s' if tools != 1 else ''}")
    if refs:
        parts.append(f"{refs} evidence piece{'s' if refs != 1 else ''}")

    evidence_phrase = f" using {evidence_type} evidence" if evidence_type else ""
    sc_phrase = " (AI self-corrected)" if _was_self_corrected(finding) else ""

    if parts:
        body = f"{', '.join(parts)}{evidence_phrase}.{sc_phrase}"
        return f"{prefix} {body}".strip()
    return (prefix + sc_phrase).strip() or "—"


def _wrap_cell(value: Any, width: int) -> list[str]:
    # 31AJ-T: split on raw \n FIRST (before _text collapses newlines).
    # Then normalize each part. This lets Details cells mix wrapped plain
    # text with a colored SC-correction tag on its own line.
    if value is None:
        return [""]
    raw = str(value)
    if not raw:
        return [""]
    lines: list[str] = []
    for raw_part in raw.splitlines() or [""]:
        part = _text(raw_part)
        if not part:
            lines.append("")
            continue
        if _ANSI_RE.search(part):
            lines.append(part)
        else:
            wrapped = wrap(part, width=width, break_long_words=True, break_on_hyphens=False)
            if wrapped:
                lines.extend(wrapped)
            else:
                lines.append("")
    return lines or [""]


def _border(left: str, fill: str, join: str, right: str, widths: Sequence[int]) -> str:
    return left + join.join(fill * (w + 2) for w in widths) + right


def _render_row(cells: Sequence[Any], widths: Sequence[int]) -> list[str]:
    wrapped = [_wrap_cell(cell, width) for cell, width in zip(cells, widths)]
    height = max(len(cell_lines) for cell_lines in wrapped)
    rendered: list[str] = []
    for row_idx in range(height):
        pieces = []
        for cell_lines, width in zip(wrapped, widths):
            value = cell_lines[row_idx] if row_idx < len(cell_lines) else ""
            # 31R: pad by visible length so ANSI escapes don't skew alignment
            pad = max(0, width - _visible_len(value))
            pieces.append(" " + value + (" " * pad) + " ")
        rendered.append("│" + "│".join(pieces) + "│")
    return rendered


def _normalize_findings(findings_final: Any, kwargs: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if findings_final is None:
        findings_final = (
            kwargs.get("findings_final")
            or kwargs.get("findings")
            or kwargs.get("items")
            or []
        )
    if isinstance(findings_final, Mapping):
        findings_final = findings_final.get("findings") or findings_final.get("items") or []
    return [f for f in _as_list(findings_final) if isinstance(f, Mapping)]


# 31AJ-T: Disposition order for row sorting (CONFIRMED first, FP last)
_DISPO_ORDER_RANK = {
    # 31AJ-T: keys MUST match what _disposition() returns (space-form labels).
    "confirmed malicious atomic": 0,
    "suspicious needs review":    1,
    "inconclusive unresolved":    2,
    "synthesis narrative":        3,
    "benign or false positive":   4,
    "validator-backed":           5,
    "unknown":                    6,
}

# 31AJ-T: Severity rank within a disposition bucket (for sub-sort)
_SEV_RANK_FOR_SORT = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def _severity_unified(finding: Mapping[str, Any], routed: str) -> str:
    """31AJ-T: Unified severity label. FP bucket -> FALSE POSITIVE."""
    if routed == "benign or false positive":
        return _colorize("FALSE POSITIVE", "FP")
    sev = str(finding.get("severity", "")).strip().upper()
    if sev not in _SEV_RANK_FOR_SORT:
        sev = "LOW"
    color_key = {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}.get(sev, "LOW")
    return _colorize(sev, color_key)


def _iocs_artifacts(finding: Mapping[str, Any]) -> str:
    """31AJ-T: ALL IOCs from claims[], deduped, one per line.

    Priority order (each pass extracts ALL matching claims, not just first):
      hash > path > url/domain > user_account > connection > pid > ps:ttp.
    Returns "\n"-joined string so renderer wraps each IOC to its own visual line.
    """
    claims = finding.get("claims") or []
    if not isinstance(claims, (list, tuple)):
        return "—"

    items: list[str] = []
    seen: set[str] = set()
    def _add(s: str) -> None:
        if s and s not in seen:
            items.append(s)
            seen.add(s)

    for c in claims:
        if not isinstance(c, Mapping):
            continue
        if c.get("type") == "hash":
            for hf in ("sha256", "sha1", "md5"):
                h = c.get(hf)
                if h and isinstance(h, str):
                    suffix = "…" if len(h) > 12 else ""
                    _add(f"{hf}:{h[:12]}{suffix}")
                    break

    for c in claims:
        if not isinstance(c, Mapping):
            continue
        if c.get("type") == "path":
            pth = c.get("path") or c.get("file_path") or c.get("filepath")
            if pth and isinstance(pth, str):
                _add(pth)

    for c in claims:
        if not isinstance(c, Mapping):
            continue
        if c.get("type") in ("url", "domain"):
            v = c.get("url") or c.get("domain") or c.get("host") or c.get("hostname")
            if v and isinstance(v, str):
                _add(v)

    for c in claims:
        if not isinstance(c, Mapping):
            continue
        if c.get("type") in ("user_account", "account", "user"):
            dom = c.get("domain")
            user = c.get("username") or c.get("user") or c.get("name") or c.get("account")
            if user and isinstance(user, str):
                if dom and isinstance(dom, str):
                    _add(f"{dom}\\{user}")
                else:
                    _add(user)

    for c in claims:
        if not isinstance(c, Mapping):
            continue
        if c.get("type") == "connection":
            proc = c.get("process") or "?"
            host = c.get("foreign_addr") or c.get("remote_addr") or c.get("host") or "?"
            port = c.get("foreign_port") or c.get("remote_port") or "?"
            _add(f"{proc} -> {host}:{port}")

    for c in claims:
        if not isinstance(c, Mapping):
            continue
        if c.get("type") in ("process_exists", "pid"):
            pid = c.get("pid")
            proc = c.get("process") or c.get("name") or ""
            if pid is not None:
                _add(f"pid:{pid} {proc}".strip())

    for c in claims:
        if not isinstance(c, Mapping):
            continue
        if c.get("type") == "powershell_command":
            ttp = c.get("ttp_tag")
            if ttp and isinstance(ttp, str):
                _add(f"ps:{ttp}")

    return "\n".join(items) if items else "—"

def _details_compact(finding: Mapping[str, Any]) -> str:
    """31AJ-T: 'N AI claim(s) verified, M forensic tool(s), K evidence piece(s)'.

    Appends ' (AI self-corrected)' in dim cyan when self_corrected is True.
    """
    tel = finding.get("_validation_telemetry") or {}
    typed = int(tel.get("typed_fact_matches") or 0)
    vfr = finding.get("validator_fact_refs") or []
    if not isinstance(vfr, (list, tuple)):
        vfr = []
    verified = max(typed, len(vfr))

    claims = finding.get("claims") or []
    total_claims = len(claims) if isinstance(claims, (list, tuple)) else 0
    # Defensive: never show verified > total
    if total_claims and verified > total_claims:
        verified = total_claims

    src_tools = finding.get("source_tools") or []
    if not isinstance(src_tools, (list, tuple)):
        src_tools = []
    m = len(set(src_tools))

    def _pl(x, word):
        return f"{x} {word}" + ("" if x == 1 else "s")

    # 31AJ-T: ratio (verified/total) instead of redundant "evidence pieces"
    if total_claims > 0:
        ratio = f"{verified}/{total_claims} AI claim{'s' if total_claims != 1 else ''} verified"
    else:
        ratio = "no AI claims"
    text = f"{ratio}, {_pl(m, 'forensic tool')}"

    if _was_self_corrected(finding):
        text += "\n" + _colorize("(AI self-corrected)", "SC")

    return text


def render_compact_findings_table(
    findings_final: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    disposition_buckets: Mapping[str, Any] | None = None,
    max_rows: int | None = None,
    **kwargs: Any,
) -> str:
    """Render the requested visible live output: compact findings table only.

    31AJ-T Columns (7):
      # | Findings# | Findings Name | IOCs/Artifacts | Severity | Tools Hit | Details

    Severity vocabulary: CRITICAL / HIGH / MEDIUM / LOW / FALSE POSITIVE.
    Rows ordered by disposition (CONFIRMED first, FP last), severity within.
    """
    findings = _normalize_findings(findings_final, kwargs)
    if max_rows is None:
        max_rows = kwargs.get("rows") or kwargs.get("limit")
    try:
        limit = int(max_rows) if max_rows is not None else len(findings)
    except (TypeError, ValueError):
        limit = len(findings)
    limit = max(0, limit)

    bucket_lookup = _bucket_map(disposition_buckets or kwargs.get("buckets"))
    # 31AJ-T: 7-col layout, total ~165 chars
    widths = [3, 6, 28, 32, 14, 22, 42]
    headers = ["#", "ID", "Findings Name", "IOCs/Artifacts", "Severity", "Tools Hit", "Details"]

    lines = [
        _border("┌", "─", "┬", "┐", widths),
        *_render_row(headers, widths),
        _border("╞", "═", "╪", "╡", widths),
    ]

    visible_findings = findings[:limit]
    if not visible_findings:
        lines.extend(_render_row(["", "(none)", "No findings to display", "", "", "", ""], widths))
    else:
        # 31AJ-T: Sort by (disposition, severity, finding_id)
        def _sort_key(f):
            # 31AJ-T sort: severity-FIRST, FP always last, more tools = higher.
            # Rule: CRITICAL > HIGH > MEDIUM > LOW; FALSE POSITIVE always at bottom.
            routed = _disposition(f, bucket_lookup)
            is_fp = (routed == "benign or false positive")
            if is_fp:
                sev_rank = 99  # FP always last regardless of upstream severity
            else:
                sev = str(f.get("severity", "LOW")).upper()
                sev_rank = _SEV_RANK_FOR_SORT.get(sev, 9)
            tools = f.get("source_tools") or []
            tool_count = len(set(tools)) if isinstance(tools, (list, tuple)) else 0
            return (
                sev_rank,
                -tool_count,
                str(f.get("finding_id") or ""),
            )
        sorted_findings = sorted(visible_findings, key=_sort_key)

        for ordinal, finding in enumerate(sorted_findings, 1):
            routed = _disposition(finding, bucket_lookup)
            cells = [
                str(ordinal),
                _finding_id(finding, ordinal),
                _finding_name(finding),
                _iocs_artifacts(finding),
                _severity_unified(finding, routed),
                ", ".join(_source_tools(finding)) or "(none)",
                _details_compact(finding),
            ]
            if ordinal > 1:
                lines.append(_border("╞", "═", "╪", "╡", widths))
            lines.extend(_render_row(cells, widths))

    lines.append(_border("└", "─", "┴", "┘", widths))
    return "\n".join(lines)



def _load_json_file(path: Any) -> Any:
    """Best-effort display-only JSON loader for saved run artifacts."""
    try:
        import json
        from pathlib import Path

        p = Path(path)
        if not p.exists():
            return None
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        return None


# --- A+++ closed-grid findings table v7 (REAL) ---
# Confidence = evidence-reason text (no dots, no HIGH/MED/LOW labels).
# Row separators: dotted within a severity band, solid between severity changes.
# Dataset-agnostic: every label maps to a validator/ReAct/SC telemetry field.
def render_severity_grouped_findings_table(
    findings_final,
    *,
    react_results=None,
    sc_results=None,
    disposition_buckets=None,
    use_color=True,
    cost_summary=None,
):
    import re as _re
    _ANSI = _re.compile(r"\x1b\[[0-9;]*m")

    def _pad(s, w):
        s = str(s)
        plain = _ANSI.sub("", s)
        if len(plain) > w:
            return plain[:w-1] + "\u2026"
        return s + " " * (w - len(plain))

    if use_color:
        C = {
            "R": "\033[0m", "B": "\033[1m", "DIM": "\033[2m",
            "CRIT": "\033[1;97;41m",
            "HIGH": "\033[1;30;103m",
            "MED":  "\033[1;36m",
            "LOW":  "\033[34m",
            "FP":   "\033[2;37m",
        }
    else:
        C = {k: "" for k in ("R","B","DIM","CRIT","HIGH","MED","LOW","FP")}

    SEV_LABEL = {
        "CRITICAL": f"{C['CRIT']} CRITICAL {C['R']}",
        "HIGH":     f"{C['HIGH']} HIGH     {C['R']}",
        "MEDIUM":   f"{C['MED']} MEDIUM   {C['R']}",
        "LOW":      f"{C['LOW']} LOW      {C['R']}",
        "FP":       f"{C['FP']} FP       {C['R']}",
    }
    SEV_RANK = {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "FP":4}

    react_map = {(r.get("finding_id") or r.get("id")): r for r in (react_results or [])}
    sc_map    = {(s.get("finding_id") or s.get("id")): s for s in (sc_results or [])}

    def _rc_dict(f):
        rc = f.get("react_conclusion")
        if isinstance(rc, dict): return rc
        if isinstance(rc, str):  return {"conclusion": rc}
        return {}

    def title_of(f):
        for k in ("title","description","artifact","finding_type","finding_id"):
            v = f.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return "(unnamed)"

    def is_self_corrected(f):
        return bool(f.get("self_corrected")) or bool((f.get("self_correction") or {}).get("applied"))

    def confidence_reason(f):
        bits = []
        fid = f.get("finding_id") or f.get("id")
        rc = _rc_dict(f)
        r = react_map.get(fid, {}) or {}
        v = (r.get("verdict") or rc.get("verdict") or "").lower()
        if v == "confirmed_malicious":
            bits.append("ReAct (AI Cross-Check) verified malicious")
        elif v == "confirmed_benign":
            bits.append("ReAct (AI Cross-Check) verified FP")
        elif v == "inconclusive":
            bits.append("ReAct (AI Cross-Check) inconclusive")
        if is_self_corrected(f) or sc_map.get(fid):
            cr = (f.get("correction_reason") or "").strip()
            if cr:
                cr_short = cr[:24] + ("\u2026" if len(cr) > 24 else "")
                bits.append(f"SC-corrected ({cr_short})")
            else:
                bits.append("SC-corrected")
        tel = f.get("_validation_telemetry") or {}
        typed = int(tel.get("typed_fact_matches") or 0)
        refs = len(f.get("validator_fact_refs") or [])
        best = max(typed, refs)
        if best >= 3:
            bits.append(f"{best} typed refs")
        elif best >= 1:
            bits.append(f"{best} typed ref" + ("s" if best > 1 else ""))
        else:
            bits.append("no typed refs")
        tools = len(set(f.get("source_tools") or []))
        if tools >= 3:
            bits.append(f"{tools} tools agree")
        elif tools == 2:
            bits.append("2 tools")
        elif tools == 1:
            bits.append("single tool")
        return " \u00B7 ".join(bits[:3])

    def source_origin(f):
        fid = f.get("finding_id") or f.get("id")
        parts = ["Inv2-AI"]
        r = react_map.get(fid) or {}
        if not r:
            rc = _rc_dict(f)
            if rc.get("verdict") or rc.get("is_false_positive"):
                r = {"verdict": rc.get("verdict") or ("confirmed_benign" if rc.get("is_false_positive") else "")}
        if r:
            v = (r.get("verdict") or "").lower()
            if v:
                tag = "FP" if v == "confirmed_benign" else ("MAL" if v == "confirmed_malicious" else v[:5])
                parts.append(f"CrossCheck:{tag}")
        if is_self_corrected(f) or sc_map.get(fid):
            parts.append("SC")
        return " \u2192 ".join(parts)

    def tools_of(f, maxn=3):
        ts = list(dict.fromkeys(f.get("source_tools") or []))
        if not ts: return "(none)"
        if len(ts) <= maxn:
            return ", ".join(ts)
        return ", ".join(ts[:maxn]) + f", +{len(ts)-maxn}"

    def bucket_for(f):
        fid = f.get("finding_id") or f.get("id")
        r = react_map.get(fid, {}) or {}
        rc = _rc_dict(f)
        verdict = (r.get("verdict") or f.get("react_verdict") or rc.get("verdict") or "").lower()
        disp = (f.get("disposition") or f.get("routing_disposition") or "").lower()
        _route = (f.get("routing_bucket") or f.get("final_bucket") or "").lower()
        sev = (f.get("severity") or "").upper()
        is_fp = (
            verdict == "confirmed_benign" or disp == "benign_or_false_positive"
            or bool(f.get("forced_low_by_react_fp")) or bool(rc.get("is_false_positive"))
            or "benign" in _route or "false_positive" in _route
            or (f.get("confidence_forced_low") is True)
        )
        if is_fp: return "FP"
        if sev in SEV_RANK: return sev
        return "LOW"

    rows_data = [(bucket_for(f), f) for f in (findings_final or [])]
    rows_data.sort(key=lambda x: (SEV_RANK.get(x[0], 99), x[1].get("finding_id") or ""))

    headers = ["#", "ID", "Finding", "Severity", "Confidence (evidence)", "Source-Origin", "Tools Hit"]
    widths  = [3,   6,    42,         10,         48,                       26,              28]

    def hline(left, fill, join, right):
        return left + join.join(fill * (w + 2) for w in widths) + right

    def render_row(cells):
        return "\u2502 " + " \u2502 ".join(_pad(c, w) for c, w in zip(cells, widths)) + " \u2502"

    lines = []
    lines.append(hline("\u250C", "\u2500", "\u252C", "\u2510"))
    lines.append(render_row(headers))
    lines.append(hline("\u255E", "\u2550", "\u256A", "\u2561"))

    prev_bucket = None
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"FP":0}
    for n, (bucket, f) in enumerate(rows_data, 1):
        counts[bucket] = counts.get(bucket, 0) + 1
        if prev_bucket is None:
            pass
        elif bucket != prev_bucket:
            lines.append(hline("\u251C", "\u2500", "\u253C", "\u2524"))
        else:
            lines.append(hline("\u251C", "\u2504", "\u253C", "\u2524"))
        cells = [
            str(n),
            (f.get("finding_id") or "?"),
            title_of(f),
            SEV_LABEL[bucket],
            confidence_reason(f),
            source_origin(f),
            tools_of(f),
        ]
        lines.append(render_row(cells))
        prev_bucket = bucket

    lines.append(hline("\u2514", "\u2500", "\u2534", "\u2518"))

    total = sum(counts.values())
    sev_summary = (
        f"{C['B']}FINAL FINDINGS{C['R']}  \u2502  "
        f"{C['CRIT']} {counts['CRITICAL']} crit {C['R']}  "
        f"{C['HIGH']} {counts['HIGH']} high {C['R']}  "
        f"{C['MED']} {counts['MEDIUM']} med {C['R']}  "
        f"{C['LOW']} {counts['LOW']} low {C['R']}  "
        f"{C['FP']} {counts['FP']} fp {C['R']}  \u2502  {total} total"
    )

    banner_lines = []
    if cost_summary:
        elapsed_min = (cost_summary.get("elapsed_seconds") or 0) / 60.0
        in_tok  = cost_summary.get("input_tokens") or 0
        out_tok = cost_summary.get("output_tokens") or 0
        cost_usd = cost_summary.get("cost_usd")
        # Rate + label come from the RESOLVED model (was hardcoded "Haiku 4.5",
        # which mislabeled + mispriced every Qwen run). resolve_rates honors the
        # SIFT_PRICE_* overrides, so a pinned console rate still wins.
        _model = cost_summary.get("model") or ""
        try:
            from sift_sentinel.pricing import resolve_rates as _rr
            from sift_sentinel.model_roles import resolve_model as _rm
            _model = _model or _rm("analysis")
            p_in, p_out = _rr(_model)
            _label = _model
        except Exception:
            import os as _os
            p_in  = float(_os.environ.get("SIFT_PRICE_INPUT_PER_MTOK", "1.0"))
            p_out = float(_os.environ.get("SIFT_PRICE_OUTPUT_PER_MTOK", "5.0"))
            _label = _model or "est"
        if cost_usd is None:
            cost_usd = (in_tok / 1_000_000) * p_in + (out_tok / 1_000_000) * p_out
        banner_lines.append(
            f"{C['B']}PIPELINE STATS{C['R']}  \u2502  "
            f"Time: {C['B']}{elapsed_min:.1f} min{C['R']}  \u2502  "
            f"Tokens: {C['B']}{in_tok:,}{C['R']} in / {C['B']}{out_tok:,}{C['R']} out  \u2502  "
            f"Cost: {C['B']}~${cost_usd:.4f}{C['R']}  ({_label} @ ${p_in:.2f}/${p_out:.2f} per MTok)"
        )

    return "\n".join([""] + banner_lines + ([""] if banner_lines else []) + [sev_summary, ""] + lines)


def _build_summary_header(summary: Any) -> str:
    """31AJ-T: One-line header above the table: time / cost / models. Defensive.

    Reads whatever fields exist in *summary*; emits empty string if nothing found.
    """
    if not isinstance(summary, Mapping):
        return ""
    parts: list[str] = []

    # Time (try minutes, then seconds)
    for k in ("total_time_minutes", "pipeline_duration_minutes", "elapsed_minutes", "duration_minutes"):
        v = summary.get(k)
        if v is not None:
            try:
                parts.append(f"Time: {float(v):.1f}m")
                break
            except (TypeError, ValueError):
                pass
    if not any(p.startswith("Time:") for p in parts):
        for k in ("total_time_seconds", "elapsed_seconds", "duration_seconds", "elapsed_s", "elapsed", "wall_elapsed_s", "serial_elapsed_s"):
            v = summary.get(k)
            if v is not None:
                try:
                    parts.append(f"Time: {float(v)/60:.1f}m")
                    break
                except (TypeError, ValueError):
                    pass

    # Cost
    cost = summary.get("cost_usd") or summary.get("total_cost") or summary.get("api_cost_usd")
    if cost is None:
        cs = summary.get("cost_summary") or {}
        if isinstance(cs, Mapping):
            cost = cs.get("total") or cs.get("total_usd") or cs.get("usd")
    if cost is not None:
        try:
            parts.append(f"Cost: ${float(cost):.4f}")
        except (TypeError, ValueError):
            pass

    # Models — try several shapes
    models = (summary.get("models_used")
              or summary.get("models")
              or summary.get("models_per_invocation"))
    if isinstance(models, Mapping):
        # {Inv1: claude-haiku, Inv2: claude-opus, ...}
        seen: set[str] = set()
        labels: list[str] = []
        for k, v in models.items():
            if isinstance(v, str) and v not in seen:
                labels.append(f"{k}={v}")
                seen.add(v)
        if labels:
            parts.append(f"Models: {', '.join(labels)}")
    elif isinstance(models, (list, tuple, set)):
        uniq = sorted({str(m) for m in models if m})
        if uniq:
            parts.append(f"Models: {', '.join(uniq)}")
    elif isinstance(models, str):
        parts.append(f"Models: {models}")

    # Tokens (token_usage dict or flat keys)
    tu = summary.get("token_usage") or summary.get("tokens")
    if isinstance(tu, Mapping):
        tin = tu.get("total_input") or tu.get("input") or tu.get("input_tokens")
        tout = tu.get("total_output") or tu.get("output") or tu.get("output_tokens")
        if tin is not None or tout is not None:
            try:
                in_str = f"{int(tin or 0):,}"
                out_str = f"{int(tout or 0):,}"
                parts.append(f"Tokens: {in_str} in / {out_str} out")
            except (TypeError, ValueError):
                pass
    elif summary.get("total_input_tokens") is not None or summary.get("total_output_tokens") is not None:
        try:
            in_str = f"{int(summary.get('total_input_tokens') or 0):,}"
            out_str = f"{int(summary.get('total_output_tokens') or 0):,}"
            parts.append(f"Tokens: {in_str} in / {out_str} out")
        except (TypeError, ValueError):
            pass

    # API calls / invocations
    n_calls = summary.get("api_calls") or summary.get("invocations") or summary.get("n_invocations")
    if isinstance(n_calls, int) and n_calls > 0:
        parts.append(f"API calls: {n_calls}")

    if not parts:
        return ""
    sep = _colorize(" · ", "DIM")
    return _colorize("SIFT Sentinel run", "B") + "  " + sep.join(parts)


def print_compact_pipeline_summary(
    summary: Mapping[str, Any] | None = None,
    *,
    findings_final: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    disposition_buckets: Mapping[str, Any] | None = None,
    state_dir: Any = None,
    max_rows: int | None = None,
    **kwargs: Any,
) -> str:
    """Print the compact live table expected by run_pipeline.

    Display-only compatibility wrapper. It does not create, validate,
    promote, suppress, or mutate findings. It only renders already-saved
    findings/buckets into the visible terminal table.
    """
    if findings_final is None and isinstance(summary, Mapping):
        findings_final = (
            summary.get("findings_final")
            or summary.get("findings")
            or summary.get("items")
        )

    if disposition_buckets is None and isinstance(summary, Mapping):
        maybe = summary.get("finding_disposition_buckets") or summary.get("disposition_buckets")
        if isinstance(maybe, Mapping):
            disposition_buckets = maybe

    if disposition_buckets is None and state_dir:
        try:
            from pathlib import Path

            loaded = _load_json_file(Path(state_dir) / "finding_disposition_buckets.json")
            if isinstance(loaded, Mapping):
                disposition_buckets = loaded
        except Exception:
            disposition_buckets = None

    header = _build_summary_header(summary)
    if header:
        print(header)
    table = render_compact_findings_table(
        findings_final,
        disposition_buckets=disposition_buckets,
        max_rows=max_rows,
        **kwargs,
    )
    print(table)
    return table


# Compatibility aliases: keep run_pipeline import stable if prior patch used another name.
def render_live_findings_table(*args: Any, **kwargs: Any) -> str:
    return render_compact_findings_table(*args, **kwargs)


def render_findings_table(*args: Any, **kwargs: Any) -> str:
    return render_compact_findings_table(*args, **kwargs)


def render_compact_live_findings_table(*args: Any, **kwargs: Any) -> str:
    return render_compact_findings_table(*args, **kwargs)


def format_compact_findings_table(*args: Any, **kwargs: Any) -> str:
    return render_compact_findings_table(*args, **kwargs)


def compact_findings_table(*args: Any, **kwargs: Any) -> str:
    return render_compact_findings_table(*args, **kwargs)


__all__ = [
    "render_severity_grouped_findings_table",
    "render_compact_findings_table",
    "render_live_findings_table",
    "render_findings_table",
    "render_compact_live_findings_table",
    "format_compact_findings_table",
    "compact_findings_table",
    "print_compact_pipeline_summary",
]
