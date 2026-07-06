"""Markdown run-summary report -- every live-run detail in one nicely-formatted file.

A judge/customer-facing companion to report.md: the same facts the terminal
PIPELINE SUMMARY banner shows (sample, runtime, findings breakdown, tools, ReAct,
model, tokens, cost, artifact paths), rendered as clean markdown tables. Pure
function of the summary dict + disposition buckets; dataset-agnostic; never raises.
"""
from __future__ import annotations

import json
import os
from typing import Any

_BUCKET_ROWS = [
    ("confirmed_malicious_atomic", "🔴 Confirmed malicious"),
    ("suspicious_needs_review", "🟠 Needs review"),
    ("inconclusive_unresolved", "🟡 Inconclusive"),
    ("benign_or_false_positive", "⚪ Benign / false positive (ReAct AI-Cross-Check · SC layer 1)"),
    ("synthesis_narrative", "🔗 Context / synthesis"),
]


def _hms(v) -> str:
    try:
        v = int(round(float(v or 0)))
    except Exception:
        v = 0
    mm, ss = divmod(v, 60)
    hh, mm = divmod(mm, 60)
    return ("%dh %dm %ds" % (hh, mm, ss)) if hh else ("%dm %ds" % (mm, ss))


def _count(buckets: dict, key: str) -> int:
    v = (buckets or {}).get(key)
    return len(v) if isinstance(v, list) else 0


def _derive_sample(summary, image_path, disk_path, disk_mount) -> str:
    # Common name of the sample pair (shared stem of the memory + disk file names) + each
    # artefact's size -- never the parent bucket folder. Shared with the terminal banner.
    from sift_sentinel.reporting.sample_label import sample_label
    return sample_label(summary, image_path, disk_path, disk_mount)


def _derive_model(summary, state_dir) -> str:
    try:
        if state_dir:
            d = json.load(open(os.path.join(str(state_dir), "inv2_ensemble_stats.json")))
            models = [m.get("model") for m in (d.get("members") or [])
                      if isinstance(m, dict) and m.get("model")]
            cnt = d.get("completed_member_count") or d.get("requested_member_count") or len(models)
            if models:
                uniq = sorted(set(models))
                base = uniq[0] if len(uniq) == 1 else " + ".join(uniq)
                return ("%s  (%d-member ensemble)" % (base, cnt)) if cnt else base
    except Exception:
        pass
    return str((summary or {}).get("model") or "unknown")


def _tbl(rows):
    out = ["| Field | Value |", "|---|---|"]
    for k, v in rows:
        out.append("| **%s** | %s |" % (k, v))
    return out


def render_run_summary_md(
    summary: dict,
    buckets: dict | None = None,
    *,
    image_path: str = "",
    disk_path: str = "",
    disk_mount: str = "",
    state_dir: str = "",
    report_path: str = "",
    return_code: Any = None,
) -> str:
    sm = summary if isinstance(summary, dict) else {}
    buckets = buckets if isinstance(buckets, dict) else {}

    trc = sm.get("tool_record_counts") or {}
    n_hit = sum(1 for v in trc.values() if isinstance(v, (int, float)) and v > 0)
    n_exec = sm.get("tools_count") or (len(trc) if trc else 0)
    n_failed = (sm.get("tool_health") or {}).get("failed", 0) or 0
    data_only = sorted(t for t, v in trc.items()
                       if isinstance(v, (int, float)) and v > 0
                       and t not in set(sm.get("contributing_tools") or []))
    # data-only count if precomputed, else best-effort from trc
    n_data_only = sm.get("data_only_count")
    if n_data_only is None:
        n_data_only = len(data_only)

    react = sm.get("react_stats") or {}
    tu = sm.get("token_usage") or {}
    tin = int(tu.get("total_input", 0) or 0)
    tout = int(tu.get("total_output", 0) or 0)
    tcr = int(tu.get("total_cache_read", 0) or 0)
    tcc = int(tu.get("total_cache_creation", 0) or 0)
    # Resolve rates from the ACTUAL model (ensemble-member-derived), not a
    # hardcoded Haiku default -- an Opus run must price at $15/$75, not $1/$5.
    _cost_model = _derive_model(sm, state_dir)
    try:
        from sift_sentinel.pricing import resolve_rates as _resolve_rates
        _ri, _ro = _resolve_rates(_cost_model)
    except Exception:
        _ri, _ro = 1.0, 5.0
    p_in = os.environ.get("SIFT_PRICE_INPUT_PER_MTOK", str(_ri))
    p_out = os.environ.get("SIFT_PRICE_OUTPUT_PER_MTOK", str(_ro))
    # Cache-aware cost: uncached figure + '(~$Y with prompt caching)' when caching active.
    try:
        from sift_sentinel.pricing import format_cost as _fmt_cost
        _cost_str = _fmt_cost(_cost_model, uncached_input=tin, output=tout,
                              cache_read=tcr, cache_creation=tcc)
    except Exception:
        try:
            _cost_str = "~$%.2f" % (tin / 1e6 * float(p_in) + tout / 1e6 * float(p_out))
        except Exception:
            _cost_str = "~$0.00"

    counts = {k: _count(buckets, k) for k, _ in _BUCKET_ROWS}
    n_holdout = len(sm.get("sc_unresolved_holdout") or [])
    total_obs = sum(counts.values()) + n_holdout

    L: list[str] = []
    L.append("# 🛡️ Sentinel Ensemble - Run Summary")
    L.append("")
    L.append("> **Fully Autonomous Agentic-AI DFIR Platform**")
    L.append("")
    L += _tbl([
        ("Sample", _derive_sample(sm, image_path, disk_path, disk_mount)),
        ("Status", str(sm.get("status") or "?")),
        ("Runtime", _hms(sm.get("elapsed_s", 0))),
        ("Model", _derive_model(sm, state_dir)),
        ("LLM provider", sm.get("llm_provider") or "unknown"),
    ] + ([("Return code", str(return_code))] if return_code is not None else []))
    L.append("")

    L.append("## Findings")
    L.append("")
    L.append("| Disposition | Count |")
    L.append("|---|---:|")
    for key, label in _BUCKET_ROWS:
        if counts[key] or key in ("confirmed_malicious_atomic", "benign_or_false_positive"):
            L.append("| %s | %d |" % (label, counts[key]))
    if n_holdout:
        L.append("| ◻️ Unresolved (held for review) | %d |" % n_holdout)
    L.append("| **Total observations** | **%d** |" % total_obs)
    L.append("")

    L.append("## Tools")
    L.append("")
    L.append("| Swept | Hit | Failed | Data-only |")
    L.append("|---:|---:|---:|---:|")
    L.append("| %d | %d | %d | %d |" % (n_exec, n_hit, n_failed, n_data_only))
    if data_only:
        L.append("")
        L.append("_Data-only (ran, produced data, cited by no finding): %s_"
                 % ", ".join(data_only))
    L.append("")

    if react:
        L.append("## ReAct AI-Cross-Check")
        L.append("")
        L += _tbl([
            ("Probes", react.get("calls", 0)),
            ("Tools used", "%s (%s beyond sweep)" % (
                react.get("distinct", 0), len(react.get("new") or []))),
            ("Findings examined", react.get("findings", 0)),
        ])
        L.append("")

    L.append("## Cost & Tokens")
    L.append("")
    L += _tbl([
        ("Tokens in", ("{:,} uncached + {:,} cached".format(tin, tcr + tcc)
                       if (tcr + tcc) else "{:,}".format(tin))),
        ("Tokens out", "{:,}".format(tout)),
        ("Est. cost", "%s  (@ $%s / $%s per MTok)" % (_cost_str, p_in, p_out)),
    ])
    L.append("")

    if state_dir or report_path:
        L.append("## Artifacts")
        L.append("")
        L.append("| | |")
        L.append("|---|---|")
        if state_dir:
            L.append("| State | `%s` |" % state_dir)
        if report_path:
            L.append("| Report | `%s` |" % report_path)
        L.append("")

    return "\n".join(L).rstrip() + "\n"


def add_html_report_row(md_text: str, html_path) -> str:
    """Insert a 'Report (HTML)' row into the Artifacts box, right after the
    Report row. The HTML report is generated AFTER run_summary.md is first
    written (Step 18 vs Step 16), so the row is patched in once the path
    exists. Idempotent (no duplicate row on re-run); fail-safe (returns the
    input unchanged when the anchor or path is missing). Universal: pure
    table-row insertion, no case data."""
    try:
        if not md_text or not html_path or "Report (HTML)" in md_text:
            return md_text
        out = []
        inserted = False
        for line in md_text.splitlines():
            out.append(line)
            if not inserted and line.startswith("| Report |"):
                out.append("| Report (HTML) | `%s` |" % html_path)
                inserted = True
        return "\n".join(out) + ("\n" if md_text.endswith("\n") else "")
    except Exception:
        return md_text


__all__ = ["render_run_summary_md", "add_html_report_row"]
