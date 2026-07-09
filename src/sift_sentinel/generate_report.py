"""Sentinel Qwen Ensemble -- HTML Report Generator.

Reads pipeline state (findings, summary) and produces a styled HTML
incident report with confidence-level legend and finding cards.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from sift_sentinel.console import load_state
from sift_sentinel.reporting import display_finding_id, finding_title

# ── Confidence legend (matches console.py definitions) ─────────────────

CONFIDENCE_LEGEND_HTML = """\
<div class="confidence-legend">
    <strong>Confidence Levels</strong>
    <div class="legend-row"><span class="legend-dot green"></span> HIGH &mdash; Multiple independent evidence types agree (memory + disk + network)</div>
    <div class="legend-row"><span class="legend-dot yellow"></span> MEDIUM &mdash; Confirmed but limited source types</div>
    <div class="legend-row"><span class="legend-dot red"></span> LOW &mdash; Single source, treat as lead</div>
</div>"""

# ── HTML template pieces ───────────────────────────────────────────────

_CSS = """\
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'DM Sans', -apple-system, sans-serif; max-width: 960px; margin: 0 auto; padding: 24px; line-height: 1.6; color: #1a1a2e; background: #f8fafc; }
.report-header { text-align: center; padding: 32px 0; border-bottom: 3px solid #1e40af; margin-bottom: 24px; }
.report-header h1 { color: #1e40af; font-size: 1.8em; }
.report-header .subtitle { color: #64748b; font-size: 0.95em; }
.report-header .brand { color: #f97316; font-weight: 700; font-size: 0.85em; margin-top: 8px; }
.metrics-bar { display: flex; justify-content: space-around; background: #1e293b; color: white; padding: 16px; border-radius: 8px; margin: 24px 0; }
.metric { text-align: center; }
.metric-value { display: block; font-size: 1.4em; font-weight: 700; }
.metric-label { display: block; font-size: 0.75em; color: #94a3b8; }
.integrity-verified { color: #4ade80; }
h2 { color: #1e40af; font-size: 1.25em; margin: 20px 0 10px; }
table { border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 0.9em; }
th { background: #1e40af; color: white; padding: 10px 12px; text-align: left; }
td { border: 1px solid #e2e8f0; padding: 8px 12px; }
tr:nth-child(even) { background: #f1f5f9; }
.badge-high { background: #dcfce7; color: #166534; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.badge-medium { background: #fef9c3; color: #854d0e; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.badge-low { background: #fee2e2; color: #991b1b; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.badge-unknown { background: #f1f5f9; color: #475569; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.sev-critical { background: #fee2e2; color: #991b1b; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.sev-high { background: #ffedd5; color: #9a3412; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.sev-medium { background: #fef9c3; color: #854d0e; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.sev-low { background: #f1f5f9; color: #475569; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.validator-passed { background: #dcfce7; color: #166534; padding: 3px 8px; border-radius: 4px; font-size: 0.75em; }
.validator-blocked { background: #fee2e2; color: #991b1b; padding: 3px 8px; border-radius: 4px; font-size: 0.75em; }
.badge-known-good { background: #dbeafe; color: #1e40af; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }
.finding-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }
.finding-header { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
.finding-id { font-weight: 700; color: #1e40af; }
.claims { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }
.claim { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-family: monospace; }
.claim-pid { background: #dbeafe; color: #1e40af; }
.claim-hash { background: #fef3c7; color: #92400e; }
.claim-conn { background: #fce7f3; color: #9d174d; }
.confidence-legend { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 18px; margin: 16px 0; font-size: 0.9em; }
.confidence-legend strong { display: block; margin-bottom: 6px; color: #1e40af; }
.legend-row { margin: 4px 0; display: flex; align-items: center; gap: 8px; }
.legend-dot { width: 12px; height: 12px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.legend-dot.green { background: #22c55e; }
.legend-dot.yellow { background: #eab308; }
.legend-dot.red { background: #ef4444; }
.integrity-box { background: #dcfce7; border: 2px solid #166534; padding: 12px; border-radius: 8px; margin: 16px 0; text-align: center; font-weight: 600; color: #166534; }
.footer { text-align: center; margin-top: 48px; padding: 16px; border-top: 2px solid #e2e8f0; color: #64748b; font-size: 0.8em; }"""


_SEV_DESC = {
    "CRITICAL": "attacker can steal credentials or move laterally",
    "HIGH": "active attack technique detected",
    "MEDIUM": "suspicious activity worth investigating",
    "LOW": "informational anomaly",
}


def _badge(level: str) -> str:
    """Return an HTML badge span for a confidence level."""
    cls = f"badge-{level.lower()}" if level.lower() in ("high", "medium", "low") else "badge-unknown"
    return f'<span class="{cls}">{escape(level)}</span>'


def _severity_badge(level: str) -> str:
    """Return an HTML badge span for a severity level."""
    cls = f"sev-{level.lower()}" if level.lower() in ("critical", "high", "medium", "low") else "sev-low"
    desc = _SEV_DESC.get(level.upper(), "")
    title = f' title="{escape(desc)}"' if desc else ""
    return f'<span class="{cls}"{title}>{escape(level)}</span>'


def _claim_spans(claims: list[dict]) -> str:
    """Build claim badge HTML from a list of claim dicts."""
    parts: list[str] = []
    for c in claims:
        ctype = c.get("type", "")
        if ctype == "pid":
            text = f"PID {c.get('pid', '?')} = {c.get('process', '?')}"
            parts.append(f'<span class="claim claim-pid">{escape(text)}</span>')
        elif ctype == "hash":
            sha = c.get("sha1", "")[:12]
            text = f"SHA1: {sha}... = {c.get('filename', '?')}"
            parts.append(f'<span class="claim claim-hash">{escape(text)}</span>')
        elif ctype == "connection":
            text = f"{c.get('foreign_addr', '?')}:{c.get('foreign_port', '?')}"
            parts.append(f'<span class="claim claim-conn">{escape(text)}</span>')
    return "".join(parts)


def _validator_badge(det_check: str) -> str:
    """Return HTML for deterministic check result."""
    if det_check == "passed":
        return '<span class="validator-passed">passed</span>'
    return f'<span class="validator-blocked">{escape(str(det_check))}</span>'


def generate_html_report(
    findings: list[dict],
    summary: dict | None = None,
    disposition_counts: dict | None = None,
) -> str:
    """Generate a complete HTML incident report string.

    Parameters
    ----------
    findings : list[dict]
        Validated findings from findings_final.json.
    summary : dict, optional
        Pipeline summary from pipeline_summary.json.
    disposition_counts : dict, optional
        Final disposition bucket counts (Slot 31E-DB.4). When present,
        the metrics bar and findings heading report the two-layer truth
        (validator-backed observations vs confirmed malicious atomic)
        instead of presenting every finding as confirmed.

    Returns
    -------
    str
        Complete HTML document.
    """
    summary = summary or {}
    disposition_counts = disposition_counts or summary.get(
        "disposition_counts") or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    elapsed = f"{summary.get('elapsed_s', 0):.1f}s"
    n_tools = len(summary.get("tools_run", []))
    integrity_match = summary.get("integrity", {}).get("match", False)
    integrity_label = "VERIFIED" if integrity_match else "UNKNOWN"
    integrity_cls = "integrity-verified" if integrity_match else ""

    # ── Disposition truth (Slot 31E-DB.4) ──────────────────────────────
    _has_disp = bool(disposition_counts)
    _obs = summary.get("findings_total", len(findings))
    _cm = disposition_counts.get("confirmed_malicious_atomic", 0)
    _bn = disposition_counts.get("benign_or_false_positive", 0)
    _ic = disposition_counts.get("inconclusive_unresolved", 0)
    _su = disposition_counts.get("suspicious_needs_review", 0)
    _sy = disposition_counts.get("synthesis_narrative", 0)

    # ── Build finding cards ────────────────────────────────────────────
    cards: list[str] = []
    total = len(findings)
    for f in findings:
        fid = escape(display_finding_id(f.get("finding_id", "?"), total))
        level = f.get("confidence_level", "?")
        severity = f.get("severity", "LOW")
        artifact = escape(finding_title(f))
        det_check = f.get("deterministic_check", "?")
        claims = f.get("claims", [])

        known_good_html = ""
        if f.get("known_good"):
            kg_note = escape(f.get("known_good_note", ""))
            known_good_html = (
                f'\n    <span class="badge-known-good">'
                f'Likely benign: {kg_note}</span>'
            )

        card = (
            '<div class="finding-card">\n'
            '  <div class="finding-header">\n'
            f'    <span class="finding-id">{fid}</span>\n'
            f"    {_badge(level)}\n"
            f"    {_severity_badge(severity)}\n"
            f"    {_validator_badge(str(det_check))}\n"
            f"    {known_good_html}\n"
            "  </div>\n"
            f"  <h3>{artifact}</h3>\n"
            f'  <div class="claims">{_claim_spans(claims)}</div>\n'
            "</div>"
        )
        cards.append(card)

    findings_html = "\n".join(cards)

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel Qwen Ensemble - Incident Report</title>
<style>
{_CSS}
</style>
</head>
<body>
<div class="report-header">
    <h1>Sentinel Qwen Ensemble -- Incident Report</h1>
    <div class="subtitle">Autonomous DFIR Pipeline | 16-Step Forensic Analysis</div>
    <div class="brand">SolventAi CyberSecurity | solventcyber.com</div>
</div>
<div class="integrity-box">SHA256 Evidence Integrity: {integrity_label}</div>

<div class="metrics-bar">
    <div class="metric"><span class="metric-value">{elapsed}</span><span class="metric-label">Pipeline Time</span></div>
    <div class="metric"><span class="metric-value">{n_tools}</span><span class="metric-label">Tools Run</span></div>
    <div class="metric"><span class="metric-value">{_obs if _has_disp else len(findings)}</span><span class="metric-label">Validator-backed</span></div>
    {(f'<div class="metric"><span class="metric-value">{_cm}</span><span class="metric-label">Confirmed malicious atomic</span></div>') if _has_disp else ''}
    <div class="metric"><span class="metric-value {integrity_cls}">{integrity_label}</span><span class="metric-label">Evidence Integrity</span></div>
</div>

<div class="findings-section">
<h2>Findings</h2>
{(f'<p style="color:#64748b;font-size:0.9em;margin:8px 0 14px;">{_obs} validator-backed observations after correction. After final disposition routing: {_cm} confirmed malicious atomic, {_bn} benign/false positive, {_ic} inconclusive/unresolved, {_su} suspicious needing review, {_sy} synthesis/narrative. The pipeline does not promote unsupported claims; unsupported or misattributed claims are blocked by validation and either corrected, downgraded, or routed out of confirmed malicious output.</p>') if _has_disp else ''}
{CONFIDENCE_LEGEND_HTML}
{findings_html}
</div>

<div class="footer">Generated by Sentinel Qwen Ensemble | {now} | solventcyber.com</div>
</body>
</html>"""
    return html


# ── CLI entry point ────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate HTML incident report from pipeline state.",
    )
    parser.add_argument(

        "-o", "--output", default="reports/incident_report.html",
        help="Output HTML path (default: reports/incident_report.html)",
    )
    args = parser.parse_args(argv)

    findings = load_state("findings_final.json")
    if not findings:
        print("No findings found in any state directory.", file=sys.stderr)
        return 1

    summary = load_state("pipeline_summary.json") or {}
    # Slot 31E-DB.4: prefer the disposition-bucket truth source.
    _disp_counts = summary.get("disposition_counts") or {}
    if not _disp_counts:
        _buckets = load_state("finding_disposition_buckets.json") or {}
        if isinstance(_buckets, dict):
            _disp_counts = {
                k: len(v) for k, v in _buckets.items()
                if isinstance(v, list)
            }
    html = generate_html_report(findings, summary, _disp_counts)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    print(f"Report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
