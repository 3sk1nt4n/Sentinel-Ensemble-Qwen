#!/usr/bin/env python3
"""Generate styled HTML incident report from pipeline markdown output."""
import os
import sys
import json
import re
from html import escape

def generate(md_path=None, findings_path=None, summary_path=None, out_path=None):
    if not md_path:
        candidates = [f for f in os.listdir("reports") if f.endswith(".md")] if os.path.isdir("reports") else []
        if candidates:
            md_path = os.path.join("reports", sorted(candidates)[-1])
        else:
            print("ERROR: No markdown report found in reports/")
            sys.exit(1)
    if not findings_path:
        findings_path = "analysis/findings_final.json"
    if not summary_path:
        summary_path = "analysis/pipeline_summary.json"
    if not out_path:
        out_path = md_path.replace(".md", ".html")

    with open(md_path) as f:
        md_content = f.read()

    findings = []
    if os.path.exists(findings_path):
        with open(findings_path) as f:
            findings = json.load(f)

    summary = {}
    if os.path.exists(summary_path):
        with open(summary_path) as f:
            summary = json.load(f)

    html_body = md_to_html(md_content)

    elapsed = summary.get("elapsed_s", 0)
    # Handle both run_pipeline.py and coordinator.run_pipeline() summary shapes
    tools = summary.get("tools_count", len(summary.get("tools_run", [])))
    accuracy = summary.get("accuracy", {})
    passed = summary.get("findings_passed", accuracy.get("passed", 0))
    blocked = summary.get("findings_blocked", accuracy.get("blocked", 0))
    # coordinator uses integrity dict; run_pipeline uses integrity_match bool
    _integrity_val = summary.get("integrity_match", None)
    if _integrity_val is None:
        _integrity_obj = summary.get("integrity", {})
        _integrity_val = _integrity_obj.get("match", None) if isinstance(_integrity_obj, dict) else None
    integrity = "VERIFIED" if _integrity_val else "UNKNOWN"

    metrics_html = f"""
    <div class="metrics-bar">
        <div class="metric"><span class="metric-value">{elapsed:.1f}s</span><span class="metric-label">Pipeline Time</span></div>
        <div class="metric"><span class="metric-value">{tools}</span><span class="metric-label">Tools Run</span></div>
        <div class="metric"><span class="metric-value">{passed}</span><span class="metric-label">Findings Validated</span></div>
        <div class="metric"><span class="metric-value">{blocked}</span><span class="metric-label">Findings Blocked</span></div>
        <div class="metric"><span class="metric-value integrity-{integrity.lower()}">{integrity}</span><span class="metric-label">Evidence Integrity</span></div>
    </div>"""

    findings_html = ""
    # Only deterministically validated findings belong here; blocked findings
    # are rendered once, under "Requires Analyst Review" below.
    validated = [f for f in findings if f.get("deterministic_check") == "passed"]
    if validated:
        findings_html = '<div class="findings-section"><h2>Validated Findings</h2>'
        for f in validated:
            fid = escape(str(f.get("finding_id", "?")))
            conf = escape(str(f.get("confidence_level", "UNKNOWN")).upper())
            badge_class = f"badge-{conf.lower()}" if conf in ("HIGH", "MEDIUM", "LOW") else "badge-unknown"
            title = escape(str(f.get("title", f.get("artifact", "")) or ""))
            desc = escape(str(f.get("description", "") or "")[:300])
            check = escape(str(f.get("deterministic_check", "?")))
            claims = f.get("claims", [])
            claims_html = ""
            for c in claims:
                ctype = c.get("type", "?")
                if ctype == "pid":
                    text = f'PID {c.get("pid")} = {c.get("process", "?")}'
                    claims_html += f'<span class="claim claim-pid">{escape(text)}</span>'
                elif ctype == "hash":
                    text = f'SHA1: {str(c.get("sha1", "?"))[:12]}... = {c.get("filename", "?")}'
                    claims_html += f'<span class="claim claim-hash">{escape(text)}</span>'
                elif ctype == "connection":
                    text = f'{c.get("foreign_addr", "?")}:{c.get("foreign_port", "?")}'
                    claims_html += f'<span class="claim claim-conn">{escape(text)}</span>'
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-id">{fid}</span>
                    <span class="{badge_class}">{conf}</span>
                    <span class="validator-{check}">{check}</span>
                </div>
                <h3>{title}</h3>
                <p>{desc}</p>
                <div class="claims">{claims_html}</div>
            </div>"""
        findings_html += "</div>"

    # Add review section for blocked findings
    blocked = [f for f in findings if f.get("deterministic_check") != "passed"]
    if blocked:
        findings_html += '<div class="review-section"><h2>Requires Analyst Review</h2>'
        findings_html += '<p>These observations could not be machine-verified. Each entry explains why and what to do next.</p>'
        for bf in blocked:
            fid = escape(str(bf.get("finding_id", "?")))
            title = escape(str(bf.get("title", bf.get("artifact", "")) or ""))
            desc = escape(str(bf.get("description", "") or "")[:300])
            reason = str(bf.get("block_reason", "No checkable claims attached"))

            rl = reason.lower()
            if "no checkable claims" in rl or "no recognized claim" in rl:
                friendly = ("AI identified this activity but could not attach "
                            "verifiable evidence (PIDs, hashes, connections). "
                            "Manual review of tool outputs recommended.")
            elif "cross-contamination" in rl:
                friendly = ("Process name mismatch detected. The claimed process "
                            "does not match the PID in evidence. Check pstree output.")
            elif "not found" in rl and "reference set" in rl:
                friendly = ("Claimed artifact not found in evidence collection. "
                            "May be fabricated. Check amcache and MFT timeline.")
            elif "no connection" in rl:
                friendly = ("Network connection claimed but no matching PID "
                            "ownership in netscan. Connection may be orphaned.")
            elif "not found for" in rl:
                friendly = ("Timestamp mismatch. The claimed time does not match "
                            "known timestamps for this artifact.")
            else:
                friendly = reason

            findings_html += f"""
            <div class="finding-card" style="border-left: 4px solid #f59e0b;">
                <div class="finding-header">
                    <span class="finding-id">{fid}</span>
                    <span class="badge-unknown">NEEDS REVIEW</span>
                </div>
                <h3>{title}</h3>
                <div style="background: #fffbeb; padding: 10px; border-radius: 6px; margin: 8px 0;">
                    <strong>Why this needs review:</strong> {escape(friendly)}
                </div>
                <p>{desc}</p>
                <p style="color: #6b7280; font-size: 0.85em;">
                    <strong>What to do:</strong> Check raw tool outputs in the analysis/ folder.
                    Look for this activity in pstree, netscan, and amcache data.
                </p>
            </div>"""
        findings_html += '</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel Qwen Ensemble - Incident Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'DM Sans', -apple-system, sans-serif; max-width: 960px; margin: 0 auto; padding: 24px; line-height: 1.6; color: #1a1a2e; background: #f8fafc; }}
    .report-header {{ text-align: center; padding: 32px 0; border-bottom: 3px solid #1e40af; margin-bottom: 24px; }}
    .report-header h1 {{ color: #1e40af; font-size: 1.8em; }}
    .report-header .subtitle {{ color: #64748b; font-size: 0.95em; }}
    .report-header .brand {{ color: #f97316; font-weight: 700; font-size: 0.85em; margin-top: 8px; }}
    .metrics-bar {{ display: flex; justify-content: space-around; background: #1e293b; color: white; padding: 16px; border-radius: 8px; margin: 24px 0; }}
    .metric {{ text-align: center; }}
    .metric-value {{ display: block; font-size: 1.4em; font-weight: 700; }}
    .metric-label {{ display: block; font-size: 0.75em; color: #94a3b8; }}
    .integrity-verified {{ color: #4ade80; }}
    .integrity-unknown {{ color: #fbbf24; }}
    h1 {{ color: #1e40af; font-size: 1.5em; margin: 24px 0 12px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }}
    h2 {{ color: #1e40af; font-size: 1.25em; margin: 20px 0 10px; }}
    h3 {{ color: #334155; font-size: 1.05em; margin: 8px 0; }}
    p {{ margin: 8px 0; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 0.9em; }}
    th {{ background: #1e40af; color: white; padding: 10px 12px; text-align: left; }}
    td {{ border: 1px solid #e2e8f0; padding: 8px 12px; }}
    tr:nth-child(even) {{ background: #f1f5f9; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
    .badge-high {{ background: #dcfce7; color: #166534; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }}
    .badge-medium {{ background: #fef9c3; color: #854d0e; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }}
    .badge-low {{ background: #fee2e2; color: #991b1b; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }}
    .badge-unknown {{ background: #f1f5f9; color: #475569; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8em; }}
    .validator-passed {{ background: #dcfce7; color: #166534; padding: 3px 8px; border-radius: 4px; font-size: 0.75em; }}
    .validator-blocked {{ background: #fee2e2; color: #991b1b; padding: 3px 8px; border-radius: 4px; font-size: 0.75em; }}
    .finding-card {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
    .finding-header {{ display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }}
    .finding-id {{ font-weight: 700; color: #1e40af; }}
    .claims {{ margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }}
    .claim {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-family: monospace; }}
    .claim-pid {{ background: #dbeafe; color: #1e40af; }}
    .claim-hash {{ background: #fef3c7; color: #92400e; }}
    .claim-conn {{ background: #fce7f3; color: #9d174d; }}
    .footer {{ text-align: center; margin-top: 48px; padding: 16px; border-top: 2px solid #e2e8f0; color: #64748b; font-size: 0.8em; }}
    .integrity-box {{ background: #dcfce7; border: 2px solid #166534; padding: 12px; border-radius: 8px; margin: 16px 0; text-align: center; font-weight: 600; color: #166534; }}
    ul, ol {{ margin: 8px 0 8px 24px; }}
    li {{ margin: 4px 0; }}
    hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 24px 0; }}
</style>
</head>
<body>
    <div class="report-header">
        <h1>Sentinel Qwen Ensemble - Incident Report</h1>
        <div class="subtitle">Autonomous DFIR Pipeline | 16-Step Forensic Analysis</div>
        <div class="brand">Solvent CyberSecurity | solventcyber.com</div>
    </div>
    <div class="integrity-box">SHA256 Evidence Integrity: {integrity} (pre/post analysis match)</div>
    {metrics_html}
    {findings_html}
    <hr>
    {html_body}
    <div class="footer">Generated by Sentinel Qwen Ensemble | Solvent CyberSecurity | solventcyber.com | Global AI Hackathon with Qwen Cloud - Track 4</div>
</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html)
    print(f"Report generated: {out_path} ({len(html):,} bytes)")

def md_to_html(md):
    lines = md.split("\n")
    html_lines = []
    in_table = False
    in_list = False
    in_code = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                html_lines.append("</code></pre>")
                in_code = False
            else:
                html_lines.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            html_lines.append(escape(line))
            continue
        if stripped.startswith("### "):
            html_lines.append(f"<h3>{inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            html_lines.append(f"<h2>{inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            html_lines.append(f"<h1>{inline(stripped[2:])}</h1>")
        elif stripped.startswith("---"):
            html_lines.append("<hr>")
        elif "|" in stripped and not stripped.startswith("    "):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(set(c) <= set("- :") for c in cells):
                continue
            if not in_table:
                html_lines.append("<table>")
                tag = "th"
                in_table = True
            else:
                tag = "td"
            row = "".join(f"<{tag}>{inline(c)}</{tag}>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")
        else:
            if in_table:
                html_lines.append("</table>")
                in_table = False
            if stripped.startswith("- ") or stripped.startswith("* "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                html_lines.append(f"<li>{inline(stripped[2:])}</li>")
            elif re.match(r"^\d+\. ", stripped):
                if not in_list:
                    html_lines.append("<ol>")
                    in_list = True
                text = re.sub(r"^\d+\. ", "", stripped)
                html_lines.append(f"<li>{inline(text)}</li>")
            else:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                if stripped:
                    html_lines.append(f"<p>{inline(stripped)}</p>")
    if in_table:
        html_lines.append("</table>")
    if in_list:
        html_lines.append("</ul>")
    if in_code:
        html_lines.append("</code></pre>")
    return "\n".join(html_lines)

def inline(text):
    # The markdown is built from evidence-derived (and LLM-generated) content:
    # escape it before layering the inline HTML markup on top.
    text = escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2">\1</a>', text)
    return text

if __name__ == "__main__":
    generate()
