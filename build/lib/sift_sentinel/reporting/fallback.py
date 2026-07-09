"""Deterministic Inv4 fallback report renderer.

Used when the live Inv4 API call fails (network error, empty response,
wrong JSON shape). Pure Python, no model calls, no external
dependencies. Renders each validated finding as a dedicated markdown
section so the report is publishable even without AI narrative
synthesis.

Why this module exists:
  Run 8 on Gemini hit an Inv4 503 error and fell back to a 9-line
  stub. This module replaces that stub with structured content derived
  directly from the validated findings list, keeping the report
  publishable and judge-readable when the narrative generator is
  unavailable.
"""
from __future__ import annotations

from sift_sentinel.reporting.display import finding_title


def render_fallback_report(pre_disposition_findings: list[dict]) -> str:
    """Render a deterministic structured markdown report.

    Legacy non-bucket entry point. Slot 31E-DB.5: this renders a flat
    pre-disposition finding list and is NOT the final report truth.
    Callers on the truth path must use
    ``render_fallback_report_from_buckets`` so confirmed/critical
    sections only ever contain the confirmed disposition bucket. Kept
    for backward compatibility with non-bucket callers.

    Every field access uses defensive defaults because the Inv2 model
    may omit optional fields; the validator only guarantees the claim
    fields, not the human-readable title/description. Multi-line
    raw_excerpt values are wrapped in 4-backtick fenced code blocks so
    any embedded triple-backticks do not terminate the fence early.

    Args:
        pre_disposition_findings: flat pre-disposition finding list.

    Returns:
        Markdown string suitable for writing as the report.md fallback.
    """
    flat_list = list(pre_disposition_findings or [])
    lines: list[str] = [
        "# Sentinel Qwen Ensemble Incident Report",
        "",
        "## Status",
        "",
        (
            "The AI narrative generator was unavailable for this run. "
            "This report is a deterministic rendering of every "
            "validated finding produced by the pipeline. All findings "
            "below passed the deterministic validator against the "
            "paired reference set."
        ),
        "",
        f"**Validated findings:** {len(flat_list)}",
        "",
        "## Findings",
        "",
    ]

    for f in flat_list:
        fid = f.get("finding_id", "?")
        title = finding_title(f)
        severity = (
            f.get("severity")
            or f.get("confidence_level")
            or "UNKNOWN"
        )
        timestamp = f.get("timestamp", "") or ""
        evidence_type = f.get("evidence_type", "") or ""
        source_tools = f.get("source_tools") or []
        description = (
            f.get("description")
            or f.get("alternative_explanations")
            or ""
        )
        raw = f.get("raw_excerpt", "") or ""

        lines.append(f"### {fid} -- {title} ({severity})")
        lines.append("")
        if timestamp:
            lines.append(f"**Timestamp:** {timestamp}")
        if evidence_type:
            lines.append(f"**Evidence type:** {evidence_type}")
        if source_tools:
            lines.append(
                f"**Source tools:** {', '.join(str(t) for t in source_tools)}"
            )
        lines.append("")
        if description:
            lines.append(str(description))
            lines.append("")
        if raw:
            lines.append("**Raw excerpt:**")
            lines.append("")
            lines.append("````")
            lines.append(str(raw))
            lines.append("````")
            lines.append("")

    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "This fallback report was generated without AI narrative "
        "synthesis. Section ordering is by finding_id, not by attack "
        "chain. For a full narrative with kill chain analysis, rerun "
        "with the Inv4 API available."
    )
    lines.append("")
    return "\n".join(lines)


def _section(lines: list[str], heading: str, items: list[dict]) -> None:
    lines.append("## %s" % heading)
    lines.append("")
    if not items:
        lines.append("_None._")
        lines.append("")
        return
    for f in items:
        if not isinstance(f, dict):
            continue
        fid = f.get("finding_id", "?")
        title = finding_title(f)
        severity = (
            f.get("severity") or f.get("confidence_level") or "UNKNOWN"
        )
        lines.append("### %s -- %s (%s)" % (fid, title, severity))
        lines.append("")
        src = f.get("source_tools") or []
        if src:
            lines.append(
                "**Source tools:** %s"
                % ", ".join(str(t) for t in src)
            )
        raw = f.get("raw_excerpt", "") or ""
        desc = f.get("description") or ""
        if desc:
            lines.append("")
            lines.append(str(desc))
        if raw:
            lines.append("")
            lines.append("**Raw excerpt:**")
            lines.append("")
            lines.append("````")
            lines.append(str(raw))
            lines.append("````")
        lines.append("")


def render_fallback_report_from_buckets(
    finding_disposition_buckets: dict,
    report_truth: dict | None = None,
) -> str:
    """Deterministic bucket-driven fallback report (Slot 31E-DB.5.3).

    The single truth-path fallback. Each section is fed by exactly one
    disposition bucket:

      * Confirmed Malicious (atomic) <- confirmed_malicious_atomic ONLY
      * Requiring Further Investigation <- suspicious_needs_review
      * Investigated and Dispositioned Benign/False Positive
        <- benign_or_false_positive
      * Evidence Insufficient to Confirm <- inconclusive_unresolved

    synthesis_narrative may inform narrative context but never
    increments the atomic confirmed count. The report never states that
    every validated finding is malicious, nor that every
    validator-backed observation is confirmed.
    """
    b = finding_disposition_buckets or {}
    confirmed = list(b.get("confirmed_malicious_atomic", []) or [])
    suspicious = list(b.get("suspicious_needs_review", []) or [])
    benign = list(b.get("benign_or_false_positive", []) or [])
    inconclusive = list(b.get("inconclusive_unresolved", []) or [])
    synthesis = list(b.get("synthesis_narrative", []) or [])
    observations = None
    if isinstance(report_truth, dict):
        observations = report_truth.get("validator_backed_observations")

    lines: list[str] = [
        "# Sentinel Qwen Ensemble Incident Report",
        "",
        "## Status",
        "",
        (
            "The AI narrative generator was unavailable for this run. "
            "This is a deterministic rendering driven by the final "
            "disposition buckets (the report-truth source). The "
            "pipeline is evidence-gated: unsupported or misattributed "
            "claims are blocked or downgraded and routed out of "
            "confirmed malicious output. Not every validator-backed "
            "observation is confirmed malicious."
        ),
        "",
        "**Validator-backed observations:** %s"
        % (observations if observations is not None
           else "see pipeline_summary"),
        "**Confirmed malicious atomic:** %d" % len(confirmed),
        "",
    ]
    _section(lines, "Confirmed Malicious (atomic)", confirmed)
    _section(lines, "Requiring Further Investigation", suspicious)
    _section(
        lines,
        "Investigated and Dispositioned as Benign/False Positive",
        benign,
    )
    _section(lines, "Evidence Insufficient to Confirm", inconclusive)
    lines.append("## Synthesis / Narrative Context")
    lines.append("")
    lines.append(
        "%d synthesis/narrative item(s). These inform attack-chain "
        "context only and do NOT increase the atomic confirmed count."
        % len(synthesis)
    )
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "Deterministic fallback (no AI narrative synthesis). Section "
        "membership is bucket-driven; rerun with the Inv4 model "
        "available for full kill-chain narrative."
    )
    lines.append("")
    return "\n".join(lines)


def apply_schema_warning_banner(report: str, errors: list[str]) -> str:
    """B3/B4 FIX: prepend schema validation warnings as banner, keep report.

    Called when validate_report returns valid=False. Previously the
    pipeline replaced the full inv4 report with a 170-byte fallback stub
    at this point, losing the AI-generated analysis entirely. This
    helper keeps the report content and surfaces the schema errors as a
    markdown blockquote banner so reviewers see both the analysis and
    the provenance-level issues.

    Empty or missing errors list returns the report unchanged.

    Args:
        report: the full report text from inv4.
        errors: list of schema validation error strings.

    Returns:
        Banner + original report if errors present; original report
        unchanged if errors is empty.
    """
    if not errors:
        return report
    banner_lines = ["> **SCHEMA VALIDATION WARNINGS:**"]
    for err in errors:
        banner_lines.append(f"> - {err}")
    banner = "\n".join(banner_lines) + "\n\n"
    return banner + report
