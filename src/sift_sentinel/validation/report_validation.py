"""

Sentinel Qwen Ensemble -- Report validation (Pipeline Step 14).
Python validates every citation before the report ships.

Safety nets:
  1. Citation check: every F-XXX in narrative must exist in validated findings.
  2. Schema enforcement: every finding must have finding_id, tool_call_ids, raw_excerpt.
  3. Vocabulary constraint (WARNING only): narrative terms vs finding vocabulary.
"""

from __future__ import annotations

import re

# Required fields per the Finding model (sift_sentinel/schema/finding.py)
_REQUIRED_FIELDS = ("finding_id", "tool_call_ids", "raw_excerpt")

# Finding ID pattern: F-001, F-002, etc.
_FINDING_ID_RE = re.compile(r"\bF-\d{3}\b")

# Stop words excluded from vocabulary comparison
_STOP_WORDS = frozenset({
    "the", "is", "and", "or", "a", "an", "in", "of", "to",
    "for", "was", "were", "that", "this", "with", "from",
    "at", "by", "on", "not", "no", "but", "it", "its",
    "are", "be", "has", "had", "have", "been", "will",
    "can", "do", "did", "does", "may", "would", "should",
    "all", "each", "every", "both", "more", "most", "other",
    "some", "such", "than", "too", "very", "also", "just",
    "about", "after", "before", "between", "into", "through",
    "during", "without", "within", "under", "over", "above",
    "see", "shows", "found", "using", "based",
    # Common report terms (not forensic vocabulary)
    "finding", "findings", "report", "investigation", "summary",
    "timeline", "evidence", "analysis", "confirmed", "observed",
    "section", "conclusion", "recommendation", "limitation",
})

_WORD_RE = re.compile(r"\b\w+\b")


def validate_report(
    report: dict,
    validated_findings: list[dict],
) -> dict:
    """Validate a report against validated findings.

    Returns {"valid": bool, "errors": list[str], "warnings": list[str]}.
    Any error makes valid=False. Warnings are informational only.
    """
    errors: list[str] = []
    warnings: list[str] = []

    narrative = report.get("report", "")
    report_findings = report.get("findings", [])

    # ── Empty-report warnings ────────────────────────────────────────
    if not narrative:
        warnings.append("Empty narrative in report")

    if not validated_findings:
        warnings.append("No validated findings provided")

    # ── Safety net 1: Citation check ─────────────────────────────────
    _check_citations(narrative, validated_findings, errors)

    # ── Safety net 3: Schema enforcement ─────────────────────────────
    _check_schema(report_findings, errors)

    # ── Vocabulary constraint (warnings only) ────────────────────────
    if narrative and validated_findings:
        _check_vocabulary(narrative, validated_findings, warnings)

    # ── Confirm-context consistency (warning only): prose may not label a
    #    finding 'confirmed' unless it is in the confirmed findings set.
    #    The report-write chokepoint reconciles the text deterministically;
    #    this is the audit-trail record that a contradiction was caught. ──
    try:
        from sift_sentinel.analysis.confirmed_consistency import (
            scan_confirmed_contradictions,
        )
        confirmed_ids = {
            str(f.get("finding_id", ""))
            for f in report_findings
            if isinstance(f, dict)
        }
        for h in scan_confirmed_contradictions(narrative, confirmed_ids):
            warnings.append(
                "Confirm-context cites %s which is not in the confirmed "
                "findings set (line %d)" % (h["finding_id"], h["line_no"])
            )
    except Exception:
        pass

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }


def _check_citations(
    narrative: str,
    validated_findings: list[dict],
    errors: list[str],
) -> None:
    """Every F-XXX in narrative must exist in validated findings."""
    if not narrative:
        return
    valid_ids = {f.get("finding_id", "") for f in validated_findings}
    cited_ids = set(_FINDING_ID_RE.findall(narrative))
    for cid in sorted(cited_ids - valid_ids):
        errors.append(f"Citation {cid} not found in validated findings")


def _check_schema(
    report_findings: list[dict],
    errors: list[str],
) -> None:
    """Every finding in report must have required fields with non-empty values."""
    for i, finding in enumerate(report_findings):
        fid = finding.get("finding_id", f"findings[{i}]")
        for field in _REQUIRED_FIELDS:
            val = finding.get(field)
            if val is None or val == "":
                errors.append(
                    f"Finding {fid}: missing required field '{field}'"
                )
            elif field == "tool_call_ids" and isinstance(val, list) and len(val) == 0:
                errors.append(
                    f"Finding {fid}: empty tool_call_ids list"
                )


def _check_vocabulary(
    narrative: str,
    validated_findings: list[dict],
    warnings: list[str],
) -> None:
    """Narrative terms not in finding vocabulary produce warnings (not errors)."""
    allowed = _extract_vocabulary(validated_findings)
    narrative_tokens = set(_WORD_RE.findall(narrative.lower()))
    narrative_tokens -= _STOP_WORDS
    # Remove finding ID patterns (F-001 etc.) - checked separately
    narrative_tokens = {t for t in narrative_tokens
                        if not re.match(r"^f$", t)
                        and not re.match(r"^\d{3}$", t)}
    unknown = sorted(narrative_tokens - allowed)
    if unknown:
        warnings.append(
            f"Vocabulary not in findings: {', '.join(unknown[:10])}"
            + (f" (+{len(unknown) - 10} more)" if len(unknown) > 10 else "")
        )


def _extract_vocabulary(findings: list[dict]) -> set[str]:
    """Build allowed vocabulary from all validated finding fields."""
    vocab: set[str] = set()
    text_fields = ("artifact", "raw_excerpt", "finding_id",
                   "evidence_type", "correction_reason")
    for f in findings:
        for field in text_fields:
            val = f.get(field, "")
            if isinstance(val, str):
                vocab.update(_WORD_RE.findall(val.lower()))
        # Also index source_tools and tool_call_ids
        for lst_field in ("source_tools", "tool_call_ids"):
            for item in f.get(lst_field, []):
                vocab.update(_WORD_RE.findall(str(item).lower()))
    return vocab
