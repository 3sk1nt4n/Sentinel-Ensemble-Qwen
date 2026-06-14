"""Display helpers for finding rendering.

finding_title(f) returns the richest available description for a
finding, handling the post-SC schema split where self-corrected
findings store rewritten text in ``summary`` and the original pre-SC
artifact text in ``original_draft.artifact``.

Priority P2 (preserves richer pre-SC forensic content):
  1. artifact               - pre-SC or non-SC finding title
  2. original_draft.artifact - pre-SC rich content when SC rewrote
  3. summary                - post-SC rewritten description
  4. title                  - older-schema fallback
  5. "(no description available)" - sentinel

This priority assumes SC rewrites can lose forensic content (C2 IPs,
endpoints, attack chain details). If C33 self-assessment penalty
lands and SC becomes trusted, this priority may flip to prefer
summary over original_draft.artifact.
"""
from __future__ import annotations


def finding_title(f: dict) -> str:
    """Return richest available title text for a finding."""
    if not isinstance(f, dict):
        return "(no description available)"
    artifact = f.get("artifact")
    if isinstance(artifact, str) and artifact.strip():
        return artifact
    original = f.get("original_draft")
    if isinstance(original, dict):
        orig_artifact = original.get("artifact")
        if isinstance(orig_artifact, str) and orig_artifact.strip():
            return orig_artifact
    summary = f.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary
    title = f.get("title")
    if isinstance(title, str) and title.strip():
        return title
    return "(no description available)"
