"""Cheapest-first triage for SC-blocked findings -- so the 'held for transparency'
limbo is eliminated and the expensive paths run only when they must.

WHERE (the perfect timing): at the Step-10/11 -> Step-12 boundary. By then each
finding's validation status (Step 10) AND its ReAct verdict (Step 11, which runs
CONCURRENTLY with Step 10 -> no added wall-time) are known. Today the ~24/25
blocked findings with no ReAct verdict fall into the Step-12 self-correction
token-sink (~22 KB dossier each, ~600 K tokens to salvage one) and then drop into
'UNRESOLVED'. This routes them instead.

PRIORITY (cheapest first, to cut usage):
  1. reuse the existing Step-11 ReAct verdict        -- FREE (already computed)
  2. a deterministic structural malice/benign signal -- FREE (no AI)
  3. a single targeted ReAct investigation           -- the ONLY new AI cost,
                                                         and ReAct (concurrent,
                                                         1024-tok turns) is far
                                                         cheaper than the SC sink

Every blocked finding ends in benign/FP or needs_review (after the react step
re-triages on its verdict) -- no standalone UNRESOLVED row.

Universal / dataset-agnostic: keys only on verdict NAMES and boolean structural
signals -- no tool, case, IP, path, or hash literals.
"""
from __future__ import annotations

_BENIGN_VERDICTS = frozenset({
    "confirmed_benign", "benign", "likely_fp", "false_positive", "fp",
})
_SUSPICIOUS_VERDICTS = frozenset({
    "confirmed_malicious", "malicious", "inconclusive", "suspicious", "needs_review",
})

# routes
ROUTE_BENIGN = "benign"            # -> benign / FP+SC section
ROUTE_NEEDS_REVIEW = "needs_review"  # -> findings section
ROUTE_REACT = "react"             # -> run ONE targeted ReAct, then re-triage


def triage_route(react_verdict: str | None = None,
                 has_malice_signal: bool = False,
                 has_benign_signal: bool = False) -> tuple[str, str]:
    """Return (route, reason) for an SC-blocked finding. See module docstring."""
    v = str(react_verdict or "").strip().lower()
    if v in _BENIGN_VERDICTS:
        return (ROUTE_BENIGN, "react:%s" % v)
    if v in _SUSPICIOUS_VERDICTS:
        return (ROUTE_NEEDS_REVIEW, "react:%s" % v)
    # no usable verdict -> deterministic structural signal (free) next
    if has_malice_signal and not has_benign_signal:
        return (ROUTE_NEEDS_REVIEW, "structural_malice")
    if has_benign_signal and not has_malice_signal:
        return (ROUTE_BENIGN, "structural_benign")
    # genuinely ambiguous -> the only case that spends a new ReAct investigation
    return (ROUTE_REACT, "ambiguous_needs_react")


__all__ = ["triage_route", "ROUTE_BENIGN", "ROUTE_NEEDS_REVIEW", "ROUTE_REACT"]
