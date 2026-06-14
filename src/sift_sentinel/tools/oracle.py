"""Tool fitness oracle — dataset-agnostic tier + score ranking.

Synthesizes tool-selection signals into 4 categorical tiers with an
auxiliary numeric score for stable intra-tier ranking.

Tiers:
  PREFERRED  — strong positive signal (records, category coverage, health)
  AVAILABLE  — registered, no negative signal
  PENALIZED  — prior run returned 0 records OR health warnings
  EXCLUDED   — not registered OR profile-incompatible kernel dependency

Inputs (all optional, caller-supplied):
  - profile_healthy: bool (default True)
  - profile_reasons: list[str] (DEGRADED reason codes)
  - tool_health: dict[str, dict]   run-local health per tool
  - investigation_history: list[dict]   prior turn results (optional)
  - already_selected: set[str]   tools already chosen this round
  - registered_tools: set[str]   _TOOL_REGISTRY keys
  - artifact_map: dict[str, str] tool -> artifact type (M/N/A/T/E/R/D)
  - category_map: dict[str, str] tool -> category label

Feature-gated via SIFT_USE_ORACLE=1. Default off. No callers wired in C4;
C5 wires Inv1 and ReAct turn-N+1.

Generic design:
  - No tool names referenced in scoring logic.
  - No dataset codes referenced anywhere.
  - Kernel-dependent detection via caller-supplied artifact_map entry 'M'
    (memory) combined with profile_healthy == False.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Tier(str, Enum):
    PREFERRED = "PREFERRED"
    AVAILABLE = "AVAILABLE"
    PENALIZED = "PENALIZED"
    EXCLUDED = "EXCLUDED"


@dataclass
class TierRanked:
    tool: str
    tier: Tier
    score: float
    reason: str


def is_enabled() -> bool:
    """Return True when oracle is enabled via SIFT_USE_ORACLE=1."""
    return os.environ.get("SIFT_USE_ORACLE") == "1"


def _profile_score(
    tool: str,
    profile_healthy: bool,
    profile_reasons: list[str],
    artifact_map: dict[str, str],
) -> tuple[float, Optional[str]]:
    """Penalize memory-artifact tools when profile DEGRADED."""
    if profile_healthy:
        return 0.0, None
    artifact = artifact_map.get(tool, "")
    if artifact == "M":
        reason_codes = ",".join(profile_reasons) if profile_reasons else "unknown"
        return -100.0, f"profile DEGRADED ({reason_codes}), memory tool kernel-blocked"
    return 0.0, None


def _health_score(tool: str, tool_health: dict[str, dict]) -> tuple[float, Optional[str]]:
    """Penalize tools that failed in current run."""
    entry = tool_health.get(tool)
    if not entry:
        return 0.0, None
    if entry.get("failed"):
        return -10.0, f"health: failed in current run ({entry.get('reason', 'unknown')})"
    return 0.0, None


def _history_score(
    tool: str, investigation_history: list[dict]
) -> tuple[float, Optional[str]]:
    """Penalize tools that already returned 0 records this run."""
    for entry in investigation_history:
        if entry.get("tool") != tool:
            continue
        if entry.get("skipped"):
            return -5.0, f"history: prior skip ({entry.get('skip_reason', 'low yield')})"
        if entry.get("result_count", 1) == 0:
            return -5.0, "history: prior turn returned 0 records"
    return 0.0, None


def _artifact_score(
    tool: str,
    already_selected: set[str],
    artifact_map: dict[str, str],
) -> tuple[float, Optional[str]]:
    """Prefer tools whose artifact type is not yet represented in selection."""
    artifact = artifact_map.get(tool)
    if not artifact:
        return 0.0, None
    represented = {artifact_map.get(t) for t in already_selected if t in artifact_map}
    if artifact in represented:
        return 0.0, None
    return 3.0, f"artifact {artifact} not yet represented in selection"


class ToolOracle:
    """Score candidate tools by tier + numeric sort key."""

    def __init__(
        self,
        profile_healthy: bool = True,
        profile_reasons: Optional[list[str]] = None,
        tool_health: Optional[dict[str, dict]] = None,
        investigation_history: Optional[list[dict]] = None,
        already_selected: Optional[set[str]] = None,
        registered_tools: Optional[set[str]] = None,
        artifact_map: Optional[dict[str, str]] = None,
        category_map: Optional[dict[str, str]] = None,
    ) -> None:
        self.profile_healthy = profile_healthy
        self.profile_reasons = profile_reasons or []
        self.tool_health = tool_health or {}
        self.investigation_history = investigation_history or []
        self.already_selected = already_selected or set()
        self.registered_tools = registered_tools or set()
        self.artifact_map = artifact_map or {}
        self.category_map = category_map or {}

    def verdict(self, tool: str) -> TierRanked:
        """Return tier + score + reason for a single tool."""
        if self.registered_tools and tool not in self.registered_tools:
            return TierRanked(
                tool=tool, tier=Tier.EXCLUDED, score=-1000.0,
                reason="not in tool registry",
            )

        reasons: list[str] = []
        score = 0.0

        p_delta, p_reason = _profile_score(
            tool, self.profile_healthy, self.profile_reasons, self.artifact_map,
        )
        if p_delta <= -100.0:
            return TierRanked(
                tool=tool, tier=Tier.EXCLUDED, score=p_delta,
                reason=p_reason or "profile-incompatible",
            )
        score += p_delta
        if p_reason:
            reasons.append(p_reason)

        h_delta, h_reason = _health_score(tool, self.tool_health)
        score += h_delta
        if h_reason:
            reasons.append(h_reason)

        hist_delta, hist_reason = _history_score(tool, self.investigation_history)
        score += hist_delta
        if hist_reason:
            reasons.append(hist_reason)

        art_delta, art_reason = _artifact_score(
            tool, self.already_selected, self.artifact_map,
        )
        score += art_delta
        if art_reason:
            reasons.append(art_reason)

        if score <= -100.0:
            tier = Tier.EXCLUDED
        elif score < 0:
            tier = Tier.PENALIZED
        elif score > 0:
            tier = Tier.PREFERRED
        else:
            tier = Tier.AVAILABLE
            reasons.append("registered, no positive or negative signal")

        return TierRanked(
            tool=tool, tier=tier, score=score, reason="; ".join(reasons),
        )

    def rank(self, candidate_tools: list[str]) -> list[TierRanked]:
        """Return all candidates sorted by tier then score descending."""
        verdicts = [self.verdict(t) for t in candidate_tools]
        tier_order = {
            Tier.PREFERRED: 0,
            Tier.AVAILABLE: 1,
            Tier.PENALIZED: 2,
            Tier.EXCLUDED: 3,
        }
        verdicts.sort(key=lambda v: (tier_order[v.tier], -v.score, v.tool))
        return verdicts
