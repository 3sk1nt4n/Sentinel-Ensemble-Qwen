# ToolOracle - C4 design

## Purpose
Dataset-agnostic fitness ranking for forensic tools. Returns (Tier, score,
reason) per tool. C5 wires into Inv1 selection and Step 11 ReAct turn-N+1.

## Tiers
- **PREFERRED** - positive net signal (artifact coverage, healthy context)
- **AVAILABLE** - registered, neutral (score == 0)
- **PENALIZED** - negative signal but still usable (history, health)
- **EXCLUDED** - unregistered OR kernel-blocked on DEGRADED profile

Tier derived from cumulative score: <=-100 EXCLUDED, <0 PENALIZED,
>0 PREFERRED, ==0 AVAILABLE.

Short-circuit: when `_profile_score` returns -100 (kernel-blocked memory
tool on DEGRADED profile), `verdict()` returns EXCLUDED immediately,
bypassing other scorers. Rationale: a tool that physically cannot run
must not be ranked by artifact novelty. Mirrors the `registered_tools`
short-circuit at top of `verdict()`.

## Scorers (4 private functions)
1. `_profile_score` - -100 for memory tools on DEGRADED profile
2. `_health_score` - -10 if tool failed in current run
3. `_history_score` - -5 if tool returned 0 records or was skipped
4. `_artifact_score` - +3 if tool's artifact type is not yet represented

## Inputs
All optional. Caller passes what it has.
- `profile_healthy`, `profile_reasons`
- `tool_health` (run-local)
- `investigation_history` (Step 11 context_results shape)
- `already_selected`
- `registered_tools`
- `artifact_map` (TOOL_TO_ARTIFACT_TYPE)
- `category_map` (_TOOL_CATEGORY - reserved for future category rules)

## Feature flag
`SIFT_USE_ORACLE=1` via `is_enabled()`. Default off. C4 does not wire.

## Dataset-agnostic contract
- No tool names in source code.
- No dataset codes anywhere.
- Enforced by `test_7_dataset_agnostic_no_tool_names_hardcoded_in_scores`.

## Existing systems subsumed (C5)
- `LOW_YIELD_TOOLS` dict in coordinator.py → history_score input.
- `SKIP_LOW_YIELD` env gate → replaced when `SIFT_USE_ORACLE=1`.
- `build_tool_catalog_advertisement(degraded_profile)` → caller filters via oracle.

## Drift deferred to C8
- DISK_TOOLS duplicated (confidence.py vs coordinator.py inline).
- MEMORY_TOOLS vs TOOL_TO_ARTIFACT_TYPE disagree on vol_netscan.
- Oracle does not resolve; reads neither. C8 cleans up.
