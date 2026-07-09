#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

# SIFT_FRESH_COMPLETION_BUCKET_FAITHFUL_TABLE_V1E
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import build_bucket_faithful_customer_findings_table as _sift_bucket_table_v1e


# SIFT_FRESH_RUN_COMPLETION_GATE_V1B
#
# Universal post-run acceptance contract:
# - A run is not accepted unless the log reaches STEP 16.
# - Pre-report crashes invalidate the run.
# - A final customer table is rendered only from a real completed state.
# - State/log pairing is checked to prevent mixing a new empty state with an old log.
# - Dataset-agnostic: no PIDs, IPs, paths, hashes, or case-specific values.

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_STATE_FILES = [
    "all_outputs.json",
    "evidence_db.json",
    "finding_disposition_buckets.json",
]

REQUIRED_BUCKET_KEYS = [
    "confirmed_malicious_atomic",
    "suspicious_needs_review",
    "inconclusive_unresolved",
    "benign_or_false_positive",
    "synthesis_narrative",
]

REQUIRED_TABLE_SNIPPETS = [
    "Sentinel Qwen Ensemble Customer Findings",
    "Confirmed malicious findings",
    "Suspicious findings needing analyst review",
    "Self-correction / inconclusive / withheld",
    "Benign or false-positive findings",
    "## Actionable / Needs Review",
    "## Self-Correction / Inconclusive",
    "## Benign / False Positive",
]

FATAL_PATTERNS = {
    "python_traceback": r"Traceback \(most recent call last\)",
    "none_state_crash": r"Path\(None\)|NoneType|state_dir=None",
    "pre_report_gate_fail": r"TOOL_HIT_INTEGRITY_PRE_REPORT_GATE=FAIL|PROVENANCE_TAXONOMY_GATE=FAIL",
    "wrong_os_volatility_plugin": r"LIVE VOL: Running\s+\S+\s+\(linux\.",
}

WARN_PATTERNS = {
    "provider_429": r"HTTP/1\.1 429 Too Many Requests|rate_limit_error",
    "self_correction_api_error": r"API error for Inv SC|corrector_returned_none",
}

MAX_STATE_LOG_MTIME_DELTA_S = float(os.environ.get("SIFT_STATE_LOG_MAX_AGE_DELTA_S", "7200"))


def _latest_state() -> Path | None:
    candidates = sorted(
        Path("/tmp").glob("sift-sentinel-run-*"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _latest_log() -> Path | None:
    logs = sorted(
        (ROOT / "logs").glob("*/run.log"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    return logs[0] if logs else None


def _find_log_for_state(state: Path) -> Path | None:
    env_log = os.environ.get("SIFT_RUN_LOG") or os.environ.get("RUN_LOG")
    if env_log and Path(env_log).exists():
        return Path(env_log)

    logs = sorted(
        (ROOT / "logs").glob("*/run.log"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )

    state_text = str(state)
    for log in logs:
        try:
            text = log.read_text(errors="replace")
        except Exception:
            continue
        if state_text in text or state.name in text:
            return log

    return logs[0] if logs else None


def _load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(errors="replace"))
    except Exception:
        pass
    return default


def _bucket_data(state: Path) -> Any:
    data = _load_json(state / "finding_disposition_buckets.json", {})
    if isinstance(data, dict) and "finding_disposition_buckets" in data:
        data = data.get("finding_disposition_buckets") or {}
    return data


def _bucket_counts(state: Path) -> dict[str, int]:
    data = _bucket_data(state)
    if not isinstance(data, dict):
        return {}
    return {str(k): len(v) for k, v in data.items() if isinstance(v, list)}


def _validate_buckets(state: Path) -> tuple[bool, str, dict[str, int]]:
    data = _bucket_data(state)
    if not isinstance(data, dict):
        return False, "bucket_file_not_object", {}

    missing = [k for k in REQUIRED_BUCKET_KEYS if k not in data]
    if missing:
        return False, "missing_bucket_keys:" + ",".join(missing), _bucket_counts(state)

    bad = [k for k in REQUIRED_BUCKET_KEYS if not isinstance(data.get(k), list)]
    if bad:
        return False, "non_list_bucket_keys:" + ",".join(bad), _bucket_counts(state)

    return True, "ok", _bucket_counts(state)


def _state_log_pair_status(state: Path, log: Path, log_text: str) -> tuple[bool, str]:
    if str(state) in log_text or state.name in log_text:
        return True, "state_marker_in_log"

    try:
        delta = abs(state.stat().st_mtime - log.stat().st_mtime)
    except Exception:
        return False, "state_log_pair_unknown"

    if delta <= MAX_STATE_LOG_MTIME_DELTA_S:
        return True, f"mtime_near_no_state_marker:delta_s={delta:.1f}"

    return False, f"state_log_mismatch:delta_s={delta:.1f}"


def _render_customer_table(state: Path) -> tuple[bool, str, str]:
    try:
        from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table
    except Exception as exc:
        return False, "", f"import_failed:{type(exc).__name__}:{exc}"

    try:
        text = render_customer_findings_table(state_dir=str(state))
    except Exception as exc:
        return False, "", f"render_failed:{type(exc).__name__}:{exc}"

    if not isinstance(text, str) or not text.strip():
        return False, "", "render_empty"

    missing = [s for s in REQUIRED_TABLE_SNIPPETS if s not in text]
    if missing:
        return False, text, "missing_table_snippets:" + ",".join(missing)

    forbidden = [s for s in ("Severity", "Confidence", "/mnt/windows_mount") if s in text]
    if forbidden:
        return False, text, "forbidden_table_tokens:" + ",".join(forbidden)

    return True, text, "ok"


def main(argv: list[str]) -> int:
    args = list(argv)
    write_table = False
    if "--write-table" in args:
        args.remove("--write-table")
        write_table = True

    state = Path(args[0]) if args else _latest_state()
    log = Path(args[1]) if len(args) > 1 else (_find_log_for_state(state) if state else _latest_log())

    failures: list[str] = []
    warnings: list[str] = []

    if not state or not state.exists():
        print("FRESH_RUN_COMPLETION_GATE=FAIL reason=no_state")
        return 2

    if not log or not log.exists():
        print(f"FRESH_RUN_COMPLETION_GATE=FAIL reason=no_log state={state}")
        return 2

    log_text = log.read_text(errors="replace")

    missing_files = [name for name in REQUIRED_STATE_FILES if not (state / name).exists()]
    if missing_files:
        failures.append("missing_state_files=" + ",".join(missing_files))

    pair_ok, pair_reason = _state_log_pair_status(state, log, log_text)
    if not pair_ok:
        failures.append(pair_reason)
    elif "no_state_marker" in pair_reason:
        warnings.append(pair_reason)

    step16 = bool(re.search(r"STEP 16:\s+ANALYSIS COMPLETE", log_text))
    if not step16:
        failures.append("missing_STEP_16")

    for label, pattern in FATAL_PATTERNS.items():
        hits = re.findall(pattern, log_text)
        if hits:
            failures.append(f"{label}={len(hits)}")

    for label, pattern in WARN_PATTERNS.items():
        hits = re.findall(pattern, log_text)
        if hits:
            warnings.append(f"{label}={len(hits)}")

    buckets_ok = False
    bucket_reason = "skipped_missing_state_files"
    bucket_counts: dict[str, int] = {}
    if not missing_files:
        buckets_ok, bucket_reason, bucket_counts = _validate_buckets(state)
        if not buckets_ok:
            failures.append("buckets=" + bucket_reason)

    table_reason = "skipped_until_required_state_files_exist"
    table_text = ""
    if not missing_files and buckets_ok:
        ok_table, table_text, table_reason = _render_customer_table(state)
        if not ok_table:
            failures.append("customer_table=" + table_reason)
        elif write_table and not failures:
            out = state / "customer_findings_table.md"
            out.write_text(table_text)
            table_reason = f"ok_written:{out}"
    elif write_table:
        warnings.append("customer_table_not_written_incomplete_state")

    print("# Fresh Run Completion + Customer Table Gate")
    print()
    print(f"- state: `{state}`")
    print(f"- log: `{log}`")
    print(f"- state_log_pair: `{pair_reason}`")
    print(f"- step16: `{step16}`")
    print(f"- bucket_status: `{bucket_reason}`")
    print(f"- bucket_counts: `{bucket_counts}`")
    print(f"- customer_table: `{table_reason}`")

    if warnings:
        print()
        print("## Warnings")
        for item in warnings:
            print(f"- WARN: {item}")

    if failures:
        print()
        print("## Failures")
        for item in failures:
            print(f"- FAIL: {item}")
        print()
        print(f"FRESH_RUN_COMPLETION_GATE=FAIL state={state} log={log}")
        return 1

    print()
    print(f"FRESH_RUN_COMPLETION_GATE=PASS state={state} log={log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
