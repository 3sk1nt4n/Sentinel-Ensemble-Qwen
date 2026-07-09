"""Sentinel Qwen Ensemble - report-stage hard gates (Slot 31E-DB.5.5/.6/.7).

Three independent truth gates that run *after* the report is written:

  * ``enforce_report_validation_gate`` -- a non-empty
    ``report_validation.errors`` can never end in an overall PASS. It
    flips ``pipeline_summary.status`` and returns a nonzero code so the
    wrapper aborts instead of shipping a silently-invalid report.
  * ``format_tool_health_summary`` -- one wording surface for tool
    health that never conflates "not applicable" with "failed".
  * ``check_report_bucket_consistency`` / ``postrun_report_checks`` --
    confirmed/critical atomic sections may only ever contain
    ``confirmed_malicious_atomic``; severity or a flat pre-disposition
    finding list is never the final report truth.

Reverting Slot 31E-DB.5 deletes this module and its run_pipeline call
sites; report shipping degrades to the prior log-and-ship behaviour.
"""

from __future__ import annotations

import json
import os

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    BUCKET_SYNTHESIS,
)

_NON_CONFIRMED_BUCKETS = (
    BUCKET_SUSPICIOUS,
    BUCKET_BENIGN,
    BUCKET_INCONCLUSIVE,
    BUCKET_SYNTHESIS,
)


# ── 31E-DB.5.5: report validation hard-fail ────────────────────────────

def enforce_report_validation_gate(
    report_validation: dict,
    pipeline_summary: dict | None = None,
) -> int:
    """Return 0 when the report validated clean, 1 otherwise.

    A non-empty ``errors`` list is a hard fail: it prints
    ``REPORT_VALIDATION_GATE=FAIL``, marks the pipeline summary
    ``completed_with_report_validation_issues`` and records the gate in
    the machine-readable ledger. The caller MUST treat a nonzero return
    as a wrapper abort (``raise SystemExit(1)``) -- a report-validation
    failure can never produce an overall PASS.
    """
    errors = []
    if isinstance(report_validation, dict):
        errors = report_validation.get("errors") or []

    def _ledger(value: str) -> None:
        if isinstance(pipeline_summary, dict):
            gates = pipeline_summary.setdefault("gates", {})
            gates["REPORT_VALIDATION_GATE"] = value

    if errors:
        print("REPORT_VALIDATION_GATE=FAIL", flush=True)
        for e in errors:
            print("  report_validation_error: %s" % e, flush=True)
        if isinstance(pipeline_summary, dict):
            pipeline_summary["status"] = (
                "completed_with_report_validation_issues"
            )
            pipeline_summary["report_validation_errors"] = list(errors)
        _ledger("FAIL")
        return 1

    print("REPORT_VALIDATION_GATE=PASS", flush=True)
    if isinstance(pipeline_summary, dict):
        pipeline_summary["report_validation_errors"] = []
    _ledger("PASS")
    return 0


# ── 31E-DB.5.6: tool-health wording ────────────────────────────────────

def format_tool_health_summary(
    selected: int,
    data_producing: int,
    not_applicable: int,
    failed: int,
) -> str:
    """Render tool health without conflating N/A with failure.

    "Not applicable" means the tool's artifact class is absent for this
    evidence (e.g. a disk tool on a memory-only image) -- it is neither
    an attempt that succeeded nor a failure. The wording makes that
    explicit so ``19/20`` never reads as a partial failure.
    """
    note = (
        "Not applicable means the artifact class is absent for this "
        "evidence and is not a failure."
    )
    return (
        "Tools selected: %d | Data-producing tools: %d | "
        "Not applicable: %d | Failed: %d (%s)"
        % (
            int(selected),
            int(data_producing),
            int(not_applicable),
            int(failed),
            note,
        )
    )


# ── 31E-DB.5.7: report/bucket consistency ──────────────────────────────

def _confirmed_ids(buckets: dict) -> set[str]:
    out: set[str] = set()
    for f in (buckets.get(BUCKET_CONFIRMED) or []):
        if isinstance(f, dict) and f.get("finding_id"):
            out.add(str(f["finding_id"]))
    return out


def check_report_bucket_consistency(
    buckets: dict,
    disposition_counts: dict | None = None,
    report_truth: dict | None = None,
) -> list[str]:
    """Return violation strings; empty list == consistent.

    Mechanically asserts:
      * confirmed/critical atomic truth == ``confirmed_malicious_atomic``
      * no non-confirmed bucket finding id leaks into the confirmed set
      * synthesis_narrative never increments the confirmed atomic count
      * bucket count and report_truth/disposition_counts agree
    """
    violations: list[str] = []
    if not isinstance(buckets, dict):
        return ["buckets_not_a_dict"]

    confirmed = buckets.get(BUCKET_CONFIRMED) or []
    confirmed_n = len(confirmed)
    confirmed_ids = _confirmed_ids(buckets)

    for name in _NON_CONFIRMED_BUCKETS:
        for f in (buckets.get(name) or []):
            if not isinstance(f, dict):
                continue
            fid = f.get("finding_id")
            if fid and str(fid) in confirmed_ids:
                violations.append(
                    "%s:%s_finding_also_in_confirmed" % (fid, name)
                )

    if isinstance(disposition_counts, dict):
        dc = disposition_counts.get(BUCKET_CONFIRMED)
        if dc is not None and dc != confirmed_n:
            violations.append(
                "disposition_count_mismatch:bucket=%d counts=%s"
                % (confirmed_n, dc)
            )
        syn = disposition_counts.get(BUCKET_SYNTHESIS)
        if syn is not None and isinstance(dc, int) and dc > 0 and (
            dc == confirmed_n + syn and syn > 0
        ):
            # confirmed count must not silently fold synthesis in.
            violations.append("synthesis_folded_into_confirmed_count")

    if isinstance(report_truth, dict):
        rt = report_truth.get("bucket_counts") or {}
        rc = rt.get(BUCKET_CONFIRMED)
        if rc is not None and rc != confirmed_n:
            violations.append(
                "report_truth_confirmed_mismatch:bucket=%d report=%s"
                % (confirmed_n, rc)
            )

    return violations



# ── 31G-D2c: final confirmed-section coverage gate ─────────────────────
def _d2c_load_report_markdown(state_dir: str) -> str | None:
    """Load final state report.md for post-run render checks.

    Dataset-agnostic: no case values, no finding IDs, no line numbers.
    """
    path = os.path.join(state_dir, "report.md")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _d2c_confirmed_ids_from_buckets(buckets: dict | None) -> list[str]:
    if not isinstance(buckets, dict):
        return []
    ids: set[str] = set()
    for item in (buckets.get(BUCKET_CONFIRMED) or []):
        if isinstance(item, dict) and item.get("finding_id"):
            ids.add(str(item["finding_id"]))
        elif isinstance(item, str) and item.strip():
            ids.add(item.strip())
    return sorted(ids)


def check_confirmed_section_render_coverage(
    report_md: str | None,
    buckets: dict | None,
    report_truth: dict | None = None,
) -> list[str]:
    """Return final-report confirmed-section coverage violations.

    31G-D2c backstop: D2b writes ``confirmed_section_render`` into
    report_truth before validation. This post-run gate re-checks the
    final persisted report text so later transforms cannot silently drop
    confirmed IDs or duplicate/misplace the confirmed section.

    The gate activates for D2b/D2c-era truth packages:
      * report_truth.confirmed_section_render exists, or
      * report_truth.behavior_groups exists.

    Older/minimal synthetic states without those keys remain compatible.
    """
    import re

    violations: list[str] = []
    if not isinstance(report_truth, dict):
        return violations

    audit = report_truth.get("confirmed_section_render")
    has_groups = "behavior_groups" in report_truth
    if not isinstance(audit, dict) and not has_groups:
        return violations

    expected_ids = _d2c_confirmed_ids_from_buckets(buckets)
    if isinstance(audit, dict):
        # ``audit["gate"]`` is advisory here. This post-run validator is the
        # independent source of truth for the persisted report text. Older
        # audits may have failed only because they counted unrelated
        # "Confirmed Malicious" subsections outside the deterministic primary
        # section. Explicit audit errors / missing IDs are still checked below.
        gate = str(audit.get("gate") or "").upper()
        if gate and gate != "PASS" and audit.get("error"):
            violations.append("confirmed_section_render_gate:%s" % gate)

        try:
            audit_expected = int(audit.get("expected_count"))
        except (TypeError, ValueError):
            audit_expected = None
        if audit_expected is not None and audit_expected != len(expected_ids):
            violations.append(
                "confirmed_section_expected_count_mismatch:"
                "bucket=%d audit=%d" % (len(expected_ids), audit_expected)
            )

        try:
            audit_missing = int(audit.get("missing_count") or 0)
        except (TypeError, ValueError):
            audit_missing = 0
        audit_missing_ids = [
            str(x) for x in (audit.get("missing_finding_ids") or []) if x
        ]
        if audit_missing or audit_missing_ids:
            violations.append(
                "confirmed_section_render_missing_ids:%s"
                % ",".join(audit_missing_ids[:20])
            )

    if not expected_ids:
        return violations

    if not isinstance(report_md, str) or not report_md.strip():
        violations.append("report.md_missing_for_confirmed_section_gate")
        return violations

    # Tolerate the optional "N. " prefix the deterministic polish pass adds when it
    # renumbers level-2 headings (## 3. Confirmed Malicious Atomic Findings).
    header_re = re.compile(
        r"^##\s+(?:\d+\.\s+)?Confirmed Malicious(?: Atomic)? Findings[^\n]*$",
        re.MULTILINE,
    )
    section_re = re.compile(
        r"(^##\s+(?:\d+\.\s+)?Confirmed Malicious(?: Atomic)? Findings[^\n]*$)(.*?)(?=^##\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    headings = header_re.findall(report_md)
    if len(headings) != 1:
        violations.append("confirmed_section_heading_count:%d" % len(headings))

    section_match = section_re.search(report_md)
    if not section_match:
        violations.append("confirmed_section_missing")
        return violations

    section = section_match.group(0)

    def _id_present(fid: str) -> bool:
        return re.search(
            r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(fid),
            section,
        ) is not None

    missing = [fid for fid in expected_ids if not _id_present(fid)]
    if missing:
        suffix = "" if len(missing) <= 20 else "+%d_more" % (len(missing) - 20)
        violations.append(
            "confirmed_section_missing_ids:%s%s"
            % (",".join(missing[:20]), suffix)
        )

    return violations


def postrun_report_checks(state_dir: str) -> tuple[bool, list[str]]:
    """Post-run truth check over persisted state artifacts.

    Returns ``(ok, errors)``. Requires:
      * ``report_validation.json`` exists and ``errors == []``
      * report confirmed count == bucket confirmed count
      * non-confirmed buckets absent from the confirmed set
      * synthesis count does not affect the confirmed atomic count
    """
    errors: list[str] = []

    def _load(name: str):
        p = os.path.join(state_dir, name)
        if not os.path.isfile(p):
            return None
        try:
            with open(p) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    rv = _load("report_validation.json")
    if rv is None:
        errors.append("report_validation.json_missing")
    elif rv.get("errors"):
        errors.append("report_validation_errors_present:%d"
                      % len(rv["errors"]))

    buckets = _load("finding_disposition_buckets.json")
    report_truth = _load("report_truth.json")
    _d2c_report_md = _d2c_load_report_markdown(state_dir)
    summary = _load("pipeline_summary.json")

    if not isinstance(buckets, dict):
        errors.append("finding_disposition_buckets.json_missing")
        return (len(errors) == 0), errors

    dc = None
    if isinstance(summary, dict):
        dc = summary.get("disposition_counts")
    errors.extend(
        check_report_bucket_consistency(buckets, dc, report_truth)
    )

    # 31G-D2c: final persisted report must cover confirmed IDs.
    errors.extend(check_confirmed_section_render_coverage(
        _d2c_report_md, buckets, report_truth))

    return (len(errors) == 0), errors
