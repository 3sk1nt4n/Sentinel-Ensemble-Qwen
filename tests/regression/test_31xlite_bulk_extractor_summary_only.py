"""31X-LITE bulk_extractor / summary-only coverage-gate unblock.

Pins three invariants:

1. ``run_bulk_extractor`` emits exactly ONE summary record and
   ``record_count == len(output)``. Carved-feature totals are kept as
   DATA inside the record (``carved_feature_total``), never overwriting
   the envelope's record count.

2. A summary-only tool (one with no entity facts, no compiler by
   design) trips NEITHER of the EvidenceDB coverage gates:
     * ``silent_dropped_tools_without_compiler``
     * ``zero_typed_fact_families_for_nonempty_source_tools``
   and ``validate_evidencedb_coverage_snapshot`` returns no error-severity
   verdicts when only summary-only and well-formed tools are present.

3. The structural invariant: every member of
   ``drift_gate._SUMMARY_ONLY_TOOLS`` is dataset-agnostic
   (no IPs/PIDs/hashes/case strings) and absent from
   ``FAMILY_RAW_SOURCES`` (so it cannot drive a family expectation).

Synthetic only. No live API, no /mnt/windows_mount, no ground-truth
counts. Counts vary per image -- this test asserts shape, not numbers.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sift_sentinel.analysis.drift_gate import (  # noqa: E402
    FAMILY_RAW_SOURCES,
    _SUMMARY_ONLY_TOOLS,
    build_evidencedb_coverage_snapshot,
    validate_evidencedb_coverage_snapshot,
)
from sift_sentinel.tools.generic import run_bulk_extractor  # noqa: E402


# ── 1) record_count == len(output) ──────────────────────────────────


def test_run_bulk_extractor_record_count_equals_len_output(tmp_path):
    """The envelope's record_count must equal len(output) (==1) regardless
    of how many features were carved into the per-feature txt files.
    """
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""

    # Synthetic carved-output stub: many features per file. The exact
    # numbers don't matter -- only the invariant that record_count
    # never picks them up.
    file_contents = {
        "/tmp/sift-sentinel-tools/bulk_out/email.txt": "\n".join(
            f"u{i}@example.invalid" for i in range(17)
        ) + "\n",
        "/tmp/sift-sentinel-tools/bulk_out/url.txt": "\n".join(
            f"https://example.invalid/{i}" for i in range(33)
        ) + "\n",
        "/tmp/sift-sentinel-tools/bulk_out/domain.txt": "\n".join(
            f"d{i}.example.invalid" for i in range(11)
        ) + "\n",
    }
    carved_total = 17 + 33 + 11

    def fake_open(path, *a, **kw):
        from io import StringIO
        return StringIO(file_contents.get(path, ""))

    with patch(
        "sift_sentinel.tools.generic.subprocess.run",
        return_value=mock_result,
    ), patch("os.path.exists", return_value=True), \
       patch("os.path.isdir", return_value=False), \
       patch("os.makedirs"), \
       patch("builtins.open", side_effect=fake_open):
        env = run_bulk_extractor("/synthetic/image.dd")

    assert env["tool_name"] == "bulk_extractor"
    assert isinstance(env["output"], list)
    assert len(env["output"]) == 1, "summary-only tool must emit exactly one record"
    # The headline invariant of this rung.
    assert env["record_count"] == len(env["output"])
    assert env["record_count"] == 1
    # Carved totals survive as DATA on the summary record.
    rec = env["output"][0]
    assert rec["emails"] == 17
    assert rec["urls"] == 33
    assert rec["domains"] == 11
    assert rec["carved_feature_total"] == carved_total


# ── 2) Coverage gate behavior on summary-only tools ─────────────────


def _good_typed_evdb_with_summary_only() -> tuple[dict, dict]:
    """A minimal but reconciliation-clean evidence_db + tool_outputs
    pair that includes one summary-only tool (bulk_extractor) producing
    one record and no family-driver tools at all.

    Counts are arbitrary; the assertions never read them.
    """
    tool_outputs = {
        "bulk_extractor": {
            "tool_name": "bulk_extractor",
            "evidence_path": "/synthetic/image.dd",
            "output": [{
                "emails": 5, "urls": 7, "domains": 3,
                "carved_feature_total": 15,
            }],
            "record_count": 1,
        },
    }
    # An empty typed-evdb is a legitimate state when no compiler-backed
    # tool emitted records -- the snapshot relies on `coverage` and
    # `typed_facts`, but we leave both empty to mirror "only summary
    # tool ran". The coverage gate must not invent violations here.
    evdb = {"coverage": {}, "typed_facts": {}}
    return evdb, tool_outputs


def test_summary_only_tool_not_in_silent_drops():
    evdb, tool_outputs = _good_typed_evdb_with_summary_only()
    snap = build_evidencedb_coverage_snapshot(evdb, tool_outputs)
    assert "bulk_extractor" not in snap["silent_dropped_tools_without_compiler"], (
        "bulk_extractor is a summary-only tool by design and must not "
        "trip the silent-drop check"
    )


def test_summary_only_tool_does_not_drive_zero_typed_family():
    evdb, tool_outputs = _good_typed_evdb_with_summary_only()
    snap = build_evidencedb_coverage_snapshot(evdb, tool_outputs)
    fams = [
        z["fact_family"]
        for z in snap["zero_typed_fact_families_for_nonempty_source_tools"]
    ]
    # No family driven solely by a summary-only tool can fire.
    assert fams == [] or "bulk_extractor" not in {
        s
        for z in snap["zero_typed_fact_families_for_nonempty_source_tools"]
        for s in (z.get("nonempty_raw_sources") or [])
    }


def test_summary_only_tool_passes_validate_with_zero_errors():
    evdb, tool_outputs = _good_typed_evdb_with_summary_only()
    snap = build_evidencedb_coverage_snapshot(evdb, tool_outputs)
    verdicts = validate_evidencedb_coverage_snapshot(snap)
    errors = [v for v in verdicts if v.get("severity") == "error"]
    assert errors == [], (
        f"summary-only tool tripped error verdicts: "
        f"{[v.get('kind') for v in errors]}"
    )
    assert snap["all_reconciled"] is True
    assert "bulk_extractor" in snap["summary_only_tools"]


def test_strict_check_still_fires_for_unknown_silent_drop_tool():
    """The summary-only allowlist must not weaken the gate for any
    other tool. A nonempty unknown tool with no compiler must still
    fail the silent-drop check.
    """
    evdb = {"coverage": {}, "typed_facts": {}}
    tool_outputs = {
        # NOT in _TOOL_COMPILERS, NOT in _SUMMARY_ONLY_TOOLS, has records.
        "synth_unknown_tool": {
            "tool_name": "synth_unknown_tool",
            "evidence_path": "/x",
            "output": [{"k": 1}, {"k": 2}, {"k": 3}],
            "record_count": 3,
        },
    }
    snap = build_evidencedb_coverage_snapshot(evdb, tool_outputs)
    assert "synth_unknown_tool" in snap["silent_dropped_tools_without_compiler"]
    errs = [
        v for v in validate_evidencedb_coverage_snapshot(snap)
        if v.get("severity") == "error"
    ]
    assert any(
        v.get("kind") == "missing_compiler_for_nonempty_tool"
        and v.get("details", {}).get("tool") == "synth_unknown_tool"
        for v in errs
    ), "strict silent-drop check was weakened for non-allowlisted tool"


# ── 3) Structural invariant on the allowlist itself ─────────────────


def test_summary_only_set_is_disjoint_from_family_raw_sources():
    """Membership policy: a summary-only tool emits no typed facts and
    therefore must not appear as a family-driving raw source. If a
    future maintainer adds a tool to both sets, the family check would
    be silently weakened for that family.
    """
    all_family_sources = {
        s for sources in FAMILY_RAW_SOURCES.values() for s in sources
    }
    overlap = sorted(_SUMMARY_ONLY_TOOLS & all_family_sources)
    assert overlap == [], (
        f"summary-only tools must not drive a fact family; overlap: {overlap}"
    )


def test_summary_only_set_is_dataset_agnostic():
    """No member of the allowlist is a case literal (IP/host/path/hash)."""
    banned_fragments = (
        ".", "/", "\\", "@",
    )
    for name in _SUMMARY_ONLY_TOOLS:
        assert isinstance(name, str) and name
        for frag in banned_fragments:
            assert frag not in name, (
                f"summary-only tool name {name!r} contains case-literal "
                f"fragment {frag!r}"
            )


# ── 4) Test-file hygiene guards ─────────────────────────────────────


def test_no_dataset_literals_in_this_test():
    src = Path(__file__).read_text(errors="replace")
    banned = [
        "172." + "16.",
        "td" + "ungan",
        "sp" + "sql",
        "OUT" + "LOOK",
        "base-" + "rd01",
        "squirrel" + "directory",
        "shield" + "base",
        "Wmi" + "PrvSE",
    ]
    for token in banned:
        assert token not in src, f"forbidden dataset literal: {token}"


def test_no_run_pipeline_import():
    text = Path(__file__).read_text(errors="replace")
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("import run_pipeline") or stripped.startswith(
            "from run_pipeline"
        ):
            raise AssertionError(
                f"this test must not depend on run_pipeline (synthetic only): {line!r}"
            )
