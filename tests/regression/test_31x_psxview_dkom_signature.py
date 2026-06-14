"""slot31AV-narrow regression: process_view_inconsistency must fire ONLY
on the active-but-unlinked DKOM signature, never on benign cross-view
disagreement.

DKOM signature (signal must fire):
  - pslist  is False    (unlinked from active EPROCESS list)
  - psscan  is True     (still present in pool scan)
  - NOT terminated      (Exit Time / ExitTime empty)
  - non-kernel          (PID not in {0,4}; name not a system meta-process)
  - active threads      (when a thread view key exists in this Vol3
                         build, at least one of thrdscan/thrdproc is True;
                         when neither key exists, allow — preserves recall)

Counter-cases (signal must NOT fire):
  - terminated process (exit_time set + thrdscan=False)
  - psscan-only with no live threads (= terminated by definition)
  - process visible in pslist and psscan (active, present)
  - kernel meta-process (PID 4 / "System") with csrss=False

Dataset-agnostic: standard Windows kernel names/PIDs and Vol3 view-field
names only; no case-specific PIDs, hostnames, paths, or counts. Random
synthetic identifiers for the non-kernel positives.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sift_sentinel.analysis.candidate_observations import (  # noqa: E402
    _score_fact,
    build_candidate_observations,
)


SIGNAL = "process_view_inconsistency"


def _psxview_fact(pid, name, views, exit_time=""):
    """Build a synthetic psxview_fact in the runtime-storage shape.

    The candidate scorer reads ``raw_excerpt`` (verbatim Vol3 record
    JSON), not the typed view_* fields — mirror that shape.
    """
    raw = {"Name": name, "PID": pid, "Exit Time": exit_time}
    for k in ("pslist", "psscan", "thrdproc", "thrdscan",
              "csrss", "session", "deskthrd"):
        if k in views:
            raw[k] = views[k]
    return {
        "fact_id": f"psxview_fact-{pid}",
        "fact_type": "psxview_fact",
        "entity_id": f"psxview:pid:{pid}",
        "source_tool": "vol_psxview",
        "record_ref": f"vol_psxview#{pid}",
        "raw_excerpt": json.dumps(raw),
        "artifact": [name],
    }


def _fires(fact) -> bool:
    """Return True iff _score_fact emits process_view_inconsistency."""
    _, signals, _ = _score_fact(fact)
    return SIGNAL in signals


def _random_user_pid() -> int:
    # Avoid PIDs <=4 (kernel meta) and the well-known 100/200/300 fixtures.
    return 1000 + secrets.randbelow(50_000)


def _random_user_proc_name() -> str:
    return "p" + secrets.token_hex(3) + ".exe"


# ── POSITIVES: signal must fire ─────────────────────────────────────


def test_fires_for_active_hidden_dkom_signature():
    """pslist=F, psscan=T, thrdscan=T, no exit, normal pid -> DKOM."""
    fact = _psxview_fact(
        _random_user_pid(),
        _random_user_proc_name(),
        {"pslist": False, "psscan": True, "thrdscan": True},
        exit_time="",
    )
    assert _fires(fact), (
        "active-but-unlinked DKOM signature must trip "
        "process_view_inconsistency"
    )
    # End-to-end via build_candidate_observations: a process-hiding
    # candidate must be present and validation-ready.
    payload = build_candidate_observations({"typed_facts": {"psxview_fact": [fact]}})
    hiding = [c for c in payload["candidates"]
              if c.get("candidate_type") == "process_hiding_indicator"]
    assert hiding, "DKOM fact produced no process_hiding_indicator candidate"
    assert any(c.get("validation_ready") for c in hiding)


def test_fires_when_no_thread_view_key_present():
    """Recall preservation: in a Vol3 build with NO thrdscan/thrdproc
    key at all on this row, the signal still fires when the unlinked-
    pool-active signature holds.
    """
    fact = _psxview_fact(
        _random_user_pid(),
        _random_user_proc_name(),
        # Note: NO thrdscan, NO thrdproc keys in this dict.
        {"pslist": False, "psscan": True, "csrss": True, "session": True},
        exit_time="",
    )
    assert _fires(fact), (
        "DKOM signature with no thread-view key must still fire "
        "(recall preservation across Vol3 builds)"
    )


# ── NEGATIVES: signal must NOT fire ─────────────────────────────────


def test_does_not_fire_for_terminated_with_exit_time():
    """Terminated process: exit_time set, thrdscan False, pslist F,
    psscan T. This is the dominant false-positive shape — must not
    trip the signal.
    """
    fact = _psxview_fact(
        _random_user_pid(),
        _random_user_proc_name(),
        {"pslist": False, "psscan": True, "thrdscan": False},
        exit_time="2026-05-22 03:05:00.000000",
    )
    assert not _fires(fact)


def test_does_not_fire_for_psscan_only_with_no_threads():
    """pslist=F, psscan=T, thrdscan=F, no exit string — but no live
    threads still means terminated. Must not trip the signal.
    """
    fact = _psxview_fact(
        _random_user_pid(),
        _random_user_proc_name(),
        {"pslist": False, "psscan": True, "thrdscan": False},
        exit_time="",
    )
    assert not _fires(fact)


def test_does_not_fire_for_active_process_present_in_pslist():
    """Active process present: pslist=T, psscan=T, csrss=F. csrss
    absence alone is not DKOM — many user processes legitimately miss
    csrss/session/deskthrd views.
    """
    fact = _psxview_fact(
        _random_user_pid(),
        _random_user_proc_name(),
        {"pslist": True, "psscan": True, "csrss": False},
        exit_time="",
    )
    assert not _fires(fact)


def test_does_not_fire_for_kernel_pid_4_system():
    """Kernel meta-process: PID 4, name "System", csrss/session False
    by design. Must not trip the signal regardless of view shape.
    """
    fact = _psxview_fact(
        4,
        "System",
        {"pslist": False, "psscan": True, "thrdscan": True,
         "csrss": False, "session": False, "deskthrd": False},
        exit_time="",
    )
    assert not _fires(fact)


def test_does_not_fire_for_kernel_meta_name_registry():
    """Kernel meta-process by NAME (Registry) — even if PID is not 0/4
    in some Vol3 outputs — must not trip the signal.
    """
    fact = _psxview_fact(
        88,  # arbitrary non-kernel-PID-shaped value
        "Registry",
        {"pslist": False, "psscan": True, "thrdscan": True},
        exit_time="",
    )
    assert not _fires(fact)


def test_does_not_fire_for_memory_compression():
    """Kernel meta-process "Memory Compression" must not trip even
    with the DKOM-looking view shape.
    """
    fact = _psxview_fact(
        _random_user_pid(),
        "Memory Compression",
        {"pslist": False, "psscan": True, "thrdscan": True},
        exit_time="",
    )
    assert not _fires(fact)


# ── No view data → suppressed (existing contract) ───────────────────


def test_no_view_data_emits_suppression():
    """A psxview_fact with zero view keys must record the existing
    psxview_no_view_data suppression and not fire the strong signal.
    """
    fact = _psxview_fact(
        _random_user_pid(), _random_user_proc_name(), {}, exit_time="",
    )
    _, signals, suppressions = _score_fact(fact)
    assert SIGNAL not in signals
    assert "psxview_no_view_data" in suppressions


# ── Property: per-row idempotence + no-promote-on-disagreement-alone ──


def test_no_validation_ready_on_inconsistency_signal_alone_for_terminated():
    """End-to-end: a fact set consisting solely of terminated/benign
    disagreement rows must yield ZERO validation-ready
    process_hiding_indicator candidates.
    """
    facts = []
    for _ in range(8):
        facts.append(_psxview_fact(
            _random_user_pid(),
            _random_user_proc_name(),
            {"pslist": False, "psscan": True, "thrdscan": False},
            exit_time="2026-05-22 03:00:00.000000",
        ))
    payload = build_candidate_observations({"typed_facts": {"psxview_fact": facts}})
    hiding_ready = [
        c for c in payload["candidates"]
        if c.get("candidate_type") == "process_hiding_indicator"
        and c.get("validation_ready")
    ]
    assert hiding_ready == [], (
        f"benign terminated disagreement rows produced "
        f"{len(hiding_ready)} validation-ready process-hiding "
        f"candidates — should be zero"
    )


# ── Dataset-agnostic guards ─────────────────────────────────────────


def test_no_dataset_literals_in_this_test():
    src = Path(__file__).read_text(errors="replace")
    banned = [
        "172." + "16.",
        "td" + "ungan",
        "sp" + "sql",
        "OUT" + "LOOK",
        "base-" + "rd01",
        "rd-" + "01",
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
