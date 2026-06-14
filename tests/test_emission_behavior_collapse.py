"""Behavior-level collapse of deterministic candidate emissions.

The deterministic emitter produces ONE finding per artifact instance, so a
single behaviour -- e.g. sdelete64.exe run from five PowerShell command lines
and two prefetch files -- explodes into many near-identical findings. This
collapses deterministic emissions that share the SAME (declared-signal-class,
binary-basename) into one representative carrying the instances as
corroboration. Universal: keyed on the registered signal name + the file
basename SHAPE, never a case literal. Synthetic values only.
"""
from __future__ import annotations

from sift_sentinel.analysis.candidate_findings import (
    _emit_basename,
    build_candidate_semantic_findings,
)


def _cand(entity_key, signal="anti_forensics_execution", score=200, ek_extra=None):
    c = {
        "entity_key": entity_key,
        "candidate_type": "behavioral_anomaly",
        "validation_ready": True,
        "supporting": True,
        "score": score,
        "malicious_semantic_signals": [signal],
        "signals": [signal],
        "source_tools": ["parse_powershell_transcripts"],
        "fact_ids": ["does-not-resolve"],
    }
    if ek_extra:
        c.update(ek_extra)
    return c


# ── basename extraction ──────────────────────────────────────────────────

def test_emit_basename_from_path():
    assert _emit_basename(r"path:c:/users/x/downloads/sdelete64.exe") == "sdelete64.exe"


def test_emit_basename_from_artifact_command_line():
    ek = r'''artifact:[".\\sdelete64.exe -nobanner -z -c d:", "", "consolehost_history.txt"]'''
    assert _emit_basename(ek) == "sdelete64.exe"


def test_emit_basename_from_prefetch_path():
    assert _emit_basename("path:tmp/x/windows/prefetch/sdelete.exe-2bd91720.pf") == "sdelete.exe"


def test_emit_basename_none_when_no_executable_token():
    assert _emit_basename("ip:203.0.113.7") == ""
    assert _emit_basename("registry:hklm/system/x") == ""


# ── collapse end-to-end ──────────────────────────────────────────────────

def _sdelete_candidates():
    # one behaviour, two binaries: sdelete64.exe run from three locations +
    # sdelete.exe seen in two prefetch files (the real F055/F062/F063 shape).
    # Distinct full paths -> not pre-deduped; collapse merges by basename.
    return [
        _cand("path:c:/users/jdoe/documents/dept admin/host-prep/sdelete64.exe"),
        _cand("path:c:/users/bobby/downloads/sdelete/sdelete64.exe"),
        _cand("path:c:/users/jay-r/downloads/sdelete64.exe"),
        _cand("path:tmp/x/windows/prefetch/sdelete.exe-2bd91720.pf"),
        _cand("path:tmp/x/windows/prefetch/sdelete.exe-0e837e93.pf"),
    ]


def test_collapse_on_by_default(monkeypatch):
    monkeypatch.delenv("SIFT_EMIT_COLLAPSE", raising=False)
    out = build_candidate_semantic_findings(
        {"candidates": _sdelete_candidates()}, existing_findings=[])
    # sdelete64.exe (4 instances) collapses to 1; sdelete.exe (2 prefetch) to 1
    bnames = {}
    for f in out:
        for cl in f.get("claims", []):
            pass
    assert len(out) == 2, [f.get("title") for f in out]
    # the representative carries the collapsed instance count
    reps = sorted(out, key=lambda f: -len(f.get("_collapsed_instances", [])))
    assert reps[0]["_collapsed_instances"], reps[0]
    assert reps[0].get("_collapsed_instance_count", 0) >= 3


def test_collapse_off_emits_each_instance(monkeypatch):
    monkeypatch.setenv("SIFT_EMIT_COLLAPSE", "0")
    out = build_candidate_semantic_findings(
        {"candidates": _sdelete_candidates()}, existing_findings=[])
    assert len(out) >= 5            # pre-collapse behaviour preserved


def test_different_binaries_same_signal_not_merged(monkeypatch):
    monkeypatch.delenv("SIFT_EMIT_COLLAPSE", raising=False)
    cands = [
        _cand("path:c:/x/sdelete64.exe"),
        _cand("path:c:/x/bleachbit.exe"),
    ]
    out = build_candidate_semantic_findings({"candidates": cands}, existing_findings=[])
    assert len(out) == 2            # distinct binaries stay distinct


def test_different_signal_same_binary_not_merged(monkeypatch):
    # same basename but different declared behaviour -> distinct findings
    monkeypatch.delenv("SIFT_EMIT_COLLAPSE", raising=False)
    cands = [
        _cand("path:c:/x/rundll32.exe", signal="anti_forensics_execution"),
        _cand("path:c:/y/rundll32.exe", signal="spawned_by_lolbin_with_suspicious_chain"),
    ]
    out = build_candidate_semantic_findings({"candidates": cands}, existing_findings=[])
    assert len(out) == 2


def test_collapse_preserves_a_finding_when_single_instance(monkeypatch):
    monkeypatch.delenv("SIFT_EMIT_COLLAPSE", raising=False)
    out = build_candidate_semantic_findings(
        {"candidates": [_cand("path:c:/x/sdelete64.exe")]}, existing_findings=[])
    assert len(out) == 1
    assert out[0].get("_collapsed_instance_count", 1) in (0, 1)


def test_metamorphic_relabel_instance_count_stable(monkeypatch):
    monkeypatch.delenv("SIFT_EMIT_COLLAPSE", raising=False)
    def run(bn):
        cs = [_cand(f"path:c:/a/{bn}"), _cand(f"path:c:/b/{bn}"),
              _cand(f"path:c:/c/{bn}")]
        out = build_candidate_semantic_findings({"candidates": cs}, existing_findings=[])
        return len(out), out[0].get("_collapsed_instance_count", 0)
    assert run("sdelete64.exe") == run("wiper99.exe")
