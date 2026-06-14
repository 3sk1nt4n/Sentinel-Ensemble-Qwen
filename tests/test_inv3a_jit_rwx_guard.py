"""D7: the inv3a finalize pass must not PROMOTE a finding whose only malicious
signal is a single uncorroborated RWX/injection in a system/service context --
the classic JIT/.NET false positive. Adversarially-adjusted design:

  * the guard RE-RESOLVES semantics via disposition.has_malicious_semantic
    (the persisted field is only written for confirmed findings, so reading it
    on ambiguous buckets would be vacuously empty -> misfire both ways);
  * fires ONLY when the resolved set is non-empty AND weak-alone-only AND
    exactly one injection-class source tool AND a weak/uncorroborated floor
    reason is present;
  * blocks PROMOTION only -- a guarded finding can still be downgraded to FP;
  * fail-closed: no evidence_db / resolver error => guard inert (promotable).

Engine-level: finalize_dispositions gains an injected promotion_guard_fn (pure,
unit-testable). Kill-switch SIFT_INV3A_JIT_RWX_GUARD (default OFF, validate
live first). Synthetic findings only -- fabricated names/ids; no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.inv3a_finalize import (  # noqa: E402
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    build_jit_rwx_promotion_guard,
    finalize_dispositions,
)


def _finding(fid):
    return {"finding_id": fid, "description": "synthetic RWX region in fakeproc.exe",
            "source_tools": ["vol_malfind"],
            "disposition_reasons": ["benign:uncorroborated_weak_or_history_only"]}


def _adjudicator_for(verdict):
    def _fn(prompt):
        import json as _j
        ids = [ln.split("finding_id=")[1].split(" ")[0]
               for ln in prompt.splitlines() if "finding_id=" in ln]
        return _j.dumps({"verdicts": [
            {"finding_id": i, "disposition": verdict, "reason": "synthetic"} for i in ids]})
    return _fn


# ── engine: injected promotion guard ─────────────────────────────────────────

def test_guarded_finding_promotion_blocked():
    buckets = {BUCKET_INCONCLUSIVE: [_finding("G001")]}
    out, ledger = finalize_dispositions(
        buckets, _adjudicator_for("needs_review"),
        promotion_guard_fn=lambda f: True)        # guard says: promotion blocked
    assert [f["finding_id"] for f in out[BUCKET_INCONCLUSIVE]] == ["G001"]
    assert ledger == []


def test_guarded_finding_downgrade_still_allowed():
    buckets = {BUCKET_INCONCLUSIVE: [_finding("G002")]}
    out, ledger = finalize_dispositions(
        buckets, _adjudicator_for("false_positive"),
        promotion_guard_fn=lambda f: True)
    assert [f["finding_id"] for f in out[BUCKET_BENIGN]] == ["G002"]
    assert len(ledger) == 1


def test_unguarded_finding_promotes_normally():
    buckets = {BUCKET_INCONCLUSIVE: [_finding("G003")]}
    out, ledger = finalize_dispositions(
        buckets, _adjudicator_for("needs_review"),
        promotion_guard_fn=lambda f: False)
    assert [f["finding_id"] for f in out[BUCKET_SUSPICIOUS]] == ["G003"]


def test_no_guard_is_byte_identical_legacy():
    buckets = {BUCKET_INCONCLUSIVE: [_finding("G004")]}
    out, _ = finalize_dispositions(buckets, _adjudicator_for("needs_review"))
    assert [f["finding_id"] for f in out[BUCKET_SUSPICIOUS]] == ["G004"]


# ── builder: env-gated, fail-closed ──────────────────────────────────────────

def _resolver_weak(f, db):
    return True, ["rwx_memory_region_with_unusual_protection"]


def _resolver_strong(f, db):
    return True, ["rwx_memory_region_with_unusual_protection",
                  "injected_pe_image_in_executable_memory"]


def _resolver_empty(f, db):
    return False, []


def test_builder_on_by_default(monkeypatch):
    # DEFAULT ON (live-validated): a default-flag run on a fresh sample showed
    # the finalize sweep promoting four single-signal RWX findings in AV/system
    # service processes -- exactly what this guard vetoes. Kill-switch=0 only.
    monkeypatch.delenv("SIFT_INV3A_JIT_RWX_GUARD", raising=False)
    assert build_jit_rwx_promotion_guard({"x": 1}, _resolver=_resolver_weak) is not None


def test_builder_kill_switch_off(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_JIT_RWX_GUARD", "0")
    assert build_jit_rwx_promotion_guard({"x": 1}, _resolver=_resolver_weak) is None


def test_builder_inert_without_evidence_db(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_JIT_RWX_GUARD", "1")
    assert build_jit_rwx_promotion_guard(None, _resolver=_resolver_weak) is None


def test_guard_fires_on_single_tool_weak_alone(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_JIT_RWX_GUARD", "1")
    g = build_jit_rwx_promotion_guard({"x": 1}, _resolver=_resolver_weak)
    assert g(_finding("G005")) is True


def test_guard_inert_on_multi_tool_corroboration(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_JIT_RWX_GUARD", "1")
    g = build_jit_rwx_promotion_guard({"x": 1}, _resolver=_resolver_weak)
    f = _finding("G006")
    f["source_tools"] = ["vol_malfind", "vol_ldrmodules"]   # 2 injection tools
    assert g(f) is False


def test_guard_inert_on_strong_signal(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_JIT_RWX_GUARD", "1")
    g = build_jit_rwx_promotion_guard({"x": 1}, _resolver=_resolver_strong)
    assert g(_finding("G007")) is False        # non-weak signal present


def test_guard_inert_on_empty_resolved_set(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_JIT_RWX_GUARD", "1")
    g = build_jit_rwx_promotion_guard({"x": 1}, _resolver=_resolver_empty)
    assert g(_finding("G008")) is False        # empty -> inert, NOT vacuously true


def test_guard_inert_without_floor_reason(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_JIT_RWX_GUARD", "1")
    g = build_jit_rwx_promotion_guard({"x": 1}, _resolver=_resolver_weak)
    f = _finding("G009")
    f["disposition_reasons"] = ["gate:something_else"]
    assert g(f) is False
