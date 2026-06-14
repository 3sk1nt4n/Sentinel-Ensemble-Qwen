"""Canonical artifact normalization: one artifact => one key, across every
spelling the model emits.

Live A+++ review found the SAME artifact reported with TWO verdicts because the
dedup/reconcile keys never intersected across three universal spelling
variances (probed from the run's real bucket state):

  1. escaped backslashes: a model-emitted claim carries literal ``\\\\`` so
     ``replace("\\\\","/")`` yields ``hklm//system//...`` != ``hklm/system/...``
     -- the SAME registry key/path produced disjoint keys;
  2. drive-letter variance: ``c:/windows/system32/x.exe`` vs
     ``windows/system32/x.exe`` (the typed validator already matches paths
     drive-agnostically -- the dedup keys did not);
  3. prose label prefix: a claim value of ``"Registry key HKLM\\..."`` failed the
     anchored hive-root regex and produced NO key at all.

Fix: collapse separator runs + strip the drive prefix in the shared
``_norm_path`` (confirmed_dedup -- feeds entity_keys used by BOTH dedup passes
and the cross-bucket reconcile), and make the registry key extractor tolerate a
short prose label before the hive root. Universal grammar only (separators,
drive-letter shape, hive names); no case data. Kill-switch
SIFT_ARTIFACT_NORM_V2=0 restores legacy behavior.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.confirmed_dedup import _norm_path, entity_keys  # noqa: E402
from sift_sentinel.analysis.signature_reconcile import (                    # noqa: E402
    _registry_entity_keys,
    reconcile_cross_bucket_by_entity,
)


def _f(fid, *paths, reasons=None):
    f = {"finding_id": fid,
         "claims": [{"type": "path", "value": p} for p in paths]}
    if reasons:
        f["disposition_reasons"] = list(reasons)
    return f


def _empty():
    return {k: [] for k in ("confirmed_malicious_atomic", "suspicious_needs_review",
                            "benign_or_false_positive", "inconclusive_unresolved",
                            "synthesis_narrative")}


# ── 1. escaped-backslash runs collapse ──────────────────────────────────────
def test_norm_path_collapses_escaped_backslash_runs():
    assert _norm_path("C:\\\\Windows\\\\temp\\\\tool.exe") == \
        _norm_path("C:\\Windows\\temp\\tool.exe")


def test_entity_keys_intersect_across_escape_variants():
    a = entity_keys(_f("A", "C:\\Windows\\Temp\\tool.exe"))
    b = entity_keys(_f("B", "C:\\\\Windows\\\\temp\\\\tool.exe"))
    assert a & b, f"escaped vs plain spelling of one path must share a key: {a} vs {b}"


# ── 2. drive-agnostic path identity ─────────────────────────────────────────
def test_entity_keys_drive_agnostic():
    a = entity_keys(_f("A", "C:\\Tools\\Utils\\agent.exe"))
    b = entity_keys(_f("B", "Tools\\Utils\\agent.exe"))
    assert a & b, f"drive-letter spelling must not split one artifact: {a} vs {b}"


def test_different_binaries_never_merge():
    a = entity_keys(_f("A", "C:\\Windows\\Temp\\alpha.exe"))
    b = entity_keys(_f("B", "C:\\Windows\\Temp\\bravo.exe"))
    assert not (a & b)


# ── 3. registry keys: prose prefix + escape variance ───────────────────────
def test_registry_key_prose_label_prefix_still_keys():
    bare = _registry_entity_keys(
        _f("A", "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell"))
    prose = _registry_entity_keys(
        _f("B", "Registry key HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell"))
    assert bare and prose and (bare & prose)


def test_registry_key_escape_variants_intersect():
    a = _registry_entity_keys(
        _f("A", "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell"))
    b = _registry_entity_keys(
        _f("B", "HKLM\\\\System\\\\ControlSet001\\\\Control\\\\SafeBoot\\\\AlternateShell"))
    assert a and b and (a & b)


def test_different_controlsets_stay_distinct():
    a = _registry_entity_keys(
        _f("A", "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell"))
    b = _registry_entity_keys(
        _f("B", "HKLM\\System\\ControlSet002\\Control\\SafeBoot\\AlternateShell"))
    assert not (a & b), "CS001 and CS002 are different keys and must not collide"


# ── 4. end-to-end: the live split-verdict now reconciles ────────────────────
def test_split_verdict_same_artifact_now_escalates():
    b = _empty()
    # never-adjudicated benign sibling + suspicious member, same key, variant spellings
    b["suspicious_needs_review"] = [
        _f("F1", "C:\\Windows\\System32\\example.exe")]
    b["benign_or_false_positive"] = [
        _f("F2", "windows\\system32\\example.exe")]          # drive-less spelling
    new, ledger = reconcile_cross_bucket_by_entity(b)
    assert ledger, "same artifact in benign+review must be detected as contradicted"
    assert "F2" in {f["finding_id"] for f in new["suspicious_needs_review"]}


def test_kill_switch_restores_legacy(monkeypatch):
    monkeypatch.setenv("SIFT_ARTIFACT_NORM_V2", "0")
    a = entity_keys(_f("A", "C:\\Tools\\Utils\\agent.exe"))
    b = entity_keys(_f("B", "Tools\\Utils\\agent.exe"))
    assert not (a & b), "kill-switch must restore the legacy (drive-sensitive) keys"


# ── 5. registry identity reaches the DEDUP passes too ───────────────────────
def test_dedup_review_merges_same_registry_key_findings():
    """Registry-only findings (no exe path, no hash) were invisible to
    dedup_review -- entity_keys emitted only p:/h: keys -- so three findings on
    the SAME persistence key survived as triplicated rows. Registry identity is
    artifact identity; it must reach the dedup passes with the same depth guard
    (>=3 separators) so a bare hive root never merges unrelated keys."""
    from sift_sentinel.analysis.confirmed_dedup import dedup_review
    b = {k: [] for k in ("confirmed_malicious_atomic", "suspicious_needs_review",
                         "benign_or_false_positive", "inconclusive_unresolved",
                         "synthesis_narrative")}
    b["suspicious_needs_review"] = [
        _f("F1", "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell"),
        _f("F2", "Registry key HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell"),
        _f("F3", "HKLM\\Software\\Vendor\\App\\Setting"),     # different key -> stays
    ]
    new, ledger = dedup_review(b)
    ids = {f["finding_id"] for f in new["suspicious_needs_review"]}
    assert len(new["suspicious_needs_review"]) == 2, ids
    assert "F3" in ids
    assert any(e["finding_id"] in ("F1", "F2") for e in ledger)


def test_entity_keys_bare_hive_root_never_keys():
    from sift_sentinel.analysis.confirmed_dedup import entity_keys as ek
    assert not any(k.startswith("r:") for k in ek(_f("A", "HKLM\\Software")))
