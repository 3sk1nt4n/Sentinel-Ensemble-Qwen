"""Cross-bucket dedup: the same artifact surfaced in BOTH confirmed and
needs_review collapses into one representative in the higher-priority bucket.

Same EXACT identity rule as the within-bucket dedup (shared file hash or
fully-qualified exe/dll/sys path, never a bare basename), so different files
never merge and theme-dupes are left alone. Benign and every other bucket are
untouched -- suppression is deliberate, never resurrected or buried.
Synthetic values only.
"""
from __future__ import annotations

from sift_sentinel.analysis.confirmed_dedup import (
    CONFIRMED,
    NEEDS_REVIEW,
    dedup_cross_bucket,
)

_H = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"   # 32-hex synthetic md5


def _f(fid, **kw):
    claims = []
    if "hash" in kw:
        claims.append({"type": "hash", "sha1": kw["hash"]})
    if "path" in kw:
        claims.append({"type": "path", "value": kw["path"]})
    return {"finding_id": fid, "title": kw.get("title", fid),
            "source_tools": kw.get("tools", ["t1"]), "claims": claims}


def test_same_hash_across_buckets_collapses_into_confirmed():
    buckets = {
        CONFIRMED: [_f("F1", hash=_H, tools=["a", "b", "c"])],
        NEEDS_REVIEW: [_f("F2", hash=_H, tools=["a"])],
        "benign": [],
    }
    out, ledger = dedup_cross_bucket(buckets)
    assert [f["finding_id"] for f in out[CONFIRMED]] == ["F1"]
    assert out[NEEDS_REVIEW] == []
    assert "F2" in out[CONFIRMED][0]["_merged_duplicate_ids"]
    assert ledger and ledger[0]["finding_id"] == "F2"
    assert ledger[0]["into_bucket"] == CONFIRMED


def test_same_full_path_across_buckets_collapses():
    p = r"C:\Windows\Temp\eviltool.exe"
    buckets = {
        CONFIRMED: [_f("F1", path=p, tools=["a", "b"])],
        NEEDS_REVIEW: [_f("F2", path=p.replace("\\", "/").lower())],
    }
    out, ledger = dedup_cross_bucket(buckets)
    assert len(out[CONFIRMED]) == 1 and out[NEEDS_REVIEW] == []
    assert "F2" in out[CONFIRMED][0]["_merged_duplicate_ids"]


def test_different_full_paths_never_merge():
    buckets = {
        CONFIRMED: [_f("F1", path=r"C:\a\one.exe")],
        NEEDS_REVIEW: [_f("F2", path=r"C:\b\two.exe")],
    }
    out, ledger = dedup_cross_bucket(buckets)
    assert len(out[CONFIRMED]) == 1 and len(out[NEEDS_REVIEW]) == 1
    assert ledger == []


def test_bare_basename_does_not_merge():
    # a basename with no directory must not be used as a cross-bucket key
    buckets = {
        CONFIRMED: [_f("F1", path="evil.exe")],
        NEEDS_REVIEW: [_f("F2", path="evil.exe")],
    }
    out, ledger = dedup_cross_bucket(buckets)
    assert len(out[NEEDS_REVIEW]) == 1 and ledger == []


def test_benign_bucket_untouched_even_with_shared_hash():
    buckets = {
        CONFIRMED: [_f("F1", hash=_H)],
        NEEDS_REVIEW: [],
        "benign": [_f("B1", hash=_H)],
    }
    out, ledger = dedup_cross_bucket(buckets)
    assert [f["finding_id"] for f in out["benign"]] == ["B1"]
    assert ledger == []


def test_theme_dupes_different_binaries_not_merged():
    buckets = {
        CONFIRMED: [_f("F1", path=r"C:\x\regsvr32.exe")],
        NEEDS_REVIEW: [_f("F2", path=r"C:\x\rundll32.exe"),
                       _f("F3", path=r"C:\x\powershell.exe")],
    }
    out, ledger = dedup_cross_bucket(buckets)
    assert len(out[NEEDS_REVIEW]) == 2 and ledger == []


def test_noop_returns_shallow_copy_when_nothing_intersects():
    buckets = {CONFIRMED: [_f("F1", hash=_H)], NEEDS_REVIEW: []}
    out, ledger = dedup_cross_bucket(buckets)
    assert ledger == []
    assert out[CONFIRMED][0]["finding_id"] == "F1"
    assert out is not buckets


def test_within_confirmed_dedup_still_available():
    # the new function is additive -- the existing within-bucket entrypoints
    # remain importable and independent
    from sift_sentinel.analysis.confirmed_dedup import (
        dedup_confirmed,
        dedup_review,
    )
    assert callable(dedup_confirmed) and callable(dedup_review)


def test_metamorphic_relabel_hash_identical_behaviour():
    def run(h):
        b = {CONFIRMED: [_f("F1", hash=h, tools=["a", "b"])],
             NEEDS_REVIEW: [_f("F2", hash=h)]}
        out, _ = dedup_cross_bucket(b)
        return len(out[CONFIRMED]), len(out[NEEDS_REVIEW])
    assert run(_H) == run("f0e1d2c3b4a5968778695a4b3c2d1e0f")
