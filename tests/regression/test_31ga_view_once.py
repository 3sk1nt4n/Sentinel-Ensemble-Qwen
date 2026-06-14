"""31G-A: view-once cache for malicious_semantics._view (all synthetic data).

Locks: (1) cached view == uncached, byte-identical; (2) cache hit returns the
same object; (3) _clear_view_cache empties it; (4) has_malicious_semantic with
evidence_db=None self-clears warm route entries (cross-step staleness guard)."""
from sift_sentinel.analysis import malicious_semantics as ms


def _fact(**kw):
    base = {"type": "process_fact", "canonical_entity_id": "e1", "raw_excerpt": "{}"}
    base.update(kw)
    return base


def test_cached_view_equals_uncached():
    ms._clear_view_cache()
    for i in range(20):
        f = _fact(action="C:/Temp/x%d.exe" % i, value_data="payload%d" % i)
        assert ms._view(f) == ms._view_uncached(f)


def test_cache_hit_returns_same_object():
    ms._clear_view_cache()
    f = _fact(action="rundll32.exe")
    assert ms._view(f) is ms._view(f)


def test_clear_view_cache_empties():
    ms._clear_view_cache()
    ms._view(_fact())
    assert len(ms._VIEW_CACHE) >= 1
    ms._clear_view_cache()
    assert len(ms._VIEW_CACHE) == 0


def test_none_evidence_db_self_clears_warm_entries():
    ms._clear_view_cache()
    warm = [_fact(action="C:/Temp/a%d" % i) for i in range(5)]
    for f in warm:
        ms._view(f)
    assert len(ms._VIEW_CACHE) == 5
    ms.has_malicious_semantic(
        {"finding_id": "F1", "artifact": "x", "description": "y"}, None
    )
    # the warm route facts (still alive here) must be gone -> guard cleared them
    assert all(id(f) not in ms._VIEW_CACHE for f in warm)
