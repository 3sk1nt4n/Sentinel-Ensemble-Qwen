"""R2: tactic-aware ensemble fingerprint (env-gated, default OFF).

_fingerprint is the ensemble CONSENSUS key: members reporting the same entity
merge to cross-validate. Splitting that key reduces consensus, so the tactic
dimension only activates under SIFT_TACTIC_DEDUP=1, and only when BOTH
findings declare MITRE technique IDs -- the universal structural tactic label.
Default behaviour must stay byte-identical. Synthetic values only.
"""
from __future__ import annotations

from sift_sentinel.ensemble import _fingerprint


def _f(ttps=None):
    f = {
        "title": "synthetic finding",
        "claims": [{"type": "pid", "pid": 4242}],
    }
    if ttps is not None:
        f["ttps"] = ttps
    return f


def test_default_off_same_entity_different_tactic_merges(monkeypatch):
    monkeypatch.delenv("SIFT_TACTIC_DEDUP", raising=False)
    assert _fingerprint(_f(["T1055"])) == _fingerprint(_f(["T1543"]))


def test_default_off_tuple_shape_unchanged(monkeypatch):
    monkeypatch.delenv("SIFT_TACTIC_DEDUP", raising=False)
    fp = _fingerprint(_f())
    assert isinstance(fp, tuple) and len(fp) == 1


def test_on_same_entity_different_technique_splits(monkeypatch):
    monkeypatch.setenv("SIFT_TACTIC_DEDUP", "1")
    assert _fingerprint(_f(["T1055"])) != _fingerprint(_f(["T1543"]))


def test_on_same_entity_same_technique_merges(monkeypatch):
    monkeypatch.setenv("SIFT_TACTIC_DEDUP", "1")
    assert _fingerprint(_f(["T1055"])) == _fingerprint(_f(["T1055"]))


def test_on_missing_techniques_merge_among_themselves(monkeypatch):
    # Fingerprint equality is an equivalence relation, so an untagged finding
    # cannot simultaneously merge with two differently-tagged ones. The
    # coherent rule: untagged findings share one ("") sentinel tactic and
    # merge with each other; a tagged finding keys on its technique.
    monkeypatch.setenv("SIFT_TACTIC_DEDUP", "1")
    assert _fingerprint(_f()) == _fingerprint(_f())
    assert _fingerprint(_f([])) == _fingerprint(_f())


def test_on_technique_read_from_ttp_tags_too(monkeypatch):
    monkeypatch.setenv("SIFT_TACTIC_DEDUP", "1")
    a = {"claims": [{"type": "pid", "pid": 7}], "ttp_tags": ["T1055.002"]}
    b = {"claims": [{"type": "pid", "pid": 7}], "ttps": ["T1543"]}
    assert _fingerprint(a) != _fingerprint(b)
