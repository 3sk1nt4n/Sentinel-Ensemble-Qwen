from sift_sentinel.analysis.confidence import (
    clamp_severity_to_confidence as clamp,
    _SEV_ORDER, _CONF_SEV_CEILING, _CONF_SEV_FLOOR,
)
_CONFS = ("UNRESOLVED", "SPECULATIVE", "LOW", "MEDIUM", "HIGH")
def _r(s): return _SEV_ORDER.index(s)

def test_output_always_valid():
    for kw in _SEV_ORDER:
        for c in _CONFS + ("nonsense", "", None):
            assert clamp(kw, c) in _SEV_ORDER

def test_ceiling_never_exceeded():
    for kw in _SEV_ORDER:
        for c in _CONFS:
            assert _r(clamp(kw, c)) <= _r(_CONF_SEV_CEILING.get(c, "LOW"))

def test_floor_for_strong_evidence():
    for kw in _SEV_ORDER:
        for c in _CONFS:
            fl = _CONF_SEV_FLOOR.get(c)
            if fl: assert _r(clamp(kw, c)) >= _r(fl)

def test_idempotent():
    for kw in _SEV_ORDER:
        for c in _CONFS:
            o = clamp(kw, c); assert clamp(o, c) == o

def test_monotonic_in_keyword():
    for c in _CONFS:
        prev = -1
        for kw in _SEV_ORDER:
            r = _r(clamp(kw, c)); assert r >= prev; prev = r

def test_policy_contract():
    assert clamp("CRITICAL", "LOW") == "LOW"
    assert clamp("CRITICAL", "SPECULATIVE") == "LOW"
    assert clamp("HIGH", "LOW") == "LOW"
    assert clamp("LOW", "HIGH") == "HIGH"
    assert clamp("MEDIUM", "HIGH") == "HIGH"
    assert clamp("CRITICAL", "HIGH") == "CRITICAL"
    assert clamp("MEDIUM", "MEDIUM") == "MEDIUM"
    assert clamp("CRITICAL", "weird") == "LOW"
    assert clamp(None, None) == "LOW"
