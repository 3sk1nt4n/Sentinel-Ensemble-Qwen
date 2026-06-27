"""Track-4 human-in-the-loop checkpoint: pure override logic + gating.
The interactive driver is TTY-gated and a no-op under pytest (no TTY)."""
from sift_sentinel import hitl_checkpoint as h


def test_checkpoint_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SIFT_HITL_CHECKPOINT", raising=False)
    assert h.checkpoint_enabled() is False


def test_checkpoint_enabled_flag(monkeypatch):
    monkeypatch.setenv("SIFT_HITL_CHECKPOINT", "1")
    assert h.checkpoint_enabled() is True


def test_apply_override_moves_finding_and_is_pure():
    b = {"confirmed_malicious_atomic": [{"finding_id": "F1"}],
         "benign_or_false_positive": []}
    nb, ok, msg = h.apply_override(b, "F1", "benign")
    assert ok, msg
    assert nb["confirmed_malicious_atomic"] == []
    assert nb["benign_or_false_positive"][0]["finding_id"] == "F1"
    # PURE: original untouched
    assert b["confirmed_malicious_atomic"][0]["finding_id"] == "F1"


def test_apply_override_unknown_bucket_rejected():
    b = {"confirmed_malicious_atomic": [{"finding_id": "F1"}]}
    nb, ok, msg = h.apply_override(b, "F1", "bogus")
    assert not ok and "unknown bucket" in msg and nb is b


def test_apply_override_missing_finding_rejected():
    b = {"confirmed_malicious_atomic": [{"finding_id": "F1"}]}
    nb, ok, msg = h.apply_override(b, "F404", "benign")
    assert not ok and "not found" in msg and nb is b


def test_bucket_alias_resolution():
    assert h.resolve_bucket("confirmed") == "confirmed_malicious_atomic"
    assert h.resolve_bucket("needs-review") == "suspicious_needs_review"
    assert h.resolve_bucket("fp") == "benign_or_false_positive"
    assert h.resolve_bucket("inconclusive") == "inconclusive_unresolved"
    assert h.resolve_bucket("bogus") is None


def test_run_checkpoint_is_noop_without_tty():
    # under pytest stdin is not a TTY -> unchanged buckets, no override
    b = {"confirmed_malicious_atomic": [{"finding_id": "F1"}]}
    nb, overrode = h.run_checkpoint(b)
    assert nb is b and overrode is False
