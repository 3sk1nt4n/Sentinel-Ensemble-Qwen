"""TDD: removable-media (USB) connection signal from usb_device_fact.

usb_device_fact (USBSTOR serial / MountedDevices drive letter / per-user
MountPoints2 volume) emits a corroborating removable_media_connection signal so
USB device usage surfaces for review and can corroborate data-movement / anti-
forensics findings. Bounded by design: a lone single-source/single-type signal
stays review_worthy and never auto-promotes (validation_ready needs multi-source
+ multi-fact-type + score>=60). Dataset-agnostic: keys on the fact type/structure,
no device/serial/user literal.
"""
from sift_sentinel.analysis.candidate_observations import _score_fact, _candidate_type


def _usb(**kw):
    f = {"fact_type": "usb_device_fact", "device_kind": "usb_device"}
    f.update(kw)
    return f


def test_usb_device_emits_removable_media_signal():
    score, signals, _ = _score_fact(
        _usb(serial="AABBCCDD1122", vendor="Acme", product="FlashMax"))
    assert "removable_media_connection" in signals
    assert score >= 25
    assert _candidate_type(set(signals)) == "removable_media_usage"


def test_mount_point_with_user_emits_signal():
    _, signals, _ = _score_fact({
        "fact_type": "usb_device_fact", "device_kind": "mount_point",
        "volume": "{guid-1}", "user": "analyst"})
    assert "removable_media_connection" in signals


def test_signal_is_corroborating_not_auto_promoting():
    # A lone removable-media signal must stay below the auto-promote score floor (60).
    score, signals, _ = _score_fact(_usb(serial="X", drive_letter="E:"))
    assert "removable_media_connection" in signals
    assert score < 60


def test_non_usb_fact_emits_no_removable_media_signal():
    _, signals, _ = _score_fact(
        {"fact_type": "registry_persistence_fact", "value_name": "x"})
    assert "removable_media_connection" not in signals
