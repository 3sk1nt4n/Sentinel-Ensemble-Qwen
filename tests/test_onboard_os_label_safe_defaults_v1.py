from pathlib import Path


def test_onboard_engine_has_safe_os_label_defaults():
    src = Path("src/sift_sentinel/onboard/engine.py").read_text(errors="replace")
    assert "SIFT_ONBOARD_OS_LABEL_SAFE_DEFAULTS_V1" in src
    assert 'os_label = str(os_profile_raw.get("os") or "unknown")' in src
    assert 'os_source = str(os_profile_raw.get("source") or "none")' in src
