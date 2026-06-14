"""Slot 31I-gamma: the production Vol3 surface is dynamic, not seeded.

Asserts the Vol3 surface producers (tools/common.py + run_pipeline.py)
do not emit or rely on a hardcoded Vol3 plugin-count model, and that in
normal runtime (discovery active) the static seed count is exactly 0.
"""

from pathlib import Path

import sift_sentinel.tools.common as common

_REPO = Path(__file__).resolve().parents[2]
_PRODUCERS = (
    _REPO / "src" / "sift_sentinel" / "tools" / "common.py",
    _REPO / "run_pipeline.py",
)

# Literal phrases that signal a hardcoded Vol3 plugin-count model.
_FORBIDDEN = ("23 hardcoded", "hardcoded +", "hardcoded Vol3")


def test_producers_do_not_emit_hardcoded_vol3_model():
    for path in _PRODUCERS:
        text = path.read_text()
        for phrase in _FORBIDDEN:
            assert phrase not in text, (
                f"{path.name} still contains hardcoded Vol3 phrase "
                f"{phrase!r}"
            )


def test_runtime_log_string_is_dynamically_discovered():
    common_src = _PRODUCERS[0].read_text()
    rp_src = _PRODUCERS[1].read_text()
    assert "dynamically discovered" in common_src
    assert "dynamically discovered" in rp_src
    # The old merge format string must be gone everywhere.
    assert "%d hardcoded + %d dynamic" not in common_src
    assert "%d hardcoded + %d dynamic" not in rp_src


def test_alias_fallback_count_is_zero_in_normal_runtime():
    # Imported module reflects the real runtime build on this host.
    assert common.VOL3_DISCOVERY_ACTIVE is True, (
        "expected dynamic discovery active in normal runtime"
    )
    assert common.VOL3_ALIAS_FALLBACK_COUNT == 0, (
        f"alias_fallback_count={common.VOL3_ALIAS_FALLBACK_COUNT} > 0 in "
        "normal runtime -- hardcoded surface is leaking"
    )
    assert common.VOL3_DISCOVERED_PLUGIN_COUNT == len(
        common.VOLATILITY_PLUGINS
    )


def test_safety_net_fill_name_list_retired():
    import sift_sentinel.coordinator as c

    assert not hasattr(c, "_SAFETY_NET_FILL"), (
        "_SAFETY_NET_FILL exact-name list must be retired"
    )
    assert hasattr(c, "_SAFETY_NET_BUCKET_PRIORITY")
