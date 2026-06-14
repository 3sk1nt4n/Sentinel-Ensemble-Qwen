"""vol_malfind's light injection discriminators (vol_ldrmodules + vol_psxview)
are paired with it at COLLECTION time (after the safety net), so ReAct
corroborates injection findings from cache instead of falling back to the slow
vol_vadinfo. Universal: structural pairing keyed on malfind, no case data.

pair_injection_corroborators is a SEPARATE step so safety_net_tools keeps its
"preserve a valid selection unchanged" contract."""

from sift_sentinel.coordinator import (
    pair_injection_corroborators, MAX_SELECTED_TOOLS,
)


def test_malfind_pairs_its_discriminators():
    out = pair_injection_corroborators(["vol_pstree", "vol_malfind", "vol_netscan"])
    assert "vol_ldrmodules" in out
    assert "vol_psxview" in out


def test_no_pairing_without_malfind():
    base = ["vol_pstree", "vol_netscan", "vol_cmdline", "vol_dlllist"]
    assert pair_injection_corroborators(base) == base


def test_no_duplicate_when_already_present():
    out = pair_injection_corroborators(["vol_malfind", "vol_ldrmodules", "vol_pstree"])
    assert out.count("vol_ldrmodules") == 1
    assert "vol_psxview" in out


def test_respects_band_cap_by_eviction():
    # A full band (MAX tools) with malfind but without the discriminators: the
    # discriminators are added by evicting lowest-priority tools, count stays <= cap.
    full = ["vol_malfind"] + [f"vol_generic_{i}" for i in range(MAX_SELECTED_TOOLS - 1)]
    out = pair_injection_corroborators(full)
    assert "vol_ldrmodules" in out
    assert "vol_psxview" in out
    assert "vol_malfind" in out
    assert len(out) <= MAX_SELECTED_TOOLS
