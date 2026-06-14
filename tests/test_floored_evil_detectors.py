"""The five evil-class detectors are FLOORED in _slot31k_priority_add so coverage
of exfil / lateral / anti-forensics / execution / priv-esc is a property of the
pipeline, not the model's tool choice. Each is registered + evidence-gated.
Source-structural (the floor lives in run_pipeline.py module body, run at import).

USB-WIRE: parse_usb_devices REPLACES vol_hollowprocesses in the auto-floor
(higher-value removable-media/exfil coverage that emits a typed fact, needed in
every paired/disk case). vol_hollowprocesses is NOT deregistered -- it stays in
_TOOL_REGISTRY so ReAct can call it on suspicion; it is just no longer force-
injected. The injection class is still floored by the mandatory malfind prefix +
psxview/ldrmodules pairing.
"""
import pathlib
from sift_sentinel import coordinator as C

_RP = (pathlib.Path(__file__).resolve().parents[1] / "run_pipeline.py").read_text()

_FLOORED = [
    "parse_usb_devices",     # exfil: removable-media connection/usage -- disk
    "parse_rdp_artifacts",   # lateral (T1021.001) -- disk
    "sleuthkit_tsk_recover", # anti-forensics (T1070.004) -- disk
    "vol_userassist",        # execution (T1204) -- memory
    "vol_privileges",        # priv-esc (T1134) -- memory
]


def test_band_ceiling_is_35():
    assert C.MIN_SELECTED_TOOLS == 20
    assert C.MAX_SELECTED_TOOLS == 35


def test_five_detectors_registered_and_evidence_gated():
    for t in _FLOORED:
        assert t in C._TOOL_REGISTRY, t
        aw = (C.get_capability(t) or {}).get("applicable_when") or []
        # every floored detector is gated to memory and/or disk (never source-agnostic)
        assert "windows_evidence" in aw or "disk_evidence" in aw, (t, aw)


def test_five_detectors_in_priority_floor():
    # they appear in the _slot31k_priority_add tuple (the deterministic floor)
    floor_region = _RP.split("_slot31k_priority_add = (", 1)[1].split("\n)", 1)[0]
    for t in _FLOORED:
        assert f'"{t}"' in floor_region, f"{t} not floored in _slot31k_priority_add"


def test_each_has_an_artifact_gate():
    # _slot31k_artifact_exists_for must name each floored tool (memory/disk gate)
    gate_region = _RP.split("def _slot31k_artifact_exists_for", 1)[1][:4000]
    for t in _FLOORED:
        assert t in gate_region, f"{t} has no artifact gate"


def test_hollowprocesses_registered_but_not_force_floored():
    # USB-WIRE: hollowprocesses is NOT deregistered -- ReAct can still call it --
    # but it is no longer in the auto-floor (parse_usb_devices took its slot).
    assert "vol_hollowprocesses" in C._TOOL_REGISTRY
    floor_region = _RP.split("_slot31k_priority_add = (", 1)[1].split("\n)", 1)[0]
    assert '"vol_hollowprocesses"' not in floor_region
