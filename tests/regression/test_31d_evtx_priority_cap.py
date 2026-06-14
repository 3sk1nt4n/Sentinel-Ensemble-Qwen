"""31D-EVTX-PRIORITY-CAP: deterministic per-channel selector.

Synthetic-only. Tests ``_select_evtx_priority_records`` directly +
one parse_event_logs env-wiring smoke via a mocked python-evtx loader.
No run_pipeline import. No /mnt/windows_mount. No real-mount numeric
retention floors.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import sift_sentinel.tools.disk_extended as de  # noqa: E402
from sift_sentinel.tools.disk_extended import (  # noqa: E402
    HIGH_VALUE_EVTX_CHANNELS,
    _select_evtx_priority_records,
    parse_event_logs,
)


SCHEMA = {"EventID", "TimeCreated", "Provider", "Channel", "Computer", "Message"}


def _mk(channel: str, eid: int = 0, t: str = "2030-01-01T00:00:00Z") -> dict:
    return {
        "EventID": eid,
        "TimeCreated": t,
        "Provider": "p",
        "Channel": channel,
        "Computer": "h",
        "Message": "",
    }


def _flood(channel: str, n: int, start_seq: int = 0) -> list[dict]:
    """n records for `channel`, EventID encodes sequence; TimeCreated DESC of EventID."""
    out = []
    for i in range(n):
        s = (start_seq + i) % 60
        mi = ((start_seq + i) // 60) % 60
        hr = ((start_seq + i) // 3600) % 24
        day = ((start_seq + i) // 86400) % 28 + 1
        out.append(
            _mk(channel, eid=start_seq + i,
                t=f"2030-01-{day:02d}T{hr:02d}:{mi:02d}:{s:02d}Z")
        )
    return out


# 1) HV survives flood ------------------------------------------------


def test_hv_survives_flood():
    """A single HV channel with only 3 records survives a 5-channel flood."""
    hv = "Security"  # member of HIGH_VALUE_EVTX_CHANNELS
    assert hv in HIGH_VALUE_EVTX_CHANNELS
    records: list[dict] = []
    records.extend(_flood(hv, 3))
    for i in range(5):
        records.extend(_flood(f"NoiseCh{i:02d}", 50_000))
    out, tel = _select_evtx_priority_records(
        records,
        max_records=100,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert len(out) <= 100
    assert tel["by_channel_kept"].get(hv, 0) >= 1
    assert hv not in tel["high_value_starved"]


# 2) Many HV survive --------------------------------------------------


def test_many_hv_survive_with_enough_budget():
    hv_channels = [
        "Security",
        "System",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
    ]
    for c in hv_channels:
        assert c in HIGH_VALUE_EVTX_CHANNELS
    records: list[dict] = []
    for c in hv_channels:
        records.extend(_flood(c, 5))
    for i in range(3):
        records.extend(_flood(f"NoiseCh{i:02d}", 100_000))
    # max_records >> number of present HV channels => each must keep > 0.
    out, tel = _select_evtx_priority_records(
        records,
        max_records=1000,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert len(out) <= 1000
    for c in hv_channels:
        assert tel["by_channel_kept"].get(c, 0) > 0, (
            f"HV channel starved: {c} kept={tel['by_channel_kept'].get(c, 0)}"
        )
    assert tel["high_value_starved"] == []


# 3) Newest within channel -------------------------------------------


def test_newest_within_channel_missing_times_last():
    hv = "Security"
    n = 100
    records = _flood(hv, n)  # eid 0..99 with monotonically increasing time
    # Append two records with missing/unparseable TimeCreated; both must
    # land at the END (sort last) for their channel, never in the top-k.
    records.append(_mk(hv, eid=10_001, t=""))
    records.append(_mk(hv, eid=10_002, t="not-a-date"))

    out, _ = _select_evtx_priority_records(
        records,
        max_records=10,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert all(r["Channel"] == hv for r in out)
    eids = [r["EventID"] for r in out]
    # Newest (largest eid in the parseable set) appears first.
    assert eids[0] == n - 1
    # First 10 are the top-10 newest parseable, descending.
    assert eids == list(range(n - 1, n - 1 - 10, -1))
    # Missing/unparseable never make the top-k.
    assert 10_001 not in eids
    assert 10_002 not in eids


# 4) Budget -----------------------------------------------------------


def test_budget_never_exceeds_max():
    records = _flood("AnyCh", 999)
    out, tel = _select_evtx_priority_records(
        records,
        max_records=100,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert len(out) <= 100
    assert tel["selected_total"] <= 100


def test_budget_reaches_max_with_plenty_of_supply():
    # Many channels, each within per-channel caps, sum >> budget.
    records: list[dict] = []
    for c in ("Security", "System"):
        records.extend(_flood(c, 10_000))
    for i in range(20):
        records.extend(_flood(f"NoiseCh{i:02d}", 1000))
    out, tel = _select_evtx_priority_records(
        records,
        max_records=5000,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert tel["selected_total"] == 5000
    assert len(out) == 5000


# 5) No-domination A --------------------------------------------------


def test_single_noise_channel_cannot_exceed_other_cap():
    records = _flood("NoiseFlood", 1_000_000)
    out, tel = _select_evtx_priority_records(
        records,
        max_records=10_000,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert tel["selected_total"] == 2000
    assert tel["by_channel_kept"].get("NoiseFlood", 0) == 2000
    assert len(out) == 2000


# 6) No-domination B --------------------------------------------------


def test_many_noise_channels_share_budget_no_starvation():
    records: list[dict] = []
    for i in range(10):
        records.extend(_flood(f"NoiseCh{i:02d}", 1000))
    out, tel = _select_evtx_priority_records(
        records,
        max_records=5000,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert tel["selected_total"] == 5000
    assert len(out) == 5000
    for chan, kept in tel["by_channel_kept"].items():
        assert kept <= 2000, f"{chan} exceeded other_cap: {kept}"
        assert kept > 0, f"{chan} starved to 0"


# 7) Standard channel mix --------------------------------------------


def test_standard_channel_mix_each_retains_records():
    hv_present = (
        "System",
        "Security",
        "Microsoft-Windows-TaskScheduler/Operational",
    )
    records: list[dict] = []
    for c in hv_present:
        records.extend(_flood(c, 100))
    records.extend(_flood("NoiseFlood", 100_000))
    out, tel = _select_evtx_priority_records(
        records,
        max_records=10_000,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    for c in hv_present:
        assert tel["by_channel_kept"].get(c, 0) > 0, f"{c} starved"
    assert tel["high_value_starved"] == []
    assert len(out) <= 10_000


# 8) Schema unchanged -------------------------------------------------


def test_selected_records_keep_six_field_schema():
    records = _flood("Security", 25)
    out, _ = _select_evtx_priority_records(
        records,
        max_records=10,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    assert out
    for r in out:
        assert set(r) == SCHEMA


# 9) Telemetry --------------------------------------------------------


def test_telemetry_has_required_keys():
    records = _flood("Security", 5) + _flood("NoiseCh", 50)
    _, tel = _select_evtx_priority_records(
        records,
        max_records=20,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    for key in (
        "source_total",
        "selected_total",
        "by_channel_source",
        "by_channel_kept",
        "by_channel_dropped",
        "high_value_present",
        "high_value_starved",
    ):
        assert key in tel, f"missing telemetry key: {key}"
    assert tel["source_total"] == 55
    assert isinstance(tel["high_value_present"], list)
    assert isinstance(tel["high_value_starved"], list)
    assert "Security" in tel["high_value_present"]


# 10) Env caps honored ------------------------------------------------


def test_explicit_caps_change_outcome():
    """Passing different caps to the helper changes its retention math."""
    records: list[dict] = []
    for i in range(5):
        records.extend(_flood(f"NoiseCh{i:02d}", 1000))
    _, tel_big = _select_evtx_priority_records(
        records,
        max_records=10_000,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=2000,
        fill_chunk=256,
    )
    _, tel_small = _select_evtx_priority_records(
        records,
        max_records=10_000,
        high_value_per_channel_cap=5000,
        other_per_channel_cap=500,
        fill_chunk=128,
    )
    for kept in tel_big["by_channel_kept"].values():
        assert kept <= 2000
    for kept in tel_small["by_channel_kept"].values():
        assert kept <= 500
    assert tel_small["selected_total"] <= 5 * 500
    assert tel_small["selected_total"] < tel_big["selected_total"]


def test_env_caps_honored_through_parse_event_logs(monkeypatch, tmp_path):
    """parse_event_logs reads SIFT_EVTX_* env vars and passes them through."""
    monkeypatch.delenv("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", raising=False)
    monkeypatch.setenv("SIFT_EVENT_LOG_MAX_RECORDS", "10000")
    monkeypatch.setenv("SIFT_EVTX_OTHER_PER_CHANNEL_CAP", "300")
    monkeypatch.setenv("SIFT_EVTX_HV_PER_CHANNEL_CAP", "5000")
    monkeypatch.setenv("SIFT_EVTX_FILL_CHUNK", "128")

    # Force python-evtx path (single, deterministic shape).
    monkeypatch.setattr(de, "_load_pyevtx", lambda: None)

    class FakeRecord:
        def __init__(self, eid: int, channel: str):
            self._eid = eid
            self._ch = channel

        def xml(self):
            return (
                '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                f"<System><EventID>{self._eid}</EventID>"
                f'<TimeCreated SystemTime="2030-01-01T00:00:{self._eid % 60:02d}Z"/>'
                f'<Provider Name="P"/>'
                f"<Channel>{self._ch}</Channel>"
                "<Computer>H</Computer></System>"
                "<EventData><Data>k=v</Data></EventData></Event>"
            )

    class FakeEvtx:
        def __init__(self, path: str):
            self._path = path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def records(self):
            # Channel name encoded in filename stem (one channel per file).
            ch = Path(self._path).stem
            for i in range(1000):
                yield FakeRecord(i, ch)

    fake_mod = types.SimpleNamespace(Evtx=FakeEvtx)
    monkeypatch.setattr(de, "_load_python_evtx", lambda: fake_mod)

    logs_dir = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    logs_dir.mkdir(parents=True)
    # Use generic, non-HV channel filenames so default OTHER cap governs.
    for name in ("NoiseChAA", "NoiseChBB"):
        (logs_dir / f"{name}.evtx").write_bytes(b"\x00")

    res = parse_event_logs(disk_mount=str(tmp_path))
    assert "error" not in res, res
    # Each (non-HV) channel capped at OTHER_CAP=300 -> 2 * 300 = 600 max.
    assert res["record_count"] <= 600
    # Per-channel ceiling actually enforced (not the global cap of 10000).
    by_chan: dict[str, int] = {}
    for r in res["output"]:
        by_chan[r["Channel"]] = by_chan.get(r["Channel"], 0) + 1
    for chan, kept in by_chan.items():
        assert kept <= 300, f"{chan} exceeded OTHER_CAP=300: kept={kept}"


# 31D-MCP-STDOUT-HYGIENE ----------------------------------------------


def test_parse_event_logs_emits_no_stdout(monkeypatch, tmp_path):
    """parse_event_logs must not write to stdout: MCP stdio is JSON-RPC.

    Forces the python-evtx path via a controlled fake, then captures
    stdout across the entire call (including the priority selector +
    telemetry block) and asserts both: empty output AND no EVTX_*
    token leaked through stdout.
    """
    import contextlib
    import io

    monkeypatch.setattr(de, "_load_pyevtx", lambda: None)

    class FakeRecord:
        def __init__(self, eid: int, channel: str):
            self._eid = eid
            self._ch = channel

        def xml(self):
            return (
                '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                f"<System><EventID>{self._eid}</EventID>"
                f'<TimeCreated SystemTime="2030-01-01T00:00:{self._eid % 60:02d}Z"/>'
                f'<Provider Name="P"/>'
                f"<Channel>{self._ch}</Channel>"
                "<Computer>H</Computer></System>"
                "<EventData><Data>k=v</Data></EventData></Event>"
            )

    class FakeEvtx:
        def __init__(self, path: str):
            self._path = path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def records(self):
            ch = Path(self._path).stem
            # Include one HV-named file so the selector takes the
            # reserve path; the second is a non-HV channel exercising
            # the general fill + dropped log line.
            for i in range(50):
                yield FakeRecord(i, ch)

    fake_mod = types.SimpleNamespace(Evtx=FakeEvtx)
    monkeypatch.setattr(de, "_load_python_evtx", lambda: fake_mod)

    logs_dir = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    logs_dir.mkdir(parents=True)
    # Filename stem becomes the Channel value via FakeEvtx.records().
    (logs_dir / "Security.evtx").write_bytes(b"\x00")
    (logs_dir / "NoiseChAA.evtx").write_bytes(b"\x00")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        res = parse_event_logs(disk_mount=str(tmp_path))

    captured = buf.getvalue()
    assert captured == "", (
        "parse_event_logs wrote to stdout (MCP JSON-RPC corruption); "
        f"first 200 chars: {captured[:200]!r}"
    )
    assert "EVTX_" not in captured, (
        f"EVTX_* telemetry leaked to stdout: {captured[:200]!r}"
    )
    # Sanity: the call itself still worked.
    assert "error" not in res, res
    assert res["record_count"] > 0


def test_parse_event_logs_source_contains_no_print_call():
    """Static guard: parse_event_logs body must contain no ``print(`` token.

    Broader than the prior AST-walker check because formatted-name
    prints (``print(_summary_line, flush=True)``) bypass simple
    identifier matching but still corrupt MCP stdio.
    """
    import inspect

    src = inspect.getsource(parse_event_logs)
    assert "print(" not in src, (
        "parse_event_logs source contains a print() call — MCP stdio "
        "expects JSON-RPC on stdout. Route telemetry through "
        "``logger.info`` / ``logger.warning`` instead."
    )


# Dataset-agnostic guard for this test file ---------------------------


def test_no_dataset_literals_in_this_test():
    src = Path(__file__).read_text(errors="replace")
    banned = [
        "172." + "16.",
        "td" + "ungan",
        "sp" + "sql",
        "OUT" + "LOOK",
        "base-" + "rd01",
        "squirrel" + "directory",
        "shield" + "base",
        "Wmi" + "PrvSE",
    ]
    for token in banned:
        assert token not in src, f"forbidden dataset literal: {token}"
