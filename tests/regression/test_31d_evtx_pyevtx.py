"""31D-EVTX-PYEVTX: Rust PyEvtxParser fast path in parse_event_logs.

The legacy ``python-evtx`` + ``xml.etree`` per-record path is pure-Python
and CPU-bound; on the System.evtx hot file (100k records) it times out
at 63s standalone (no contention), 196s under the full pipeline. The
Rust-backed ``evtx.PyEvtxParser`` does the same 100k records with full
extraction in ~0.6s.

This module pins the contract that lets us switch:

1. Field parity -- the 6-field schema (EventID/TimeCreated/Provider/
   Channel/Computer/Message) is identical regardless of which parser
   processed the .evtx. Verified field-for-field on real Windows
   event records when a sample log is reachable on this host; pure
   unit tests cover the common shapes either way.
2. EventID coercion -- the PyEvtxParser JSON shape uses either a
   scalar int OR a dict-with-``#text`` (when ``<EventID Qualifiers=..>``
   is present). Both must map to the same int the xml.etree path
   produces.
3. ImportError fallback -- if the Rust ``evtx`` wheel is absent, the
   public function must transparently fall back to the python-evtx +
   xml.etree path and still return records.
4. Schema completeness -- every emitted record carries all 6 keys.

Dataset-agnostic: no hostnames, usernames, IPs, PIDs, or hashes from
any specific case are hardcoded. Real-evtx test discovers a sample at
runtime and skips when none is available.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sift_sentinel.tools import disk_extended as de
from sift_sentinel.tools.disk_extended import (
    _load_pyevtx,
    _load_python_evtx,
    _map_pyevtx_record,
    parse_event_logs,
)


# ── _map_pyevtx_record: unit-level field-parity contracts ────────────


def _common_named_record() -> dict:
    """A synthetic PyEvtxParser JSON dict modeling Security.evtx 4688."""
    return {
        "Event": {
            "#attributes": {
                "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event",
            },
            "System": {
                "Provider": {
                    "#attributes": {
                        "Name": "Microsoft-Windows-Security-Auditing",
                        "Guid": "{00000000-0000-0000-0000-000000000000}",
                    },
                },
                "EventID": 4688,
                "TimeCreated": {
                    "#attributes": {"SystemTime": "2030-01-02T03:04:05.000000Z"},
                },
                "Channel": "Security",
                "Computer": "synthetic-host.local",
            },
            "EventData": {
                "SubjectUserName": "synuser",
                "SubjectDomainName": "syndomain",
                "NewProcessName": "C:/synthetic/path/proc.exe",
            },
        },
    }


def test_mapper_common_named_event_data_full_schema():
    rec = _map_pyevtx_record(_common_named_record())
    assert set(rec) == {
        "EventID", "TimeCreated", "Provider", "Channel", "Computer", "Message",
    }
    assert rec["EventID"] == 4688
    # TimeCreated is normalized to the python-evtx str(datetime) format so
    # downstream consumers see the same string regardless of parser.
    assert rec["TimeCreated"] == "2030-01-02 03:04:05+00:00"
    assert rec["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert rec["Channel"] == "Security"
    assert rec["Computer"] == "synthetic-host.local"
    # Message: joined non-#-prefixed EventData values with " | ", in order.
    assert rec["Message"] == (
        "synuser | syndomain | C:/synthetic/path/proc.exe"
    )


def test_mapper_eventid_scalar_int_maps_to_int():
    d = _common_named_record()
    d["Event"]["System"]["EventID"] = 7
    assert _map_pyevtx_record(d)["EventID"] == 7


def test_mapper_eventid_dict_with_text_maps_to_int():
    d = _common_named_record()
    d["Event"]["System"]["EventID"] = {
        "#attributes": {"Qualifiers": 16384},
        "#text": 7036,
    }
    assert _map_pyevtx_record(d)["EventID"] == 7036


def test_mapper_eventid_missing_defaults_to_zero():
    d = _common_named_record()
    del d["Event"]["System"]["EventID"]
    assert _map_pyevtx_record(d)["EventID"] == 0


def test_mapper_eventid_garbage_string_defaults_to_zero():
    d = _common_named_record()
    d["Event"]["System"]["EventID"] = "not-an-int"
    assert _map_pyevtx_record(d)["EventID"] == 0


def test_mapper_all_six_keys_for_empty_event():
    rec = _map_pyevtx_record({"Event": {}})
    assert set(rec) == {
        "EventID", "TimeCreated", "Provider", "Channel", "Computer", "Message",
    }
    assert rec["EventID"] == 0
    assert rec["TimeCreated"] == ""
    assert rec["Provider"] == ""
    assert rec["Channel"] == ""
    assert rec["Computer"] == ""
    assert rec["Message"] == ""


def test_mapper_all_six_keys_for_completely_empty_dict():
    rec = _map_pyevtx_record({})
    assert set(rec) == {
        "EventID", "TimeCreated", "Provider", "Channel", "Computer", "Message",
    }


def test_mapper_event_data_none_yields_empty_message():
    d = _common_named_record()
    d["Event"]["EventData"] = None
    assert _map_pyevtx_record(d)["Message"] == ""


def test_mapper_event_data_with_attributes_skips_attributes_key():
    """EventData ``#attributes`` carries the EventData tag's own attrs
    (e.g. ``Name="EVENT_HIVE_LEAK"``); the legacy xml.etree path joins
    only ``<Data>`` text content, so #-prefixed keys must be skipped.
    """
    d = _common_named_record()
    d["Event"]["EventData"] = {
        "#attributes": {"Name": "TMP_EVENT_SYNTHETIC"},
        "Detail": "synthetic detail",
        "Code": 42,
    }
    msg = _map_pyevtx_record(d)["Message"]
    assert "TMP_EVENT_SYNTHETIC" not in msg  # attribute name not joined
    assert msg == "synthetic detail | 42"


def test_mapper_message_truncated_to_200_chars():
    d = _common_named_record()
    d["Event"]["EventData"] = {"Big": "x" * 500}
    assert len(_map_pyevtx_record(d)["Message"]) == 200


def test_mapper_provider_scalar_string_yields_empty_provider():
    """Defensive: if Provider isn't a dict, the legacy code path took
    ``prov_el.get('Name','')`` on an absent element and returned ''.
    PyEvtxParser path must match that default rather than blow up.
    """
    d = _common_named_record()
    d["Event"]["System"]["Provider"] = "weird-scalar"
    assert _map_pyevtx_record(d)["Provider"] == ""


def test_mapper_time_created_missing_yields_empty_string():
    d = _common_named_record()
    del d["Event"]["System"]["TimeCreated"]
    assert _map_pyevtx_record(d)["TimeCreated"] == ""


def test_mapper_channel_and_computer_remain_plain_strings():
    d = _common_named_record()
    out = _map_pyevtx_record(d)
    assert isinstance(out["Channel"], str)
    assert isinstance(out["Computer"], str)


# ── Real-evtx field-parity smoke (skipped when no sample reachable) ──


def _discover_sample_evtx() -> Path | None:
    """Locate a small .evtx with records reachable on this host.

    Iterates the canonical SIFT mount path and prefers smaller files
    that contain records. Returns None when no usable sample is found
    -- the caller skips rather than fails (dataset-agnostic).
    """
    PyEvtxParser = _load_pyevtx()
    if PyEvtxParser is None:
        return None
    candidates_root = Path("/mnt/windows_mount/Windows/System32/winevt/Logs")
    if not candidates_root.is_dir():
        return None
    cands = sorted(
        candidates_root.glob("*.evtx"),
        key=lambda p: p.stat().st_size,
    )
    for f in cands:
        try:
            p = PyEvtxParser(str(f))
            for _ in p.records_json():
                return f
        except Exception:
            continue
    return None


def _parse_via_pyevtx(path: Path) -> list[dict]:
    import json as _json
    PyEvtxParser = _load_pyevtx()
    out: list[dict] = []
    p = PyEvtxParser(str(path))
    for rec in p.records_json():
        try:
            d = _json.loads(rec["data"])
        except Exception:
            continue
        out.append(_map_pyevtx_record(d))
    return out


def _parse_via_python_evtx(path: Path) -> list[dict]:
    import xml.etree.ElementTree as ET
    evtx_mod = _load_python_evtx()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    out: list[dict] = []
    with evtx_mod.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            system = root.find("e:System", ns)
            if system is None:
                continue
            eid_el = system.find("e:EventID", ns)
            time_el = system.find("e:TimeCreated", ns)
            prov_el = system.find("e:Provider", ns)
            chan_el = system.find("e:Channel", ns)
            comp_el = system.find("e:Computer", ns)
            msg = ""
            event_data = root.find("e:EventData", ns)
            if event_data is not None:
                parts = []
                for data_el in event_data.findall("e:Data", ns):
                    if data_el.text:
                        parts.append(data_el.text)
                msg = " | ".join(parts)[:200]
            out.append({
                "EventID": (int(eid_el.text)
                            if eid_el is not None and eid_el.text else 0),
                "TimeCreated": (time_el.get("SystemTime", "")
                                if time_el is not None else ""),
                "Provider": (prov_el.get("Name", "")
                             if prov_el is not None else ""),
                "Channel": (chan_el.text
                            if chan_el is not None else ""),
                "Computer": (comp_el.text
                             if comp_el is not None else ""),
                "Message": msg,
            })
    return out


def test_field_parity_pyevtx_vs_python_evtx_on_real_evtx():
    if _load_pyevtx() is None:
        pytest.skip("Rust evtx wheel not installed; nothing to compare")
    if _load_python_evtx() is None:
        pytest.skip("python-evtx not installed; legacy oracle unavailable")
    sample = _discover_sample_evtx()
    if sample is None:
        pytest.skip("no reachable sample .evtx with records on this host")

    pyx = _parse_via_pyevtx(sample)
    pyl = _parse_via_python_evtx(sample)
    assert pyx, "pyevtx returned zero records for a non-empty sample"
    assert pyl, "python-evtx returned zero records for a non-empty sample"
    # File-level count parity is the cleanest invariant: same input,
    # same record stream, identical row count regardless of parser.
    assert len(pyx) == len(pyl), (
        f"record count mismatch: pyevtx={len(pyx)} python-evtx={len(pyl)}"
    )
    # Order parity (both walk the .evtx in chunk order).
    mismatches: list[str] = []
    for i, (a, b) in enumerate(zip(pyx, pyl)):
        for key in ("EventID", "TimeCreated", "Provider",
                    "Channel", "Computer", "Message"):
            if a.get(key) != b.get(key):
                mismatches.append(
                    f"[#{i}/{key}] pyevtx={a.get(key)!r} != python-evtx={b.get(key)!r}"
                )
        if len(mismatches) >= 10:
            break
    assert not mismatches, (
        "FIELD PARITY broken between PyEvtxParser-mapped and xml.etree "
        "records (showing up to 10): " + " || ".join(mismatches)
    )


def test_every_pyevtx_record_carries_all_six_schema_keys_on_real_evtx():
    if _load_pyevtx() is None:
        pytest.skip("Rust evtx wheel not installed")
    sample = _discover_sample_evtx()
    if sample is None:
        pytest.skip("no reachable sample .evtx with records on this host")
    pyx = _parse_via_pyevtx(sample)
    assert pyx
    expected = {"EventID", "TimeCreated", "Provider",
                "Channel", "Computer", "Message"}
    for i, rec in enumerate(pyx):
        assert set(rec) == expected, (
            f"record {i} missing/extra keys: {set(rec) ^ expected}"
        )


# ── ImportError fallback: pyevtx absent → python-evtx path runs ──────


def test_import_error_fallback_invokes_python_evtx(monkeypatch, tmp_path):
    """Simulate ``from evtx import PyEvtxParser`` failing: parse_event_logs
    must fall back to the python-evtx + xml.etree path and still return
    records when a reachable sample is on disk.
    """
    if _load_python_evtx() is None:
        pytest.skip("python-evtx not installed; cannot test fallback path")
    sample = _discover_sample_evtx()
    if sample is None:
        pytest.skip("no reachable sample .evtx with records on this host")

    # Stage a synthetic disk mount that exposes the sample under the
    # canonical winevt/Logs/ subtree. Symlink so we don't copy.
    stage = tmp_path / "synth_mount"
    logs_dir = stage / "Windows" / "System32" / "winevt" / "Logs"
    logs_dir.mkdir(parents=True)
    (logs_dir / sample.name).symlink_to(sample)

    # Force pyevtx unavailable.
    monkeypatch.setattr(de, "_load_pyevtx", lambda: None)

    captured: list[str] = []

    class _CapturingHandler:
        def __init__(self):
            self.level = 0
        def handle(self, record):
            captured.append(record.getMessage())
        def createLock(self):
            self.lock = None
        def acquire(self):
            pass
        def release(self):
            pass

    import logging as _logging
    handler = _logging.StreamHandler()
    handler.emit = lambda r: captured.append(r.getMessage())  # type: ignore
    de.logger.addHandler(handler)
    de.logger.setLevel(_logging.INFO)
    try:
        out = parse_event_logs(disk_mount=str(stage), max_records=50)
    finally:
        de.logger.removeHandler(handler)

    assert "error" not in out, f"unexpected error: {out.get('error')}"
    assert out["record_count"] > 0, "fallback path returned zero records"
    # Telemetry must announce the fallback parser, not pyevtx.
    summary = [m for m in captured if m.startswith("EVTX_SUMMARY")]
    assert summary, "no EVTX_SUMMARY emitted on fallback path"
    assert "parser=python-evtx" in summary[-1], (
        f"fallback summary did not declare python-evtx parser: {summary[-1]}"
    )
    file_results = [m for m in captured if m.startswith("EVTX_FILE_RESULT")]
    assert file_results, "no EVTX_FILE_RESULT emitted"
    assert any("parser=python-evtx" in m for m in file_results), (
        "fallback file result did not declare python-evtx parser"
    )
    # And every record returned carries the full 6-field schema.
    expected = {"EventID", "TimeCreated", "Provider",
                "Channel", "Computer", "Message"}
    for rec in out["output"]:
        assert set(rec) == expected


# ── Dataset-agnostic guard for this test file itself ─────────────────


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
    ]
    for token in banned:
        assert token not in src, f"forbidden dataset literal in test: {token}"
