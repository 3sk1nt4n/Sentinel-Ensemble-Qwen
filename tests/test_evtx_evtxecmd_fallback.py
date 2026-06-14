"""TDD (D1a): EVTX EvtxECmd last-resort fallback.

Recovers EVTX files the pure-Python copy/parse path cannot handle -- e.g. the
FUSE read EOVERFLOW ([Errno 75] "Value too large for defined data type") that
dropped Security.evtx and TerminalServices-RemoteConnectionManager to
``copy-skip`` (0 records) in the live Acme run.

Dataset-agnostic: the fallback keys on NO channel/host/IP/path/content. It runs
only on the error path, where the Python parsers already yielded nothing, and
maps EvtxECmd CSV rows into the same 6-field schema as the pyevtx path.
"""
from sift_sentinel.tools import disk_extended as dx


def test_map_evtxecmd_record_maps_six_field_schema():
    row = {
        "EventId": "4624",
        "TimeCreated": "2020-11-02 08:28:14.6560000",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "ACME-PC",
        "MapDescription": "Successful logon",
        "Payload": "{...}",
    }
    out = dx._map_evtxecmd_record(row)
    assert out["EventID"] == 4624
    assert out["Channel"] == "Security"
    assert out["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert out["Computer"] == "ACME-PC"
    assert out["TimeCreated"].startswith("2020-11-02")
    assert "logon" in out["Message"].lower()
    assert set(out) == {
        "EventID", "TimeCreated", "Provider", "Channel", "Computer", "Message",
    }


def test_map_evtxecmd_record_defaults_on_garbage():
    out = dx._map_evtxecmd_record({"EventId": "", "Channel": None})
    assert out["EventID"] == 0
    assert out["Channel"] == ""
    assert out["Message"] == ""


def test_evtxecmd_fallback_maps_records_on_success(monkeypatch):
    def fake_run_evtxecmd(path, *a, **k):
        return {
            "tool_name": "EvtxECmd",
            "record_count": 2,
            "output": [
                {"EventId": "4624", "Channel": "Security", "Provider": "P",
                 "Computer": "C", "TimeCreated": "T", "MapDescription": "logon"},
                {"EventId": "21",
                 "Channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                 "Provider": "P2", "Computer": "C", "TimeCreated": "T2",
                 "MapDescription": "RDP connect"},
            ],
        }
    monkeypatch.setattr(
        "sift_sentinel.tools.generic.run_evtxecmd", fake_run_evtxecmd)
    recs, err = dx._evtx_evtxecmd_fallback("/nonexistent/Security.evtx", timeout_s=10)
    assert err is None
    assert len(recs) == 2
    assert recs[0]["EventID"] == 4624
    assert recs[1]["Channel"].endswith("RemoteConnectionManager/Operational")


def test_evtxecmd_fallback_returns_error_when_tool_errors(monkeypatch):
    monkeypatch.setattr(
        "sift_sentinel.tools.generic.run_evtxecmd",
        lambda path, *a, **k: {"error": "EvtxECmd binary not found",
                               "output": [], "record_count": 0},
    )
    recs, err = dx._evtx_evtxecmd_fallback("/x/Security.evtx", timeout_s=10)
    assert recs == []
    assert err is not None


def test_evtxecmd_fallback_skips_complete_no_data_marker(monkeypatch):
    monkeypatch.setattr(
        "sift_sentinel.tools.generic.run_evtxecmd",
        lambda path, *a, **k: {"output": [{"status": "complete_no_data",
                                           "output": "x.csv"}], "record_count": 0},
    )
    recs, err = dx._evtx_evtxecmd_fallback("/x/Security.evtx", timeout_s=10)
    assert err is None
    assert recs == []
