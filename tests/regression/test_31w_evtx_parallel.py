"""31W regression: parallel EVTX-file parsing via inner ThreadPoolExecutor.
Property-based, dataset-agnostic. No hardcoded filenames or event IDs.
"""
import importlib, sys, time, types
from contextlib import contextmanager
from pathlib import Path
import pytest

@contextmanager
def mocked_evtx(per_file_records=10, per_file_delay_s=0.05, slow_file_substr=None):
    class FakeRecord:
        def __init__(self, eid, tc): self._eid = eid; self._tc = tc
        def xml(self):
            return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                    f'<System><EventID>{self._eid}</EventID>'
                    f'<TimeCreated SystemTime="{self._tc}"/>'
                    '<Provider Name="Test"/><Channel>X</Channel><Computer>HOST</Computer>'
                    '</System><EventData><Data>k=v</Data></EventData></Event>')
    class FakeEvtx:
        def __init__(self, path): self._path = path
        def __enter__(self):
            if slow_file_substr and slow_file_substr in str(self._path):
                time.sleep(30)
            else:
                time.sleep(per_file_delay_s)
            return self
        def __exit__(self, *a): return False
        def records(self):
            for i in range(per_file_records):
                yield FakeRecord(4624 + (i % 5), f"2025-01-01T00:00:{i:02d}Z")
    mod = types.ModuleType("Evtx.Evtx"); mod.Evtx = FakeEvtx
    parent = types.ModuleType("Evtx")
    saved = {k: sys.modules.get(k) for k in ("Evtx", "Evtx.Evtx")}
    sys.modules["Evtx"] = parent; sys.modules["Evtx.Evtx"] = mod
    try: yield
    finally:
        for k, v in saved.items():
            if v is None: sys.modules.pop(k, None)
            else: sys.modules[k] = v

@pytest.fixture
def tmp_evtx_dir(tmp_path):
    logs = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    for i in range(8):
        (logs / f"channel_{i:02d}.evtx").write_bytes(b"\x00" * 64)
    return str(tmp_path)

@pytest.fixture
def parse_event_logs():
    import sift_sentinel.tools.disk_extended as de
    importlib.reload(de)
    return de.parse_event_logs

def test_31w_basic_correctness(tmp_evtx_dir, parse_event_logs, monkeypatch):
    monkeypatch.setenv("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", "4")
    monkeypatch.delenv("SIFT_EVENT_LOG_MAX_RECORDS", raising=False)
    with mocked_evtx(per_file_records=10, per_file_delay_s=0.02):
        res = parse_event_logs(disk_mount=tmp_evtx_dir)
    assert isinstance(res, dict)
    assert "output" in res and "record_count" in res
    assert res["record_count"] == 8 * 10

def test_31w_determinism(tmp_evtx_dir, parse_event_logs, monkeypatch):
    monkeypatch.setenv("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", "4")
    monkeypatch.delenv("SIFT_EVENT_LOG_MAX_RECORDS", raising=False)
    counts = []
    for _ in range(3):
        with mocked_evtx(per_file_records=10, per_file_delay_s=0.02):
            counts.append(parse_event_logs(disk_mount=tmp_evtx_dir)["record_count"])
    assert len(set(counts)) == 1, f"non-deterministic: {counts}"

def test_31w_cap_respected(tmp_evtx_dir, parse_event_logs, monkeypatch):
    monkeypatch.setenv("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", "4")
    monkeypatch.setenv("SIFT_EVENT_LOG_MAX_RECORDS", "25")
    with mocked_evtx(per_file_records=10, per_file_delay_s=0.02):
        res = parse_event_logs(disk_mount=tmp_evtx_dir, max_records=25)
    assert res["record_count"] <= 25

def test_31w_slow_file_does_not_block_pipeline(tmp_evtx_dir, parse_event_logs, monkeypatch):
    monkeypatch.setenv("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", "4")
    monkeypatch.setenv("SIFT_EVTX_TIMEOUT_BASE_S", "1")
    monkeypatch.setenv("SIFT_EVTX_TIMEOUT_S", "1")
    monkeypatch.delenv("SIFT_EVENT_LOG_MAX_RECORDS", raising=False)
    with mocked_evtx(per_file_records=10, per_file_delay_s=0.02, slow_file_substr="channel_03"):
        t0 = time.time()
        res = parse_event_logs(disk_mount=tmp_evtx_dir)
        elapsed = time.time() - t0
    assert elapsed < 5.0, f"slow file blocked: {elapsed:.2f}s"
    assert res["record_count"] == 70

def test_31w_static_markers_present():
    src = Path("src/sift_sentinel/tools/disk_extended.py").read_text()
    assert "ThreadPoolExecutor" in src
    assert "as_completed" in src
    assert "SIFT_PARSE_EVENT_LOGS_INNER_WORKERS" in src
    assert "31W" in src
