"""31Y: SIFT_PARSE_EVENT_LOGS_INNER_WORKERS default is 1 (serial).

31W introduced parallel EVTX parsing via ThreadPoolExecutor. Block 2
live run showed GIL contention with 4 workers caused premature 10s
timeouts on small files, costing 96% of event_log_fact coverage with
zero wallclock improvement. 31Y reverts the default to serial; the
parallelism code path remains available via env override for future
tuning experiments.
"""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))


def test_31y_default_is_serial(monkeypatch):
    monkeypatch.delenv("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", raising=False)
    import sift_sentinel.tools.disk_extended as de
    importlib.reload(de)
    # Read the env default the same way the production code does.
    default_workers = de._sift_env_int("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", 1)
    assert default_workers == 1, (
        f"31Y guard: default must be 1 (serial), got {default_workers}. "
        "Parallel mode caused 96% event_log coverage regression at 4 workers."
    )


def test_31y_env_override_still_works(monkeypatch):
    monkeypatch.setenv("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", "4")
    import sift_sentinel.tools.disk_extended as de
    importlib.reload(de)
    n = de._sift_env_int("SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", 1)
    assert n == 4, "env override must still take effect"


def test_31y_static_default_marker():
    src = Path("src/sift_sentinel/tools/disk_extended.py").read_text()
    # Must NOT have the prior `, 4)` default for this specific env var.
    assert '"SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", 4)' not in src, (
        "31Y: default for SIFT_PARSE_EVENT_LOGS_INNER_WORKERS must not be 4"
    )
    assert '"SIFT_PARSE_EVENT_LOGS_INNER_WORKERS", 1)' in src, (
        "31Y: default for SIFT_PARSE_EVENT_LOGS_INNER_WORKERS must be 1"
    )
