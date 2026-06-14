"""31AD: EVTX GIL-aware timeout scaling.

31W shipped parallel inner-thread EVTX parsing with default 4 workers.
Block 2 measured a 96% event_log_fact coverage regression with zero
wallclock improvement -- python-evtx + xml.etree are pure-Python and
the GIL serializes them. Each worker got ~1/4 of one core's effective
compute, so the 10s base timeout fired prematurely on previously-fast
files. 31Y reverted default to serial.

31AD makes parallel safe via the pure helper _compute_evtx_timeouts:
when workers > 1, both per-file base and cap multiply by worker count
to preserve parsing coverage. Serial mode unchanged. Default still
serial (31Y); parallel is opt-in via SIFT_PARSE_EVENT_LOGS_INNER_WORKERS.

GIL synthetic harness uses CPU-busy loop (NOT time.sleep). Sleep
releases the GIL and would mask the contention. This was the 31W V3
mistake; 31AD V3 corrects it.
"""
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sift_sentinel.tools.disk_extended import _compute_evtx_timeouts


def test_31ad_helper_serial_no_scaling():
    assert _compute_evtx_timeouts(10, 60, 1) == (10, 60)


def test_31ad_helper_4_workers_scales_4x():
    assert _compute_evtx_timeouts(10, 60, 4) == (40, 240)


def test_31ad_helper_2_workers_scales_2x():
    assert _compute_evtx_timeouts(10, 60, 2) == (20, 120)


def test_31ad_helper_8_workers_scales_8x():
    assert _compute_evtx_timeouts(10, 60, 8) == (80, 480)


def test_31ad_helper_zero_or_one_workers_no_scaling():
    """Defensive: workers <= 1 must not zero-out or shrink timeouts."""
    assert _compute_evtx_timeouts(10, 60, 0) == (10, 60)
    assert _compute_evtx_timeouts(10, 60, 1) == (10, 60)


def test_31ad_helper_preserves_input_for_serial():
    """Identity property: workers=1 returns inputs unchanged."""
    for base, cap in [(5, 30), (10, 60), (15, 90), (20, 120)]:
        assert _compute_evtx_timeouts(base, cap, 1) == (base, cap)


def test_31ad_helper_linear_scaling_property():
    """Property: output = (base*N, cap*N) for N > 1."""
    for n in range(2, 10):
        b, c = _compute_evtx_timeouts(10, 60, n)
        assert b == 10 * n
        assert c == 60 * n


def test_31ad_synthetic_gil_busy_harness():
    """V3 self-test: CPU-busy loop demonstrates GIL contention.

    If parallel-4 wallclock < serial/2.5x, the GIL is being released
    (synthetic is wrong, would mask real contention). For real
    python-evtx workloads, threads cannot release the GIL during
    parsing, so we expect parallel ~= serial.
    """
    def cpu_busy(iters):
        x = 0
        for i in range(iters):
            x = (x + i * 7) % 1_000_007
        return x

    ITERS = 2_000_000
    N_TASKS = 8

    t0 = time.perf_counter()
    for _ in range(N_TASKS):
        cpu_busy(ITERS)
    t_serial = time.perf_counter() - t0

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as ex:
        list(ex.map(cpu_busy, [ITERS] * N_TASKS))
    t_parallel = time.perf_counter() - t0

    speedup = t_serial / max(t_parallel, 0.001)
    print(f"\n  GIL harness: serial={t_serial:.3f}s parallel4={t_parallel:.3f}s "
          f"speedup={speedup:.2f}x")
    assert speedup < 2.5, (
        f"31AD harness invalid: {speedup:.2f}x parallel speedup means the GIL "
        f"isn't held by the busy loop. Real python-evtx parsing IS GIL-bound, "
        f"so this synthetic would mask the contention 31AD compensates for."
    )
