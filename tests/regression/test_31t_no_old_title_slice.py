"""31T regression: run_pipeline.py has no stale [:50]/[:60] slices.

The Block 2 live audit checks run_pipeline.py source for any [:50] or
[:60] slice and fails the static gate if found. This guard prevents
the stale source behavior from creeping back. Renderer-side display
formatting in src/sift_sentinel/* may have its own column width
logic; this test scopes to run_pipeline.py only.
"""
import re
from pathlib import Path


def test_31t_no_50_or_60_slice_in_run_pipeline():
    src = Path("run_pipeline.py").read_text()
    bad = []
    for i, ln in enumerate(src.splitlines(), start=1):
        if re.search(r'\[:\s*(?:50|60)\s*\]', ln):
            bad.append((i, ln.strip()))
    assert not bad, (
        "31T regression: [:50]/[:60] slice survived in run_pipeline.py. "
        "Lines:\n  " +
        "\n  ".join(f"L{i}: {l[:120]}" for i, l in bad[:10])
    )
