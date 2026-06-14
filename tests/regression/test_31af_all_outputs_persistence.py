"""31AF regression: live state must persist aggregate all_outputs.json.

A++ audit/rebuild workflows need both:
- per-tool files under tool_outputs/<tool>.json
- aggregate state/all_outputs.json built from the same in-memory all_outputs map

This test is intentionally static and dataset-agnostic. It prevents future
refactors from keeping only per-tool outputs while losing the aggregate rebuild
artifact.
"""

from pathlib import Path


def test_run_pipeline_persists_aggregate_all_outputs_before_reference_set():
    src = Path("run_pipeline.py").read_text()

    persist = 'write_state(STATE_DIR, "all_outputs.json", all_outputs)'
    build_ref = "build_reference_set(all_outputs"

    assert persist in src, (
        "31AF: run_pipeline.py must persist state/all_outputs.json from the "
        "actual all_outputs dict before building downstream evidence."
    )
    assert build_ref in src, "sanity check: build_reference_set(all_outputs) marker missing"

    assert src.index(persist) < src.index(build_ref), (
        "31AF: all_outputs.json should be saved before reference_set/EvidenceDB "
        "so failed later stages still leave rebuildable tool-output input."
    )
