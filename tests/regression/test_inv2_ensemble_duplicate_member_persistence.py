from __future__ import annotations

import json
from pathlib import Path


def test_duplicate_model_roster_keeps_four_member_slots(monkeypatch):
    import sift_sentinel.ensemble as ens

    monkeypatch.setattr(ens.anthropic, "Anthropic", lambda: object())

    def fake_call(client, model, prompt, max_tokens=16384):
        return {
            "model": model,
            "short_name": ens._short_name(model),
            "findings": [{
                "finding_id": "F-SYN",
                "title": "Synthetic duplicate finding",
                "artifact": "same-artifact",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "source_tools": ["synthetic_tool"],
                "claims": [{"type": "raw", "value": "synthetic"}],
            }],
            "error": None,
            "input_tokens": 1,
            "output_tokens": 2,
            "duration_s": 0.01,
            "raw_text": "{}",
        }

    monkeypatch.setattr(ens, "_call_one_model", fake_call)

    result = ens.run_inv2_ensemble(
        "synthetic prompt",
        models=["same-model"] * 4,
    )

    assert sorted(result["per_model"]) == [
        "member_00_same-model",
        "member_01_same-model",
        "member_02_same-model",
        "member_03_same-model",
    ]

    for idx, member_id in enumerate(sorted(result["per_model"])):
        rec = result["per_model"][member_id]
        assert rec["member_id"] == member_id
        assert rec["member_index"] == idx
        assert len(rec["findings"]) == 1

    stats = result["dedup_stats"]
    assert stats["raw_total_findings"] == 4
    assert stats["merged_survivor_count"] == 1
    assert stats["dropped_by_merge_count"] == 3
    assert len(stats["dropped_by_merge"]) == 3
    assert all(d["merge_reason"] == "duplicate_fingerprint" for d in stats["dropped_by_merge"])


def test_per_member_state_records_have_unique_filenames(tmp_path, monkeypatch):
    import sift_sentinel.ensemble as ens

    per_model = {
        "member_00_same-model": {
            "model": "same-model",
            "short_name": "same-model",
            "member_id": "member_00_same-model",
            "member_index": 0,
            "findings": [{"finding_id": "F001"}],
            "error": None,
            "input_tokens": 1,
            "output_tokens": 1,
            "duration_s": 0.01,
        },
        "member_01_same-model": {
            "model": "same-model",
            "short_name": "same-model",
            "member_id": "member_01_same-model",
            "member_index": 1,
            "findings": [{"finding_id": "F002"}],
            "error": None,
            "input_tokens": 1,
            "output_tokens": 1,
            "duration_s": 0.01,
        },
    }

    out_paths = []
    for idx, (member_id, rec) in enumerate(per_model.items()):
        state_rec = ens.build_inv2_state_record(
            rec,
            sample_index=idx,
            sample_count=len(per_model),
            runtime_model_count=1,
        )
        out = tmp_path / f"inv2_ensemble_{member_id}.json"
        out.write_text(json.dumps(state_rec, indent=2, default=str))
        out_paths.append(out)

    assert len(out_paths) == 2
    assert len({p.name for p in out_paths}) == 2
    assert all(p.exists() for p in out_paths)

    loaded = [json.loads(p.read_text()) for p in out_paths]
    assert loaded[0]["member_id"] == "member_00_same-model"
    assert loaded[1]["member_id"] == "member_01_same-model"


def test_run_pipeline_persists_merged_ensemble_artifact_and_dynamic_wording():
    src = Path("run_pipeline.py").read_text()
    assert "inv2_ensemble_merged.json" in src
    assert "dispatching to 4 models in parallel" not in src
    assert "dispatching configured model roster in parallel" in src
