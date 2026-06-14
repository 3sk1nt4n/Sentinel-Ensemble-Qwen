"""31G bulk_extractor bounded samples.

The tool remains summary-only: one output record and one
ioc_carve_summary_fact. Bounded samples are preserved so
extract_network_iocs can derive corroborating network_ioc_fact rows,
but bulk-only samples must not become validation-ready findings.
"""
from pathlib import Path

from sift_sentinel.analysis.candidate_observations import build_candidate_observations
from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
from sift_sentinel.tools.extract_network_iocs import extract_network_iocs


def _iter_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _iter_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_dicts(value)


def _bulk_record():
    return {
        "emails": 2,
        "urls": 2,
        "domains": 2,
        "carved_feature_total": 6,
        "emails_sample": ["analyst@example.invalid"],
        "urls_sample": [
            "http://example.invalid/path",
            "https://sub.example.invalid/a",
        ],
        "domains_sample": [
            "example.invalid",
            "sub.example.invalid",
        ],
    }


def test_run_bulk_extractor_keeps_one_record_with_bounded_samples(monkeypatch, tmp_path):
    import sift_sentinel.tools.generic as gen

    image = tmp_path / "image.dd"
    image.write_bytes(b"synthetic")
    out_dir = tmp_path / "bulk-out"

    monkeypatch.setenv("SIFT_BULK_EMAIL_SAMPLE_MAX", "1")
    monkeypatch.setenv("SIFT_BULK_URL_SAMPLE_MAX", "1")
    monkeypatch.setenv("SIFT_BULK_DOMAIN_SAMPLE_MAX", "1")
    monkeypatch.setattr(gen, "_safe_output_dir", lambda output_dir, default: str(out_dir))

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        target = Path(cmd[2])
        target.mkdir(parents=True, exist_ok=True)
        (target / "email.txt").write_text(
            "# header\n"
            "0\tanalyst@example.invalid\tcontext\n"
            "1\tsecond@example.invalid\tcontext\n",
            encoding="utf-8",
        )
        (target / "url.txt").write_text(
            "# header\n"
            "0\thttp://example.invalid/path\tcontext\n"
            "1\thttps://sub.example.invalid/a\tcontext\n",
            encoding="utf-8",
        )
        (target / "domain.txt").write_text(
            "# header\n"
            "0\texample.invalid\tcontext\n"
            "1\tsub.example.invalid\tcontext\n",
            encoding="utf-8",
        )
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    result = gen.run_bulk_extractor(str(image), str(out_dir))
    assert result["record_count"] == 1
    assert len(result["output"]) == 1

    rec = result["output"][0]
    assert rec["emails"] == 2
    assert rec["urls"] == 2
    assert rec["domains"] == 2
    assert rec["carved_feature_total"] == 6

    assert rec["emails_sample"] == ["analyst@example.invalid"]
    assert rec["urls_sample"] == ["http://example.invalid/path"]
    assert rec["domains_sample"] == ["example.invalid"]


def test_bulk_summary_fact_persists_counts_and_samples():
    db = build_typed_evidence_db({
        "run_bulk_extractor": {
            "tool_name": "run_bulk_extractor",
            "record_count": 1,
            "output": [_bulk_record()],
        }
    })

    facts = [
        d for d in _iter_dicts(db)
        if isinstance(d, dict) and d.get("fact_type") == "ioc_carve_summary_fact"
    ]
    assert len(facts) == 1
    fact = facts[0]

    assert fact["source_tool"] == "run_bulk_extractor"
    assert fact["emails"] == 2
    assert fact["urls"] == 2
    assert fact["domains"] == 2
    assert fact["carved_feature_total"] == 6
    assert fact["urls_sample"] == [
        "http://example.invalid/path",
        "https://sub.example.invalid/a",
    ]
    assert fact["domains_sample"] == [
        "example.invalid",
        "sub.example.invalid",
    ]


def test_bulk_samples_bridge_to_network_iocs_but_not_validation_ready():
    bulk = {
        "tool_name": "run_bulk_extractor",
        "record_count": 1,
        "output": [_bulk_record()],
    }
    tool_outputs = {"run_bulk_extractor": bulk}

    iocs = extract_network_iocs(tool_outputs=tool_outputs)
    assert iocs["record_count"] >= 2

    combined = dict(tool_outputs)
    combined["extract_network_iocs"] = iocs
    db = build_typed_evidence_db(combined)

    netfacts = [
        d for d in _iter_dicts(db)
        if isinstance(d, dict) and d.get("fact_type") == "network_ioc_fact"
    ]
    assert netfacts

    summary_facts = [
        d for d in _iter_dicts(db)
        if isinstance(d, dict) and d.get("fact_type") == "ioc_carve_summary_fact"
    ]
    assert len(summary_facts) == 1

    payload = build_candidate_observations(db)
    hits = []
    for cand in payload.get("candidates") or []:
        text = str(cand).lower()
        if "example.invalid" in text or "bulk_extractor" in text:
            hits.append(cand)

    assert not any(c.get("validation_ready") for c in hits)
