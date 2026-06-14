from pathlib import Path


def _join(*parts: str) -> str:
    return "".join(parts)


def _forbidden_terms():
    return [
        _join("base", "-", "rd01"),
        _join("base", "-", "rd", "-", "01"),
        _join("win7", "-64-", "alice"),
        _join("172", ".", "16", ".", "5", ".", "50"),
    ]


def _facts_from_triples(triples):
    return [fact for _, fact, reason in triples if fact is not None and reason is None]


def test_run_mftecmd_has_dedicated_evidencedb_compiler_mapping():
    from sift_sentinel.analysis import evidence_db

    compilers = getattr(evidence_db, "_TOOL_COMPILERS")
    assert "run_mftecmd" in compilers
    assert compilers["run_mftecmd"].__name__ == "_c_mftecmd"


def test_run_mftecmd_compiler_emits_fact_from_full_path_shape():
    from sift_sentinel.analysis import evidence_db

    compiler = evidence_db._TOOL_COMPILERS["run_mftecmd"]
    facts = _facts_from_triples(compiler([
        {
            "EntryNumber": "123",
            "SequenceNumber": "4",
            "FileName": "sample.exe",
            "FullPath": r"C:\Temp\sample.exe",
            "LastModified0x10": "2026-01-01T00:00:00Z",
        }
    ]))

    assert facts
    fact = facts[0]
    assert fact["fact_type"] == "filesystem_timeline_fact"
    assert fact["source_tool"] == "run_mftecmd"
    assert fact["path_kind"] == "path"
    assert fact["artifact"] == fact["path"]
    assert fact["artifact_locator"].startswith("mftecmd:")
    assert "sample.exe" in fact["path"]


def test_run_mftecmd_compiler_emits_locator_when_full_path_missing():
    from sift_sentinel.analysis import evidence_db

    compiler = evidence_db._TOOL_COMPILERS["run_mftecmd"]
    facts = _facts_from_triples(compiler([
        {
            "EntryNumber": "987",
            "SequenceNumber": "2",
            "Name": "name-only.dll",
        }
    ]))

    assert facts
    fact = facts[0]
    assert fact["fact_type"] == "filesystem_timeline_fact"
    assert fact["path_kind"] in {"name_only", "row_locator"}
    assert fact["artifact"]
    assert fact["artifact_locator"].startswith("mftecmd:")


def test_run_mftecmd_compiler_reports_drop_reason_for_unusable_record():
    from sift_sentinel.analysis import evidence_db

    compiler = evidence_db._TOOL_COMPILERS["run_mftecmd"]
    triples = list(compiler([123]))
    assert triples == [(0, None, "non_dict_record")]


def test_run_mftecmd_build_typed_evidence_db_accepts_synthetic_record():
    from sift_sentinel.analysis.evidence_db import build_typed_evidence_db

    db = build_typed_evidence_db({
        "run_mftecmd": {
            "records": [
                {
                    "EntryNumber": "42",
                    "SequenceNumber": "9",
                    "ParentPath": ".",
                    "FileName": "dynamic-test.bin",
                    "LastModified0x10": "2026-01-01T00:00:00Z",
                }
            ],
            "record_count": 1,
        }
    })

    per = db["coverage"]["per_tool"]["run_mftecmd"]
    assert per["record_count"] == 1
    assert per["attributed_fact_count"] >= 1
    assert per["dropped_record_count"] == 0
    assert db["coverage"]["totals"]["fact_type_counts"]["filesystem_timeline_fact"] >= 1


def test_run_mftecmd_mapping_neighborhood_has_no_case_specific_terms():
    text = Path("src/sift_sentinel/analysis/evidence_db.py").read_text().lower()
    idx = text.index("run_mftecmd")
    nearby = text[max(0, idx - 1000): idx + 1200]
    for bad in _forbidden_terms():
        assert bad.lower() not in nearby


def test_test_file_itself_does_not_embed_case_literals_contiguously():
    text = Path(__file__).read_text().lower()
    for bad in _forbidden_terms():
        assert bad.lower() not in text
