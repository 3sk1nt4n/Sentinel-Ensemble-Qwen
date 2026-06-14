import json
from pathlib import Path

from sift_sentinel.analysis.evidencedb_family_index import index_evidencedb_families


def test_evidencedb_family_index_handles_nested_and_dedupes_ids(tmp_path):
    p = tmp_path / "evidence_db.json"
    fact = {
        "fact_id": "fact-1",
        "fact_type": "network_connection_fact",
        "source_tool": "vol_netscan",
    }
    p.write_text(json.dumps({
        "typed_facts": [fact],
        "by_family": {"network_connection_fact": [fact]},
        "nested": {"records": [fact]},
    }))

    idx = index_evidencedb_families(p)
    assert idx["by_tool"]["vol_netscan"]["network_connection_fact"] == 1
    assert idx["by_family"]["network_connection_fact"] == 1
