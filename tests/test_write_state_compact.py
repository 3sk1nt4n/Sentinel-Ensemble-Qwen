"""write_state(compact=True) writes minified JSON for huge artifacts.

Live regression: Step 7 wrote a multi-hundred-MB evidence_db.json with
indent=2 -- pretty-printing inflates the file ~40% and slows json.dump
substantially at that scale. Small state files stay pretty (default
unchanged); the EvidenceDB call site opts into compact separators.
Universal: formatting only, identical data.
"""
import json
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.coordinator import write_state, read_state  # noqa: E402


def test_default_stays_pretty(tmp_path):
    write_state(tmp_path, "x.json", {"a": [1, 2]})
    text = (tmp_path / "x.json").read_text()
    assert "\n" in text                      # indented (legacy default)
    assert read_state(tmp_path, "x.json") == {"a": [1, 2]}


def test_compact_is_minified_and_roundtrips(tmp_path):
    data = {"typed_facts": {"f": [{"fact_id": "f-1", "n": i} for i in range(50)]}}
    write_state(tmp_path, "db.json", data, compact=True)
    text = (tmp_path / "db.json").read_text()
    assert "\n  " not in text                # no indent
    assert ", " not in text                  # compact separators
    assert read_state(tmp_path, "db.json") == data


def test_compact_smaller_than_pretty(tmp_path):
    data = {"k": [{"a": i, "b": str(i)} for i in range(2000)]}
    write_state(tmp_path, "p.json", data)
    write_state(tmp_path, "c.json", data, compact=True)
    assert (tmp_path / "c.json").stat().st_size < (tmp_path / "p.json").stat().st_size


def test_string_payload_unchanged(tmp_path):
    write_state(tmp_path, "s.txt", "raw text", compact=True)
    assert (tmp_path / "s.txt").read_text() == "raw text"
