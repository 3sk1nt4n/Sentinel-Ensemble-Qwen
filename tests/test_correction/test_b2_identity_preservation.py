"""
Sentinel Qwen Ensemble - B2 identity-preservation tests.

Unit-tests _preserve_identity helper directly. No SC invocation, no
ref_set construction, no corrector_fn mocking. Tests only the logic
added by the B2 fix: restoring identity fields from the rejected
original when the corrector's clean-slate dict omits them.
"""

from __future__ import annotations

from sift_sentinel.correction.self_correct import _preserve_identity


def test_b2_preserves_identity_when_corrector_omits():
    """Corrector returns a fresh dict; identity fields restored from original."""
    original = {
        "finding_id": "F001",
        "source_tools": ["vol_pstree", "vol_netscan"],
        "tool_call_ids": ["call_abc", "call_def"],
        "raw_excerpt": "process tree showing cmd.exe spawn",
        "claims": [{"type": "hash", "value": "old_bad"}],
    }
    candidate = {
        "claims": [
            {"type": "pid", "value": 9001, "source_tools": ["vol_pstree"]},
            {"type": "pid", "value": 8261, "source_tools": ["vol_netscan"]},
        ],
    }

    result = _preserve_identity(candidate, original)

    assert result["finding_id"] == "F001"
    assert result["source_tools"] == ["vol_pstree", "vol_netscan"]
    assert result["tool_call_ids"] == ["call_abc", "call_def"]
    assert result["raw_excerpt"] == "process tree showing cmd.exe spawn"
    assert len(result["claims"]) == 2
    assert result["claims"][0]["value"] == 9001


def test_b2_does_not_overwrite_corrector_emitted_fields():
    """If corrector emits identity field with non-empty value, respect it."""
    original = {
        "finding_id": "F001",
        "source_tools": ["vol_pstree"],
        "claims": [],
    }
    candidate = {
        "finding_id": "F999",
        "source_tools": ["vol_netscan"],
        "claims": [],
    }

    result = _preserve_identity(candidate, original)

    assert result["finding_id"] == "F999"
    assert result["source_tools"] == ["vol_netscan"]


def test_b2_does_not_fabricate_missing_originals():
    """If a field is missing from BOTH, it stays missing."""
    original = {
        "finding_id": "F001",
    }
    candidate = {
        "claims": [{"type": "pid", "value": 1234}],
    }

    result = _preserve_identity(candidate, original)

    assert result["finding_id"] == "F001"
    assert "source_tools" not in result
    assert "tool_call_ids" not in result
    assert "raw_excerpt" not in result


def test_b2_treats_empty_string_as_missing():
    """Empty string triggers restoration from original."""
    original = {"finding_id": "F001", "raw_excerpt": "real content"}
    candidate = {"finding_id": "", "raw_excerpt": "", "claims": []}

    result = _preserve_identity(candidate, original)

    assert result["finding_id"] == "F001"
    assert result["raw_excerpt"] == "real content"


def test_b2_treats_empty_list_as_missing():
    """Empty list triggers restoration from original."""
    original = {
        "finding_id": "F001",
        "source_tools": ["vol_pstree", "vol_netscan"],
    }
    candidate = {
        "finding_id": "F001",
        "source_tools": [],
        "claims": [],
    }

    result = _preserve_identity(candidate, original)

    assert result["source_tools"] == ["vol_pstree", "vol_netscan"]
