"""
SIFT Sentinel -- B5 confidence records-gate tests.

Unit-tests calibrate_confidence with tool_records kwarg. Validates
that tools in source_tools but with 0 records (or absent from the
tool_records dict entirely) do not contribute to artifact-type
counting or cross-domain upgrade. No pipeline invocation; no
_ToolHealth mocking.
"""

from __future__ import annotations

from sift_sentinel.analysis.confidence import calibrate_confidence


def test_b5_records_gt_zero_allows_high():
    """Tool has records: cross-domain (memory + disk) upgrade fires."""
    finding = {
        "finding_id": "F001",
        "source_tools": ["vol_pstree", "get_amcache"],
        "confidence_level": "MEDIUM",
        "claims": [
            {"type": "pid", "value": 2396, "source_tools": ["vol_pstree"]},
            {"type": "hash", "value": "abc", "source_tools": ["get_amcache"]},
        ],
    }
    tool_records = {"vol_pstree": 138, "get_amcache": 42}

    result = calibrate_confidence(
        finding, ssdt_trust="full", tool_records=tool_records,
    )

    assert result == "HIGH", (
        "B5: both tools have records>0; cross-domain upgrade should fire"
    )


def test_b5_records_eq_zero_blocks_high():
    """Tool cited in source_tools but returned 0 records: NO upgrade."""
    finding = {
        "finding_id": "F008",
        "source_tools": ["vol_pstree", "get_amcache"],
        "confidence_level": "MEDIUM",
        "claims": [
            {"type": "pid", "value": 2396, "source_tools": ["vol_pstree"]},
        ],
    }
    tool_records = {"vol_pstree": 138, "get_amcache": 0}

    result = calibrate_confidence(
        finding, ssdt_trust="full", tool_records=tool_records,
    )

    assert result != "HIGH", (
        "B5: get_amcache returned 0 records; should not count as disk "
        "corroboration"
    )


def test_b5_no_tool_records_preserves_legacy():
    """When tool_records is not passed, behavior matches pre-fix."""
    finding = {
        "finding_id": "F001",
        "source_tools": ["vol_pstree", "get_amcache"],
        "confidence_level": "MEDIUM",
        "claims": [
            {"type": "pid", "value": 2396, "source_tools": ["vol_pstree"]},
            {"type": "hash", "value": "abc", "source_tools": ["get_amcache"]},
        ],
    }

    result = calibrate_confidence(finding, ssdt_trust="full")

    assert result == "HIGH", (
        "Legacy cross-domain upgrade preserved when tool_records is None"
    )


def test_b5_tool_not_in_records_dict_treated_as_zero():
    """Tool cited in source_tools but absent from tool_records dict should
    be filtered (treated as zero records). This can happen if ReAct
    invoked a tool after the initial collection snapshot at line 1324 --
    can't claim corroboration from an unmeasured tool. Default 0 on
    missing key is the ZEROFAKE-honest choice: unverifiable = phantom,
    not permissive-count."""
    finding = {
        "finding_id": "F010",
        "source_tools": ["vol_pstree", "parse_event_logs"],
        "confidence_level": "MEDIUM",
        "claims": [
            {"type": "pid", "value": 2396, "source_tools": ["vol_pstree"]},
        ],
    }
    # parse_event_logs absent from tool_records -- treated as 0 records
    tool_records = {"vol_pstree": 138}

    result = calibrate_confidence(
        finding, ssdt_trust="full", tool_records=tool_records,
    )

    assert result != "HIGH", (
        "B5: parse_event_logs not in tool_records dict; should not count "
        "as event-log corroboration for cross-domain upgrade"
    )
