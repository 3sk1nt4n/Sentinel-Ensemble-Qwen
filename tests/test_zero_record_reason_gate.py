from sift_sentinel.analysis.zero_record_reasons import (
    audit_zero_record_reasons,
    choose_tool_outputs_for_zero_audit,
)


def test_zero_record_gate_reads_real_output_mapping_not_empty_object():
    selected = ["vol_pstree", "parse_prefetch", "run_srumecmd", "vol_userassist"]
    outputs = {
        "vol_pstree": {"record_count": 36, "output": [{"PID": 4}]},
        "parse_prefetch": {
            "record_count": 0,
            "records": [],
            "status": "not_applicable",
            "reason": "Windows/Prefetch directory absent on mount",
        },
        "run_srumecmd": {
            "record_count": 0,
            "records": [],
            "status": "not_applicable",
            "reason": "SRUDB.dat not found under Windows/System32/sru",
        },
        "vol_userassist": {
            "record_count": 0,
            "output": [],
        },
    }

    audit = audit_zero_record_reasons(selected, outputs)

    assert audit["gate"] == "PASS"
    tools = {row["tool"]: row for row in audit["zero_record_tools"]}
    assert "vol_pstree" not in tools
    assert tools["parse_prefetch"]["status"] == "not_applicable"
    assert tools["run_srumecmd"]["status"] == "not_applicable"
    assert tools["vol_userassist"]["status"] == "ok_no_records"
    assert audit["missing_reason_tools"] == []


def test_missing_selected_output_envelope_is_hard_fail():
    audit = audit_zero_record_reasons(
        ["vol_pstree", "vol_cmdline"],
        {"vol_pstree": {"record_count": 1, "output": [{"PID": 1}]}},
    )

    assert audit["gate"] == "FAIL"
    assert audit["missing_reason_tools"]
    assert audit["missing_reason_tools"][0]["tool"] == "vol_cmdline"
    assert audit["missing_reason_tools"][0]["status"] == "missing_output_envelope"


def test_choose_tool_outputs_prefers_mapping_with_selected_envelopes():
    selected = ["vol_pstree", "parse_prefetch"]
    namespace = {
        "wrong_counts": {"vol_pstree": 36, "parse_prefetch": 0},
        "raw_outputs": {
            "vol_pstree": {"record_count": 36, "output": [{"PID": 4}]},
            "parse_prefetch": {
                "record_count": 0,
                "records": [],
                "status": "not_applicable",
                "reason": "Windows/Prefetch directory absent on mount",
            },
        },
    }

    chosen = choose_tool_outputs_for_zero_audit(selected, namespace=namespace)
    audit = audit_zero_record_reasons(selected, chosen)

    assert audit["gate"] == "PASS"
    assert audit["output_source"]["source"] == "namespace:raw_outputs"
    assert [row["tool"] for row in audit["zero_record_tools"]] == ["parse_prefetch"]


def test_tool_prefix_normalization():
    audit = audit_zero_record_reasons(
        ["tool_parse_prefetch"],
        {
            "parse_prefetch": {
                "record_count": 0,
                "records": [],
                "status": "not_applicable",
                "reason": "Prefetch unavailable",
            }
        },
    )
    assert audit["gate"] == "PASS"
    assert audit["zero_record_tools"][0]["tool"] == "parse_prefetch"
