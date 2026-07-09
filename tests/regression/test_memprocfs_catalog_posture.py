from __future__ import annotations

import importlib
import re

import sift_sentinel.coordinator as c
import sift_sentinel.tool_semantics as ts


def _render_catalog() -> str:
    ts_mod = importlib.reload(ts)
    c_mod = importlib.reload(c)
    return ts_mod.format_grouped_inv1_tool_catalog(c_mod._TOOL_REGISTRY, c_mod.get_capability)


def _section_lines(catalog: str, header: str) -> list[str]:
    lines = catalog.splitlines()
    try:
        start = lines.index(header)
    except ValueError:
        return []
    out: list[str] = []
    for line in lines[start + 1:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("-"):
            break
        out.append(line)
    return out


def test_memprocfs_semantics_are_memory_specific_and_rich() -> None:
    ts_mod = importlib.reload(ts)

    sem = ts_mod.get_tool_semantics(
        "run_memprocfs",
        c._TOOL_REGISTRY["run_memprocfs"],
        c.get_capability("run_memprocfs"),
    )

    assert sem["evidence_domains"] == ("memory",)
    assert sem["buckets"] == ("memprocfs",)
    assert sem["cost"] == "medium"
    assert "forensic tool" not in sem["notes"].lower()

    detects = set(sem["detects"])
    required = {
        "findevil_indicators",
        "memory_process_baseline",
        "memory_service_baseline",
        "memory_network_state",
        "memory_dns_resolution",
        "memory_persistence",
        "memory_execution_history",
        "memory_module_anomalies",
        "memory_timeline_process",
        "memory_timeline_task",
    }
    assert required <= detects


def test_memprocfs_catalog_section_is_elevated_out_of_generic() -> None:
    catalog = _render_catalog()

    assert "MEMPROCFS / FINDEVIL MEMORY TRIAGE" in catalog
    mem_lines = _section_lines(catalog, "MEMPROCFS / FINDEVIL MEMORY TRIAGE")
    generic_lines = _section_lines(catalog, "GENERIC / UNCATEGORIZED")

    assert any("run_memprocfs" in line for line in mem_lines)
    assert not any("run_memprocfs" in line for line in generic_lines)


def test_memprocfs_catalog_line_contains_fact_families_and_medium_cost() -> None:
    catalog = _render_catalog()
    line = next(line for line in catalog.splitlines() if line.startswith("- run_memprocfs "))

    lower = line.lower()
    for term in (
        "findevil",
        "process baseline",
        "service baseline",
        "network state",
        "dns resolution",
        "persistence",
        "execution history",
        "module anomalies",
        "timeline process",
        "timeline task",
        "10 fact families",
    ):
        assert term in lower

    assert "cost=medium" in line
    assert "cost=high" not in line
    assert "yields findevil indicators |" not in lower


def test_memprocfs_catalog_position_is_near_memory_tools() -> None:
    catalog = _render_catalog()

    mem_pos = catalog.index("run_memprocfs")
    malfind_pos = catalog.index("vol_malfind")
    generic_pos = catalog.index("GENERIC / UNCATEGORIZED")

    assert mem_pos < generic_pos
    assert mem_pos < catalog.index("run_yara")
    assert mem_pos < len(catalog) // 2
    assert abs(mem_pos - malfind_pos) < 5000


def test_catalog_still_advertises_only_registered_tools() -> None:
    catalog = _render_catalog()
    advertised = set(re.findall(r"(?m)^- (\S+) - .*\| platform=", catalog))

    assert advertised
    assert advertised <= set(c._TOOL_REGISTRY)
    assert "run_memprocfs" in advertised
