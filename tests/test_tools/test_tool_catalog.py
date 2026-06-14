"""Tests for tool catalog: discovery, categories, recommendations."""

import pytest

from sift_sentinel.tools.tool_catalog import (
    TOOL_CATALOG,
    get_categories,
    get_tools_for_category,
    recommend_tools,
)


EXPECTED_CATEGORIES = [
    "process_analysis",
    "malware_detection",
    "network_analysis",
    "persistence",
    "credential_access",
    "filesystem_analysis",
    "registry_analysis",
    "yara_scanning",
]


class TestGetCategories:
    def test_returns_all_8_categories(self):
        cats = get_categories()
        assert set(cats.keys()) == set(EXPECTED_CATEGORIES)
        assert len(cats) == len(EXPECTED_CATEGORIES)

    def test_every_category_has_description(self):
        cats = get_categories()
        for cat, desc in cats.items():
            assert isinstance(desc, str), f"{cat} description is not a string"
            assert len(desc) > 0, f"{cat} has empty description"


class TestGetToolsForCategory:
    def test_process_analysis_returns_tools_and_plugins(self):
        result = get_tools_for_category("process_analysis")
        assert result["category"] == "process_analysis"
        assert "vol_pstree" in result["specific_tools"]
        assert "vol_cmdline" in result["specific_tools"]
        assert len(result["volatility_plugins"]) > 0
        assert result["total_available"] > 0

    def test_unknown_category_returns_error(self):
        result = get_tools_for_category("unknown")
        assert "error" in result
        assert "Unknown category" in result["error"]
        assert "unknown" in result["error"]

    def test_filesystem_has_sleuthkit(self):
        result = get_tools_for_category("filesystem_analysis")
        assert "fls" in result["sleuthkit_commands"]
        assert "icat" in result["sleuthkit_commands"]

    def test_yara_has_disk_tools(self):
        result = get_tools_for_category("yara_scanning")
        assert "yara" in result["disk_tools"]

    def test_total_available_counts_all_types(self):
        result = get_tools_for_category("filesystem_analysis")
        expected = (
            len(result["specific_tools"])
            + len(result["volatility_plugins"])
            + len(result["sleuthkit_commands"])
            + len(result["disk_tools"])
        )
        assert result["total_available"] == expected


class TestRecommendTools:
    def test_suspicious_process_injection_returns_malware(self):
        result = recommend_tools("suspicious process injection")
        assert "recommended_categories" in result
        assert "malware_detection" in result["recommended_categories"]

    def test_network_connections_returns_network(self):
        result = recommend_tools("network connections")
        cats = result["recommended_categories"]
        assert cats[0] == "network_analysis"

    def test_registry_keys_returns_registry(self):
        result = recommend_tools("registry keys")
        cats = result["recommended_categories"]
        assert "registry_analysis" in cats

    def test_gibberish_returns_all_categories(self):
        result = recommend_tools("xyzzy foobar quux")
        assert "recommended" in result
        assert set(result["recommended"]) == set(EXPECTED_CATEGORIES)

    def test_recommendation_includes_tools(self):
        result = recommend_tools("What processes are hiding?")
        assert "tools" in result
        assert len(result["tools"]) > 0


class TestCatalogIntegrity:
    def test_every_category_has_description_in_catalog(self):
        for cat, info in TOOL_CATALOG.items():
            assert "description" in info, f"{cat} missing description"
            assert len(info["description"]) > 0, f"{cat} has empty description"

    def test_no_empty_categories(self):
        for cat, info in TOOL_CATALOG.items():
            total = (
                len(info.get("tools", {}))
                + len(info.get("generic_plugins", []))
                + len(info.get("sleuthkit", []))
                + len(info.get("disk_tools", []))
            )
            assert total > 0, f"{cat} has no tools or plugins"
