"""Tests for Step 18: HTML report with MITRE ATT&CK and confidence."""

import ast
import pytest
from pathlib import Path


@pytest.fixture(scope="module")
def _loaded():
    """Extract functions and constants from run_pipeline.py without
    executing the top-level pipeline script."""
    src = Path("run_pipeline.py").read_text()
    tree = ast.parse(src)

    names = [
        "MITRE_MAP", "CONFIDENCE_EXPLAIN", "ALL_TACTICS",
        "get_mitre_tags", "generate_html_report",
    ]
    # Inject cross-module dependencies that the extracted functions rely on.
    # CC#15 added display_finding_id usage in generate_html_report; the AST
    # exec namespace must carry it explicitly (the import statement at the
    # top of run_pipeline.py is not evaluated here).
    from sift_sentinel.reporting import display_finding_id
    ns = {
        "Path": Path,
        "__builtins__": __builtins__,
        "display_finding_id": display_finding_id,
    }

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef) and node.name in names:
            exec(compile(ast.get_source_segment(src, node), "run_pipeline.py", "exec"), ns)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names:
                    exec(compile(ast.get_source_segment(src, node), "run_pipeline.py", "exec"), ns)

    return ns


@pytest.fixture(scope="module")
def mitre_map(_loaded):
    return _loaded["MITRE_MAP"]


@pytest.fixture(scope="module")
def confidence_explain(_loaded):
    return _loaded["CONFIDENCE_EXPLAIN"]


@pytest.fixture(scope="module")
def get_mitre_tags_fn(_loaded):
    return _loaded["get_mitre_tags"]


@pytest.fixture(scope="module")
def generate_html_fn(_loaded):
    return _loaded["generate_html_report"]


@pytest.fixture
def sample_html_inputs():
    """Inputs that exercise MITRE matching and confidence display."""
    summary = {
        "findings_total": 5, "findings_passed": 4, "findings_blocked": 1,
        "corrections_attempted": 1, "corrections_succeeded": 0,
        "elapsed_s": 240.0,
        "token_usage": {"total_input": 40000, "total_output": 8000},
        "disk_integrity": "not_checked (mounted filesystem)",
    }
    findings_final = [
        {"finding_id": "F001", "confidence": "HIGH",
         "artifact": "powershell lateral movement", "source_tools": ["vol_pstree", "get_amcache"]},
        {"finding_id": "F002", "confidence": "MEDIUM",
         "artifact": "WMI remote execution", "source_tools": ["vol_netscan"]},
        {"finding_id": "F003", "confidence": "LOW",
         "artifact": "generic process", "source_tools": ["vol_psscan"]},
        {"finding_id": "F004", "confidence": "HIGH",
         "artifact": "netstat recon activity", "source_tools": ["vol_cmdline"]},
    ]
    blocked_list = [{"finding_id": "F005", "reason": "PID not in reference set"}]
    tool_record_counts = {
        "vol_pstree": 45, "vol_psscan": 50, "vol_netscan": 12,
        "get_amcache": 635, "parse_prefetch": 0,
    }
    investigation_summaries = [
        {"pid": 1234, "process": "powershell.exe", "turns": 3},
    ]
    return (summary, findings_final, blocked_list,
            tool_record_counts, 8.5, True, investigation_summaries)


# ── MITRE mapping tests ──────────────────────────────────────────────────


class TestMitreMapping:

    def test_mitre_mapping_powershell(self, get_mitre_tags_fn):
        """'powershell' maps to T1059.001."""
        finding = {"artifact": "powershell.exe spawned by sqlsvc"}
        tags = get_mitre_tags_fn(finding)
        assert any(t["id"] == "T1059.001" for t in tags)

    def test_mitre_mapping_multiple(self, get_mitre_tags_fn):
        """'WMI lateral' maps to 2+ techniques."""
        finding = {"artifact": "WMI lateral movement detected"}
        tags = get_mitre_tags_fn(finding)
        ids = {t["id"] for t in tags}
        assert len(ids) >= 2
        assert "T1047" in ids   # WMI
        assert "T1021" in ids   # lateral

    def test_mitre_no_match(self, get_mitre_tags_fn):
        """'generic process' returns empty list."""
        finding = {"artifact": "generic process"}
        tags = get_mitre_tags_fn(finding)
        assert tags == []


# ── Confidence explanation tests ─────────────────────────────────────────


class TestConfidenceExplain:

    def test_confidence_all_levels(self, confidence_explain):
        """HIGH, MEDIUM, LOW all have explanations."""
        for level in ("HIGH", "MEDIUM", "LOW"):
            assert level in confidence_explain
            ci = confidence_explain[level]
            assert "explain" in ci
            assert "label" in ci
            assert "color" in ci
            assert len(ci["explain"]) > 20


# ── HTML report structure tests ──────────────────────────────────────────


class TestHtmlReport:

    def _gen(self, generate_html_fn, sample_html_inputs, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = generate_html_fn(*sample_html_inputs)
        return Path(path).read_text()

    def test_html_has_mitre_section(self, generate_html_fn, sample_html_inputs,
                                    tmp_path, monkeypatch):
        """Output contains MITRE ATT&CK heading."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "MITRE ATT" in html

    def test_html_has_confidence_explain(self, generate_html_fn, sample_html_inputs,
                                         tmp_path, monkeypatch):
        """Output contains confidence explanation text."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "Why High Confidence" in html

    def test_html_has_recommendations(self, generate_html_fn, sample_html_inputs,
                                      tmp_path, monkeypatch):
        """Output contains recommended actions."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "Recommended Actions" in html

    def test_html_has_executive_summary(self, generate_html_fn, sample_html_inputs,
                                        tmp_path, monkeypatch):
        """Output contains executive summary."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "Executive Summary" in html

    def test_html_has_heatmap(self, generate_html_fn, sample_html_inputs,
                              tmp_path, monkeypatch):
        """Output contains tactic names from the heatmap."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "Execution" in html
        assert "Discovery" in html
        assert "Lateral Movement" in html

    def test_html_valid_structure(self, generate_html_fn, sample_html_inputs,
                                  tmp_path, monkeypatch):
        """Output contains <html> and </html> tags."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "<html" in html
        assert "</html>" in html

    def test_html_has_methodology(self, generate_html_fn, sample_html_inputs,
                                  tmp_path, monkeypatch):
        """Output contains methodology section."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "How We Score" in html

    def test_html_has_can_cannot(self, generate_html_fn, sample_html_inputs,
                                 tmp_path, monkeypatch):
        """Output contains both CAN and CANNOT measure sections."""
        html = self._gen(generate_html_fn, sample_html_inputs, tmp_path, monkeypatch)
        assert "What We CAN Measure" in html
        assert "What We CANNOT Measure" in html
