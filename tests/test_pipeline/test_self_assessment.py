"""Tests for Step 17: self-assessment scoring from run metrics."""

import ast
import textwrap
import pytest
from pathlib import Path


@pytest.fixture(scope="module")
def generate_fn():
    """Extract generate_self_assessment from run_pipeline.py source
    without executing the top-level pipeline script."""
    src = Path("run_pipeline.py").read_text()
    tree = ast.parse(src)
    # Find the function definition node
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "generate_self_assessment":
            func_src = ast.get_source_segment(src, node)
            break
    else:
        pytest.fail("generate_self_assessment not found in run_pipeline.py")

    # CC#15: self-assessment markdown now renders "Finding N of T" via
    # display_finding_id, so the isolated namespace must carry that helper.
    from sift_sentinel.reporting import display_finding_id
    ns = {
        "Path": Path,
        "__builtins__": __builtins__,
        "display_finding_id": display_finding_id,
    }
    exec(compile(func_src, "run_pipeline.py", "exec"), ns)
    return ns["generate_self_assessment"]


@pytest.fixture
def sample_inputs():
    """Minimal inputs that exercise every scoring branch."""
    summary = {
        "findings_total": 7,
        "findings_passed": 6,
        "findings_blocked": 1,
        "corrections_attempted": 2,
        "corrections_succeeded": 1,
        "elapsed_s": 300.5,
        "token_usage": {"total_input": 50000, "total_output": 10000},
        "token_breakdown": {"inv1": 100, "inv2": 200},
        "disk_integrity": "not_checked (mounted filesystem)",
    }
    findings_final = [
        {"finding_id": f"F{i:03d}", "confidence": c, "artifact": f"proc{i}.exe"}
        for i, c in enumerate(["HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "HIGH"], 1)
    ]
    blocked_list = [{"finding_id": "F007", "reason": "PID not in reference set"}]
    investigation_summaries = [
        {"pid": 1234, "process": "sqlsvc.exe", "turns": 3, "conclusion": "SUSPICIOUS"},
        {"pid": 9004, "process": "cmd.exe", "turns": 3, "conclusion": "BENIGN"},
        {"pid": 9012, "process": "rundll32.exe", "turns": 4, "conclusion": "SUSPICIOUS"},
    ]
    tool_record_counts = {
        "vol_pstree": 45, "vol_psscan": 50, "vol_netscan": 12,
        "vol_malfind": 3, "get_amcache": 635, "parse_prefetch": 42,
        "parse_event_logs": 1200, "extract_mft_timeline": 0,
    }
    report_text = "x" * 8000
    return (summary, findings_final, blocked_list,
            investigation_summaries, tool_record_counts,
            True, report_text)


class TestSelfAssessment:
    """generate_self_assessment must produce a valid report and score."""

    def test_self_assessment_generates(self, generate_fn, sample_inputs, tmp_path, monkeypatch):
        """Returns a path and a positive score."""
        monkeypatch.chdir(tmp_path)
        path, score = generate_fn(*sample_inputs)
        assert Path(path).exists()
        assert score > 0

    def test_self_assessment_has_scores(self, generate_fn, sample_inputs, tmp_path, monkeypatch):
        """Report file contains all criterion headings."""
        monkeypatch.chdir(tmp_path)
        path, _ = generate_fn(*sample_inputs)
        content = Path(path).read_text()
        assert "C1" in content
        assert "C2" in content
        assert "C3" in content
        assert "C4" in content
        assert "C5" in content
        assert "C7" in content
        assert "Overall" in content

    def test_self_assessment_score_range(self, generate_fn, sample_inputs, tmp_path, monkeypatch):
        """Average score must be between 0 and 10 inclusive."""
        monkeypatch.chdir(tmp_path)
        _, score = generate_fn(*sample_inputs)
        assert 0 <= score <= 10

    def test_assessment_has_methodology(self, generate_fn, sample_inputs, tmp_path, monkeypatch):
        """Markdown contains Scoring Methodology section."""
        monkeypatch.chdir(tmp_path)
        path, _ = generate_fn(*sample_inputs)
        content = Path(path).read_text()
        assert "Scoring Methodology" in content

    def test_assessment_has_precision(self, generate_fn, sample_inputs, tmp_path, monkeypatch):
        """Markdown contains Precision label in C2 scoring."""
        monkeypatch.chdir(tmp_path)
        path, _ = generate_fn(*sample_inputs)
        content = Path(path).read_text()
        assert "Precision:" in content

    def test_assessment_has_recall_unknown(self, generate_fn, sample_inputs, tmp_path, monkeypatch):
        """Markdown acknowledges recall cannot be measured."""
        monkeypatch.chdir(tmp_path)
        path, _ = generate_fn(*sample_inputs)
        content = Path(path).read_text()
        assert "CANNOT be measured" in content


class TestRatioScoring:
    """Ratio-based scoring: same pass rate -> same score regardless of count."""

    def _make_inputs(self, total, passed, tools_ok, tools_all, high=0):
        summary = {
            "findings_total": total, "findings_passed": passed,
            "findings_blocked": total - passed,
            "corrections_attempted": 0, "corrections_succeeded": 0,
            "elapsed_s": 60, "token_usage": {"total_input": 1000, "total_output": 500},
            "token_breakdown": {}, "disk_integrity": "verified",
        }
        findings = [
            {"finding_id": f"F{i:03d}",
             "confidence": "HIGH" if i <= high else "MEDIUM",
             "artifact": f"proc{i}.exe"}
            for i in range(1, passed + 1)
        ]
        blocked = [{"finding_id": f"F{i:03d}", "reason": "test"}
                   for i in range(passed + 1, total + 1)]
        counts = {f"tool_{i}": (1 if i <= tools_ok else 0)
                  for i in range(1, tools_all + 1)}
        return (summary, findings, blocked, [], counts, False, "short")

    def test_ratio_score_full_pass(self, generate_fn, tmp_path, monkeypatch):
        """5/5 verified -> same C2 as 7/7 (both 100% precision)."""
        monkeypatch.chdir(tmp_path)
        _, score_5 = generate_fn(*self._make_inputs(5, 5, 3, 5))
        _, score_7 = generate_fn(*self._make_inputs(7, 7, 3, 5))
        assert abs(score_5 - score_7) < 0.01

    def test_ratio_score_partial(self, generate_fn, tmp_path, monkeypatch):
        """3/5 verified -> lower C2 than 5/5."""
        monkeypatch.chdir(tmp_path)
        _, score_full = generate_fn(*self._make_inputs(5, 5, 3, 5))
        _, score_part = generate_fn(*self._make_inputs(5, 3, 3, 5))
        assert score_part < score_full

    def test_ratio_score_zero(self, generate_fn, tmp_path, monkeypatch):
        """0 findings -> base score only."""
        monkeypatch.chdir(tmp_path)
        _, score = generate_fn(*self._make_inputs(0, 0, 3, 5))
        assert score > 0  # base scores still nonzero
        assert score < 8  # but not inflated

    def test_ratio_c3_coverage(self, generate_fn, tmp_path, monkeypatch):
        """4/6 tools -> proportional C3, less than 6/6."""
        monkeypatch.chdir(tmp_path)
        _, score_4of6 = generate_fn(*self._make_inputs(5, 5, 4, 6))
        _, score_6of6 = generate_fn(*self._make_inputs(5, 5, 6, 6))
        assert score_4of6 < score_6of6
