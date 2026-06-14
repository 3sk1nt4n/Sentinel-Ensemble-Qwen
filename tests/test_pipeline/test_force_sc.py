"""Tests for --strict-validation: stricter corroboration requirements for findings."""

from __future__ import annotations

import copy

import pytest

from sift_sentinel.validation.reference_set import build_reference_set
from sift_sentinel.validation.validator import validate_finding
from sift_sentinel.coordinator import step_10_validate, step_12_self_correct


# ── Helpers ──────────────────────────────────────────────────────────────


def _sample_tool_outputs():
    """Minimal tool outputs with flat pstree for testing.

    _extract_pstree only processes top-level records (not __children),
    so all PIDs must be at the top level to appear in the reference set.
    The real pipeline gets child PIDs via netscan/malfind/cmdline.
    """
    return {
        "vol_pstree": {
            "output": [
                {"PID": 4, "ImageFileName": "System",
                 "CreateTime": "2018-08-30T13:51:58+00:00", "__children": []},
                {"PID": 9001, "ImageFileName": "sample_payload.exe",
                 "CreateTime": "2018-08-30T22:15:18+00:00", "__children": []},
                {"PID": 9002, "ImageFileName": "powershell.exe",
                 "CreateTime": "2018-08-30T16:43:36+00:00", "__children": []},
                {"PID": 9003, "ImageFileName": "powershell.exe",
                 "CreateTime": "2018-08-30T16:43:36+00:00", "__children": []},
                {"PID": 6768, "ImageFileName": "rundll32.exe",
                 "CreateTime": "2018-08-30T18:31:04+00:00", "__children": []},
                {"PID": 5452, "ImageFileName": "rundll32.exe",
                 "CreateTime": "2018-08-30T21:40:18+00:00", "__children": []},
                {"PID": 9999, "ImageFileName": "notepad.exe",
                 "CreateTime": "2018-08-30T22:00:00+00:00", "__children": []},
            ],
            "record_count": 7,
        },
    }


# ── Test classes ─────────────────────────────────────────────────────────


class TestStrictValidationSingleClaimFails:
    """Strict validation: 1 MATCH claim -> MISMATCH."""

    def test_single_pid_claim_blocked(self):
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_STRICT",
            "artifact": "sample_payload.exe single source",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MISMATCH"
        assert "Strict validation" in result["detail"]
        assert "1 corroborating claim" in result["detail"]
        assert "requires 3+" in result["detail"]

    def test_single_hash_claim_blocked(self):
        outputs = _sample_tool_outputs()
        outputs["get_amcache"] = {
            "output": [
                {"sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "path": r"C:\Windows\Temp\sample_payload.exe"},
            ],
        }
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_HASH",
            "artifact": "hash only",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "sample_payload.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MISMATCH"
        assert "Strict validation" in result["detail"]


class TestStrictValidationThreeClaimsPasses:
    """Strict validation: 3+ MATCH claims -> MATCH."""

    def test_three_pid_claims_pass(self):
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_MULTI",
            "artifact": "corroborated finding",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                {"type": "pid", "pid": 9002, "process": "powershell.exe"},
                {"type": "pid", "pid": 9003, "process": "powershell.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MATCH"

    def test_pid_plus_hash_plus_pid_pass(self):
        outputs = _sample_tool_outputs()
        outputs["get_amcache"] = {
            "output": [
                {"sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "path": r"C:\Windows\Temp\sample_payload.exe"},
            ],
        }
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_CROSS",
            "artifact": "cross-source corroboration",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "sample_payload.exe"},
                {"type": "pid", "pid": 9002, "process": "powershell.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MATCH"


class TestStrictValidationOffSinglePasses:
    """Default (strict=False): 1 MATCH claim -> MATCH as before."""

    def test_single_claim_passes_without_strict(self):
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_NORMAL",
            "artifact": "single source ok",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
            ],
        }
        result = validate_finding(finding, ref_set)
        assert result["status"] == "MATCH"

    def test_explicit_false_same_as_default(self):
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_EXPLICIT",
            "artifact": "explicit false",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=False)
        assert result["status"] == "MATCH"


class TestStrictValidationSCPrompt:
    """Verify SC prompt includes corroboration guidance when strict."""

    def test_sc_prompt_includes_guidance(self, tmp_path):
        """When strict_validation triggers SC, error message has guidance."""
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_SC_STRICT",
            "artifact": "weak finding",
            "confidence_level": "MEDIUM",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
            ],
        }
        # Validate with strict -> MISMATCH
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MISMATCH"
        error = result["detail"]

        # Track what error the corrector receives
        received_errors = []

        def corrector(raw_data, err):
            received_errors.append(err)
            # Add claims to pass strict validation (3+ required)
            return {
                "finding_id": "F_SC_STRICT",
                "artifact": "strengthened finding",
                "confidence_level": "MEDIUM",
                "claims": [
                    {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                    {"type": "pid", "pid": 9002, "process": "powershell.exe"},
                    {"type": "pid", "pid": 9003, "process": "powershell.exe"},
                ],
            }

        results = step_12_self_correct(
            [(finding, error)], outputs, ref_set, tmp_path, corrector,
            strict_validation=True,
        )
        assert len(results) == 1
        # Corrector received enriched error with guidance
        assert len(received_errors) >= 1
        assert "fewer than 3" in received_errors[0]
        assert "additional tools" in received_errors[0]


class TestNoPidCorruptionCodeExists:
    """Verify no PID corruption code remains in the codebase."""

    def test_no_10000_shift_in_source(self):
        """PID corruption guard: no code may add/subtract 10000 from PID values.
    
        Legitimate 10000 constants exist for token budgets, record caps, and
        numeric sanity checks. This test only fails on arithmetic where a PID-like
        expression is shifted by 10000.
        """
        import ast as _ast
        from pathlib import Path as _Path
    
        repo_root = _Path(__file__).resolve().parents[2]
        scan_paths = [repo_root / "run_pipeline.py"]
        scan_paths.extend((repo_root / "src").rglob("*.py"))
    
        def expr_mentions_pid(expr):
            for child in _ast.walk(expr):
                if isinstance(child, _ast.Name) and "pid" in child.id.lower():
                    return True
                if isinstance(child, _ast.Attribute) and "pid" in child.attr.lower():
                    return True
                if isinstance(child, _ast.Constant) and isinstance(child.value, str):
                    if "pid" in child.value.lower():
                        return True
            return False
    
        def is_10000(expr):
            return isinstance(expr, _ast.Constant) and expr.value == 10000
    
        offenders = []
    
        for path in scan_paths:
            source = path.read_text(errors="ignore")
            try:
                module = _ast.parse(source)
            except SyntaxError as exc:
                offenders.append(f"{path.relative_to(repo_root)}: parse error: {exc}")
                continue
    
            for node in _ast.walk(module):
                if isinstance(node, _ast.BinOp) and isinstance(
                    node.op, (_ast.Add, _ast.Sub)
                ):
                    left_pid = expr_mentions_pid(node.left)
                    right_pid = expr_mentions_pid(node.right)
                    left_10000 = is_10000(node.left)
                    right_10000 = is_10000(node.right)
    
                    if (left_pid and right_10000) or (right_pid and left_10000):
                        rel = path.relative_to(repo_root)
                        offenders.append(f"{rel}:{node.lineno} PID arithmetic shift by 10000")
    
                if isinstance(node, _ast.AugAssign) and isinstance(
                    node.op, (_ast.Add, _ast.Sub)
                ):
                    if expr_mentions_pid(node.target) and is_10000(node.value):
                        rel = path.relative_to(repo_root)
                        offenders.append(f"{rel}:{node.lineno} PID augassign shift by 10000")
    
        assert offenders == [], (
            "PID corruption arithmetic still present:\n" + "\n".join(offenders)
        )

    def test_no_force_sc_demo_in_source(self):
        """No force_sc_demo / force-sc-demo references in source.

        Worktree-relative scan via pure Python re (no subprocess, no
        hardcoded main-repo path). Matches function names, CLI flags,
        and string-literal references with one pattern.
        """
        import re
        from pathlib import Path as _Path

        repo_root = _Path(__file__).resolve().parents[2]
        scan_paths = [repo_root / "run_pipeline.py"]
        scan_paths.extend((repo_root / "src").rglob("*.py"))

        pattern = re.compile(r"force[._-]sc[._-]demo")
        offenders = []
        for path in scan_paths:
            try:
                source = path.read_text(errors="ignore")
            except Exception:
                continue
            for ln, line in enumerate(source.splitlines(), 1):
                if pattern.search(line):
                    offenders.append(
                        f"{path.relative_to(repo_root)}:{ln}: {line.strip()}"
                    )

        assert offenders == [], (
            "force_sc_demo references still present:\n" + "\n".join(offenders)
        )


class TestStrictValidationStep10Integration:
    """Integration: step_10_validate with strict_validation."""

    def test_step10_strict_blocks_single_claim(self):
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        findings = [
            {
                "finding_id": "F_SINGLE",
                "artifact": "one claim",
                "claims": [
                    {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                ],
            },
        ]
        passed, blocked = step_10_validate(
            findings, ref_set, strict_validation=True,
        )
        assert len(passed) == 0
        assert len(blocked) == 1
        assert "Strict validation" in blocked[0][1]

    def test_step10_strict_passes_three_claims(self):
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        findings = [
            {
                "finding_id": "F_MULTI",
                "artifact": "three claims",
                "claims": [
                    {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                    {"type": "pid", "pid": 9002, "process": "powershell.exe"},
                    {"type": "pid", "pid": 9003, "process": "powershell.exe"},
                ],
            },
        ]
        passed, blocked = step_10_validate(
            findings, ref_set, strict_validation=True,
        )
        assert len(passed) == 1
        assert len(blocked) == 0

    def test_step10_default_passes_single_claim(self):
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        findings = [
            {
                "finding_id": "F_DEFAULT",
                "artifact": "one claim default",
                "claims": [
                    {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                ],
            },
        ]
        passed, blocked = step_10_validate(findings, ref_set)
        assert len(passed) == 1
        assert len(blocked) == 0


class TestStrictMode3PlusThreshold:
    """Strict mode requires 3+ claims (raised from 2+)."""

    def test_strict_mode_3_claims_pass(self):
        """Finding with 3 claims passes strict validation."""
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_3PASS",
            "artifact": "three sources",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                {"type": "pid", "pid": 9002, "process": "powershell.exe"},
                {"type": "pid", "pid": 6768, "process": "rundll32.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MATCH"

    def test_strict_mode_2_claims_fail(self):
        """Finding with 2 claims fails strict validation."""
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_2FAIL",
            "artifact": "two sources insufficient",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                {"type": "pid", "pid": 9002, "process": "powershell.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MISMATCH"
        assert "Strict" in result["detail"]
        assert "2 corroborating claims" in result["detail"]
        assert "requires 3+" in result["detail"]

    def test_strict_mode_1_claim_fail(self):
        """Finding with 1 claim fails strict validation."""
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_1FAIL",
            "artifact": "single source",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=True)
        assert result["status"] == "MISMATCH"
        assert "1 corroborating claim" in result["detail"]
        assert "requires 3+" in result["detail"]

    def test_normal_mode_2_claims_pass(self):
        """Finding with 2 claims passes default (non-strict) validation."""
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        finding = {
            "finding_id": "F_2NORM",
            "artifact": "two sources default",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                {"type": "pid", "pid": 9002, "process": "powershell.exe"},
            ],
        }
        result = validate_finding(finding, ref_set, strict_validation=False)
        assert result["status"] == "MATCH"

    def test_strict_flag_sets_threshold(self):
        """--strict-validation sets min_claims=3 (2 claims blocked)."""
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        # 2 claims: passes default, fails strict
        finding = {
            "finding_id": "F_THRESH",
            "artifact": "threshold test",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
                {"type": "pid", "pid": 9002, "process": "powershell.exe"},
            ],
        }
        default = validate_finding(finding, ref_set, strict_validation=False)
        strict = validate_finding(finding, ref_set, strict_validation=True)
        assert default["status"] == "MATCH"
        assert strict["status"] == "MISMATCH"


class TestSCOllamaOverhead:
    """Ollama mode: reduced SC delay and limited blocked count."""

    def test_sc_delay_ollama(self, tmp_path):
        """inter_finding_delay and inter_attempt_delay are passed through."""
        from unittest.mock import patch
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        blocked = [
            ({"finding_id": "F1", "claims": [{"type": "pid", "pid": 1}]}, "err1"),
            ({"finding_id": "F2", "claims": [{"type": "pid", "pid": 2}]}, "err2"),
        ]

        def noop_corrector(raw_data, err):
            return None

        with patch(
            "sift_sentinel.correction.self_correct.time.sleep",
        ) as mock_sc_sleep, patch(
            "sift_sentinel.coordinator.time.sleep",
        ) as mock_coord_sleep:
            results = step_12_self_correct(
                blocked, outputs, ref_set, tmp_path, noop_corrector,
                inter_finding_delay=5.0,
                inter_attempt_delay=5.0,
            )
        assert len(results) == 2
        # Between-finding sleep uses 5, not 30
        if mock_coord_sleep.call_count > 0:
            for call in mock_coord_sleep.call_args_list:
                assert call[0][0] == 5.0
        # No 30s sleeps anywhere
        for call in mock_sc_sleep.call_args_list:
            assert call[0][0] != 30.0

    def test_sc_limit_ollama(self, tmp_path):
        """Slicing blocked[:2] limits corrections to 2 findings."""
        from unittest.mock import patch
        outputs = _sample_tool_outputs()
        ref_set = build_reference_set(outputs)
        blocked_5 = [
            ({"finding_id": f"F{i}", "claims": []}, f"err{i}")
            for i in range(5)
        ]
        limited = blocked_5[:2]

        def noop_corrector(raw_data, err):
            return None

        with patch("sift_sentinel.correction.self_correct.time.sleep"):
            results = step_12_self_correct(
                limited, outputs, ref_set, tmp_path, noop_corrector,
                inter_finding_delay=0,
                inter_attempt_delay=0,
            )
        assert len(results) == 2
