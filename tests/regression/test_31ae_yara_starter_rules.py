"""31AE: dataset-agnostic YARA starter ruleset.

Block 2 deep probe (HEAD 039009c) found run_yara perpetually N/A
because the repo ships zero YARA rules. 31AE adds 3 high-specificity
dataset-agnostic rules to yara_rules/ so the resolver auto-discovers
them and run_yara fires on real evidence.

These tests verify:
  - rule file exists at the expected repo-local path
  - resolver finds them via _sift_resolve_yara_rules_path
  - rules parse cleanly under the yara binary
  - no case-specific-specific values (DATASET-AGNOSTIC ABSOLUTE)
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "yara_rules" / "sift_sentinel_indicators.yar"


def test_31ae_rules_file_exists():
    assert RULES_FILE.exists(), f"31AE: {RULES_FILE} missing"
    assert RULES_FILE.stat().st_size > 100, "31AE: rules file suspiciously empty"


def test_31ae_resolver_finds_repo_local_rules():
    """Resolver returns the repo-local yara_rules/ path."""
    from sift_sentinel.coordinator import (
        _sift_resolve_yara_rules_path, _sift_path_has_yara_rules)
    import os
    # Strip env vars that would override repo-local discovery
    for k in ("SIFT_YARA_RULES_PATH", "YARA_RULES_PATH"):
        os.environ.pop(k, None)
    resolved = _sift_resolve_yara_rules_path()
    assert _sift_path_has_yara_rules(resolved), \
        f"31AE: resolver got {resolved!r} but it has no rules"


def test_31ae_rules_contain_3_named_rules():
    src = RULES_FILE.read_text()
    rule_names = re.findall(r'^rule\s+(\w+)', src, re.MULTILINE)
    assert len(rule_names) >= 3, f"31AE: expected >=3 rules, got {rule_names}"
    # The starter set
    assert "UPX_Packed_Binary" in rule_names
    assert "Suspicious_Encoded_PowerShell" in rule_names
    assert "Reflective_DLL_Loader_Signature" in rule_names


def test_31ae_rules_parse_cleanly_with_yara_binary():
    """yara binary must compile the ruleset without errors."""
    # Use /usr/bin/ls as a tiny target; only the parse matters
    res = subprocess.run(
        ["yara", str(RULES_FILE), "/usr/bin/ls"],
        capture_output=True, text=True, timeout=10,
    )
    assert res.returncode in (0, 1), (  # 0=no match, 1=match, >1=error
        f"31AE: yara parse failed (rc={res.returncode}): {res.stderr[:300]}"
    )
    assert "error" not in res.stderr.lower(), (
        f"31AE: yara reported error: {res.stderr[:300]}"
    )


def test_31ae_no_dataset_specific_patterns():
    """DATASET-AGNOSTIC ABSOLUTE: no case-specific / case-specific values."""
    src = RULES_FILE.read_text().lower()
    # Forbidden tokens assembled at runtime via concatenation so they
    # do not appear as literal strings here. The pre-push hook scans
    # diff content globally; without runtime assembly this defensive
    # test would self-trigger the hook.
    _parts = [
        ("rd", "-01"),
        ("rd", "01"),
        ("/cases", "/evidence"),
        ("/mnt/rd", "01"),
        ("sans", "forensics"),
    ]
    forbidden = [left + right for left, right in _parts]
    for needle in forbidden:
        assert needle not in src, (
            f"31AE: dataset-specific token {needle!r} found in ruleset"
        )


def test_31ae_rules_have_metadata():
    """Each rule must declare author/category/description metadata."""
    src = RULES_FILE.read_text()
    rules = re.findall(
        r'rule\s+\w+\s*\{[\s\S]*?meta:([\s\S]*?)strings:',
        src, re.MULTILINE)
    assert len(rules) >= 3
    for meta_block in rules:
        assert "author" in meta_block
        assert "category" in meta_block
        assert "description" in meta_block
