"""Mechanical enforcement of dataset-agnostic + finding-agnostic contract.

Runs on every pytest execution. Cannot be silently disabled without
modifying this file (which is visible in git history).

Source tree under src/ is scanned. Tests and fixtures are exempt by design.
Lines with AGNOSTIC-OK or EXAMPLE-ONLY pragma are skipped.
"""
from __future__ import annotations

import pathlib
import re

SRC_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src"


# Tokens that should NEVER appear in source - specific datasets/scenarios.
FORBIDDEN_DATASET: list[str] = [
    "CRIMSON", "OSPREY", "Stark Research", "wkstn-01",
    "BASE" "-RD" "-01", "BASE" "-RD" "-02",
]

# Specific malware families / actor groups - AI may output these,
# code/prompts must not prime AI toward them.
FORBIDDEN_ATTRIBUTION: list[str] = [
    "Cobalt Strike",
    "APT28", "APT29", "Fancy Bear", "Cozy Bear",
    "Lazarus", "FIN7", "Conti", "Ryuk", "LockBit",
]

# Specific scenario artifacts - may appear in test fixtures, never in src/.
FORBIDDEN_SCENARIO_ARTIFACTS: list[str] = [
    "sample_payload.exe", "examples.ps1.rar", "M&A Targets",
    "198.51.100.129",
    # Real case C2 IP - assembled-octet so source stays clean
    "165" "." "227" "." "50" "." "129",
]


def _scan_src(tokens: list[str]) -> list[tuple[str, int, str, str]]:
    """Scan src/ for forbidden tokens using word-boundary regex.

    Uses re.escape() + \\b word boundaries to avoid false positives where
    a forbidden token appears as a substring inside a legitimate identifier
    (e.g., 'sample_payload.exe' appearing inside 'vmacthlsample_payload.exe' as a substring).
    """
    violations: list[tuple[str, int, str, str]] = []
    # Pre-compile patterns once. \\b word boundary prevents substring matches.
    # For tokens containing dots or special regex chars, re.escape handles them.
    patterns = [(token, re.compile(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])")) for token in tokens]
    for py_file in SRC_ROOT.rglob("*.py"):
        try:
            text = py_file.read_text(errors="ignore")
        except OSError:
            continue
        for line_num, line in enumerate(text.splitlines(), 1):
            if "AGNOSTIC-OK" in line or "EXAMPLE-ONLY" in line:
                continue
            for token, pattern in patterns:
                if pattern.search(line):
                    violations.append(
                        (str(py_file.relative_to(SRC_ROOT)), line_num, token, line.strip()[:100])
                    )
    return violations


def test_no_dataset_tokens_in_src() -> None:
    """Source must not hardcode dataset identifiers."""
    violations = _scan_src(FORBIDDEN_DATASET)
    assert not violations, (
        f"Dataset tokens found in src/ ({len(violations)} violations):\n"
        + "\n".join(f"  {v[0]}:{v[1]} - {v[2]!r} in: {v[3]}" for v in violations[:10])
    )


def test_no_attribution_priming_in_src() -> None:
    """Source must not prime AI toward specific malware families or actor groups."""
    violations = _scan_src(FORBIDDEN_ATTRIBUTION)
    assert not violations, (
        f"Attribution priming found in src/ ({len(violations)} violations):\n"
        + "\n".join(f"  {v[0]}:{v[1]} - {v[2]!r} in: {v[3]}" for v in violations[:10])
    )


def test_no_scenario_artifacts_in_src() -> None:
    """Source must not hardcode scenario-specific artifacts."""
    violations = _scan_src(FORBIDDEN_SCENARIO_ARTIFACTS)
    assert not violations, (
        f"Scenario artifacts found in src/ ({len(violations)} violations):\n"
        + "\n".join(f"  {v[0]}:{v[1]} - {v[2]!r} in: {v[3]}" for v in violations[:10])
    )
