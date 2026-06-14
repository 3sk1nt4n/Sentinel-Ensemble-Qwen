"""C31 V3 side-test: real pipeline data - Inv2 claim provenance.

Property-based per slot 28. Loads v2 findings from disk, synthesizes
pre-attachment Inv2 output by stripping claim source_tools, runs
_attach_inv2_claim_source_tools, asserts invariants on real data.
Does NOT rerun full pipeline.

Skipif pattern protects against /tmp ephemerality: if v2 state dir
is cleared, tests skip gracefully rather than fail.
"""
from __future__ import annotations

import json
import os

import pytest


V2_STATE_DIR = os.environ.get("SIFT_TEST_STATE_DIR", "")
V2_FINDINGS = os.path.join(V2_STATE_DIR, "findings_final.json")
pytestmark = pytest.mark.skipif(not V2_STATE_DIR, reason="requires SIFT_TEST_STATE_DIR for optional real-state replay")


@pytest.mark.skipif(
    not os.path.exists(V2_FINDINGS),
    reason="v2 state dir not present (ephemeral /tmp)",
)
def test_attachment_populates_claim_source_tools_on_real_findings():
    """Property: after attachment, every claim has non-None source_tools."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    with open(V2_FINDINGS) as f:
        findings = json.load(f)
    for finding in findings:
        for claim in (finding.get("claims") or []):
            if isinstance(claim, dict):
                claim.pop("source_tools", None)
    result = _attach_inv2_claim_source_tools(findings)
    claims_checked = 0
    for finding in result:
        for claim in (finding.get("claims") or []):
            if not isinstance(claim, dict):
                continue
            claims_checked += 1
            st = claim.get("source_tools")
            assert st is not None, (
                f"claim in {finding.get('finding_id')} has None source_tools"
            )
            assert isinstance(st, list), (
                f"source_tools not list: {type(st).__name__}"
            )
    assert claims_checked > 0, "no claims found in real v2 findings"


@pytest.mark.skipif(
    not os.path.exists(V2_FINDINGS),
    reason="v2 state dir not present",
)
def test_attachment_mirrors_finding_source_tools_on_real_data():
    """Property: stripped claims inherit finding-level source_tools."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    with open(V2_FINDINGS) as f:
        findings = json.load(f)
    for finding in findings:
        for claim in (finding.get("claims") or []):
            if isinstance(claim, dict):
                claim.pop("source_tools", None)
    result = _attach_inv2_claim_source_tools(findings)
    for finding in result:
        finding_tools = finding.get("source_tools") or []
        for claim in (finding.get("claims") or []):
            if not isinstance(claim, dict):
                continue
            claim_tools = claim.get("source_tools") or []
            assert claim_tools == finding_tools, (
                f"{finding.get('finding_id')}: claim_tools={claim_tools} "
                f"finding_tools={finding_tools}"
            )


@pytest.mark.skipif(
    not os.path.exists(V2_FINDINGS),
    reason="v2 state dir not present",
)
def test_calibrator_extract_claim_tools_nonempty_post_attachment():
    """Property: after attachment, _extract_claim_tools returns non-empty
    list for findings with finding-level source_tools."""
    from sift_sentinel.coordinator import _attach_inv2_claim_source_tools
    from sift_sentinel.analysis.confidence import _extract_claim_tools
    with open(V2_FINDINGS) as f:
        findings = json.load(f)
    for finding in findings:
        for claim in (finding.get("claims") or []):
            if isinstance(claim, dict):
                claim.pop("source_tools", None)
    result = _attach_inv2_claim_source_tools(findings)
    findings_with_tools = 0
    findings_with_claim_tools = 0
    for finding in result:
        if finding.get("source_tools"):
            findings_with_tools += 1
            claim_tools = _extract_claim_tools(finding)
            if claim_tools:
                findings_with_claim_tools += 1
    assert findings_with_tools > 0, "expected v2 findings with source_tools"
    assert findings_with_claim_tools == findings_with_tools, (
        f"claim_tools extraction broken: {findings_with_claim_tools}/"
        f"{findings_with_tools} findings had extractable claim tools"
    )
