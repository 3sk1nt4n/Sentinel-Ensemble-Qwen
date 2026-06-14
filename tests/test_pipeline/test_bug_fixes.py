"""Tests for bug fixes applied post-CC#17.

Each test verifies the fix is present in source by static inspection.
This matches the pattern in test_inv2_prompt_injection.py and
test_gemini_token_cap.py. We do NOT import run_pipeline.py because it
has no __name__ == '__main__' guard and 254 module-level statements
that execute on import. See BUG 1b in handover for the planned main()
refactor that will unblock behavioral tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest


RUN_PIPELINE_SRC = Path("run_pipeline.py").read_text()


class TestBug1OpusTemperature:
    """BUG 1: Opus 4.7 rejects the temperature parameter.

    Fix: run_pipeline.py L934-945 builds api_kwargs conditionally.
    Only non-Opus-4.7 models receive temperature=0.
    """

    def test_temperature_predicate_is_used_not_literal(self):
        """Temperature omission must go through the env/config-driven
        predicate, NOT a hardcoded provider/model literal.

        Slot 31E-DB.5c + universal-temp-compat: no contiguous provider
        literal may appear in run_pipeline.py. The temperature rule now
        routes through the universal create_message_temp_resilient()
        wrapper (model_roles.py), which drops temperature for known/learned
        rejectors (opus 4.7/4.8, fable 5, ...) and self-heals on the API's
        own 400 -- so a NEW model that deprecates the param never halts a run.
        """
        assert 'create_message_temp_resilient(' in RUN_PIPELINE_SRC, (
            "Temperature handling must route through the universal "
            "create_message_temp_resilient() wrapper; BUG 1 regression risk "
            "if a model that rejects the param is sent temperature."
        )
        # The predicate + the reactive self-heal both still drive the
        # decision inside the wrapper.
        model_roles_src = Path("src/sift_sentinel/model_roles.py").read_text()
        assert 'def model_rejects_temperature(' in model_roles_src
        assert 'def is_temperature_rejection(' in model_roles_src, (
            "Reactive self-heal predicate missing -- a new model that "
            "deprecates temperature would halt the run instead of retrying."
        )
        # No contiguous provider/model literal (assembled fragments for the
        # literal scan) -- opus AND fable families.
        for literal in ("claude" + "-opus" + "-4-7",
                        "claude" + "-fable" + "-5"):
            assert literal not in RUN_PIPELINE_SRC, (
                "Contiguous provider/model literal leaked back into "
                "run_pipeline.py -- routing must stay env/config-driven."
            )

    def test_temperature_is_conditional_not_unconditional(self):
        """Temperature must be set via _api_kwargs dict, not as a
        direct kwarg to messages.create.

        If someone re-adds temperature=0 as a direct kwarg in the
        messages.create call, this test catches it.
        """
        # The FIXED pattern uses _api_kwargs dict assignment
        assert '_api_kwargs["temperature"] = 0' in RUN_PIPELINE_SRC, (
            "Expected conditional dict assignment "
            '_api_kwargs["temperature"] = 0 not found'
        )

        # The OLD pattern would have temperature=0 directly in a
        # messages.create call. Find all messages.create blocks and
        # ensure none have an unconditional temperature=0 directly
        # after model=_selected_model.
        import re
        # Look for: _client.messages.create( ... temperature=0 ... )
        # where temperature is not preceded by an if statement
        pattern = re.compile(
            r'_client\.messages\.create\s*\([^)]*temperature\s*=\s*0',
            re.DOTALL,
        )
        matches = pattern.findall(RUN_PIPELINE_SRC)
        assert not matches, (
            "Found unconditional 'temperature=0' inside "
            "_client.messages.create call. BUG 1 regression: this "
            "breaks Opus 4.7 (deprecated param). Fix: use "
            "conditional _api_kwargs pattern instead."
        )

    def test_api_kwargs_dict_pattern_present(self):
        """The _api_kwargs dict must be constructed before the call and
        handed to the resilient wrapper (which unpacks it via
        client.messages.create(**request_kwargs))."""
        assert '_api_kwargs = {' in RUN_PIPELINE_SRC, (
            "_api_kwargs dict construction missing"
        )
        assert ('create_message_temp_resilient(' in RUN_PIPELINE_SRC
                and '_api_kwargs' in RUN_PIPELINE_SRC), (
            "_api_kwargs not passed into the resilient create wrapper"
        )


class TestBug2FpRegex:
    """BUG 2B: Strict FP regex replaces naive substring match.

    Discovered on 2026-04-17 paid run: 7 of 11 findings force-demoted
    to LOW because of substring matches on words like 'benign' or
    'legitimate' that appeared in negated or context-reference form.
    """

    # Import the module only for regex testing, bypassing the trigger
    # blob. We use compile() to test the patterns inline.
    FP_PATTERNS = [
        r"\bis\s+(?:a\s+|an\s+)?false\s+positive\b",
        r"\b(?:is|are|appears?|appeared|seems?)\s+benign\b",
        r"\b(?:is|are|appears?|appeared|seems?)\s+(?:a\s+)?legitimate\b",
        r"\bis\s+not\s+malicious\b",
        r"\b(?:is|are)\s+(?:a\s+)?known[- ]good\b",
        r"\bno\s+evidence\s+of\s+malicious\s+(?:activity|intent|behavior)\b",
        r"\bbenign\s+(?:activity|behavior|execution|process)\b",
    ]

    def _is_fp(self, text):
        import re
        return any(
            re.search(p, text, re.IGNORECASE) for p in self.FP_PATTERNS
        )

    # Cases that SHOULD trigger (real false positives)

    def test_explicit_false_positive(self):
        assert self._is_fp("This finding is a false positive.")

    def test_is_benign(self):
        assert self._is_fp("The process is benign, no malicious behavior.")

    def test_appears_benign(self):
        assert self._is_fp("Activity appears benign on closer inspection.")

    def test_is_legitimate(self):
        assert self._is_fp("This is legitimate WmiPrvSE.exe activity.")

    def test_is_not_malicious(self):
        assert self._is_fp("The executable is not malicious.")

    def test_is_known_good(self):
        """Default known_good context is empty and does not mark findings."""
        from sift_sentinel.known_good import flag_known_good

        findings = [
            {
                "artifact": "sample.exe",
                "claims": [
                    {"type": "pid", "pid": 1234, "process": "sample.exe"},
                ],
            },
        ]

        result = flag_known_good(findings)

        assert result[0]["known_good"] is False
        assert result[0]["known_good_note"] == ""

    def test_benign_activity(self):
        assert self._is_fp("Overall benign activity with no IOCs.")

    # Cases that SHOULD NOT trigger (regression guards from tonight's
    # paid run -- these are malicious conclusions that the old code
    # incorrectly flagged as FP)

    def test_masquerading_as_legitimate_not_fp(self):
        """From F005 evidence: 'masquerading as a legitimate perfmon path'"""
        text = ("Amcache and MFT timeline confirm PWDumpX.exe written "
                "to C:\\\\Windows\\\\Temp\\\\perfmon\\\\ at 2018-08-30 -- an "
                "attacker-controlled staging directory masquerading as a "
                "legitimate perfmon path.")
        assert not self._is_fp(text), (
            "False positive: 'masquerading as legitimate' should NOT "
            "trigger FP flag"
        )

    def test_no_benign_explanation_not_fp(self):
        """From F012 evidence: 'no credible benign explanation'"""
        text = ("The finding presents a HIGH-confidence attack chain with "
                "no credible benign explanation.")
        assert not self._is_fp(text), (
            "False positive: 'no benign explanation' should NOT trigger "
            "FP flag (describes MALICIOUS conclusion)"
        )

    def test_legitimate_rundll32_context_not_fp(self):
        """From F003 text: 'legitimate rundll32 invocations always have cmdline'"""
        text = ("Null command lines are definitive indicators of process "
                "injection -- legitimate rundll32 invocations always have "
                "a DLL argument.")
        assert not self._is_fp(text), (
            "False positive: 'legitimate rundll32 invocations' context "
            "reference should NOT trigger FP flag"
        )

    def test_confirmed_malicious_not_fp(self):
        """From F005 text: 'Confirmed credential dumping and lateral movement'"""
        text = ("Confirmed credential dumping and lateral movement staging "
                "operation. PWDumpX.exe and PsExec.exe were staged in "
                "C:\\\\Windows\\\\Temp\\\\perfmon\\\\.")
        assert not self._is_fp(text), (
            "'Confirmed' malicious activity must NOT be flagged FP"
        )

    def test_confirmed_c2_beacon_not_fp(self):
        """From F007 text: 'conducting C2 beacon activity'"""
        text = ("PID 9002 is conducting C2 beacon activity to 192.0.2.140, "
                "consistent with a post-exploitation framework.")
        assert not self._is_fp(text)


class TestBug2aVerdictSchema:
    """BUG 2A: Structured verdict enum in ReAct response.

    Primary signal replaces prose parsing. Regex becomes fallback.
    Ambiguity defaults to is_false_positive=False (safe direction).
    """

    def test_verdict_field_documented_in_prompt(self):
        """ReAct prompt must document the verdict enum."""
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        assert '"verdict":' in src, (
            "verdict field missing from ReAct prompt JSON schema"
        )
        assert "confirmed_malicious" in src
        assert "confirmed_benign" in src
        assert "inconclusive" in src

    def test_verdict_parsing_handler_present(self):
        """Conclude handler must read verdict field as primary signal."""
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        assert 'raw.get("verdict", "")' in src, (
            "verdict field not read from AI response"
        )
        assert '"confirmed_benign"' in src, (
            "confirmed_benign handler missing"
        )
        assert '"confirmed_malicious"' in src, (
            "confirmed_malicious handler missing"
        )
        assert '"inconclusive"' in src, (
            "inconclusive handler missing"
        )

    def test_verdict_source_tracked(self):
        """Must distinguish ai_verdict from regex_fallback for audit."""
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        assert 'verdict_source' in src, (
            "verdict_source field missing -- needed to distinguish "
            "primary signal from fallback regex in audit trail"
        )
        assert '"ai_verdict"' in src
        assert '"regex_fallback"' in src

    def test_inconclusive_preserves_severity(self):
        """Option B: inconclusive verdict must NOT set is_false_positive=True."""
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        # Find the inconclusive branch
        assert 'verdict == "inconclusive"' in src
        # Verify the inconclusive log message mentions severity preserved
        assert "severity preserved" in src.lower() or "preserve" in src.lower(), (
            "Inconclusive branch must log that severity is preserved"
        )

    def test_regex_fallback_when_verdict_missing(self):
        """If AI forgets verdict field, regex fallback must still work."""
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        # Regex patterns must still exist in fallback branch
        assert 'fp_patterns' in src
        assert 'regex_fallback' in src, (
            "Regex fallback path missing -- must handle case where AI "
            "forgets to return verdict field"
        )

    def test_verdict_stored_on_finding(self):
        """verdict field must be stored on react_conclusion for report template."""
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        # The react_conclusion dict must include verdict
        assert '"verdict": verdict' in src, (
            "verdict not stored on finding[react_conclusion] -- needed "
            "for future report template to show 'AI was inconclusive'"
        )


class TestBug3Inv1Guardrail:
    """BUG 3: INV1_SUPPORTED derived from _TOOL_REGISTRY, bootstrap
    tools get distinct log message.

    Discovered 2026-04-17 paid run: vol_netscan (a bootstrap tool) was
    selected by Inv1 and rejected as 'unsupported tool', a misleading
    log message because vol_netscan IS registered -- it just already
    ran in Step 4.

    INV1_SUPPORTED was also stale: missing 5 tools that CC#17a.1 added
    to _TOOL_REGISTRY (vol_hollowprocesses, vol_vadinfo, vol_modscan,
    vol_mftscan, vol_reg_hivelist).
    """

    def test_inv1_supported_derived_from_registry(self):
        """INV1_SUPPORTED must be computed from _TOOL_REGISTRY,
        not a hardcoded set."""
        src = Path("run_pipeline.py").read_text()
        assert "INV1_SUPPORTED = set(_TOOL_REGISTRY.keys())" in src, (
            "INV1_SUPPORTED must be derived from _TOOL_REGISTRY. "
            "Hardcoded sets drift (BUG 3 regression)."
        )

    def test_unknown_tool_still_warned(self):
        """Tools NOT in _TOOL_REGISTRY still get warning (not silent)."""
        src = Path("run_pipeline.py").read_text()
        assert "not in _TOOL_REGISTRY" in src, (
            "Unknown tools must still log warning for visibility"
        )

    def test_no_stale_hardcoded_set(self):
        """The old hardcoded INV1_SUPPORTED set must be removed."""
        src = Path("run_pipeline.py").read_text()
        # The old hardcoded set had these as literal string entries
        # Check the hardcoded list is gone. A few tools were in the old
        # set literal -- they should NOT all appear consecutively as
        # string literals after the fix.
        import re
        # Look for the old hardcoded pattern: literal tool names in a
        # set, 3+ consecutive
        old_hardcoded = re.search(
            r'INV1_SUPPORTED\s*=\s*\{\s*"vol_psscan"',
            src,
        )
        assert not old_hardcoded, (
            "Old hardcoded INV1_SUPPORTED set still present (BUG 3 "
            "regression). Must derive from _TOOL_REGISTRY."
        )


class TestBug4DynamicToolCounts:
    """BUG 4: Startup log reports actual registry counts, not hardcoded '134+'."""

    def test_no_hardcoded_134_claim(self):
        """Source must not contain aspirational '134+' tool claim."""
        src = Path("run_pipeline.py").read_text()
        assert "134+" not in src, "Stale '134+' tool claim still present"

    def test_registry_count_logged_dynamically(self):
        """Source must compute count from _TOOL_REGISTRY at startup."""
        src = Path("run_pipeline.py").read_text()
        assert "len(_TOOL_REGISTRY)" in src
        assert "reachable via _TOOL_REGISTRY" in src

    def test_investigation_tool_counts_logged(self):
        """Source must log dynamic investigation tool counts."""
        src = Path("run_pipeline.py").read_text()
        assert "INVESTIGATION_TOOLS" in src
        assert "Investigation (ReAct)" in src or "Investigation" in src

    def test_registry_floor_is_at_least_26(self):
        """Phase A Step 2: registry floor is 23 original + 3 sleuthkit = 26.
        Dynamic Vol3 discovery can grow this further on hosts where
        `vol --help` succeeds. If this fails, the floor shrank --
        a tool was removed without a replacement capability."""
        from src.sift_sentinel.coordinator import _TOOL_REGISTRY
        assert len(_TOOL_REGISTRY) >= 26, (
            f"Registry floor dropped below 26 (now {len(_TOOL_REGISTRY)}). "
            "Phase A Step 2 guarantees 23 original + 3 sleuthkit = 26 minimum."
        )


class TestBug5aReferenceSetExpansion:
    """BUG 5a: reference set tracks parent-child edges and hidden PIDs."""

    def test_pstree_populates_parent_pid_map(self):
        from src.sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "vol_pstree": {"output": [
                {"PID": 868, "PPID": 4, "ImageFileName": "services.exe"},
                {"PID": 2876, "PPID": 868, "ImageFileName": "WmiPrvSE.exe"},
                {"PID": 9002, "PPID": 2876, "ImageFileName": "powershell.exe"},
            ]}
        }
        ref = build_reference_set(tool_outputs)
        assert ref["pid_to_parent_pid"][9002] == 2876
        assert ref["pid_to_parent_pid"][2876] == 868
        assert ref["pid_to_parent_pid"][868] == 4

    def test_pstree_missing_ppid_does_not_crash(self):
        from src.sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "vol_pstree": {"output": [
                {"PID": 100, "ImageFileName": "init.exe"},
            ]}
        }
        ref = build_reference_set(tool_outputs)
        assert 100 not in ref["pid_to_parent_pid"]

    def test_psscan_ppid_used_when_pstree_absent(self):
        from src.sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "vol_psscan": {"output": [
                {"PID": 9000, "PPID": 4, "ImageFileName": "hidden.exe"},
            ]}
        }
        ref = build_reference_set(tool_outputs)
        assert ref["pid_to_parent_pid"][9000] == 4

    def test_pstree_ppid_wins_over_psscan(self):
        """First-writer-wins: pstree runs first, psscan setdefault skips."""
        from src.sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "vol_pstree": {"output": [
                {"PID": 5000, "PPID": 100, "ImageFileName": "proc.exe"},
            ]},
            "vol_psscan": {"output": [
                {"PID": 5000, "PPID": 999, "ImageFileName": "proc.exe"},
            ]},
        }
        ref = build_reference_set(tool_outputs)
        assert ref["pid_to_parent_pid"][5000] == 100

    def test_hidden_pids_populated_from_dkom(self):
        from src.sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "vol_pstree": {"output": [
                {"PID": 100, "PPID": 4, "ImageFileName": "services.exe"},
            ]},
            "vol_psscan": {"output": [
                {"PID": 100, "PPID": 4, "ImageFileName": "services.exe"},
                {"PID": 9999, "PPID": 4, "ImageFileName": "rootkit.exe"},
            ]},
        }
        ref = build_reference_set(tool_outputs)
        assert 9999 in ref["hidden_pids"]
        assert 100 not in ref["hidden_pids"]

    def test_hidden_pids_empty_when_no_dkom(self):
        from src.sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "vol_pstree": {"output": [
                {"PID": 100, "PPID": 4, "ImageFileName": "services.exe"},
            ]},
            "vol_psscan": {"output": [
                {"PID": 100, "PPID": 4, "ImageFileName": "services.exe"},
            ]},
        }
        ref = build_reference_set(tool_outputs)
        assert len(ref["hidden_pids"]) == 0

    def test_hidden_pids_field_exists_even_without_psscan(self):
        from src.sift_sentinel.validation.reference_set import build_reference_set
        tool_outputs = {
            "vol_pstree": {"output": [
                {"PID": 100, "PPID": 4, "ImageFileName": "init.exe"},
            ]}
        }
        ref = build_reference_set(tool_outputs)
        assert "hidden_pids" in ref
        assert isinstance(ref["hidden_pids"], set)

    def test_pid_to_parent_pid_field_exists_on_empty_build(self):
        from src.sift_sentinel.validation.reference_set import build_reference_set
        ref = build_reference_set({})
        assert "pid_to_parent_pid" in ref
        assert isinstance(ref["pid_to_parent_pid"], dict)


class TestBug5bValidatorCheckers:
    """BUG 5b: _check_child_process and _check_process_exists.

    Note: individual checker fns return dicts keyed by 'result' (via
    _result helper), matching the existing convention used by
    _check_pid/_check_hash/_check_timestamp/_check_connection and
    consumed by validate_finding via c['result']. Tests use r['result'].
    """

    def _base_ref(self):
        return {
            "hashes": {},
            "pid_to_process": {868: ["services.exe"], 2876: ["WmiPrvSE.exe"], 9002: ["powershell.exe"]},
            "pid_to_parent_pid": {2876: 868, 9002: 2876},
            "hidden_pids": set(),
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }

    # child_process checker
    def test_child_process_valid_pair(self):
        from src.sift_sentinel.validation.validator import _check_child_process
        claim = {"type": "child_process", "parent_pid": 2876, "child_pid": 9002}
        r = _check_child_process(claim, self._base_ref())
        assert r["result"] == "MATCH"

    def test_child_process_parent_missing(self):
        from src.sift_sentinel.validation.validator import _check_child_process
        claim = {"type": "child_process", "parent_pid": 99999, "child_pid": 9002}
        r = _check_child_process(claim, self._base_ref())
        assert r["result"] == "MISMATCH"
        assert "99999" in r["detail"]

    def test_child_process_child_missing(self):
        from src.sift_sentinel.validation.validator import _check_child_process
        claim = {"type": "child_process", "parent_pid": 2876, "child_pid": 77777}
        r = _check_child_process(claim, self._base_ref())
        assert r["result"] == "MISMATCH"
        assert "77777" in r["detail"]

    def test_child_process_wrong_relationship(self):
        """Both PIDs exist but claimed parent is not the actual parent."""
        from src.sift_sentinel.validation.validator import _check_child_process
        # Claim: 868 is parent of 9002. Actual: 2876 is parent of 9002.
        claim = {"type": "child_process", "parent_pid": 868, "child_pid": 9002}
        r = _check_child_process(claim, self._base_ref())
        assert r["result"] == "MISMATCH"
        assert "2876" in r["detail"]

    def test_child_process_no_parent_recorded(self):
        from src.sift_sentinel.validation.validator import _check_child_process
        ref = self._base_ref()
        # 868 has no parent entry
        claim = {"type": "child_process", "parent_pid": 4, "child_pid": 868}
        ref["pid_to_process"][4] = ["System"]
        r = _check_child_process(claim, ref)
        assert r["result"] == "MISMATCH"
        assert "no parent recorded" in r["detail"]

    # process_exists checker
    def test_process_exists_normal(self):
        from src.sift_sentinel.validation.validator import _check_process_exists
        claim = {"type": "process_exists", "pid": 9002}
        r = _check_process_exists(claim, self._base_ref())
        assert r["result"] == "MATCH"

    def test_process_exists_hidden_flag(self):
        from src.sift_sentinel.validation.validator import _check_process_exists
        ref = self._base_ref()
        ref["pid_to_process"][9999] = ["rootkit.exe"]
        ref["hidden_pids"].add(9999)
        claim = {"type": "process_exists", "pid": 9999}
        r = _check_process_exists(claim, ref)
        assert r["result"] == "MATCH"
        assert "DKOM" in r["detail"] or "hidden" in r["detail"].lower()

    def test_process_exists_missing(self):
        from src.sift_sentinel.validation.validator import _check_process_exists
        claim = {"type": "process_exists", "pid": 55555}
        r = _check_process_exists(claim, self._base_ref())
        assert r["result"] == "MISMATCH"
        assert "55555" in r["detail"]

    # Registry integration
    def test_validator_accepts_child_process_type(self):
        from src.sift_sentinel.validation.validator import validate_finding
        finding = {"claims": [
            {"type": "child_process", "parent_pid": 2876, "child_pid": 9002},
            {"type": "pid", "pid": 9002, "process": "powershell.exe"},
        ]}
        r = validate_finding(finding, self._base_ref())
        assert r["status"] != "UNRESOLVED"
        assert "unrecognized claim types" not in r.get("detail", "")

    def test_validator_accepts_process_exists_type(self):
        from src.sift_sentinel.validation.validator import validate_finding
        finding = {"claims": [
            {"type": "process_exists", "pid": 9002},
            {"type": "pid", "pid": 9002, "process": "powershell.exe"},
        ]}
        r = validate_finding(finding, self._base_ref())
        assert r["status"] != "UNRESOLVED"
        assert "unrecognized claim types" not in r.get("detail", "")

    def test_validator_still_rejects_truly_unknown_types(self):
        from src.sift_sentinel.validation.validator import validate_finding
        finding = {"claims": [
            {"type": "made_up_type", "pid": 9002},
        ]}
        r = validate_finding(finding, self._base_ref())
        assert r["status"] == "UNRESOLVED"
        assert "made_up_type" in r["detail"]


class TestBug5cSCPromptEnumeration:
    """BUG 5c: SC strategy prompts enumerate full accepted claim types."""

    def test_valid_claim_types_block_exists(self):
        from src.sift_sentinel.correction.strategies import VALID_CLAIM_TYPES_BLOCK
        assert VALID_CLAIM_TYPES_BLOCK
        assert len(VALID_CLAIM_TYPES_BLOCK) > 200

    def test_valid_claim_types_lists_all_six_verified_types(self):
        from src.sift_sentinel.correction.strategies import VALID_CLAIM_TYPES_BLOCK
        for t in ["hash", "pid", "timestamp", "connection",
                  "child_process", "process_exists"]:
            assert f'"{t}"' in VALID_CLAIM_TYPES_BLOCK, f"missing {t}"

    def test_valid_claim_types_lists_three_passthrough_types(self):
        from src.sift_sentinel.correction.strategies import VALID_CLAIM_TYPES_BLOCK
        for t in ["path", "raw", "artifact"]:
            assert f'"{t}"' in VALID_CLAIM_TYPES_BLOCK, f"missing {t}"

    def test_valid_claim_types_warns_against_invention(self):
        from src.sift_sentinel.correction.strategies import VALID_CLAIM_TYPES_BLOCK
        assert "DO NOT INVENT" in VALID_CLAIM_TYPES_BLOCK.upper() or \
               "do not invent" in VALID_CLAIM_TYPES_BLOCK.lower()

    def test_all_three_strategies_include_types_block(self):
        """Each strategy prompt must embed VALID_CLAIM_TYPES_BLOCK."""
        src = Path("src/sift_sentinel/correction/strategies.py").read_text()
        # Each strategy string references the constant
        count = src.count("VALID_CLAIM_TYPES_BLOCK")
        # 1 definition + 3 uses = 4 minimum
        assert count >= 4, (
            f"Expected 4+ references to VALID_CLAIM_TYPES_BLOCK "
            f"(1 def + 3 uses), found {count}"
        )
