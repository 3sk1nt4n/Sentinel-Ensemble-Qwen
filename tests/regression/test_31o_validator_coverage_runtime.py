
"""31O: runtime validator alignment and generic coverage knobs.

Synthetic only. Dataset-agnostic. No case IOCs, answer keys, or cached findings.
"""

from pathlib import Path
import inspect


def test_powershell_command_typed_checker_is_runtime_recognized():
    import sift_sentinel.validation.validator as validator
    import sift_sentinel.validation.typed_validator as typed_validator

    src = inspect.getsource(validator)
    assert "_SIFT_TYPED_CHECKERS" in src
    assert "powershell_command" in typed_validator._TYPED_CHECKERS

    class FakeTypedDB:
        def facts_by_index(self, index, value, fact_type):
            if index == "by_ttp_tag" and value == "encoded_command" and fact_type == "powershell_command_fact":
                return [{"fact_id": "powershell_command_fact-synthetic-1"}]
            return []

    assert typed_validator._t_powershell_command(
        {"type": "powershell_command", "ttp_tag": "encoded_command"},
        FakeTypedDB(),
    )[0] == "MATCH"


def test_self_correction_prompt_advertises_powershell_command_claims():
    from sift_sentinel.correction import strategies

    block = strategies.VALID_CLAIM_TYPES_BLOCK
    assert "powershell_command" in block
    assert "ttp_tag" in block
    assert "encoded_command" in block
    assert "download_cradle" in block


def test_evtx_timeout_and_cap_are_env_driven():
    src = Path("src/sift_sentinel/tools/disk_extended.py").read_text()
    assert "SIFT_EVTX_TIMEOUT_S" in src
    assert "SIFT_EVENT_LOG_MAX_RECORDS" in src
    assert "per_file_timeout = 10" not in src


def test_yara_rules_path_is_env_driven_and_autodiscovered():
    src = Path("src/sift_sentinel/coordinator.py").read_text()
    assert "SIFT_YARA_RULES_PATH" in src
    assert "_sift_resolve_yara_rules_path()" in src
    assert 'gen.run_yara("/etc/sift-sentinel/yara_rules"' not in src


def test_self_correction_output_does_not_claim_new_proof():
    src = Path("run_pipeline.py").read_text()
    assert "AI found additional proof" not in src
    assert "claims reformulated and revalidated" in src
