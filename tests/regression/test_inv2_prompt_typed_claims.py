"""SIFT 31N-comprehensive: Inv2 prompt accepts powershell_command claims.

Covers BOTH prompt-builder paths:
  - run_pipeline.py inline (live-mode Claude branch)
  - coordinator.py build_inv2_prompt (programmatic / ensemble path)

Dataset-agnostic. Base64-encoded forbidden tokens. Precise position
checks (not just substring presence) to give mutation tests teeth.
"""
from __future__ import annotations
import base64
import pathlib
import re

RP = pathlib.Path("run_pipeline.py")
COORD = pathlib.Path("src/sift_sentinel/coordinator.py")


# -- run_pipeline.py inline prompt regression --
def test_rp_prompt_no_pid_only_blocking_rule():
    src = RP.read_text()
    assert "Findings without PID claims will be BLOCKED" not in src
    assert "Findings without any validator-typed claim will be BLOCKED" in src


def test_rp_prompt_lists_powershell_command_in_comma_list():
    """PRECISE: powershell_command is the NEXT claim-type token after the
    'Accepted claim types: ... artifact, ' prefix -- nothing else between.

    Tolerates Python adjacent string-literal seams ('"' newline indent '"')
    because run_pipeline.py builds this prompt via implicit string
    concatenation; the runtime string is contiguous even though the source
    is not. Still has mutation teeth: an inserted claim type between the
    prefix and powershell_command breaks the regex.
    """
    src = RP.read_text()
    prefix = "Accepted claim types: pid, hash, connection, path, artifact, "
    assert prefix in src, "Accepted claim types prefix not found in run_pipeline.py"
    m = re.search(re.escape(prefix) + r'(?:"\s*"|\s)*powershell_command', src)
    assert m is not None, (
        "powershell_command must be the next claim type after 'artifact, ' "
        "(string-literal concatenation seams allowed, other tokens are not)"
    )


def test_rp_prompt_contains_example_4_powershell():
    src = RP.read_text()
    assert "EXAMPLE 4 (powershell_command claim" in src
    assert '"type": "powershell_command"' in src
    assert '"ttp_tag":' in src


# -- coordinator.py build_inv2_prompt regression --
def test_coord_prompt_no_pid_hash_connection_only_rule():
    src = COORD.read_text()
    assert "Every finding MUST include at least one claim with type pid, hash, or connection" not in src, \
        "old PID-hash-connection-only rule still present in coordinator.py"
    assert "Every finding MUST include at least one validator-typed claim" in src


def test_coord_prompt_lists_powershell_command_in_critical_rules():
    """PRECISE check on coordinator.py critical_rules block."""
    src = COORD.read_text()
    prefix = "Accepted claim types: pid, hash, connection, path, artifact, powershell_command"
    assert prefix in src, \
        "coordinator.py critical_rules missing precise claim-type list"


def test_coord_anti_patterns_includes_powershell_command():
    src = COORD.read_text()
    assert 'WRONG: {"claims": [{"type": "powershell_command"}]} -- missing ttp_tag' in src
    assert 'RIGHT: {"claims": [{"type": "powershell_command", "ttp_tag":' in src


def test_coord_logger_msg_updated():
    src = COORD.read_text()
    assert "Narrative-only findings are dropped" not in src
    assert "validator-typed claim (pid, hash, connection, path, artifact, powershell_command)" in src


# -- validator regression --
def test_validator_still_supports_powershell_command():
    import sys
    sys.path.insert(0, "src")
    from sift_sentinel.validation import typed_validator as tv
    assert hasattr(tv, "_t_powershell_command")
    assert "powershell_command" in tv._TYPED_CHECKERS


# -- no-cheat (base64-encoded tokens, scoped to PROMPT-BUILDER text only) --
def test_no_cheat_no_dataset_tokens_in_prompts():
    """Guard against dataset-specific values leaking into the Inv2 prompt.

    Scope is the prompt builders themselves -- run_pipeline.py (whole file:
    its Inv2 prompt is inline) and ONLY coordinator.build_inv2_prompt's
    body. Scanning all of coordinator.py false-positives on unrelated
    generic heuristic code (e.g. a 'perfmon' entry in a suspicious-path
    list), which is not prompt text and not a dataset secret.
    """
    _enc = [
        b"MTcyLjE2Lg==", b"YmFzZS1kYw==", b"YmFzZS1maWxl",
        b"cGVyZm1vbg==", b"TW5lbW9zeW5l", b"c3ViamVjdF9zcnY=",
        b"UHNFeGVjLmV4ZQ==", b"c3F1aXJyZWxkaXJlY3Rvcnk=",
        b"ODcxMg==", b"ODI2MA==", b"NTg0OA==", b"Mjg3Ng==",
    ]
    forbidden = [base64.b64decode(t).decode() for t in _enc]

    coord_lines = COORD.read_text().splitlines()
    start = next(i for i, ln in enumerate(coord_lines)
                 if ln.startswith("def build_inv2_prompt"))
    end = next(i for i, ln in enumerate(coord_lines[start + 1:], start + 1)
               if ln.startswith("def "))
    coord_prompt_src = "\n".join(coord_lines[start:end])

    sources = {
        "run_pipeline.py": RP.read_text(),
        "coordinator.build_inv2_prompt": coord_prompt_src,
    }
    hits = {}
    for name, src in sources.items():
        found = [t for t in forbidden if t in src]
        if found:
            hits[name] = found
    assert hits == {}, f"forbidden dataset tokens in prompts: {hits}"
