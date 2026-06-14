"""Slot 31E-DB.5d GROUP A TASK A1 -- acceptance result truth propagation.

Observed bug: post-live subgates failed, but the outer acceptance
script still printed a final ``PASS``. The aggregate verdict did not
inherit subgate failure, so a broken acceptance run looked green.

This module is the single fail-closed aggregator. The final acceptance
result is ``PASS`` only when EVERY one of the following holds:

  * the live pipeline returned rc == 0,
  * the recorded run env file exists,
  * the recorded state_dir exists,
  * the post-live verifier returned rc == 0,
  * no ``=FAIL`` / ``FAIL_REVIEW`` gate line appears anywhere in the
    current acceptance session transcript.

Otherwise the result is ``FAIL_REVIEW``. There is deliberately no third
"warn but pass" state -- ZEROFAKE, honest failure over a green lie.

Dataset-agnostic and model-flexible: the transcript is opaque text, no
provider/model name, evidence path, or case id is referenced.
"""
from __future__ import annotations

import re
import sys

ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE = (
    "ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE"
)

RESULT_PASS = "PASS"
RESULT_FAIL_REVIEW = "FAIL_REVIEW"

# A gate failure line follows the repo convention ``<GATE_NAME>=FAIL``
# (optionally with a parenthetical reason). ``FAIL_REVIEW`` itself, or a
# bare ``FAIL (`` produced by a subgate, also counts. Reasoning prose
# such as "this could fail" must NOT trip the detector, so we only match
# the structured forms.
_FAIL_LINE_RE = re.compile(
    r"(?:[A-Z0-9_]+=FAIL(?:_REVIEW)?\b|\bFAIL_REVIEW\b|\bFAIL\s*\()",
)


def transcript_has_fail_gate(transcript: str) -> bool:
    """True when the session transcript carries any structured FAIL.

    Only structured gate failures count -- a sentence merely containing
    the word "fail" does not (avoids false fail-closed on narration).
    """
    if not transcript:
        return False
    for line in str(transcript).splitlines():
        if _FAIL_LINE_RE.search(line):
            return True
    return False


def aggregate_acceptance_result(
    transcript: str,
    *,
    live_rc: int,
    recorded_env_exists: bool,
    recorded_state_dir_exists: bool,
    post_live_rc: int,
) -> dict:
    """Fail-closed aggregate of one acceptance session.

    Returns a dict with ``result`` (``PASS`` | ``FAIL_REVIEW``), the
    gate name, a boolean ``passed`` and the list of failing
    ``reasons``. ``PASS`` requires every precondition AND a clean
    transcript; any single failure forces ``FAIL_REVIEW``.
    """
    reasons: list[str] = []

    if live_rc != 0:
        reasons.append("live_pipeline_rc!=0:%s" % live_rc)
    if not recorded_env_exists:
        reasons.append("recorded_run_env_missing")
    if not recorded_state_dir_exists:
        reasons.append("recorded_state_dir_missing")
    if post_live_rc != 0:
        reasons.append("post_live_rc!=0:%s" % post_live_rc)
    if transcript_has_fail_gate(transcript):
        reasons.append("subgate_fail_line_in_transcript")

    passed = not reasons
    return {
        "gate": ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE,
        "result": RESULT_PASS if passed else RESULT_FAIL_REVIEW,
        "passed": passed,
        "reasons": reasons,
    }


def _cli(argv: list[str]) -> int:
    """Thin CLI for the shell wrapper.

    Usage:
      acceptance_aggregate.py LIVE_RC ENV_EXISTS STATE_EXISTS POST_RC \
          < transcript

    ENV_EXISTS / STATE_EXISTS are ``1``/``0``. The transcript is read
    from stdin. Prints the gate line and exits non-zero on
    ``FAIL_REVIEW`` so the outer script cannot mask a subgate failure.
    """
    if len(argv) != 4:
        sys.stderr.write(
            "usage: acceptance_aggregate.py LIVE_RC ENV_EXISTS "
            "STATE_EXISTS POST_RC < transcript\n"
        )
        return 2
    live_rc = int(argv[0])
    env_exists = argv[1] == "1"
    state_exists = argv[2] == "1"
    post_rc = int(argv[3])
    transcript = sys.stdin.read()
    res = aggregate_acceptance_result(
        transcript,
        live_rc=live_rc,
        recorded_env_exists=env_exists,
        recorded_state_dir_exists=state_exists,
        post_live_rc=post_rc,
    )
    print("%s=%s" % (res["gate"],
                     "PASS" if res["passed"] else "FAIL"))
    print("ACCEPTANCE_RESULT=%s" % res["result"])
    if res["reasons"]:
        print("acceptance_fail_reasons: %s" % ",".join(res["reasons"]))
    return 0 if res["passed"] else 1


if __name__ == "__main__":  # pragma: no cover - exercised via shell
    raise SystemExit(_cli(sys.argv[1:]))
