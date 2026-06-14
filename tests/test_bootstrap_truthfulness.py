"""P0-A fix: bootstrap skip logic must reflect actual execution state.

Run 16.5 (2026-04-24) produced a judge-facing contradiction:

  Step 4 log:  "Bootstrap SKIPPED (default). Use --bootstrap to enable."
  Step 5 log:  "Inv1 selected bootstrap tool vol_pstree (already ran in
                Step 4), skipping to avoid re-running"

The second message is a lie when --bootstrap was not passed: vol_pstree
and vol_netscan did NOT run in Step 4. The filter was unconditionally
dropping any tool in BOOTSTRAP_TOOLS, regardless of whether bootstrap
actually ran.

Fix: the Inv1 post-filter must skip a bootstrap tool only when that tool
is actually in the `mandatory` dict (which is populated only when Step 4
ran bootstrap). When --bootstrap is off, mandatory is {} and Inv1-picked
bootstrap tools must fall through to the INV1_SUPPORTED branch so Step 6
runs them normally.

Tests use static source inspection to match the pattern in
test_pipeline/test_bug_fixes.py -- run_pipeline.py has no __name__ guard
and executes 254 module-level statements on import.
"""

from __future__ import annotations

import re
from pathlib import Path


RUN_PIPELINE_SRC = Path("run_pipeline.py").read_text()


class TestBootstrapTruthfulness:
    """The 'already ran in Step 4' log must reflect reality."""

    def test_skip_requires_tool_actually_ran(self):
        """Skip must AND BOOTSTRAP_TOOLS membership with mandatory membership.

        Before fix: `if _clean in BOOTSTRAP_TOOLS:` fires when --bootstrap
        is off, producing a false "already ran" log.

        After fix: the condition must also require the tool be present in
        the `mandatory` dict (empty when bootstrap was skipped).
        """
        assert "_clean in BOOTSTRAP_TOOLS and _clean in mandatory" in RUN_PIPELINE_SRC, (
            "Skip condition must AND `_clean in BOOTSTRAP_TOOLS` with "
            "`_clean in mandatory`. Without the second clause, the "
            "'already ran in Step 4' log is false when --bootstrap was "
            "not passed."
        )

    def test_no_unconditional_bootstrap_skip(self):
        """The bare `if _clean in BOOTSTRAP_TOOLS:` pattern must be gone.

        That single-clause form is the P0-A bug -- it skips regardless
        of whether Step 4 actually ran.
        """
        bare = re.search(
            r"if\s+_clean\s+in\s+BOOTSTRAP_TOOLS\s*:",
            RUN_PIPELINE_SRC,
        )
        assert not bare, (
            "Bare `if _clean in BOOTSTRAP_TOOLS:` is the P0-A bug. Skip "
            "must also require `_clean in mandatory`, otherwise the "
            "'already ran' log lies when bootstrap is off."
        )

    def test_already_ran_log_retained_for_real_case(self):
        """The 'already ran in Step 4' log must remain for the real case.

        We are not removing the log; we are gating it on truth.
        """
        assert "already ran in Step 4" in RUN_PIPELINE_SRC, (
            "Log message removed entirely -- it should remain, gated on "
            "the tool actually being in `mandatory`."
        )

    def test_bootstrap_tools_constant_still_imported(self):
        """BOOTSTRAP_TOOLS import must stay -- the filter references it."""
        assert "BOOTSTRAP_TOOLS" in RUN_PIPELINE_SRC, (
            "BOOTSTRAP_TOOLS reference removed from run_pipeline.py"
        )

    def test_mandatory_dict_initialized_empty_when_bootstrap_off(self):
        """Anchor: when --bootstrap is off, `mandatory = {}` -- which is
        what lets the new condition correctly NOT skip.

        If this initialization were changed (e.g., prepopulated with
        bootstrap tool names), the truthfulness fix would regress.
        """
        # Match the skip branch: `if not _args.bootstrap:` followed by
        # `mandatory = {}` within a few lines.
        skip_branch = re.search(
            r"if\s+not\s+_args\.bootstrap\s*:.*?mandatory\s*=\s*\{\s*\}",
            RUN_PIPELINE_SRC,
            re.DOTALL,
        )
        assert skip_branch, (
            "Expected `if not _args.bootstrap:` branch to set "
            "`mandatory = {}`. The truthfulness fix depends on mandatory "
            "being empty when bootstrap is skipped."
        )
