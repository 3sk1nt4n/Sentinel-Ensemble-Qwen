# 🤝 Contributor Onboarding - Sentinel Ensemble

New to the codebase? This page gets you from clone to confident change in
one sitting. *(Internal Python package name: `sift_sentinel`.)*

## What you are walking into

An autonomous DFIR agent: a **deterministic Python conductor** drives a
16-step pipeline over Windows evidence (memory + disk), invoking the model
(Qwen on Alibaba Cloud DashScope by default) **5 times** (the 4 numbered
invocations + the Step-13AA self-correction finalize). The AI has **zero shell
access** - every forensic tool is a typed MCP function - and every AI claim is
validated against real tool output before it reaches the report. A ~4,900-test
suite guards the behavior.

## First steps

1. Clone and install: `pip install -r requirements.txt` (venv on PEP-668 systems).
2. Smoke test: `./findevil.sh --demo` → must end in **"Everything verified and ready."**
3. Read [`ARCHITECTURE.md`](ARCHITECTURE.md) - the Step 0→16 pipeline diagram and the 14 defense layers.
4. Run the suite once so you know your baseline: `pytest tests/ -q`.

## Map of the code

| Path | Responsibility |
|---|---|
| `run_pipeline.py` | the conductor - top-level 16-step orchestrator (module-level script) |
| `step0_onboard.py` / `findevil.sh` | conversational onboarding: evidence profiling, read-only mounting, launch |
| `src/sift_sentinel/coordinator.py` | tool dispatch, registry, ReAct investigation loop |
| `src/sift_sentinel/tools/` | typed MCP tools (memory, disk, capabilities, common) |
| `src/sift_sentinel/validation/` | deterministic validator - claims vs. the paired reference set |
| `src/sift_sentinel/analysis/` | disposition, dedup/reconcile, confidence, report-integrity passes |
| `src/sift_sentinel/reporting/` | customer findings table, display hygiene, report polish |
| `tests/` | the contract - ~4,900 tests, `conftest.py` has autouse fixtures |

**Adding a forensic tool?** See [`EXTENDING.md`](EXTENDING.md) - the typed-envelope
contract, registry + capability wiring, and the drift-gate that fails CI on a
half-wired tool.

## The verify ritual (after EVERY change - no exceptions)

```bash
pytest tests/ -x                               # stop on first failure
python -m py_compile src/**/*.py               # syntax check
python -m sift_sentinel.coordinator --dry-run  # boot check, must exit 0
```

After any `run_pipeline.py` import edit, also run
`ruff check --select F821 run_pipeline.py` - it is a script the suite never
imports, so undefined names slip past everything else.

## Key rules (non-negotiable)

1. **Startup log never lies** - counts are computed at runtime, never hardcoded.
2. **No tool without a capability declaration** and negative tests.
3. **No dataset-specific content anywhere shipped** - no case hostnames,
   usernames, hashes, or tool-name allowlists in code, prompts, or fixtures.
   Detection is behavioral/structural only. `audit/nocheat.py` enforces this
   at commit time and the export pipeline hard-fails on leaks.
4. **Every new behavior is kill-switched** - env-gated `SIFT_*` flag,
   default-on only after validation, fails closed.
5. **Tests are the contract** - never delete assertions to make tests pass;
   if a test is wrong, say so and change it *visibly*.

## ZEROFAKE discipline

Every claim you make carries a label:

- **TESTED** - ran it, saw the output (paste it).
- **VERIFIED** - read the source, confirmed structurally.
- **INFERRED** - deduced from context (say so).
- **GUESSING** - admit it openly (target: zero).

Banned phrases: "probably works", "should work", "production-ready" without
runtime proof. If you cannot test something, say **"I cannot test this."**

## Gate pattern for every change

1. **Discover** - grep/read the current code first; never assume file contents.
2. **Apply** - smallest change that does the job; one concern per commit.
3. **Confirm** - re-grep that the change landed exactly where you think.
4. **Test** - targeted tests, then the full suite; compare failures against
   your pre-change baseline (zero NEW failures is the bar).
5. **Review** - `git diff` for collateral damage before committing.

## When you are stuck

1. Grep before asking - most questions have text answers in `docs/`.
2. Re-run the verify ritual - is the current state what you think it is?
3. Still stuck? Ask with full context: file:line, exact command, exact output.

*Public competition codebase: every claim must survive a line-level audit.
No overclaiming - honest failure beats a wrong answer, in code and in prose.*
