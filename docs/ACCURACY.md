# Accuracy Report - Self-Assessment

*(Required submission deliverable. Honesty over perfection: this report lists
what the agent got right, what it over-called, what it under-called, and the
hallucinations the validator blocked before they reached the report.)*

## Method

> ⚠️ **Claude reference run.** These metrics are from the **rd01 Claude
> reference run** (the architecture proven before the Qwen port), kept **local /
> not committed** (case-neutral policy). They are **not** a Qwen result; the
> **Qwen Cloud runs independently re-derive the same intrusion chain with their
> own counts** (heavy tier: 34 findings / 4 confirmed - `docs/qwen-runs/`); no
> Qwen-specific number is claimed here.

- Primary case: a paired Windows memory+disk image (see [`DATASET.md`](DATASET.md)).
- Model: Claude Opus 4.8, 4-member ensemble (the rd01 reference run).
- Every finding is traced to its tool executions in the local run directory
  `artifacts/run-rd01/` - the full investigative `report.md`, the complete
  step-by-step `agent_execution_log.txt` (every tool call, the 4-model ensemble,
  the deterministic validator verdicts, and the Step-13AA self-correction with
  per-finding reasoning), the interactive `summary_report.html`, and
  `run_summary.md` - so any claim is checkable in seconds. Reproduce with
  `./setup.sh /path/to/case`.

## How accuracy was assessed (methodology)

Accuracy here is **not self-graded by the model** - it is measured by deterministic
code checking the AI against real tool output, at four gates:

1. **Merge** - the ensemble's 81 raw findings dedupe to 51 candidates on
   structural artifact-identity keys, so the same evidence can't inflate the count
   (3 deterministic candidate-semantic findings are then emitted after the merge,
   `51 -> 54` entering validation - log gate `CANDIDATE_SEMANTIC_EMISSION`).
2. **Validator** - every candidate is checked against the paired reference set
   built from raw tool output; a claim with no typed/validated backing is
   **blocked**, not trusted (22 blocked, routed onward, never dropped).
3. **ReAct cross-check (Step 11 · SC layer 1)** - flagged findings are
   re-investigated with fresh tool calls; this is where the agent cleared its own
   false positive.
4. **Promotion gate (Step 13AA · SC layer 2)** - the model re-judges every
   ambiguous finding, but **only code** promotes a finding into the
   *confirmed-malicious* bucket, and only on typed, validated evidence
   (hash + path + PID). A model "promote" verdict alone never confirms - the final
   **2 confirmed** are code's decision, not the model's assertion.

"True positive" therefore means *traceable to tool output*, not *asserted by the
model*, and it is reproducible: re-running the same evidence re-derives the same
typed facts and the same gate decision on the confirmed set.

## The number that matters

The 4-model ensemble produced **81 raw findings**, deterministically merged to
**51 candidates** (plus 3 deterministic candidate-semantic emissions = **54**
entering validation). The validator then checked every candidate against real tool
output; **22 that lacked a typed/validated claim were blocked and routed to a
final Step-13AA cross-check - never silently dropped.** That is the architecture
working as designed: **code checks the AI; the AI never grades itself.** Every
surviving claim traces to real tool output.

| Metric | Count |
|---|---:|
| Raw findings (4-model ensemble) | 81 |
| Candidate findings (after deterministic merge) | 51 |
| Validator-blocked → routed to final cross-check (not dropped) | 22 |
| Final confirmed malicious (atomic) | 2 |
| Suspicious - needs analyst review | 42 |
| Benign / false-positive (ReAct layer 1 + 13AA layer 2) | 5 |
| Total findings / observations in report | 49 |
| *Self-correction - ambiguous re-judged (Step-13AA · second SC layer)* | *46* |
| *Self-correction - reclassified (Step-13AA)* | *39* |
| *Self-corrected in total (ReAct layer 1 + 13AA layer 2)* | *43* |

*(The last three rows are __process__ counts - how verdicts moved - not extra
findings; the 49 above is the final, de-duplicated total.)*

**Self-correction (ReAct + Step-13AA):** the agent re-judged **46** ambiguous
findings and reclassified **39** of them (36 → suspicious/needs-review, 2 →
confirmed, 1 → benign); with the 4 distinct ReAct layer-1 overturns, **43**
findings were self-corrected in total across the two passes. These are *process* counts (how the verdicts moved), not additional
findings - the 49 above is the final, de-duplicated total.

> 📄 **Every one of these corrections is enumerated** - both layers, before →
> after, each with its `agent_execution_log.txt` line ref - in
> **[`SELF-CORRECTION-PROOF.md`](../SELF-CORRECTION-PROOF.md)**.

## What it got right (true positives)

The agent independently reconstructed the real intrusion: event-log clearing,
WMI→PowerShell execution, RWX memory injection, staging from `Temp`,
credential-dumping tooling, sticky-keys persistence, PSEXESVC lateral-movement
service, SMB/RDP reconnaissance, and C2 beaconing - each cited to specific tool
output. It also **caught its own false positive**: a signed forensic tool first
flagged as a C2 listener was corrected to benign by the ReAct cross-check.

## What it got wrong - found in review, now FIXED

Honest findings from reviewing live runs, each fixed with a universal,
kill-switched, test-first change (zero new test regressions, validated on
synthetic data so a hardcoded answer could never pass):

1. **Duplicate findings - FIXED twice over.** Same-event duplicates collapse
   via (event-id + timestamp + IP-discriminator) keys; same-process memory
   findings (which carry no hash/path/event key at all) collapse via a
   composite process+PID+behavior-signature+peer-set key - distinct behaviors
   on the same PID and different external targets never merge.
   `SIFT_DEDUP_EVENT_KEYS` / `SIFT_DEDUP_PROC_KEYS`.

2. **IOC section flooded with filenames as "DGA domains" - FIXED at the root.**
   The file-extension blocklist approach was inherently incomplete (every new
   case surfaced unlisted extensions). Replaced by the inversion: a token is a
   domain **only if its final label is a registered IANA TLD** (vendored from
   the Public Suffix List - a universal standard, the opposite of an answer
   key). For the bounded set of extensions that are ALSO real TLDs
   (`.zip`/`.sh`/`.py`...), a bare token additionally needs **provenance** -
   the run must have seen it as the host of a parsed URL. Non-canonical
   dotted-quads (leading-zero / out-of-range octets) are rejected as carve
   junk. `SIFT_DGA_TLD_GATE` / `SIFT_DGA_PROVENANCE_GATE` /
   `SIFT_CARVED_IP_CANON_FILTER`.

3. **An indicator alone is not an IOC - the section is now a correlated
   ledger.** Every surviving network indicator is joined to the finding(s)
   whose own claims reference it (PID + public-IP identity, never
   process-name) and **inherits its verdict from the finding's disposition**:
   confirmed findings yield a block/hunt tier with finding IDs cited; no
   related finding means informational only. "Malicious" is earned per-run by
   correlation, never looked up. `SIFT_IOC_CORRELATE`.

4. **Machine tokens leaked into customer prose - FIXED.** Internal fact-id
   counters in range/list idioms are stripped (anchored so SIDs, USNs and
   serials survive byte-identical - the fix also caught a latent bug where the
   previous sanitizer corrupted zero-leading SID subauthorities); raw
   artifact-tuple titles render as Event-ID-grammar labels
   (`event:7045 (service installed) · <provider>`). `SIFT_TITLE_SANITIZE_V1`.

5. **One human reported as multiple users - FIXED.** A Windows 8.3 short-name
   identity (`PREFIX~1`) folds into its long form only when unambiguous (the
   DOS derivation is an OS primitive); process ownership transfers only when
   SIDs match, so a merge can never manufacture a malicious-PID attribution.
   `SIFT_USER_8DOT3_CANON`.

6. **The audit trail mislabelled the adjudicating model - FIXED.** Display
   names are now derived from the runtime model id's own grammar, so a log
   line can never claim a model that wasn't called; the final-sweep call also
   gained a dedicated model override (`SIFT_MODEL_INV3A`) and a deterministic
   cross-reference enrichment so it adjudicates with evidence (tool count,
   artifact-domain spread, weak/strong signal split) instead of nearly blind.
   `SIFT_INV3A_ENRICH`, plus a structural guard that stops promotion of
   single-signal uncorroborated RWX findings (the classic JIT/.NET false
   positive) without any process-name allowlist. `SIFT_INV3A_JIT_RWX_GUARD`.

Also: corroboration floor accepts execution-history + hash
(`SIFT_FLOOR_EXEC_HASH_CORROB`), confirmed tier orders by severity, WHO-first
identity on every finding, per-invocation prompt-cache health logging, a
Step-7 build that skips redundant same-source parsing (minutes → seconds),
and a launch-time storage guard rail.

## What it under-called / missed - honest false negatives

The promotion gate is deliberately strict (typed hash + path + PID required), so
its errors are **systematic under-calls, not over-calls**. Named examples from the
reference run:

- **Single-source-but-obvious artifacts stay in _review_, not _confirmed_.** The
  Security event-log clear (Event 1102, anti-forensics) and the PSEXESVC service
  registration are textbook-malicious, but each is backed by a single artifact
  domain, so the gate withholds promotion and routes them to analyst review. A
  senior analyst would confirm these; the agent under-calls them **by design** -
  the honest cost of "code, not the model, promotes."
- **The confirmed set is intentionally narrow (2 of a clearly multi-stage
  intrusion).** Lateral movement, C2 beaconing, and reflective-load injection are
  surfaced as corroborating _review_ items, not confirmed - none individually
  cleared the atomic typed-evidence bar. Honest under-call beats a confident wrong
  answer, but it does shift corroboration work to the analyst.

## Known limitation that remains (honest)

- **Disk-only PID/connection enrichment from event logs** is not yet
  implemented. On a disk-only image the live-process PID/connection axes are
  legitimately empty (no memory); pulling them from Event 4688/5156 requires
  parsing the EvtxECmd pipe-delimited message and is deferred rather than risk
  fabricating a PID. Memory and paired runs are unaffected.
- **Four accuracy features ship opt-in pending live validation** (finalize
  enrichment, JIT-RWX promotion guard, 8.3 identity merge, per-call model
  override). They are unit-proven on synthetic data; the validate-first policy
  keeps them off by default until a live run confirms behavior.

All fixes are **universal / dataset-agnostic** (keyed on structure, never case
data) and enforced case-neutral by guard tests + a commit-time audit.

## Evidence integrity & spoliation testing (required disclosure)

**How the architecture prevents modification of original data:**

- Evidence is mounted **read-only at the OS level** before any tool runs -
  write protection is enforced by the kernel, not by instructions.
- The model has **no write primitive to ignore**: it never gets a shell, and
  every forensic capability is a typed Python function none of which accepts
  a destructive operation. "What happens when the model ignores
  restrictions" is therefore architectural - there is no function to call.
  (Prompt-level rules exist too, but they are labeled as the weaker layer;
  see the guardrail classification in `ARCHITECTURE.md`.)
- All run outputs are written to the run's own state/report directories,
  never into evidence folders.

**How spoliation would be detected anyway (defense in depth):**

- Step 2 SHA256-fingerprints every evidence file before analysis; Step 15
  re-hashes and compares (`compare_fingerprints`). Any difference triggers a
  **SPOLIATION** alert in the report and `integrity_check.json` records the
  raw hashes.
- The comparison **fails closed**: sentinel values (missing file, unreadable,
  directory) always fail the match - two missing files are never accepted as
  proof of integrity.
- **Tested:** the detection path is unit-tested, including the deliberate
  modify-a-byte case (`test_fingerprint_detects_change`) and the
  missing-file sentinels; the rd01 reference run shows **SHA256 MATCH** across
  both evidence files (pre == post) - see `report.md` §1 and the
  `INTEGRITY VERIFIED: all hashes match` lines in the local
  `artifacts/run-rd01/agent_execution_log.txt`.

## Bottom line

On a held-out-style paired case the agent found the real attack end-to-end,
blocked and re-routed 22 unsupported claims to a final cross-check (never
silently dropped), and self-corrected 43 findings - clearing 5 to benign,
including a signed forensic tool first flagged as a possible C2 listener - fully
autonomously, in 8m 29s, for ~$15.45 (rd01 **Claude reference run** - live
Qwen Cloud timings and costs are in [`docs/qwen-runs/`](qwen-runs/)), with
evidence integrity preserved. The
known limitations above are accuracy *polish*, not
missed attacks.
