# 🔁 Self-Correction Proof - the AI overruled, on the record

> **Maps to Technical Depth & Engineering + Innovation & AI Creativity.** This
> page is the receipt. The headline scoreboard and tables are the **featured
> DC01 run on Qwen Cloud** (`qwen3.7-max`), shipped and verifiable in
> [`docs/qwen-runs/`](docs/qwen-runs/). The DC01 self-correction is broken out in
> the scoreboard and appendix below. An earlier **Claude Opus reference run**
> (`run-rd01`, a local run not committed per the case-neutral policy; reproduce
> with `./setup.sh /path/to/case`) supplies additional per-line verbatim detail
> in its own clearly-labeled section. The machinery is **model-agnostic** (same
> code, same gates), so both prove the same thing. Nothing here is narration.

Sentinel Qwen Ensemble corrects itself **twice**: once while it's *thinking* (Layer 1,
ReAct - the AI re-investigates its own findings and changes its mind), and once
while the system is *deciding* (Layer 2, Step 13AA - a final AI re-judgment
whose every promotion deterministic **code** re-gates, refusing the ones it
can't prove). The design is
in [`ARCHITECTURE.md` §"Where the self-correction credit is earned"](ARCHITECTURE.md);
this page is the **evidence**: the DC01 scoreboard below is on Qwen Cloud, and the
`run-rd01` **Claude Opus reference run** supplies the deepest per-line receipt.
The Qwen Cloud runs record the same self-correction machinery in their
shipped metrics - the `react` token counters and the `disposition_counts`
recording the 13AA outcome inside every
[`docs/qwen-runs/*.json`](docs/qwen-runs/), including the flags-off ablation
that measures Layer 2 directly (confirmations 3 → 1, inconclusive 0 → 11 without it).

---

## ✅ The same machinery on Qwen Cloud - shipped, verifiable numbers

Unlike the local reference log below, these numbers are **committed to this
repo**: open [`docs/qwen-runs/`](docs/qwen-runs/) and check every cell (the
exact JSON field is named per row).

### 🌟 Featured: DC01 (public, reproducible) - the trust layer holding honestly

DC01 is the **primary, featured case**: the PUBLIC DFIR Madness "Stolen Szechuan
Sauce" domain controller (memory 2 GB + disk ~4.9 GB, two-segment E01) any judge can download and
rerun end to end. Both tiers ran the Step-13AA consolidated finalization
(`SIFT_INV3A_FINALIZE=1` + `SIFT_INV3A_REVIEW_ALL=1`), which resolved **every**
ambiguous finding to a final verdict (**0 inconclusive**) with **0 tool failures**.

| Self-correction evidence (JSON field) | 🪶 Light (`qwen-plus` ×4) | ⚡ Heavy (`qwen3.7-max`, 4-member) |
|---|---|---|
| Confirmed malicious (`disposition_counts.confirmed_malicious_atomic`) | **0** | **0** |
| Left inconclusive (`disposition_counts.inconclusive_unresolved`) | **0** | **0** |
| Suspicious / needs-review (`…suspicious_needs_review`) | 1 | 21 |
| Benign / false-positive, cleared with reasons (`…benign_or_false_positive`) | 0 | 23 |
| Findings total | 1 | 44 |
| Runtime · cost | 3m 46s · ~$0.22 | 14m 39s · ~$1.67 |
| Tool sweep (swept / hit / failed) | 33 / 29 / **0** | 33 / 27 / **0** (+11 data-only) |
| Integrity (mem+disk SHA256) | MATCH | MATCH |

**What self-correction actually did on the heavy run** (from the run's own
summary box and log, in the committed recording):

- **Layer 1 (ReAct AI-Cross-Check)** re-investigated the ensemble's output and
  **cleared 23 false positives with reasons** (the `benign_or_false_positive`
  row above) - installer noise, VMware tooling, even the IR team's own FTK
  Imager, each dispositioned instead of inflating the report.
- **42 of the 44 findings carried at least one AI self-correction move** (the
  run box prints `(42 AI self-corrected)`; the count is a per-finding
  annotation of ReAct redirects and 13AA re-judgments).
- **Layer 2 (Step 13AA)** then re-judged every ambiguous finding to a final
  verdict. The legacy per-finding generative repair loop (Step 12) is
  **skipped by design** under 13AA (`corrections_attempted = 0` in the JSON is
  expected, not absent): its 2 blocked findings were **deferred to 13AA and
  resolved there**, in one consolidated pass instead of N expensive retries.
  Net: **0 inconclusive**, and nothing was promoted to confirmed - the
  deterministic eligibility gate held.

Heavy surfaced the **full intrusion** (`coreupdater.exe` C2, outbound and inbound
RDP, `\FileShare\Secret` exfil, memory injection into explorer / svchost /
spoolsv, and scheduled-task + WMI persistence; attributed to administrator /
public; **5 MITRE tactics** - Execution, Persistence, Defense Evasion, Lateral
Movement, Command and Control; overall risk **CRITICAL**) yet **held every
lead**: **0 confirmed** is the trust layer working, not a gap - no atomic proof
was present in this case, so nothing was auto-promoted.

> **Depth scales with the model tier (1 -> 44 findings); the confirmation bar does not.**

### And when atomic proof IS present, the same engine confirms (rd01)

On the held-back reference case where atomic proof exists on disk, the identical
gate *promotes* it. These runs are committed too, alongside a rerun and an
ablation that isolate Layer 2 directly:

| Self-correction evidence (JSON field) | 🪶 Light | ⚡ Heavy | ⚡ Repro Jul 1 | ⚡ Ablation Jul 1 (13AA **OFF**) |
|---|---|---|---|---|
| Validator blocked unproven findings (`findings_blocked`) | 0 | **4** | 0 | 0 |
| Confirmed malicious (`disposition_counts.confirmed_malicious_atomic`) | 0 | **4** | **3** | **1** |
| Left inconclusive (`disposition_counts.inconclusive_unresolved`) | 1 | **0** | **0** | **11** |
| Suspicious / needs-review (`…suspicious_needs_review`) | 9 | 21 | 15 | 6 |
| Benign / false-positive, cleared with reasons (`…benign_or_false_positive`) | 1 | 9 | 4 | 3 |
| Layer-1 ReAct re-investigation spend (`token_breakdown.react`, in/out) | ≈127.7k / 4.0k | ≈160.8k / 30.6k | ≈163.9k / 23.6k | ≈109.0k / 20.4k |

Heavy confirmed **4** on atomic evidence - PsExec lateral movement, PWDumpX
credential dumping, an IFEO `sethc.exe` sticky-keys backdoor, and `p.exe` run from
a temp dir - while light confirmed **0**.

**The Layer-2 proof in one comparison:** same case, same model, same day - with
Step-13AA finalize **ON** (repro): **0 inconclusive, 3 confirmed**; with it
**OFF** (ablation): **11 inconclusive, only 1 confirmed**. The layer *resolves*
uncertainty and never manufactures confirmations - every promotion still passes
the deterministic eligibility gate (`final_disposition_bucket_gate = PASS` in
all four files).

---

## 📊 Scoreboard - the featured DC01 heavy run **on Qwen Cloud** (`qwen3.7-max`)

Every count is from that run's own execution log (in the committed recording;
the aggregates are in [`docs/qwen-runs/dc01-heavy-13aa-metrics.json`](docs/qwen-runs/dc01-heavy-13aa-metrics.json)).

| Layer / gate | What it did | Count |
|---|---|---|
| **Step 10 - validator** | claims checked → verified / rejected | **42 verified · 2 rejected** of 44 |
| **Layer 1 - Self-Correction (ReAct, Step 11)** | AI re-investigated its own findings | **12 investigations · 33 tool turns** |
| **Layer 1 - false positives caught** | ReAct overturned flags to benign | **7** |
| **Layer 2 - Self-Correction (13AA finalize, Step 13AA)** | ambiguous findings re-judged | **37 / 44 moved** (18 → benign, 19 → needs-review) |
| **Layer 2 - promotion gate** | model `confirmed` → cleared by code | **4 proposed → 0 promoted** (all held: no atomic proof) |
| **Layer 2 - blocked rescued** | validator-blocked → final cross-check, not dropped | **2 routed** |

`Fabrication check: 4.5% (every claim traces to real tool output), 42/44 verified`
· `typed_fact_matches=42, unsupported_claim_type_count=0`. **The model proposed 4
confirmations; the deterministic gate promoted none - no single artifact carried
atomic proof.** That is the whole thesis, measured on Qwen.

---

## 📎 The most granular receipt: the reference run (Claude Opus, `run-rd01`)

The line-numbered, per-finding detail below is from an **earlier reference run on
the Claude Opus provider** (`run-rd01`) - the self-correction machinery is
**model-agnostic** (identical code, gates, and log lines; only the provider
differs), so this reference run is the richest grep-able receipt of *how* each
layer behaves. The Qwen Cloud runs record the same machinery (scoreboard above;
JSON in [`docs/qwen-runs/`](docs/qwen-runs/)).

| Layer / gate | What it did | Count | Log line |
|---|---|---|---|
| **Step 10 - validator** | claims checked → confirmed / blocked | **32 verified · 22 blocked** of 54 | `1595`, `1641` |
| **Layer 1 - Self-Correction (ReAct, Step 11)** | AI re-investigated its own findings | **15 investigations · 49 tool turns** | `1591` |
| **Layer 1 - false positives caught** | AI overturned its *own* 🔴 flags to benign | **4** | `1096,1416,1484,1553` |
| **Layer 1 - guardrail saves** | typed-tool allowlist + OS auto-rewrite | **2** | `1276`, `1123` |
| **Layer 2 - Self-Correction (13AA finalize, Step 13AA)** | ambiguous findings re-judged | **46 → 39 moved** | `1777` |
| **Layer 2 - promotion gate** | model `confirmed` → cleared by code | **27 → 2** (25 refused) | `1777`, `1775` |
| **Layer 2 - blocked rescued** | validator-blocked → final cross-check, not dropped | **22** | `1765` |
| **Post-13AA - deterministic code gates** | baseline demote · dedup merges | **2 demoted · 5 merged** | `1872,1875,1877` |

---

## 🧠 Layer 1 detail (reference run) - ReAct re-investigates itself

The agent takes each of its own suspicious findings *back to the evidence* with
live forensic tools and reaches an independent verdict. `Step 11: 15
investigations, 49 total turns (avg 3.3)` (line **1591**) - `claude-opus-4-8`,
one autonomous tool-use loop per finding.

**It changed its mind 4 times - caught its own false positives:**

| Finding | Process | The AI's own re-test conclusion (logged verbatim) | Line |
|---|---|---|---|
| **F004** | `OUTLOOK.EXE` (PID 8128) | *"RWX VadS regions contain zero-filled/non-executable data with no MZ header, shellcode opcodes, or reflective-loader patterns"* → **benign** | `1096` |
| **F011** | `subject_srv.exe` (PID 1096) | *"the legitimate F-Response Subject remote forensic agent (PE Product/version v7), running as Local System"* → **benign** | `1553` |
| **F024** | `subject_srv.exe` (PID 1096) | *"a legitimate F-Response remote forensic acquisition agent performing authorized IR collection, not attacker activity"* → **benign** | `1484` |
| **F033** | `Dashlane.exe` (PID 7868) | *"legitimately listening on loopback (127.0.0.1) as a password manager's local IPC component"* → **benign** | `1416` |

Each was a 🔴 flag the agent *itself raised*, then **withdrew after testing** - the
exact "I flagged this, I tested it, it's actually safe" arc the judges ask to see.
All four are tagged `ReAct (AI Cross-Check) flagged FALSE POSITIVE - severity will
be forced LOW`.

**It also confirmed real evil** (same loop, opposite direction): F001 (WmiPrvSE-spawned
`powershell.exe`, null command line, RWX reflective-load), F005/F006 (`p.exe` staged
in `c:\windows\temp\perfmon\`), F012/F013/F023/F035/F036 (rundll32 proxy-execution chain).

### 🛡️ Two guardrail moments (autonomy under constraint)

- **Typed-tool allowlist caught a malformed call.** The model asked for `vol_malfin`
  (a typo of `vol_malfind`); the architecture refused it:
  `Turn 0: Investigation paused: requested tool 'vol_malfin' not in approved list
  (guardrail working correctly)` (line **1276**). No shell, no free-text command -
  an invalid tool simply cannot run.
- **OS-compat gate auto-corrected a wrong plugin.** The model picked the Linux
  `pslist`; code rewrote it to the Windows one:
  `REACT_OS_COMPAT_TOOL_GATE=REWRITE tool=vol_pslist linux→windows` (line **1123**).

---

## ⚖️ Layer 2 detail (reference run) - Step 13AA, code re-judges the AI

Before the report, every finding that is **not** already proven-confirmed or
already-cleared-benign gets one last adjudication. `INV3A_FINALIZE moved=39/46
benign_or_false_positive=1 confirmed_malicious_atomic=2 suspicious_needs_review=36`
(line **1777**). It corrects in **both directions**:

- **Rescues would-be false negatives →** 36 findings parked as *inconclusive /
  synthesis / floor-benign* were promoted to *needs-review* (surfaced for the
  analyst instead of buried). **22 validator-blocked findings** were routed in for
  a final cross-check rather than silently dropped (`INV3A_REVIEW_BLOCKED routed=22`,
  line **1765**).
- **Demotes a false positive →** F010 (`UpdaterUI.exe` single RWX) → **benign**.
- **Refuses over-promotion →** 25 of the 27 model-`confirmed` verdicts were held at
  *needs-review*, each with a logged reason (`INV3A_PROMOTION_DENIALS`, line **1775**):

```
no_malicious_semantic_signal=18   missing_core_field:severity=14
no_typed_or_validated_support=14  no_durable_fact_refs=14
no_explicit_fact_id_in_claims=14  weak_alone_signal_uncorroborated=6
rwx_memory_region_uncorroborated=5  react_verdict_benign_or_FP=3
```
*(reason tallies - a finding can trip several; not a per-finding count.)*

### Then deterministic code keeps tightening (no AI)
`BASELINE_GATE demoted=2` (system-binary ShimCache-only confirms → needs-review,
line **1872**) · `CONFIRMED_DEDUP merged=2 confirmed + 2 review` (line **1875**) ·
`XBUCKET_DEDUP merged=1` (line **1877**). The pass *only* loosens upward to recover
threats and tightens downward to drop noise - it never re-litigates a settled verdict.

---

## 🔬 The validator underneath (Step 10, reference run)

`VERIFIED: 32 findings confirmed | REJECTED: 22` (line **1595**) - of 54 candidate
findings, 22 were **blocked** because a claim didn't trace to a real tool record
(`no recognized claim types`, `no connection found for PID None to 172.16.5.26`).
`Fabrication check: 40.7% … 32/54 verified` (line **1641**);
`typed_fact_matches=45, unsupported_claim_type_count=0`. The model does **not** get
to mark its own homework - Layer 1 and Layer 2 both sit on top of this code gate.

---

## ✅ Verify it yourself (no API key needed for the second block)

The log itself is **not committed** (case-neutral policy - run outputs carry
case IOCs). Regenerate a run with `./setup.sh /path/to/your-case` on your own evidence, then
run these greps against **your local** execution log (the counts below are from
the rd01 reference run and will differ on your case; the *line types* are what
to look for):

```bash
cd Sentinel-Ensemble-Qwen
LOG=/path/to/your-run/agent_execution_log.txt

# Layer 1: ReAct re-investigated its own findings and caught false positives
grep -c "flagged FALSE POSITIVE" "$LOG"           # DC01 heavy -> 7

# Layer 2: the model proposed confirmations; the gate promoted none
grep -c "verdict: confirmed" "$LOG"               # DC01 heavy -> 4 proposed
grep -n "INV3A_FINALIZE moved="  "$LOG"           # -> moved=37/44 (18 benign, 19 needs-review)
grep -n "INV3A_PROMOTION_DENIALS" "$LOG"          # the refusals, with reasons

# the validator underneath: 42 verified, 2 rejected of 44
grep -n "VERIFIED: 42 findings" "$LOG"
```

And run the self-correction engine on mock evidence (real validator, no key):
```bash
docker run --rm --entrypoint python3 sentinel-qwen:demo demo_self_correction.py
# ^ 3 strategies, incl. an honest UNRESOLVED failure (image from ./setup.sh docker;
#   native `python3 demo_self_correction.py` also works in a dev checkout - ONBOARDING.md)
```

---

## 📋 Appendix - self-correction on the featured DC01 heavy run (Qwen)

**Layer 1 (ReAct) caught 7 false positives.** ReAct re-investigated the ensemble's
suspicious findings and flagged **7** as false positives (severity forced LOW) -
every one an RWX-memory-region alarm inside a *legitimate* Windows / VMware
process with no corroborating shellcode or execution evidence:

| Finding | Process (legitimate) | Flagged | ReAct verdict |
|---|---|---|---|
| F001 | `Microsoft.Activ...` (PID 1292) | 🔴 RWX memory injection | 🟢 benign (forced LOW) |
| F003 | `ServerManager` (PID 400) | 🔴 RWX memory injection | 🟢 benign (forced LOW) |
| F018 | `WmiPrvSE.exe` (PID 2764) | 🔴 RWX / suspicious | 🟢 benign (forced LOW) |
| F019 | `vmtoolsd.exe` (PID 2608) | 🔴 RWX / suspicious | 🟢 benign (forced LOW) |
| F027 | `WmiPrvSE.exe` (PID 2056) | 🔴 RWX / suspicious | 🟢 benign (forced LOW) |
| F028 | `vmtoolsd.exe` (PID 1600) | 🔴 RWX / suspicious | 🟢 benign (forced LOW) |
| F030 | `dfsrs.exe` (PID 1332) | 🔴 RWX / suspicious | 🟢 benign (forced LOW) |

**Layer 2 (Step 13AA) re-judged 37 of the 44 findings** (`INV3A_FINALIZE
moved=37/44`): **18 to benign, 19 to needs-review**, leaving **0 inconclusive**.
The model proposed **4** confirmations (`verdict: confirmed` x4); the deterministic
promotion gate **held all 4** (`INV3A_PROMOTION_DENIALS: no_malicious_semantic_signal`,
`react_verdict_benign_or_fp`) - no single artifact carried atomic proof, so **0
were promoted**. The model proposed; the code disposed.

> The per-line verbatim receipt of the *earlier Claude reference run* (its own
> F004/F011/F024/F033 ReAct flips and 39 Step-13AA moves) is the deepest example
> of the same model-agnostic machinery; it lives in the run log, not shipped here
> per the case-neutral policy.
