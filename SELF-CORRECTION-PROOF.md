# 🔁 Self-Correction Proof - the AI overruled, on the record

> **Maps to Technical Depth & Engineering + Innovation & AI Creativity.** This
> page is the receipt. Every number below is a timestamped line in the execution
> log of the **Claude reference run** (rd01) - `artifacts/run-rd01/agent_execution_log.txt`,
> a **local** run not committed to the repo (case-neutral policy; reproduce with
> `./setup.sh /path/to/case`). It is an architecture demonstration, not a Qwen result; the
> shipped, verifiable Qwen Cloud run metrics are in
> [`docs/qwen-runs/`](docs/qwen-runs/). Nothing here is narration - it's grep-able
> once you regenerate the run.

Sentinel Qwen Ensemble corrects itself **twice**: once while it's *thinking* (Layer 1,
ReAct - the AI re-investigates its own findings and changes its mind), and once
while the system is *deciding* (Layer 2, Step 13AA - a final AI re-judgment
whose every promotion deterministic **code** re-gates, refusing the ones it
can't prove). The design is
in [`ARCHITECTURE.md` §"Where the self-correction credit is earned"](ARCHITECTURE.md);
this page is the **evidence** from the `run-rd01` **Claude (Opus 4.8) reference
run**. The Qwen Cloud runs record the same self-correction machinery in their
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
Sauce" domain controller (memory 2 GB + disk 2.4 GB) any judge can download and
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

## 📊 Scoreboard (all from the `run-rd01` log - the **Claude reference run**, not a Qwen run)

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

## 🧠 Layer 1 - Self-Correction (ReAct, Step 11): the AI re-investigates itself

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

## ⚖️ Layer 2 - Self-Correction (Step 13AA finalize): code re-judges the AI

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

## 🔬 The validator underneath (Step 10)

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

# Layer 1: ReAct re-investigated its own findings, and caught 4 false positives
grep -n "15 investigations, 49 total turns" "$LOG"
grep -c "flagged FALSE POSITIVE" "$LOG"          # -> 4

# Layer 1: the typed-tool guardrail blocked a malformed tool call
grep -n "guardrail working correctly" "$LOG"

# Layer 2: the AI asked to confirm 27, code allowed 2
grep -c "verdict: confirmed" "$LOG"               # -> 27
grep -n "INV3A_FINALIZE moved="  "$LOG"           # -> confirmed_malicious_atomic=2
grep -n "INV3A_PROMOTION_DENIALS" "$LOG"          # the 25 refusals, with reasons

# the validator underneath: 32 verified, 22 blocked
grep -n "VERIFIED: 32 findings confirmed" "$LOG"
```

And run the self-correction engine on mock evidence (real validator, no key):
```bash
docker run --rm --entrypoint python3 sentinel-qwen:demo demo_self_correction.py
# ^ 3 strategies, incl. an honest UNRESOLVED failure (image from ./setup.sh docker;
#   native `python3 demo_self_correction.py` also works in a dev checkout - ONBOARDING.md)
```

---

## 📋 Appendix A - Layer 1 Self-Correction (ReAct) corrections, in full

The 4 findings the AI overturned on its own (verbatim conclusions, log lines
`1096 / 1553 / 1484 / 1416`):

| Finding | Was flagged | ReAct turned it into | Why (AI's logged conclusion) |
|---|---|---|---|
| F004 `OUTLOOK.EXE` | 🔴 RWX memory injection | 🟢 **benign** | RWX regions zero-filled, no MZ header / shellcode / reflective-loader pattern |
| F011 `subject_srv.exe` | 🔴 C2 / remote-access listener | 🟢 **benign** | legitimate F-Response IR agent (PE v7), running as Local System |
| F024 `subject_srv.exe` | 🔴 remote-access service | 🟢 **benign** | authorized F-Response acquisition agent, not attacker activity |
| F033 `Dashlane.exe` | 🔴 high-port / loopback staging | 🟢 **benign** | loopback 127.0.0.1 password-manager IPC component |

## 📋 Appendix B - Layer 2 Self-Correction (Step 13AA) corrections, in full (39 moves)

Every reclassification from the `run-rd01` log, lines **1778-1871**
(`INV3A_FINALIZE` summary at **1777**). `⚖️` = the model said *confirmed* but
**code held it at needs-review** (the gate overruling the AI). `✅` = cleared the
gate to confirmed. `🟢` = demoted to benign (false positive caught).

| Finding | Was | → Turned into | Model verdict | Why (logged reason) |
|---|---|---|---|---|
| F005 | synthesis | **confirmed** ✅ | confirmed | p.exe staged payload corroborated across many independent tools |
| F006 | synthesis | **confirmed** ✅ | confirmed | p.exe staging corroborated across multiple tools |
| F010 | inconclusive | **benign** 🟢 | false_positive | single RWX in McAfee agent likely benign noise |
| F007 | inconclusive | needs-review ⚖️ | confirmed | cmd.exe spawning staged p.exe corroborated by cmdline, pstree, amcache |
| F009 | synthesis | needs-review ⚖️ | confirmed | PSEXESVC service + binary corroborated across registry, amcache, MFT |
| F012 | inconclusive | needs-review ⚖️ | confirmed | null-cmdline rundll32 LOLBin proxy corroborated across three tools |
| F013 | inconclusive | needs-review ⚖️ | confirmed | rundll32 proxy execution corroborated across three tools |
| F015 | inconclusive | needs-review ⚖️ | confirmed | Event 1102 audit log cleared - deterministic anti-forensic signal |
| F019 | inconclusive | needs-review ⚖️ | confirmed | admin-share access corroborated by event logs + network IOCs |
| F020 | inconclusive | needs-review ⚖️ | confirmed | RDP/WinRM/SMB lateral movement corroborated by netscan and logs |
| F023 | benign | needs-review ⚖️ | confirmed | null-cmdline rundll32 injection corroborated across three tools |
| F026 | inconclusive | needs-review ⚖️ | confirmed | IFEO sethc Debugger backdoor - registry + event logs |
| F027 | inconclusive | needs-review ⚖️ | confirmed | Event 1102 audit log cleared - deterministic anti-forensic evidence |
| F028 | inconclusive | needs-review ⚖️ | confirmed | multiple 4648 logons corroborated by event logs + amcache |
| F029 | inconclusive | needs-review ⚖️ | confirmed | admin-share access corroborated across event logs + network IOCs |
| F038 | inconclusive | needs-review ⚖️ | confirmed | Event 1102 log clearing - deterministic anti-forensic signal |
| F039 | inconclusive | needs-review ⚖️ | confirmed | admin-share access corroborated across logs, network IOCs, amcache |
| F040 | inconclusive | needs-review ⚖️ | confirmed | SMB/RDP lateral movement corroborates PsExec staging via netscan |
| F041 | inconclusive | needs-review ⚖️ | confirmed | sethc IFEO Debugger backdoor - registry + event logs |
| F043 | inconclusive | needs-review ⚖️ | confirmed | reflective loader cradle corroborated by event logs + malfind |
| F044 | inconclusive | needs-review ⚖️ | confirmed | beaconing to 8080 corroborated by netscan + network IOCs |
| F045 | inconclusive | needs-review ⚖️ | confirmed | admin-share access corroborated across logs, IOCs, amcache |
| F048 | inconclusive | needs-review ⚖️ | confirmed | sethc IFEO Debugger persistence - registry + logs |
| F050 | inconclusive | needs-review ⚖️ | confirmed | Event 1102 audit log cleared - deterministic anti-forensic signal |
| F051 | inconclusive | needs-review ⚖️ | confirmed | repeated 4648 credential reuse corroborated by logs + amcache |
| F003 | inconclusive | needs-review | needs_review | reflection TTP from single event-log source - needs review |
| F016 | inconclusive | needs-review | needs_review | multiple 4648 explicit-credential events - single source |
| F017 | inconclusive | needs-review | needs_review | sethc IFEO Debugger from single registry source - needs review |
| F018 | inconclusive | needs-review | needs_review | SafeBoot AlternateShell may be baseline - needs review |
| F022 | inconclusive | needs-review | needs_review | reflection TTP single event-log source - needs review |
| F025 | inconclusive | needs-review | needs_review | internal beaconing to 8080 - single netscan source |
| F030 | benign | needs-review | needs_review | DismHost temp executions may be benign Dism - needs review |
| F032 | benign | needs-review | needs_review | SafeBoot AlternateShell potential persistence - needs review |
| F034 | inconclusive | needs-review | needs_review | reflection pattern single source - needs review |
| F037 | inconclusive | needs-review | needs_review | internal beaconing to 8080 - needs corroboration, single source |
| F042 | inconclusive | needs-review | needs_review | multiple 4648 credential reuse - single source |
| F046 | inconclusive | needs-review | needs_review | WinRM connection single netscan source - needs review |
| F047 | inconclusive | needs-review | needs_review | closed RDP attempts suggest lateral movement - needs review |
| F049 | benign | needs-review | needs_review | SafeBoot AlternateShell single registry source - needs review |
| F002 | needs-review | needs-review *(kept)* | needs_review | duplicate of F001; injection signal needs analyst review |

**Read of the table:** 2 promoted to confirmed (✅), 1 demoted to benign (🟢), and
**22 ⚖️ rows where the model wanted *confirmed* and code held the line** at
needs-review - that, plus the 3 kept-as-needs-review-despite-`confirmed` rows
(F035/F036/F054) outside the "moved" set, is the **27 → 2** gate:
2 promoted + 22 held + 3 kept = 27 model-`confirmed`, **25 refused**.

## See also - the full judge doc set
- **[`README.md`](README.md)** - project overview + submission compliance checklist.
- **[`JUDGE-QUICKSTART.md`](JUDGE-QUICKSTART.md)** - clone → run in five minutes (free `--demo`, no key).
- **[`ARCHITECTURE.md` §"Where the self-correction credit is earned"](ARCHITECTURE.md)** - the design (two layers + the safety net).
- **[`docs/DATASET.md`](docs/DATASET.md)** - evidence dataset (SANS Windows IR images; provenance + availability inside) + what the agent found.
- **[`docs/ACCURACY.md`](docs/ACCURACY.md)** - accuracy report / methodology.
- **`artifacts/run-rd01/agent_execution_log.txt`** (local Claude reference run, not committed) - the raw, timestamped trace cited throughout.
- **`artifacts/run-rd01/report.md`** (local) - the analyst-facing report the corrections feed into.
- **`demo_self_correction.py`** - run the self-correction engine on mock evidence (real validator, no API key).

---

> **Honest caveats.** *needs-review* is **not** *confirmed* - 36 findings went to
> needs-review, only 2 to confirmed; this page never inflates that. The
> `run-rd01` evidence is a SANS-published Windows IR image (provenance and
> availability notes in [`docs/DATASET.md`](docs/DATASET.md); the original
> SANS-hosted share is no longer public); the detectors carry **no hardcoded
> IOCs** (enforced by `audit/nocheat.py`). The corrections shown are one run's
> real output - re-running the pipeline on comparable evidence (e.g. the public
> cases in the README) reproduces the same gate behaviour, though exact counts
> depend on the evidence and the model's per-run reasoning.
