# 🔁 Self-Correction Proof - the AI overruled, on the record

> **Maps to Technical Depth & Engineering + Innovation & AI Creativity.** This
> page is the receipt. Every number below is a timestamped line in the execution
> log of the **Claude reference run** (rd01) - `artifacts/run-rd01/agent_execution_log.txt`,
> a **local** run not committed to the repo (case-neutral policy; reproduce with
> `./findevil.sh`). It is an architecture demonstration, not a Qwen result; the
> shipped, verifiable Qwen Cloud run metrics are in
> [`docs/qwen-runs/`](docs/qwen-runs/). Nothing here is narration - it's grep-able
> once you regenerate the run.

Sentinel Ensemble corrects itself **twice**: once while it's *thinking* (Layer 1,
ReAct - the AI re-investigates its own findings and changes its mind), and once
while the system is *deciding* (Layer 2, Step 13AA - deterministic **code**
re-judges the AI's verdicts and refuses the ones it can't prove). The design is
in [`ARCHITECTURE.md` §"Where the self-correction credit is earned"](ARCHITECTURE.md);
this page is the **evidence** from the `run-rd01` reference run.

---

## 📊 Scoreboard (all from the `run-rd01` log)

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

## ✅ Verify it yourself (60 seconds, no API key)

Everything above is in the published log. Run these against the repo:

```bash
cd Sentinel-Ensemble
LOG=artifacts/run-rd01/agent_execution_log.txt

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
python3 demo_self_correction.py     # 3 strategies, incl. an honest UNRESOLVED failure
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
**21 ⚖️ rows where the model wanted *confirmed* and code held the line** at
needs-review - that, plus the 4 kept-as-needs-review-despite-`confirmed` rows
(F035/F036/F054 + duplicates) outside the "moved" set, is the **27 → 2** gate.

## See also - the full judge doc set
- **[`README.md`](README.md)** - project overview + submission compliance checklist.
- **[`JUDGE-QUICKSTART.md`](JUDGE-QUICKSTART.md)** - clone → run in five minutes (free `--demo`, no key).
- **[`ARCHITECTURE.md` §"Where the self-correction credit is earned"](ARCHITECTURE.md)** - the design (two layers + the safety net).
- **[`docs/DATASET.md`](docs/DATASET.md)** - evidence dataset (public SANS Windows IR images) + what the agent found.
- **[`docs/ACCURACY.md`](docs/ACCURACY.md)** - accuracy report / methodology.
- **`artifacts/run-rd01/agent_execution_log.txt`** (local Claude reference run, not committed) - the raw, timestamped trace cited throughout.
- **`artifacts/run-rd01/report.md`** (local) - the analyst-facing report the corrections feed into.
- **`demo_self_correction.py`** - run the self-correction engine on mock evidence (real validator, no API key).

---

> **Honest caveats.** *needs-review* is **not** *confirmed* - 36 findings went to
> needs-review, only 2 to confirmed; this page never inflates that. The
> `run-rd01` evidence is the **public SANS Windows IR image** (see
> [`docs/DATASET.md`](docs/DATASET.md)); the detectors carry **no hardcoded
> IOCs** (enforced by `audit/nocheat.py`). The corrections shown are one run's
> real output - re-running on the same image reproduces the same gate behaviour,
> though exact counts depend on the model's per-run reasoning.
