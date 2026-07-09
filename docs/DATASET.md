# Evidence Dataset Documentation

*(Required submission deliverable: what the agent was tested against, the source
of the data, and what it found.)*

> The Sentinel Qwen Ensemble **pipeline is dataset-agnostic** - it embeds no case
> names, IOCs, or answer keys (enforced by `audit/nocheat.py` + guard tests).
> This document records the *results* of running that neutral pipeline against
> evidence - the dataset documentation for this Qwen Cloud Track-4 submission.

## Datasets used

**Source:** all evidence is drawn from **public SANS Windows incident-response
images** (third-party DFIR image sets used to develop and validate the engine).
Nothing in this submission was tested against private or self-generated evidence.

The agent was developed and validated against these Windows incident-response
images spanning multiple OS versions and evidence shapes (memory-only, disk-only,
and paired memory+disk). Neither the raw images nor the per-run outputs (which
contain case-specific IOCs) are committed to this repo, per the **case-neutral
policy** - reproduce a run with `./setup.sh /path/to/case`; the demo video
shows a live Qwen run end to end.

> **Distribution note (2026-07-05):** the public download link that originally
> accompanied the starter case data (a SANS-hosted share) is no longer
> available, and the images are not redistributed here (third-party material +
> case-neutral policy). The docs now point at freely downloadable public
> practice cases instead (README "Get evidence to investigate" / JUDGE-QUICKSTART §4) - the pipeline
> is dataset-agnostic, so results reproduce on any Windows evidence.

| Case shape | OS | Evidence | Role |
|---|---|---|---|
| Paired (featured) | Windows Server 2012 R2 | memory (2 GB) + disk (2.4 GB) | **featured public case - DFIR Madness DC01, run live on Qwen Cloud (reproducible)** |
| Paired | Windows 10 / Server 2016+ | memory (3 GB) + disk (11.9 GB E01) | Claude reference run rd01 (secondary - atomic-confirmation proof, kept local) |
| Memory-only | Windows 7 / XP baselines | memory image | memory-only path + floor validation |
| Disk-only | Server 2012 R2 / Win7 / XP | disk (E01) | disk-only source-filter validation |

## What the agent found - featured public run (DFIR Madness DC01)

> **DC01 is the featured, primary case** - the DFIR Madness *Stolen Szechuan
> Sauce* domain-controller image, a **public case any judge can download and
> rerun** (`./setup.sh run /path/to/dc01`). Both tiers ran live on **Qwen Cloud
> (DashScope)**; the sanitized metrics ship in [`docs/qwen-runs/`](qwen-runs/) as
> `dc01-light-13aa-metrics.json` and `dc01-heavy-13aa-metrics.json`.

Configuration: `SIFT_INV3A_FINALIZE=1` + `SIFT_INV3A_REVIEW_ALL=1` (Step-13AA
consolidated finalization). Two model tiers, same evidence, same deterministic
gates:

| Tier | Model | Findings | Confirmed | Needs-review | Benign | Inconclusive | Runtime | Cost | Tools | Integrity |
|---|---|---|---|---|---|---|---|---|---|---|---|
| LIGHT | `qwen-plus` ×4 | 1 | **0** | 1 | 0 | 0 | 3m 46s | ~$0.22 | 33 swept / 29 hit / 0 failed | SHA256 MATCH |
| HEAVY | `qwen3.7-max` (4-member ensemble) | 44 | **0** | 21 | 23 | 0 | 14m 39s | ~$1.67 | 33 swept / 27 hit / 0 failed / 11 data-only | SHA256 MATCH |

**Depth scales with the model tier (1 → 44 findings); the confirmation bar does
not.** DC01 carries no atomic on-disk proof of the classic kind, so the honest
verdict is **0 confirmed on both tiers** - not a miss, but the **trust layer
holding every lead** at needs-review instead of over-claiming. Step-13AA
re-judged every ambiguous finding to a final verdict (**0 inconclusive**), and
**0 tools failed on either tier** (a fix pass added foremost + MFTECmd / SBECmd /
RBCmd and made SleuthKit offset-aware).

Despite 0 confirmations, the heavy ensemble reconstructed the **full intrusion**
and rated overall risk **CRITICAL** - attributed to `administrator` / `public`,
spanning **5 MITRE tactics**:

| Tactic (MITRE) | What the heavy ensemble surfaced on DC01 |
|---|---|
| Execution | `coreupdater.exe` run as an attacker C2 implant |
| Command & Control | `coreupdater.exe` beaconing to an external C2 endpoint |
| Lateral Movement | outbound **and** inbound RDP across internal hosts |
| Defense Evasion | code injection into `explorer.exe` / `svchost.exe` / `spoolsv.exe` |
| Persistence | scheduled task **+** WMI event-subscription |

Plus sensitive data staged for exfiltration from `\FileShare\Secret`. Every one
of these resolved to a **needs-review** disposition (never auto-promoted to
confirmed): full-picture depth without over-claiming.

**Evidence integrity (DC01):** the SHA256 of the memory image and of the disk
image was identical before and after analysis on **both tiers** - chain of
custody preserved by math.

## And when atomic proof *is* present, the same engine confirms (rd01)

DC01 held every lead at needs-review because it offered no atomic on-disk proof.
The **secondary Claude reference case rd01** is the control that shows the
confirmation path still fires when that proof exists. On the **same engine**, the
**heavy tier confirmed 4** atomic malicious findings on rd01:

- **PsExec** lateral movement
- **PWDumpX** credential dumping
- **IFEO `sethc.exe`** sticky-keys backdoor (Image-File-Execution-Options debugger hijack)
- **`p.exe`** executed from a temp directory

The **light tier confirmed 0** on the same case, and a **flags-off ablation**
(Step-13AA + review-all disabled) let **inconclusive findings rise from 0 → 11** -
direct evidence that the trust-layer finalization *resolves* uncertainty rather
than manufacturing confirmations. rd01 itself is the **Claude reference run** used
to prove the architecture before the Qwen port: **Claude Opus 4.8 (4-member
ensemble)**, run time 509s (8m 29s), cost ~$15.45 (token-derived est.), yielding
**49 findings → 2 confirmed (atomic) · 42 needs-review · 5 benign**, with code
(not the model) gating every promotion. Local artifacts (after `./setup.sh
/path/to/case`): `artifacts/run-rd01/report.md` and
`artifacts/run-rd01/agent_execution_log.txt` - kept **local, not committed**
(case-neutral policy).

**Self-correction on camera (rd01):** a service flagged as a possible C2 listener
was correctly re-classified **benign** by the ReAct cross-check after it
identified the binary as a legitimate signed forensic tool - no human
intervention.

> 📄 **Full self-correction proof** - every ReAct + Step-13AA correction from the
> rd01 run (46 ambiguous findings re-judged, ~40 self-corrected), before → after,
> with `agent_execution_log.txt` line refs:
> **[`SELF-CORRECTION-PROOF.md`](../SELF-CORRECTION-PROOF.md)**.

## Dataset-agnostic guarantee

No case-specific indicator (hostname, username, IP, tool name, PID, hash) is
embedded in pipeline code, prompts, or fixtures - detection is **behavioral and
structural only**. Enforced by `tests/test_agnostic_contract.py`,
`tests/test_analysis/test_investigation_answers_agnostic.py`, and the
commit-time `audit/nocheat.py` gate.
