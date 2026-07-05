# Evidence Dataset Documentation

*(Required submission deliverable: what the agent was tested against, the source
of the data, and what it found.)*

> The Sentinel Ensemble **pipeline is dataset-agnostic** - it embeds no case
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
policy** - reproduce a run with `./findevil.sh`; the demo video shows a live Qwen
run end to end.

> **Distribution note (2026-07-05):** the public download link that originally
> accompanied the starter case data (a SANS-hosted share) is no longer
> available, and the images are not redistributed here (third-party material +
> case-neutral policy). The docs now point at freely downloadable public
> practice cases instead (README step 3️⃣ / JUDGE-QUICKSTART §4) - the pipeline
> is dataset-agnostic, so results reproduce on any Windows evidence.

| Case shape | OS | Evidence | Role |
|---|---|---|---|
| Paired | Windows 10 / Server 2016+ | memory (3 GB) + disk (11.9 GB E01) | primary validation (Claude reference run rd01) |
| Memory-only | Windows 7 / XP baselines | memory image | memory-only path + floor validation |
| Disk-only | Server 2012 R2 / Win7 / XP | disk (E01) | disk-only source-filter validation |

## What the agent found - primary paired run (Claude reference)

> ⚠️ This is the **Claude reference run** (rd01) used to prove the architecture
> before the Qwen port - kept **local, not committed** (case-neutral policy). It
> is **not** a Qwen result; the **Qwen Cloud run regenerates** these numbers
> (shown in the demo). Paths below are local, after you run `./findevil.sh`.

Local run: `artifacts/run-rd01/report.md` · execution log:
`artifacts/run-rd01/agent_execution_log.txt` ·
model: Claude Opus 4.8 (4-member ensemble) · run time 509s (8m 29s) · cost ~$15.45 (token-derived est.).

**49 validator-backed findings/observations** → **2 confirmed malicious (atomic) · 42 suspicious / needs-review · 5 benign.**
Self-correction: 46 ambiguous findings re-judged · ~40 self-corrected (ReAct +
Step-13AA), with code - not the model - gating every promotion to confirmed.
The agent autonomously reconstructed a multi-stage intrusion:

| Stage (MITRE) | What the agent found |
|---|---|
| Defense Evasion (T1070.001) | Security event log cleared (Event ID 1102) |
| Execution (T1047 / T1059.001) | WMI provider spawning unsigned PowerShell; PowerShell with RWX-injected memory |
| Execution / Staging | `p.exe`, PWDumpX, NCPA staged + executed from `C:\Windows\Temp\` |
| Persistence (T1112 / T1547) | Sticky-keys (sethc.exe) IFEO debugger hijack; PSEXESVC service; SafeBoot AlternateShell |
| Credential Access (T1003) | Credential-dumping tool staged with confirmed hash + Executed flag |
| Lateral Movement (T1021) | Admin-share (SMB) access + RDP reconnaissance across internal hosts |
| C2 (T1071) | Beacon-pattern connections to internal + external endpoints |

**Self-correction on camera:** a service flagged as a possible C2 listener was
correctly re-classified **benign** by the ReAct cross-check after it identified
the binary as a legitimate signed forensic tool - no human intervention.

> 📄 **Full self-correction proof** - every ReAct + Step-13AA correction from this
> run, before → after, with `agent_execution_log.txt` line refs:
> **[`SELF-CORRECTION-PROOF.md`](../SELF-CORRECTION-PROOF.md)**.

**Evidence integrity:** SHA256 of both evidence files was identical before and
after analysis (chain of custody preserved by math).

## Dataset-agnostic guarantee

No case-specific indicator (hostname, username, IP, tool name, PID, hash) is
embedded in pipeline code, prompts, or fixtures - detection is **behavioral and
structural only**. Enforced by `tests/test_agnostic_contract.py`,
`tests/test_analysis/test_investigation_answers_agnostic.py`, and the
commit-time `audit/nocheat.py` gate.
