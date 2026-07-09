---
title: "I built an autonomous DFIR agent on Qwen Cloud that refuses to trust itself"
published: false
tags: QwenCloud, AlibabaCloud, AIagents, DFIR
canonical_url:
description: An autonomous incident-response agent on Qwen models where deterministic code, not the model, gets the final word, and a two-tier run plus an ablation that proves the trust layer resolves uncertainty without ever manufacturing a confirmation.
---

> **Autonomous Digital Forensics & Incident Response / Security Operations
> Center (DFIR/SOC) triage agent on Qwen Cloud (Alibaba DashScope) - Track 4
> Autopilot Agent. Deterministic trust layer: code, not the LLM model, decides
> what is confirmed.** Built for the **Global AI Hackathon with Qwen Cloud**.
> Code: https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen (MIT). 2:50 demo in
> the repo.

## The problem nobody wants to say out loud

AI is being adopted fastest exactly where a wrong answer is most expensive:
security investigations, incident response, digital forensics. A SOC analyst
under pressure at 3 a.m. is *extremely* tempted to let a model write the verdict.

But you cannot ship a forensic conclusion you cannot audit. If an AI says "this
host is compromised," a court, an auditor, or an incident commander asks one
question: **prove it.** "The model was confident" is not proof.

So for this hackathon I built **Sentinel Qwen Ensemble**, an autonomous DFIR agent
that runs end-to-end on **Qwen models hosted on Alibaba Cloud (DashScope)**, and
whose entire design is organized around a single rule:

> **The AI proposes. Deterministic code disposes. The model never gets the final word.**

## What it actually is (Track 4: an autopilot agent)

Point it at Windows evidence (a memory image, a disk image, or both) and walk
away. A **16-step deterministic conductor** runs the whole investigation with
zero human steering (the 16 steps, condensed):

1. SHA-256 fingerprints the evidence (chain of custody, before anything else).
2. Checks kernel integrity.
3. Asks Qwen which forensic tools to run for *this* evidence.
4. Runs them: **195 typed forensic tools** (Volatility 3, Sleuth Kit, EZ Tools,
   Plaso, YARA) exposed through a custom **MCP server with zero shell access**.
5. Builds a typed evidence database, cross-referencing every PID, IP, path, hash.
6. A **4-member Qwen ensemble** analyzes the evidence in parallel.
7. A deterministic validator checks **every claim** against the exact tool output
   that produced it.
8. A ReAct loop lets the agent re-investigate its own suspicious findings.
9. A consolidated Step-13AA adjudication, ~13 fail-closed promotion gates, and a
   final disposition step decide what, if anything, is "confirmed."
10. Out comes a verified, risk-ranked incident report, with an optional
    human-in-the-loop approval checkpoint before the report is written.

The model is only ever invoked *inside* well-bounded steps. Everything that
decides what reaches the report is plain, auditable Python.

## How it runs on Qwen Cloud (env only, no code change)

The whole port is one small provider seam, `make_llm_client()` plus a stdlib-only
DashScope (OpenAI-compatible) adapter. No model literal is hardcoded anywhere in
the 16-step pipeline; the provider and model are chosen purely by environment:

```bash
export SIFT_LLM_PROVIDER=qwen
export DASHSCOPE_API_KEY=...          # your Qwen Cloud key
export SIFT_DEFAULT_MODEL=qwen3.7-max
./setup.sh /path/to/case   # one line: builds the Docker image, forwards these envs, mounts evidence read-only
```

Model tiering keeps it cheap: `qwen-plus` for the high-volume work (ensemble,
ReAct, tool selection, report), `qwen3.7-max` reserved for keystone adjudication.
There is real DashScope-specific engineering under that seam, too: implicit
prompt-cache accounting (the rd01 heavy run reused **381,696 cached tokens**, ~36% off;
the featured DC01 heavy run reused **371,072**),
a `reasoning_content` fallback for Qwen thinking mode, per-model output-cap
clamps, and bounded read-timeout retries that fixed a live-run failure.

## Two tiers, one public case: depth scales, the confirmation bar doesn't

I ran the **same** real Windows intrusion case through the **identical trust
layer** at two Qwen model tiers. Nothing changed but the model. And the case is
**public and reproducible**: DFIR Madness "Stolen Szechuan Sauce" **DC01** (2 GB
memory + ~4.9 GB two-segment E01 disk), which any judge can download and rerun end to end. Both
images were mounted read-only and SHA-256 verified; the runs record their own
provenance, so this is not a claim:

```json
"llm_provider": "qwen",
"model": "qwen3.7-max",
"llm_endpoint": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions",
"integrity_match": true
```

| | Light (`qwen-plus` x4) | Heavy (`qwen3.7-max`) |
|---|---|---|
| Findings (final) | 1 | 44 |
| **Confirmed malicious** | **0** | **0** |
| Needs review | 1 | 21 |
| Benign | 0 | 23 |
| Runtime | 3m 46s | 14m 39s |
| Cost (cache-aware) | ~$0.22 | ~$1.67 |
| Tools (swept / hit / failed) | 33 / 29 / 0 | 33 / 27 / 0 |
| Integrity (mem + disk) | MATCH | MATCH |

On the **light** tier the ensemble surfaced a single lead, and the deterministic
layer held it at **needs-review** rather than confirming it. **1 finding, 0
confirmed.**

On the **heavy** tier the 4-member ensemble reconstructed the **entire intrusion**:
the `coreupdater.exe` C2 beacon, outbound and inbound RDP, data staged for exfil to
`\FileShare\Secret`, code injection into `explorer`/`svchost`/`spoolsv`, and
scheduled-task plus WMI persistence, attributed to `administrator`/`public` and
mapped to **5 MITRE tactics** (Execution, Persistence, Defense Evasion, Lateral
Movement, Command and Control), overall risk **CRITICAL**. That is **44 findings**
and the whole attack laid out. And still **0 confirmed**: 21 held at needs-review,
23 judged benign, **0 left inconclusive**. The engine saw the full compromise and
refused to stamp "confirmed" on a single lead, because none of them carried atomic
proof, and on this design *no evidence means no confirmation.*

**Depth scales with the model tier (1 -> 44 findings); the confirmation bar does
not.** The 0-confirmed result here is not a gap, it is the trust layer working. Two
more things held on both tiers: **0 tool failures** (a fix pass added `foremost`
plus MFTECmd/SBECmd/RBCmd and made Sleuth Kit offset-aware, so 33 tools swept with
none failing), and **0 inconclusive** findings, because the consolidated Step-13AA
adjudication skipped the wasteful generative self-correction and re-judged every
ambiguous finding to a final verdict.

## And when atomic proof is present, the same engine confirms

DC01 shows the engine holding leads honestly when nothing is atomic. A second real
intrusion case (`rd01`) shows the other half: when the evidence *is* atomic, the
identical layer **confirms**. On the heavy tier, **4 findings cleared every
confirmation gate**: PsExec lateral movement, PWDumpX credential dumping, an IFEO
`sethc.exe` sticky-keys backdoor, and a payload (`p.exe`) run from a temp directory.
Each traces to the exact tool output that proved it. On the light tier, `rd01`
confirmed **0**. Same gates, different depth: the bar is the constant, the model
tier just changes how much clears it.

## The ablation: the layer resolves uncertainty, it never manufactures a confirmation

Here is the experiment I care about most. A skeptic could say: sure, but does the
"trust layer" just rubber-stamp whatever the flagship wants? So on `rd01` I ran the
**same case, same `qwen3.7-max`**, and toggled only the Step-13AA finalization flags:

| Trust-layer finalization | Confirmed | Inconclusive |
|---|---|---|
| **ON** (as shipped) | **3** | **0** |
| **OFF** | **1** | **11** |

With finalization **off**, 11 findings are stranded at inconclusive and only one
clears confirmation. Turn it **on** and the layer re-judges every ambiguous
finding to a final verdict: inconclusive collapses from 11 to **0**, and the
intrusion chain re-confirms. Crucially, in *both* runs every promotion still had to
pass the same deterministic eligibility gate. **The layer resolves uncertainty; it
never manufactures a confirmation.** (That 3-confirmed reproduction is one shy of
June's 4, which is normal model non-determinism, and I would rather report that
honestly than round it up.)

That, to me, is the whole point: you can measure the trust, not just assert it.

## Why I think this matters

Most "AI agent" demos optimize for the happy path: look how much it found. The
harder and more valuable thing in high-stakes domains is the opposite: **look how
disciplined it is about what it refuses to claim.** Sentinel Qwen Ensemble is built so
the trust is *provable*: every confirmed finding traces to the exact tool output
that proves it, evidence is hashed before and after, and the code, not the model,
owns the verdict.

Qwen Cloud made the agent's reasoning cheap enough to run a four-member ensemble
plus a ReAct re-investigation loop on every case for the price of a coffee. The
trust layer made that reasoning *safe to act on.*

## Try it

- **Repo (MIT):** https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen
- **Zero-cost demo (no key, no evidence, any OS):** `./setup.sh docker` (Windows: `.\setup.cmd docker`)
- **Proof-of-Alibaba-Cloud code:** `src/sift_sentinel/llm_provider.py`
- **Shipped run metrics (public DC01 case, both tiers, plus the `rd01` confirm + ablation):** `docs/qwen-runs/`
- **Demo video (current cut):** `docs/sentinel-qwen-demo.mp4` (2:50, DC01 public case). YouTube https://youtu.be/NV6Zn0YrD1w is the previous cut, being refreshed to this one.
