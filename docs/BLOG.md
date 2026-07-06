---
title: "I built an autonomous DFIR agent on Qwen Cloud that refuses to trust itself"
published: false
tags: QwenCloud, AlibabaCloud, AIagents, DFIR
canonical_url:
description: An autonomous incident-response agent on Qwen models where deterministic code, not the model, gets the final word, and a two-tier run plus an ablation that proves the trust layer resolves uncertainty without ever manufacturing a confirmation.
---

> Built for the **Global AI Hackathon with Qwen Cloud** (Track 4, Autopilot
> Agent). Code: https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen (MIT).
> 2:52 demo in the repo.

## The problem nobody wants to say out loud

AI is being adopted fastest exactly where a wrong answer is most expensive:
security investigations, incident response, digital forensics. A SOC analyst
under pressure at 3 a.m. is *extremely* tempted to let a model write the verdict.

But you cannot ship a forensic conclusion you cannot audit. If an AI says "this
host is compromised," a court, an auditor, or an incident commander asks one
question: **prove it.** "The model was confident" is not proof.

So for this hackathon I built **Sentinel Ensemble**, an autonomous DFIR agent
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
./setup.sh run /path/to/case   # one line: builds the Docker image, forwards these envs, mounts evidence read-only
```

Model tiering keeps it cheap: `qwen-plus` for the high-volume work (ensemble,
ReAct, tool selection, report), `qwen3.7-max` reserved for keystone adjudication.
There is real DashScope-specific engineering under that seam, too: implicit
prompt-cache accounting (one heavy run reused **381,696 cached tokens**, ~36% off),
a `reasoning_content` fallback for Qwen thinking mode, per-model output-cap
clamps, and bounded read-timeout retries that fixed a live-run failure.

## Two tiers, one intrusion: 0 confirmed vs 4 confirmed

I ran the **same** real Windows intrusion case (memory + disk, both mounted
read-only, both SHA-256 verified) through the **identical trust layer** at two
Qwen model tiers. Nothing changed but the model. The runs record their own
provenance, so this is not a claim:

```json
"llm_provider": "qwen",
"model": "qwen3.7-max",
"llm_endpoint": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions",
"integrity_match": true
```

| | Light (`qwen-plus` x4) | Heavy (`qwen3.7-max`) |
|---|---|---|
| Findings (final) | 11 | 34 |
| **Confirmed malicious** | **0** | **4** |
| Runtime | 5m 37s | 14m 44s |
| Cost (cache-aware) | ~$0.28 | ~$1.53 |
| Integrity (mem + disk) | MATCH | MATCH |

On the **light** tier, the ensemble's strongest lead was code injection in
`powershell.exe`: a private memory region marked read-write-execute, the classic
signature of reflectively-loaded malware. The ReAct loop even pulled the VAD
details to confirm it. And then the deterministic layer **refused to confirm it.**
A RWX region is suggestive, not atomic proof, so the promotion gates held it back.
**11 findings, zero confirmed.** Not because the model was bad, but because none
of the leads cleared the evidence bar, and on this design *no evidence means no
confirmation.*

On the **heavy** tier the flagship reconstructed a real intrusion chain, and
**4 findings cleared every confirmation gate**: PsExec lateral movement, PWDumpX
credential dumping, an IFEO `sethc.exe` sticky-keys backdoor, and a payload run
from a temp directory. Each traces to the exact tool output that proved it.

**Same gates. Different depth.** The trust layer is the constant; the model tier
just changes how much clears the bar.

## The ablation: proving the layer resolves uncertainty (and nothing more)

Here is the experiment I care about most. A skeptic could say: sure, but does the
"trust layer" just rubber-stamp whatever the flagship wants? So I ran the **same
case, same `qwen3.7-max`**, and toggled only the Step-13AA finalization flags:

| Trust-layer finalization | Confirmed | Inconclusive |
|---|---|---|
| **ON** (as shipped) | **3** | **0** |
| **OFF** | **1** | **11** |

With finalization **off**, 11 findings are stranded at inconclusive and only one
clears confirmation. Turn it **on** and the layer re-judges every ambiguous
finding to a final verdict: inconclusive collapses to **0**, and the intrusion
chain re-confirms. Crucially, in *both* runs every promotion still had to pass
the same deterministic eligibility gate. **The layer resolves uncertainty; it
never manufactures a confirmation.** (That 3-confirmed reproduction is one shy of
June's 4, which is normal model non-determinism, and I would rather report that
honestly than round it up.)

That, to me, is the whole point: you can measure the trust, not just assert it.

## Why I think this matters

Most "AI agent" demos optimize for the happy path: look how much it found. The
harder and more valuable thing in high-stakes domains is the opposite: **look how
disciplined it is about what it refuses to claim.** Sentinel Ensemble is built so
the trust is *provable*: every confirmed finding traces to the exact tool output
that proves it, evidence is hashed before and after, and the code, not the model,
owns the verdict.

Qwen Cloud made the agent's reasoning cheap enough to run a four-member ensemble
plus a ReAct re-investigation loop on every case for the price of a coffee. The
trust layer made that reasoning *safe to act on.*

## Try it

- **Repo (MIT):** https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen
- **Zero-cost demo (no key, no evidence, any OS):** `./setup.sh docker`
- **Proof-of-Alibaba-Cloud code:** `src/sift_sentinel/llm_provider.py`
- **Shipped run metrics (both tiers + the ablation):** `docs/qwen-runs/`
- **Demo video:** <ADD-YOUTUBE-URL> (2:52, the overrule happens on camera)
