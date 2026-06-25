---
title: "I built an autonomous DFIR agent on Qwen Cloud that refuses to trust itself"
published: false
tags: QwenCloud, AlibabaCloud, AIagents, DFIR
canonical_url:
description: An autonomous incident-response agent on Qwen models where deterministic code, not the model, gets the final word — and a real run where it overruled its own best lead.
---

> Created for the **Global AI Hackathon with Qwen Cloud** (Track 4 — Autopilot
> Agent). Code: https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen (MIT).
> 90-second demo in the repo.

## The problem nobody wants to say out loud

AI is being adopted fastest exactly where a wrong answer is most expensive:
security investigations, incident response, digital forensics. A SOC analyst
under pressure at 3 a.m. is *extremely* tempted to let a model write the verdict.

But you cannot ship a forensic conclusion you cannot audit. If an AI says
"this host is compromised," a court, an auditor, or an incident commander is
going to ask one question: **prove it.** "The model was confident" is not proof.

So for this hackathon I built **Sentinel Ensemble** — an autonomous DFIR agent
that runs end-to-end on **Qwen models hosted on Alibaba Cloud (DashScope)**, and
whose entire design is organized around a single rule:

> **The AI proposes. Deterministic code disposes. The model never gets the final word.**

## What it actually is (Track 4: an autopilot agent)

Point it at Windows evidence — a memory image, a disk image, or both — and walk
away. A **16-step deterministic conductor** runs the whole investigation with
zero human steering:

1. SHA-256 fingerprints the evidence (chain of custody, before anything else).
2. Checks kernel integrity.
3. Asks Qwen which forensic tools to run for *this* evidence.
4. Runs them — **195 typed forensic tools** (Volatility 3, Sleuth Kit, EZ Tools,
   Plaso) exposed through a custom **MCP server with zero shell access**.
5. Builds a typed evidence database, cross-referencing every PID, IP, path and hash.
6. A **4-member Qwen ensemble** analyzes the evidence in parallel.
7. A deterministic validator checks **every claim** against the exact tool output
   that produced it.
8. A ReAct loop lets the agent re-investigate its own suspicious findings.
9. Two layers of self-correction, ~13 fail-closed promotion gates, and a final
   disposition step decide what — if anything — is "confirmed."
10. Out comes a verified, risk-ranked incident report.

The model is only ever invoked *inside* well-bounded steps. Everything that
decides what reaches the report is plain, auditable Python.

## How it runs on Qwen Cloud (env only, no code change)

The whole port is one small provider seam — `make_llm_client()` plus a
stdlib-only DashScope (OpenAI-compatible) adapter. No model literal is hardcoded
anywhere in the 16-step pipeline; the provider and model are chosen purely by
environment:

```bash
export SIFT_LLM_PROVIDER=qwen
export DASHSCOPE_API_KEY=...          # your Qwen Cloud key
export SIFT_DEFAULT_MODEL=qwen3.7-max
./findevil.sh /path/to/case
```

Model tiering keeps it cheap: `qwen-plus` for the high-volume work (ensemble,
ReAct, tool selection, report), `qwen3.7-max` reserved for keystone adjudication.

## The run where the agent overruled itself

Here is the part I care about most, and it is the honest result.

I ran a **paired investigation** — a Windows memory image *and* its C: drive,
both mounted read-only — entirely on Qwen Cloud. The run records its own
provenance, so this isn't a claim:

```json
"llm_provider": "qwen",
"model": "qwen3.7-max",
"llm_endpoint": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions",
"integrity": "SHA-256 MATCH"   // on both images
```

The Qwen ensemble surfaced **19 findings**. Among them, its strongest lead:
**code injection in `powershell.exe` (PID 8712)** — a private memory region
marked read-write-execute, the classic signature of reflectively-loaded malware.
The ReAct loop even went back and pulled the VAD details "to confirm the
suspicious RWX memory."

And then the deterministic layer **refused to confirm it.**

A RWX region is *suggestive*. It is not an *atomic proof* of malicious code
execution. So two fail-closed gates — `NO_SPECULATIVE_CONFIRMED_GATE` and
`MISSING_RAW_EVIDENCE_CONFIRMED_GATE` — held the finding back and routed it to
*inconclusive*. Separately, a service (`macmnsvc.exe`) listening on odd ports
8081/8082 looked alarming; the agent re-investigated and correctly assessed it
**benign** (it's the McAfee agent).

Final disposition across memory and disk:

| Bucket | Count |
|---|---|
| Confirmed malicious | **0** |
| Needs review | 1 |
| Benign / false positive | 1 |
| Inconclusive | 18 |

**Nineteen AI findings. Zero confirmed.** Not because the model was bad — it
generated good leads — but because none of them cleared the evidence bar, and on
this design *no evidence means no confirmation.* That is the feature. An agent
that will happily escalate to "confirmed compromise" without proof is worse than
no agent at all.

The whole investigation took **6 minutes 22 seconds** and cost **about
35 cents** on Qwen Cloud.

## Why I think this matters

Most "AI agent" demos optimize for the happy path: look how much it found. The
harder and more valuable thing in high-stakes domains is the opposite —
**look how disciplined it is about what it refuses to claim.** Sentinel Ensemble
is built so that the trust is *provable*: every confirmed finding traces to the
exact tool output that proves it, evidence is hashed before and after, and the
code — not the model — owns the verdict.

Qwen Cloud made the agent's reasoning cheap enough to run a four-member ensemble
plus a ReAct re-investigation loop on every case for the price of a vending-machine
snack. The trust layer made that reasoning *safe to act on.*

## Try it

- **Repo (MIT):** https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen
- **Proof-of-Alibaba-Cloud code:** `src/sift_sentinel/llm_provider.py`
- **Demo video:** `docs/sentinel-qwen-demo.mp4` (the overrule happens on camera)
- **The run's own dashboard:** `docs/qwen_paired_dashboard.png`

#QwenCloud #AlibabaCloud #AIagents #DFIR
