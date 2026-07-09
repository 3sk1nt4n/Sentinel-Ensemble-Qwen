# Verified Qwen Cloud run metrics (shipped evidence)

These files are the **sanitized aggregate metrics** for full paired
(memory + disk) investigations that ran end-to-end on **Qwen models via the
Alibaba Cloud DashScope API**. They are the source of the numbers quoted in
[`../../QWEN-SUBMISSION.md`](../../QWEN-SUBMISSION.md) and
[`../../README.md`](../../README.md).

### Featured run: DC01 (public, reproducible) - the trust layer holding honestly

DC01 is the **primary, featured case**: the PUBLIC DFIR Madness "Stolen Szechuan
Sauce" domain controller (memory 2 GB + disk 2.4 GB) that any judge can download
and rerun end to end. Both tiers ran with the Step-13AA consolidated
finalization (`SIFT_INV3A_FINALIZE=1` + `SIFT_INV3A_REVIEW_ALL=1`).

| File | Tier | Model | Confirmed | Needs-review | Benign | Findings | Runtime | Cost | Integrity |
|---|---|---|---|---|---|---|---|---|---|
| [`dc01-light-13aa-metrics.json`](dc01-light-13aa-metrics.json) | LIGHT | `qwen-plus` ×4 | **0** | 1 | 0 | 1 | 3m 46s | ~$0.22 | mem+disk SHA256 MATCH |
| [`dc01-heavy-13aa-metrics.json`](dc01-heavy-13aa-metrics.json) | HEAVY | `qwen3.7-max` (4-member ensemble) | **0** | 21 | 23 | 44 | 14m 39s | ~$1.67 | mem+disk SHA256 MATCH |

The heavy tier surfaced the **full intrusion**: `coreupdater.exe` C2, outbound
and inbound RDP, `\FileShare\Secret` exfil, memory injection (explorer / svchost
/ spoolsv), and scheduled-task + WMI persistence; attributed to administrator /
public; **5 MITRE tactics** (Execution, Persistence, Defense Evasion, Lateral
Movement, Command and Control); overall risk **CRITICAL**. And it **held every
lead**: **0 confirmed** is the trust layer working, not a gap - no atomic proof
was present in this case, so nothing was auto-promoted. **0 tool failures** on
both tiers (33 tools swept; light 29 hit, heavy 27 hit + 11 data-only), and
Step-13AA resolved every ambiguous finding to a final verdict (**0 inconclusive**).

> **Depth scales with the model tier (1 -> 44 findings); the confirmation bar does not.**

### And when atomic proof IS present, the same engine confirms (rd01)

On a held-back case where atomic proof exists on disk, the identical engine
promotes it. The June reference runs are the two-tier baseline:

| File | Tier | Model | Confirmed | Findings | Runtime | Integrity |
|---|---|---|---|---|---|---|
| [`light-run-metrics.json`](light-run-metrics.json) | LIGHT | `qwen-plus` ×4 | **0** | 11 | 5m 37s | mem+disk MATCH |
| [`heavy-run-metrics.json`](heavy-run-metrics.json) | HEAVY | `qwen3.7-max` | **4** | 34 | 14m 44s | mem+disk MATCH |

Heavy confirmed **4** on atomic evidence - PsExec lateral movement, PWDumpX
credential dumping, an IFEO `sethc.exe` sticky-keys backdoor, and `p.exe` run
from a temp dir - while light confirmed **0**. An independent rerun and an
ablation isolate what the trust-layer finalization (Step-13AA + review-all)
actually does:

| File | Trust-layer flags | Confirmed | Inconclusive | Findings | Runtime |
|---|---|---|---|---|---|
| [`heavy-repro-20260701-metrics.json`](heavy-repro-20260701-metrics.json) | **ON** (as shipped) | **3** | **0** | 22 | 18.7m |
| [`heavy-ablation-no13aa-20260701-metrics.json`](heavy-ablation-no13aa-20260701-metrics.json) | **OFF** | **1** | **11** | 21 | 11.0m |

Same case, same `qwen3.7-max`, same deterministic gates - only the finalization
flags differ. With them **on**, 13AA re-judges every ambiguous finding to a final
verdict (**0 inconclusive**) and the intrusion chain re-confirms; with them
**off**, 11 findings stay inconclusive and only 1 clears confirmation. The layer
**resolves uncertainty and never manufactures confirmations**: every promotion,
in both runs, still had to pass the same deterministic eligibility gate. (The
reproduction's 3 confirmed vs June's 4 is normal model non-determinism.)

Each file records `llm_provider: qwen`, the live `llm_endpoint`
(`https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions`), the
`model`, `disposition_counts`, `token_usage` (including DashScope
`total_cache_read`), and `integrity_match` - straight from the run's summary JSON.

**Field semantics** (so the JSON arithmetic reads correctly): `findings_total`
snapshots the candidate set entering Step-10 validation; the ReAct investigation
threads can *add* findings after that point, so `findings_passed` can exceed
`findings_total`; and `findings_final_count` is the post-dedup,
post-reconciliation report set. The three counters legitimately differ
(`run_pipeline.py` builds them at different pipeline stages).

**Why only aggregates?** Per the repo's **case-neutral policy**, full run outputs
(which contain case-specific IOCs: hostnames, paths, PIDs) are never committed.
These files carry only provider/model/endpoint, counts, timings, tokens, and the
integrity verdict - no case tokens. Reproduce the full run on your own evidence
with `./setup.sh /path/to/case`; the demo video shows a live Qwen run end to end.

> The `llm_endpoint` in each file is itself part of the **Proof of Deployment on
> Alibaba Cloud**: it shows the run's reasoning went to the DashScope
> (Alibaba Cloud) endpoint, alongside the code file
> [`../../src/sift_sentinel/llm_provider.py`](../../src/sift_sentinel/llm_provider.py).
