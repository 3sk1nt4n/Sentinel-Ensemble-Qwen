# Verified Qwen Cloud run metrics (shipped evidence)

These files are the **sanitized aggregate metrics** for full paired
(memory + disk) investigations that ran end-to-end on **Qwen models via the
Alibaba Cloud DashScope API**. They are the source of the numbers quoted in
[`../../QWEN-SUBMISSION.md`](../../QWEN-SUBMISSION.md) and
[`../../README.md`](../../README.md).

### The two-tier headline (June reference runs)

| File | Tier | Model | Confirmed | Findings | Runtime | Integrity |
|---|---|---|---|---|---|---|
| [`light-run-metrics.json`](light-run-metrics.json) | LIGHT | `qwen-plus` ×4 | **0** | 11 | 5m 37s | mem+disk MATCH |
| [`heavy-run-metrics.json`](heavy-run-metrics.json) | HEAVY | `qwen3.7-max` | **4** | 34 | 14m 44s | mem+disk MATCH |

### Reproduction + ablation (2026-07-01, same case)

An independent rerun re-confirmed the result, and an ablation isolates what the
trust-layer finalization (Step-13AA + review-all) actually does:

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
with `./setup.sh run /path/to/case`; the demo video shows a live Qwen run end to end.

> The `llm_endpoint` in each file is itself part of the **Proof of Deployment on
> Alibaba Cloud**: it shows the run's reasoning went to the DashScope
> (Alibaba Cloud) endpoint, alongside the code file
> [`../../src/sift_sentinel/llm_provider.py`](../../src/sift_sentinel/llm_provider.py).
