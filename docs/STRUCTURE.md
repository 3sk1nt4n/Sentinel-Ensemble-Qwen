# Project Structure

A map of the repository, so a new contributor knows where everything lives.
Package name is `sift_sentinel`; the product/repo is **Sentinel Ensemble**.

```
Sentinel-Ensemble/
├── findevil.sh / findevil.py     # ⭐ the one-command front door (delegates to step0_onboard)
├── step0_onboard.py              # conversational onboarding: find + profile + mount evidence
├── run_pipeline.py               # the 16-step conductor (deterministic Python)
├── console.py                    # interactive console
├── generate_report.py            # standalone report regeneration
├── start.sh / stop.sh            # MCP server lifecycle
├── requirements.txt / pyproject.toml
├── LICENSE                       # MIT
├── README.md                     # setup + compliance checklist
├── ARCHITECTURE.md               # system architecture + diagram (root-level deliverable)
├── JUDGE-QUICKSTART.md           # judge path · EXTENDING.md (add a tool) · ONBOARDING.md (contributor)
│
├── src/
│   ├── server.py                 # MCP server entry point (advertises 195 typed tools)
│   └── sift_sentinel/
│       ├── coordinator.py        # core pipeline engine (steps, invocations, ReAct loop)
│       ├── ensemble.py           # Inv2 multi-model fan-out + merge
│       ├── mcp_client.py         # typed MCP client (the AI's only tool channel)
│       ├── model_roles.py        # per-stage model resolution (env-driven, no hardcoded ids)
│       ├── pricing.py            # real-bill cost accounting
│       ├── os_capability.py      # OS / evidence-source tool applicability
│       ├── prompts.py            # invocation prompts
│       │
│       ├── onboard/              # Step-0: engine, presenter, AI advisor, archive handling
│       ├── tools/               # forensic tool wrappers (Volatility, Sleuth Kit, EZ Tools, ...)
│       ├── validation/          # reference_set.py (paired values) + validator.py
│       ├── analysis/            # disposition, confidence, dedup, malicious_semantics,
│       │                        #   logon_actor, network_ioc_rollup, finding_actor_time, ...
│       ├── reporting/           # narrative + customer findings table builders
│       ├── correction/          # self-correction loop
│       ├── schema/              # Pydantic Finding / AuditEntry models
│       ├── threads/             # investigation-thread helpers
│       └── runtime/             # runtime helpers
│
├── tests/                       # full pytest suite (deterministic validation, disposition,
│   │                            #   onboarding contracts, gates) - ~630 files
│   ├── test_validation/         # paired reference set + validator + drift gates
│   ├── test_analysis/           # disposition / confidence / actor-time
│   ├── test_tools/              # tool wrappers
│   └── regression/              # cross-cutting regression contracts
│
├── audit/
│   └── nocheat.py               # commit-time guard: bans answer-key vocab + case-specific artifacts
│
├── docs/                        # ACCURACY.md, this file, DATASET.md, INVOCATIONS.md,
│                                #   VALIDATOR.md + design/
├── yara_rules/                  # behavioural YARA signatures
├── scripts/ · bin/              # operational helpers
└── artifacts/                   # one complete run's outputs (report, findings, audit log)
```

## The five things a new user touches

| You want to… | Look at |
|---|---|
| **Run it** | `./findevil.sh` → `step0_onboard.py` |
| Understand the pipeline | [`ARCHITECTURE.md`](../ARCHITECTURE.md) (16 steps + diagrams) |
| Understand a finding's provenance | `src/sift_sentinel/validation/` + `artifacts/<run>/agent_execution_log.txt` |
| See what it was tested on | [`DATASET.md`](DATASET.md) |
| See how accurate it is | [`ACCURACY.md`](ACCURACY.md) |

## Where the AI is (and is not)

The AI (Claude via the Anthropic API) is invoked **5 times** inside
`coordinator.py` - tool selection, analysis, investigation threads, report -
plus the Step-13AA finalization sweep (the 5th AI call). **Everything else is deterministic Python.**
The AI's only tool channel is the typed MCP client (`mcp_client.py`); it has
**no shell access**. See [`ARCHITECTURE.md`](../ARCHITECTURE.md) for the full flow.
