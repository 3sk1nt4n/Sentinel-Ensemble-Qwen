# Run Sentinel Ensemble in Docker (any OS)

Run the agent on **Windows, macOS, or Linux** with nothing but Docker Desktop -
no SANS SIFT VM, no manual forensic-toolchain install. The agent, the commands,
and the trust layer are identical to the SIFT path; only the packaging differs.

> 🔒 The image **never contains a key**. `.env` and `*_API_KEY*` files are excluded
> by `.dockerignore`; you pass the key at runtime with `-e`. Evidence is mounted
> **read-only** (`:ro`), preserving chain of custody.

---

## Three image targets

| Target | Size | Adds on top | Use it for |
|---|---|---|---|
| `demo` | ~290 MB | Python + 4 deps only | The zero-cost `--demo` (synthetic case, **no key, no evidence, no tools**) |
| `full` | ~465 MB | + **Volatility 3, Sleuth Kit, EWF tools, YARA** | Real **memory/disk** investigations, lean image |
| `full-plus` **(default)** | ~990 MB | + **bulk_extractor, EZ Tools (EvtxECmd/RECmd, .NET 9), Plaso (log2timeline), RegRipper, pff-tools, photorec** | **Everything** the pipeline can call |

Base is pinned to Debian 12 "bookworm" for reproducibility (.NET needs `libicu72`).
Only the stages your target needs are built, so `--target demo` stays fast and
never compiles anything.

```bash
docker build --target demo -t sentinel-qwen:demo .   # tiny,  ~30s
docker build --target full -t sentinel-qwen:full .   # core,  ~2m
docker build -t sentinel-qwen .                       # everything (full-plus), ~15m
```

All tools were verified **running in the built image** (e.g. `vol` parsed a real
memory image read-only; `bulk_extractor` carved 403 email + 4,556 URL features
from a real memory slice; EvtxECmd/RECmd `2026.5.0`; Plaso `log2timeline 20260512`;
RegRipper lists 257 plugins).

---

## 1. Just try it (zero cost, ~30 seconds)

No API key, no evidence, no forensic tools needed.

```bash
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git
cd Sentinel-Ensemble-Qwen

docker build --target demo -t sentinel-qwen:demo .
docker run --rm -it sentinel-qwen:demo
```

You should see a synthetic case card ending in **"Everything verified and ready."**
That confirms the whole flow works on your machine. Press `Q` to quit.

---

## 2. A real investigation on Qwen Cloud

Build an image with the toolchain - `full` (lean, memory+disk) or `full-plus`
(everything) - then mount your evidence **read-only** and pass your Qwen key:

```bash
docker build -t sentinel-qwen .          # default target = full-plus (everything)

docker run --rm -it \
  -e SIFT_LLM_PROVIDER=qwen \
  -e DASHSCOPE_API_KEY=sk-your-key \
  -e SIFT_DEFAULT_MODEL=qwen3.7-max \
  -v /path/to/your/case:/evidence:ro \
  sentinel-qwen /evidence
```

- `-v /path/to/your/case:/evidence:ro` mounts your case folder (memory image,
  disk image, logs) read-only at `/evidence` (the image's default `EVIDENCE_DIR`).
- The last argument (`/evidence`) is the case path handed to `findevil.sh`.
- **Windows (PowerShell)** path example: `-v C:\cases\rd01:/evidence:ro`
- **macOS/Linux** path example: `-v $HOME/cases/rd01:/evidence:ro`

Confirm connectivity first (optional):

```bash
docker run --rm -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  --entrypoint python3 sentinel-qwen scripts/qwen_smoke.py
```

### Heavy "all-Max" reasoning (every step on the flagship)
Add these to put Inv1/Inv2/Inv3A/ReAct/Report all on `qwen3.7-max` (pricier, deepest):

```bash
  -e SIFT_INV2_ENSEMBLE_FORCE_MODEL=qwen3.7-max \
  -e SIFT_ENSEMBLE_MODELS=qwen3.7-max,qwen3.7-max,qwen3.7-max,qwen3.7-max \
  -e SIFT_ENSEMBLE_SIZE=4
```

### Anthropic fallback (optional)
The provider seam keeps the Anthropic path as a zero-regression fallback - set
`-e SIFT_LLM_PROVIDER=anthropic` and pass `-e ANTHROPIC_API_KEY=...` to run the
identical pipeline on Claude.

---

## 3. Analyzing an `.E01` disk image (needs FUSE)

Raw memory images (`.raw` / `.img` / `.vmem`) work with the plain command above -
Volatility 3 reads them directly. **Expert Witness (`.E01`) disk images** are
mounted via `ewfmount`, which needs FUSE inside the container, so add:

```bash
docker run --rm -it \
  --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
  -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  -e SIFT_DEFAULT_MODEL=qwen3.7-max \
  -v /path/to/your/case:/evidence:ro \
  sentinel-qwen /evidence
```

(`.E01` mounting needs these flags only because FUSE requires elevated
capabilities; the demo and pure-memory runs do not.)

---

## What each target covers (tool families)

| Capability | Binary | demo | full | full-plus |
|---|---|:--:|:--:|:--:|
| Memory forensics | `vol` (Volatility 3, ~138 plugins) | - | ✅ | ✅ |
| Disk / filesystem | Sleuth Kit (`fls icat mmls fsstat tsk_recover mactime sorter …`) | - | ✅ | ✅ |
| E01 mount / verify | `ewfmount ewfinfo ewfverify` | - | ✅ | ✅ |
| IOC scanning | `yara` | - | ✅ | ✅ |
| Carving / PII / network | `bulk_extractor` | - | - | ✅ |
| File carving | `photorec` (testdisk) | - | - | ✅ |
| Windows event logs | `EvtxECmd` (.NET 9) | - | - | ✅ |
| Windows registry | `RECmd` (.NET 9) + `rip.pl` (RegRipper) | - | - | ✅ |
| Super-timeline / log collection | `log2timeline.py` (Plaso) | - | - | ✅ |
| PST/OST email | `pffexport` | - | - | ✅ |

The pipeline degrades gracefully when an optional tool is absent (its tool-health
check marks it unavailable), so `full` still produces a complete memory/disk
investigation - `full-plus` just unlocks the artifact/timeline/carving tools too.

## Notes / honest limits

- `full-plus` is ~1 GB and takes ~15 min to build (two source compiles +
  the .NET 9 runtime). Use `--target full` if you only need memory/disk, or
  `--target demo` to just try the flow.
- **The container runs as root by design** - it mounts forensic images
  (`ewfmount`/FUSE for `.E01`, loop mounts), which require elevated capabilities.
  Blast radius is bounded: the container is ephemeral and single-purpose,
  **evidence is mounted read-only** (`:ro`), and the image carries **no API key**
  (`.env` excluded). Run one case per container and discard it (`--rm`).
- EZ Tools / Plaso versions track upstream "latest" at build time
  (EZ Tools download URLs are not version-pinned); rebuild to refresh them.

The **SANS SIFT VM** path in the [README](../README.md) is still a great fully
native environment, but `full-plus` now matches it for the tools the agent calls.
