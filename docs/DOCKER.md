# Run Sentinel Ensemble in Docker (any OS)

Runs on **Windows, macOS, or Linux** with nothing but **Docker Desktop** - no
VM, no forensic-toolchain install. Two commands cover everything on this page:

```bash
./setup.sh docker                   # zero-cost demo - no key, no evidence (~30 s)
./setup.sh run /path/to/your/case   # real investigation - ONE line does everything
```

`./setup.sh run` builds the image on first use, reads your key from `.env` /
the environment (or asks once, hidden), applies the verified-run config, adds
the `.E01`/FUSE capabilities, and mounts your evidence **read-only**.

**Neither command assumes Docker is installed.** If it's missing, `./setup.sh`
offers to install it for you (Linux, official `get.docker.com` script), guides
you to Docker Desktop on Windows/macOS, starts a stopped daemon, and falls back
to `sudo docker` automatically when your user isn't in the docker group.
*(Windows: run these inside WSL2 or Git Bash.)* Everything below is reference:
what those two lines run, and the manual equivalents.

> 🔒 The image **never contains a key**. `.env` and `*_API_KEY*` files are excluded
> by `.dockerignore`; the key is passed at runtime. Evidence is mounted
> **read-only** (`:ro`), preserving chain of custody.

---

## 1. Just try it (zero cost, ~30 seconds)

```bash
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git && cd Sentinel-Ensemble-Qwen
./setup.sh docker
```

You should see a synthetic case card ending in **"Everything verified and ready."**
That confirms the whole flow works on your machine. No API key, no evidence,
no forensic tools needed.

<details>
<summary>Manual equivalent (what the one line runs)</summary>

```bash
docker build --target demo -t sentinel-qwen:demo .
docker run --rm -it sentinel-qwen:demo
```

</details>

---

## 2. A real investigation on Qwen Cloud

```bash
./setup.sh run /path/to/your/case
```

That's the whole command. It handles the rest:

- **Key**: read from `.env` (`cp .env.qwen.example .env`) or `DASHSCOPE_API_KEY`;
  otherwise it asks once at a hidden prompt (never stored in the image).
- **Evidence**: put one case's files (memory image, disk image, logs) in one
  folder and pass that folder - it is mounted read-only.
- **Config**: the verified-run settings (`SIFT_HTTP_TIMEOUT=600`,
  `SIFT_ALLOW_YARA=1`) and the `.E01`/FUSE capabilities are applied for you;
  any `SIFT_*` / `DASHSCOPE_*` variable you set is forwarded into the container.
- **Results land on your machine**: the container is ephemeral (`--rm`), but the
  report, HTML dashboard, and disposition buckets are saved to
  `sentinel-results/<case-name>/` in the repo folder.

> **No evidence handy?** Free public Windows cases with direct downloads (no
> login; links verified 2026-07-05): **DFIR Madness "The Stolen Szechuan Sauce"**
> ([DC01 memory](https://dfirmadness.com/case001/DC01-memory.zip) 0.6 GB +
> [DC01 disk](https://dfirmadness.com/case001/DC01-E01.zip) 4.8 GB - paired,
> recommended) · **NIST CFReDS "Data Leakage Case"**
> ([PC disk E01](https://cfreds-archive.nist.gov/data_leakage_case/images/pc/cfreds_2015_data_leakage_pc.E01)
> 2.1 GB, disk-only) · **Digital Corpora
> ["Lone Wolf"](https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/)**
> (paired Windows 10, ~32 GB). Unzip into one folder and pass that folder.

**Optional one-liners** (env vars prefix the same command):

```bash
# connectivity check first (one cheap call, uses the demo image from step 1)
docker run --rm -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  --entrypoint python3 sentinel-qwen:demo scripts/qwen_smoke.py

# heavy "all-Max": every stage on the flagship (pricier, deepest)
SIFT_INV2_ENSEMBLE_FORCE_MODEL=qwen3.7-max \
SIFT_ENSEMBLE_MODELS=qwen3.7-max,qwen3.7-max,qwen3.7-max,qwen3.7-max \
SIFT_ENSEMBLE_SIZE=4 ./setup.sh run /path/to/your/case

# Anthropic fallback (zero-regression provider seam, identical pipeline)
SIFT_LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-... ./setup.sh run /path/to/your/case
```

<details>
<summary>Manual equivalent (what the one line runs)</summary>

```bash
docker build -t sentinel-qwen .          # default target = full-plus (everything)

# (--cap-add/--device/--security-opt enable .E01 disk mounting via FUSE - §3;
#  harmless for memory-only. The two SIFT_* envs match the verified-run config.)
docker run --rm -it \
  --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
  -e SIFT_LLM_PROVIDER=qwen \
  -e DASHSCOPE_API_KEY=sk-your-key \
  -e SIFT_DEFAULT_MODEL=qwen3.7-max \
  -e SIFT_HTTP_TIMEOUT=600 -e SIFT_ALLOW_YARA=1 \
  -v /path/to/your/case:/evidence:ro \
  sentinel-qwen /evidence
```

- `-v /path/to/your/case:/evidence:ro` mounts your case folder read-only at
  `/evidence`; the trailing argument is the case path handed to `findevil.sh`
  (the container entrypoint).
- **Windows (PowerShell)** path example: `-v C:\cases\rd01:/evidence:ro`
- **macOS/Linux** path example: `-v $HOME/cases/rd01:/evidence:ro`

</details>

---

## 3. Analyzing an `.E01` disk image (needs FUSE)

**Nothing to do - `./setup.sh run` passes the FUSE capabilities automatically.**
Raw memory images (`.raw`/`.img`/`.vmem`/`.mem`) need no special handling at all.

<details>
<summary>Why, and the manual flags</summary>

Expert Witness (`.E01`) disk images are mounted via `ewfmount`, which needs
FUSE inside the container. Manual runs must add:

```bash
--cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined
```

These flags exist only because FUSE requires elevated capabilities; the demo
and pure-memory runs do not need them.

</details>

---

## Reference: images, tools, limits

### Three image targets

| Target | Size | Adds on top | Use it for |
|---|---|---|---|
| `demo` | ~290 MB | Python + the pinned deps only | The zero-cost demo (synthetic case, **no key, no evidence, no tools**) |
| `full` | ~485 MB | + **Volatility 3, Sleuth Kit, EWF tools, YARA** | Real **memory/disk** investigations, lean image |
| `full-plus` **(default)** | ~1 GB | + **bulk_extractor, EZ Tools (EvtxECmd/RECmd, .NET 9), Plaso (log2timeline), RegRipper, pff-tools, photorec** | **Everything** the pipeline can call |

<details>
<summary>Manual build commands + base-image note</summary>

```bash
docker build --target demo -t sentinel-qwen:demo .   # tiny,  ~30s
docker build --target full -t sentinel-qwen:full .   # core,  ~2m
docker build -t sentinel-qwen .                       # everything (full-plus), ~15m
```

Base is pinned to Debian 12 "bookworm" for reproducibility (.NET needs
`libicu72`). Only the stages your target needs are built, so `--target demo`
stays fast and never compiles anything.

</details>

All tools were verified **running in the built image** (e.g. `vol` parsed a real
memory image read-only; `bulk_extractor` carved 403 email + 4,556 URL features
from a real memory slice; EvtxECmd/RECmd `2026.5.0`; Plaso `log2timeline 20260512`;
RegRipper lists 257 plugins). The **`.E01` path is verified in-container** too:
a real paired case (12 GB `.E01` + 3 GB memory image) was classified, mounted
read-only via ewf/ntfs-3g, and onboarded end-to-end (`--dry-run`) inside the
image with the documented FUSE capabilities (verified 2026-07-05).

### What each target covers (tool families)

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
| Execution history (confirm path) | `AmcacheParser` · `AppCompatCacheParser` (.NET 9) + `strings` | - | - | ✅ |
| Network usage / LNK / jumplists | `SrumECmd` · `LECmd` · `JLECmd` (.NET 9) | - | - | ✅ |
| Super-timeline / log collection | `log2timeline.py` (Plaso) | - | - | ✅ |
| PST/OST email | `pffexport` | - | - | ✅ |

The pipeline degrades gracefully when an optional tool is absent (its tool-health
check marks it unavailable), so `full` still produces a complete memory/disk
investigation - `full-plus` just unlocks the artifact/timeline/carving tools too.

### Notes / honest limits

- `full-plus` is ~1 GB and takes ~15 min to build (two source compiles +
  the .NET 9 runtime) - one time; `./setup.sh run` reuses it afterwards.
- **The container runs as root by design** - it mounts forensic images
  (`ewfmount`/FUSE for `.E01`, loop mounts), which require elevated capabilities.
  Blast radius is bounded: the container is ephemeral and single-purpose,
  **evidence is mounted read-only** (`:ro`), and the image carries **no API key**
  (`.env` excluded). Run one case per container and discard it (`--rm`).
- EZ Tools / Plaso versions track upstream "latest" at build time
  (EZ Tools download URLs are not version-pinned); rebuild to refresh them.

Contributors hacking on the code natively (test suite, tool development):
see [`ONBOARDING.md`](../ONBOARDING.md) - the `full-plus` image carries every
tool the agent itself calls.
