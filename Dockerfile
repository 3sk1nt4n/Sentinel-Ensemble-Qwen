# Sentinel Ensemble - Qwen edition - container image
#
# Three build targets (pick by size / completeness):
#   demo       ~290 MB  python + the pinned deps in requirements.txt. `findevil.sh --demo` (NO key, NO
#                       evidence, NO forensic tools). The fastest "just try it".
#   full       ~485 MB  demo + the memory/disk core: Volatility 3, Sleuth Kit,
#                       EWF tools, YARA. Real memory/disk runs.
#   full-plus  ~1 GB    full + every high-value tool the pipeline invokes:
#                       bulk_extractor, EZ Tools (EvtxECmd/RECmd via .NET 9),
#                       Plaso (log2timeline), RegRipper, pff-tools, photorec.
#                       This is the DEFAULT target (everything-in-Docker).
#
# Build:   docker build --target demo -t sentinel-qwen:demo .   # tiny, ~30s
#          docker build --target full -t sentinel-qwen:full .   # core, ~2m
#          docker build -t sentinel-qwen .                       # full-plus, ~15m
# Try it:  docker run --rm -it sentinel-qwen:demo                # zero-cost demo
#
# Base pinned to Debian 12 "bookworm" (reproducible; .NET needs libicu72, which
# the rolling python:3.12-slim -> Debian 13 "trixie" tag no longer provides).
# The image NEVER contains a key: .env is excluded by .dockerignore; pass the
# key at runtime with -e DASHSCOPE_API_KEY=... (see docs/DOCKER.md).

# ======================================================================
# Builder stages (only built when the target needs them, e.g. full-plus)
# ======================================================================

# ---- bulk_extractor builder (v2.1.0 from source; not in Debian apt) ----
FROM python:3.12-slim-bookworm AS be-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool flex \
        libssl-dev libexpat1-dev zlib1g-dev libewf-dev libre2-dev \
        git ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v2.1.0 --recurse-submodules --shallow-submodules \
        https://github.com/simsong/bulk_extractor.git /tmp/be \
 && cd /tmp/be \
 && ./bootstrap.sh \
 # bookworm pkg-config emits a -Wl,--push-state/--pop-state pair that configure
 # reorders into "--pop-state ... --push-state", breaking ld. Strip those flags
 # from RE2_LIBS; re2 still links via its plain -l flag.
 && RE2_LIBS="$(pkg-config --libs re2 | sed -E 's/-Wl,--(push|pop)-state[^ ]*//g')" \
 && ./configure --quiet RE2_LIBS="$RE2_LIBS" \
 && make -j"$(nproc)" \
 && make install \
 && strip /usr/local/bin/bulk_extractor

# ---- Plaso builder: compile the libyal C-extension wheels --------------
FROM python:3.12-slim-bookworm AS plaso-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*
# Install into a relocatable prefix we copy into the final image. pip can return
# 0 even if a wheel fails, so assert the entrypoint actually works afterwards.
RUN pip install --no-cache-dir --prefix=/install plaso==20260512
# pip can exit 0 even when a wheel fails to build, so assert the entrypoint
# actually imports. The real console script is `log2timeline` (NO .py); the .py
# shims the pipeline calls are added in the final stage.
RUN PYTHONPATH="/install/lib/python3.12/site-packages" /install/bin/log2timeline --version

# ======================================================================
# Shared base: code + python deps
# ======================================================================
FROM python:3.12-slim-bookworm AS base
# Image-wide default provider: a bare `docker run` is a Qwen run (env overrides win)
ENV SIFT_LLM_PROVIDER=qwen
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
# Normalize CRLF -> LF on shell scripts so a Windows checkout (Git autocrlf=true
# rewrites them to CRLF) still runs inside this Linux container. Without this,
# bash fails on the very first line: "set: pipefail: invalid option name".
# Belt-and-suspenders alongside .gitattributes (which fixes it at clone time).
RUN find . -type f -name '*.sh' -exec sed -i 's/\r$//' {} + 2>/dev/null || true
RUN chmod +x findevil.sh 2>/dev/null || true
VOLUME ["/evidence"]
ENTRYPOINT ["bash", "findevil.sh"]
CMD ["--demo"]

# ---- demo target: light, just the base ---------------------------------
FROM base AS demo

# ---- full target: base + the memory/disk forensic core -----------------
FROM base AS full
RUN apt-get update && apt-get install -y --no-install-recommends \
        sleuthkit ewf-tools libewf-dev yara fuse3 util-linux procps ca-certificates \
        sudo ntfs-3g dmsetup binutils \
    && rm -rf /var/lib/apt/lists/*
# binutils provides `strings`, which get_amcache uses to pull execution-history
# SHA1s out of Amcache.hve - the atomic-proof source the confirm floor needs.
RUN pip install volatility3==2.28.0

# ---- full-plus target (DEFAULT): full + every high-value tool ----------
FROM full AS full-plus

# pff-tools (PST/OST email: pffexport) + testdisk/photorec (carving) - cheap apt
RUN apt-get update && apt-get install -y --no-install-recommends \
        pff-tools testdisk \
    && rm -rf /var/lib/apt/lists/*

# bulk_extractor: binary from builder + its one extra runtime lib (bookworm: libre2-9)
RUN apt-get update && apt-get install -y --no-install-recommends libre2-9 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=be-builder /usr/local/bin/bulk_extractor /usr/local/bin/bulk_extractor

# Plaso: copy the compiled prefix (no compiler shipped) + add the .py shims the
# pipeline calls (modern plaso ships log2timeline / psort / pinfo without .py).
COPY --from=plaso-builder /install /usr/local
RUN for t in log2timeline psort pinfo image_export; do \
        ln -sf /usr/local/bin/$t /usr/local/bin/$t.py; \
    done

# RegRipper 3.0 (pipeline calls bare `rip.pl` on PATH)
RUN apt-get update \
 && apt-get install -y --no-install-recommends perl libparse-win32registry-perl git \
 && git clone --depth 1 https://github.com/keydet89/RegRipper3.0.git /opt/regripper \
 && rm -rf /opt/regripper/.git \
 # RegRipper ships CRLF + a Windows shebang; normalize both for Linux perl:
 && find /opt/regripper -type f \( -name '*.pl' -o -name '*.pm' \) -exec sed -i 's/\r$//' {} + \
 && sed -i '1s|.*|#!/usr/bin/perl|' /opt/regripper/rip.pl \
 && chmod +x /opt/regripper/rip.pl \
 && ln -s /opt/regripper/rip.pl /usr/local/bin/rip.pl \
 && apt-get purge -y git && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# EZ Tools via the .NET 9 runtime. The pipeline calls the BARE tool names on
# PATH, so install a wrapper script named exactly like each tool's .dll.
# These feed the CONFIRM path: AmcacheParser/AppCompatCacheParser give the
# execution+hash atomic proof, SrumECmd the network-usage corroboration,
# LECmd/JLECmd the LNK/jumplist activity. Missing them silently caps every
# run at 0 confirmed on cases whose proof lives on disk (regression fix).
ENV DOTNET_ROOT=/opt/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    PATH=/opt/dotnet:/usr/local/bin:$PATH
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl unzip ca-certificates libicu72; \
    curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh; \
    chmod +x /tmp/dotnet-install.sh; \
    /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir /opt/dotnet --no-path; \
    mkdir -p /opt/zimmermantools; cd /opt/zimmermantools; \
    for t in EvtxECmd RECmd AmcacheParser AppCompatCacheParser SrumECmd LECmd JLECmd; do \
        curl -fsSL -o "$t.zip" "https://download.ericzimmermanstools.com/net9/$t.zip"; \
        unzip -q -o "$t.zip"; rm -f "$t.zip"; \
        dll="$(find /opt/zimmermantools -iname "$t.dll" | head -1)"; \
        [ -n "$dll" ] || { echo "FATAL: $t.dll not found after unzip" >&2; exit 1; }; \
        printf '#!/bin/sh\nexec /opt/dotnet/dotnet "%s" "$@"\n' "$dll" > "/usr/local/bin/$t"; \
        chmod +x "/usr/local/bin/$t"; \
    done; \
    test -f /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb; \
    rm -rf /tmp/dotnet-install.sh /var/lib/apt/lists/*
