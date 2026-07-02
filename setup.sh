#!/usr/bin/env bash
# =============================================================================
# setup.sh - ONE command to install + verify everything Sentinel Ensemble needs.
#            Global AI Hackathon with Qwen Cloud - Track 4 (Autopilot Agent).
#
#   ./setup.sh            install what pip/apt can, verify EVERYTHING, run the demo
#   ./setup.sh docker     build + run the zero-cost demo in Docker (any OS, no Python)
#   ./setup.sh --check    check only (doctor mode - no install, no sudo)
#   ./setup.sh --no-sudo  install pip deps + check; skip apt system packages
#
# The DEMO and the judge path need NO API key and NO forensic tools. Forensic
# tools (Volatility 3, Sleuth Kit, ...) are only needed for REAL evidence runs
# and are reported as OPTIONAL. A DashScope (Qwen Cloud) key is only needed for a
# LIVE run. Exit 0 = ready for the demo + tests. Non-zero = a CORE item is missing.
# =============================================================================
set -uo pipefail   # NOT -e: run ALL checks and report, never abort on the first

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# ── arg parsing ──────────────────────────────────────────────────────────────
MODE_INSTALL=1; USE_SUDO=1; DOCKER=0
for a in "$@"; do
  case "$a" in
    docker)    DOCKER=1 ;;
    --check)   MODE_INSTALL=0; USE_SUDO=0 ;;
    --no-sudo) USE_SUDO=0 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  esac
done

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; C=$'\e[36m'; X=$'\e[0m'
else G=; R=; Y=; B=; C=; X=; fi
FAIL=0; WARN=0
sec()  { printf "\n${B}== %s ==${X}\n" "$1"; }
ok()   { printf "  ${G}OK${X}   %s\n" "$1"; }
warn() { printf "  ${Y}WARN${X} %s\n" "$1"; WARN=$((WARN+1)); }
bad()  { printf "  ${R}FAIL${X} %s\n" "$1"; FAIL=$((FAIL+1)); }
note() { printf "  ${B}--${X}   %s\n" "$1"; }

# =============================================================================
#  DOCKER PATH - works on any OS, no Python/forensic install needed
# =============================================================================
if [ "$DOCKER" = 1 ]; then
  printf "${B}Sentinel Ensemble - Docker demo${X}\n"
  command -v docker >/dev/null 2>&1 || { printf "  ${R}FAIL${X} Docker not found. Install Docker Desktop (docker.com), then: ./setup.sh docker\n"; exit 1; }
  docker info >/dev/null 2>&1 || { printf "  ${R}FAIL${X} Docker is installed but not running. Start Docker Desktop and re-run.\n"; exit 1; }
  sec "Building the zero-cost demo image (~290 MB, one time)"
  docker build --target demo -t sentinel-qwen:demo . || { printf "  ${R}FAIL${X} build failed (see above)\n"; exit 1; }
  ok "image built: sentinel-qwen:demo"
  sec "Running the demo (no key, no evidence)"
  docker run --rm sentinel-qwen:demo || { printf "  ${R}FAIL${X} demo run failed\n"; exit 1; }
  printf "\n  ${G}${B}✅  Docker demo works.${X}\n"
  printf "  ${B}Real investigation on Qwen Cloud:${X}\n"
  printf "    1) DashScope key: home.qwencloud.com/api-keys (Model Studio, Singapore/Intl)\n"
  printf "    2) docker build -t sentinel-qwen .          ${Y}# full toolchain image${X}\n"
  printf "    3) docker run --rm -it -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \\\\\n"
  printf "         -e SIFT_DEFAULT_MODEL=qwen3.7-max -v /path/to/case:/evidence:ro sentinel-qwen /evidence\n"
  printf "    Full guide: docs/DOCKER.md\n\n"
  exit 0
fi

# =============================================================================
#  LOCAL / SIFT VM PATH
# =============================================================================
printf "${B}Sentinel Ensemble - setup & health check${X}  (Track 4, Qwen Cloud)\n(%s)\n" \
  "$([ $MODE_INSTALL = 1 ] && echo 'install + verify + run demo' || echo 'verify only')"

# ── 1. Python interpreter + venv ────────────────────────────────────────────
sec "Python"
if ! command -v python3 >/dev/null 2>&1; then
  bad "python3 not found - install Python 3.10+ first"; printf "\n"; exit 1
fi
ok "python3 $(python3 -V 2>&1 | awk '{print $2}')"
VENV_DIR="$REPO_DIR/.venv"
_venv_ok() { [ -x "$VENV_DIR/bin/python" ] && "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1; }
_mkvenv()  { rm -rf "$VENV_DIR" 2>/dev/null; python3 -m venv "$VENV_DIR" >/dev/null 2>&1; _venv_ok; }
if [ -n "${VIRTUAL_ENV:-}" ]; then
  ok "virtualenv active: $VIRTUAL_ENV"
elif _venv_ok; then
  . "$VENV_DIR/bin/activate" && ok "using project venv: $VENV_DIR"
elif [ $MODE_INSTALL = 1 ]; then
  if [ $USE_SUDO = 1 ] && command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y python3-venv >/dev/null 2>&1 || true
  fi
  if _mkvenv; then
    . "$VENV_DIR/bin/activate" && ok "created + activated project venv: $VENV_DIR"
  else
    rm -rf "$VENV_DIR" 2>/dev/null
    warn "venv unavailable (install python3-venv for an isolated env) - using the system Python instead"
  fi
else
  warn "no virtualenv active - re-run ./setup.sh to set one up (needs the python3-venv package)"
fi

# ── 2. Install Python deps ──────────────────────────────────────────────────
if [ $MODE_INSTALL = 1 ]; then
  sec "Installing Python dependencies (requirements.txt)"
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
  if python3 -m pip install -r requirements.txt; then ok "pip install -r requirements.txt"
  else
    warn "plain pip failed - retrying with --break-system-packages (PEP 668)"
    python3 -m pip install --break-system-packages -r requirements.txt \
      && ok "pip install (--break-system-packages)" \
      || bad "pip install failed - create a venv (see Python section) and re-run ./setup.sh"
  fi
fi

# ── 3. Verify Python packages ───────────────────────────────────────────────
sec "Python packages"
# import_name  label  REQUIRED|OPTIONAL|STRETCH  note
py_check() {
  if python3 -c "import $1" 2>/dev/null; then ok "$2 ($1)"
  elif [ "$3" = REQUIRED ]; then bad "$2 MISSING - pip install $2   (import $1)"
  elif [ "$3" = STRETCH ]; then note "$2 not installed - $4"
  else warn "$2 absent (optional: $4)"; fi
}
# CORE - needed for the demo, the tests, and the judge path:
py_check pydantic    pydantic        REQUIRED ""
py_check mcp         mcp             REQUIRED ""
py_check defusedxml  defusedxml      REQUIRED ""
py_check Crypto      pycryptodome    REQUIRED ""
py_check rich        rich            REQUIRED ""
py_check psutil      psutil          REQUIRED ""
py_check Evtx        python-evtx     REQUIRED ""
# OPTIONAL - the default provider is Qwen; these only matter off the demo path:
py_check anthropic   anthropic       OPTIONAL "the Anthropic FALLBACK provider only; the Qwen path does not need it (pip install .[anthropic])"
py_check volatility3 volatility3     OPTIONAL "needed only for REAL memory-image runs (not the demo); pip install volatility3, or use SIFT's"
py_check pytsk3      pytsk3          OPTIONAL "native disk extraction for real runs; CLI fls/icat fallback exists"

# ── 4. Forensic system tools (real evidence runs only - NOT the demo) ────────
sec "Forensic tools (only for REAL evidence runs - the demo needs none)"
if [ $MODE_INSTALL = 1 ] && [ $USE_SUDO = 1 ] && command -v apt-get >/dev/null 2>&1; then
  for pkg in sleuthkit ewf-tools yara; do
    sudo apt-get install -y "$pkg" >/dev/null 2>&1 && ok "apt: $pkg" || note "apt: $pkg not installed here (verified below if present)"
  done
fi
bin_check() {
  local name="$1" fix="$2" probe="${3:-}"
  if command -v "$name" >/dev/null 2>&1; then
    if [ -n "$probe" ]; then local ver; ver=$(eval "$probe" 2>&1 | head -1 | tr -d '\r' | cut -c1-50); ok "$name  ->  ${ver:-ok}"
    else ok "$name  ($(command -v "$name"))"; fi
  else warn "$name absent (optional, real runs only) - $fix"; fi
}
bin_check vol     "pip install volatility3"          ''
bin_check fls     "sudo apt install sleuthkit"        'fls -V'
bin_check ewfinfo "sudo apt install ewf-tools"        'ewfinfo -h 2>&1 | grep -m1 -i ewfinfo'
bin_check yara    "sudo apt install yara (opt-in: SIFT_ALLOW_YARA=1)" 'yara --version'

# ── 5. Qwen Cloud readiness (only needed for a LIVE run) ─────────────────────
sec "Qwen Cloud readiness (only for a live run - the demo needs no key)"
[ -f .env.qwen.example ] && ok ".env.qwen.example present (cp .env.qwen.example .env, then paste your key)" \
                          || warn ".env.qwen.example missing"
# load .env the way findevil.sh does, then look for a key
[ -f .env ] && { set -a; . ./.env 2>/dev/null || true; set +a; }
if [ -n "${DASHSCOPE_API_KEY:-}" ] || [ -n "${QWEN_API_KEY:-}" ]; then
  ok "DashScope/Qwen key detected (live runs enabled). Verify: python3 scripts/qwen_smoke.py"
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  note "only an Anthropic (fallback) key is set; for the Qwen submission set DASHSCOPE_API_KEY"
else
  note "no key yet - fine for the demo. For a live Qwen run: cp .env.qwen.example .env and paste your DashScope key"
fi

# ── 6. Prove the demo runs (install mode only) ───────────────────────────────
if [ $MODE_INSTALL = 1 ] && [ $FAIL -eq 0 ]; then
  sec "Running the demo (no key, no evidence)"
  if ./findevil.sh --demo >/dev/null 2>&1; then ok "./findevil.sh --demo completed - the pipeline works end to end"
  else warn "demo did not complete cleanly - run ./findevil.sh --demo to see the message"; fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────
sec "Summary"
if [ $FAIL -eq 0 ]; then
  printf "\n  ${G}${B}=============================================================${X}\n"
  printf "  ${G}${B}  OK - ready for the demo and the tests.${X}\n"
  printf "  ${G}${B}  Next:  ./findevil.sh --demo       ${X}${G}(zero cost, no key)${X}\n"
  printf "  ${G}${B}  Live:  cp .env.qwen.example .env  ${X}${G}(paste DashScope key) then ./findevil.sh /path/to/case${X}\n"
  printf "  ${G}${B}=============================================================${X}\n"
  [ "$WARN" -gt 0 ] && printf "  (%d optional note(s) above - fine to ignore for the demo/judge path)\n" "$WARN"
  printf "\n"
  exit 0
else
  printf "\n  ${R}${B}=============================================================${X}\n"
  printf "  ${R}${B}  NOT READY - %d required item(s) missing.${X}\n" "$FAIL"
  printf "  ${R}${B}  Fix the red FAIL line(s) above, then re-run:  ./setup.sh${X}\n"
  printf "  ${R}${B}=============================================================${X}\n\n"
  exit 1
fi
