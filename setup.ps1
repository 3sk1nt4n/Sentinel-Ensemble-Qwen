<#
.SYNOPSIS
  Sentinel Ensemble - one-command launcher for Windows (PowerShell).

  The Windows twin of ./setup.sh. Same two commands, same experience:

    .\setup.ps1 docker                 # zero-cost demo - no key, no evidence (~30 s)
    .\setup.ps1 run C:\path\to\case    # real investigation - ONE line does everything
    .\setup.ps1 run -DryRun C:\path\to\case   # onboarding + plan only, nothing executed

  'run' builds the toolchain image on first use, reads your DashScope key from
  .env / the environment (or asks once, hidden), applies the verified-run flags,
  passes the .E01/FUSE capabilities, mounts your evidence READ-ONLY, launches the
  agent, and saves the report to sentinel-results\<case>\ on your machine.

  Requires Docker Desktop (https://www.docker.com/products/docker-desktop/).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('docker', 'run', 'help')]
    [string]$Mode = 'help',

    [Parameter(Position = 1)]
    [string]$CasePath,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$RepoDir = $PSScriptRoot
Set-Location $RepoDir

function Say  ($m) { Write-Host $m }
function Ok   ($m) { Write-Host "  OK   $m"   -ForegroundColor Green }
function Warn ($m) { Write-Host "  WARN $m"   -ForegroundColor Yellow }
function Bad  ($m) { Write-Host "  FAIL $m"   -ForegroundColor Red }
function Note ($m) { Write-Host "  --   $m"   -ForegroundColor Cyan }
function Sec  ($m) { Write-Host "`n== $m ==" -ForegroundColor White }

# ---------------------------------------------------------------------------
# Docker doctor: a bash script can't install Docker Desktop (a GUI app) on
# Windows, so guide the user precisely instead of failing cryptically.
# ---------------------------------------------------------------------------
function Test-Docker {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        Bad "Docker is not installed."
        Say "  Install Docker Desktop (free): https://www.docker.com/products/docker-desktop/"
        Say "  During install, keep the WSL2 backend enabled. Then reopen PowerShell and re-run this."
        exit 1
    }
    # Daemon reachable?
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Bad "Docker Desktop is installed but not running."
        Say "  Start Docker Desktop (wait for the whale icon to go steady), then re-run this."
        exit 1
    }
}

# Load KEY=VALUE lines from .env into a hashtable (skip comments / blanks).
function Import-DotEnv {
    $envmap = @{}
    $path = Join-Path $RepoDir '.env'
    if (Test-Path $path) {
        foreach ($line in Get-Content $path) {
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            $eq = $t.IndexOf('=')
            if ($eq -lt 1) { continue }
            $k = $t.Substring(0, $eq).Trim()
            $v = $t.Substring($eq + 1).Trim().Trim('"').Trim("'")
            if ($k) { $envmap[$k] = $v }
        }
    }
    return $envmap
}

# ===========================================================================
#  DEMO  ->  .\setup.ps1 docker
# ===========================================================================
if ($Mode -eq 'docker') {
    Write-Host "Sentinel Ensemble - Docker demo" -ForegroundColor White
    Test-Docker
    Sec "Building the zero-cost demo image (~290 MB, one time)"
    docker build --target demo -t sentinel-qwen:demo .
    if ($LASTEXITCODE -ne 0) { Bad "build failed (see above)"; exit 1 }
    Ok "image built: sentinel-qwen:demo"
    Sec "Running the demo (no key, no evidence)"
    docker run --rm -it sentinel-qwen:demo
    Write-Host "`n  OK  Docker demo works." -ForegroundColor Green
    Write-Host "  Real investigation on Qwen Cloud - ONE line:" -ForegroundColor White
    Write-Host "    .\setup.ps1 run C:\path\to\case   # image, key, flags, read-only mount: all handled"
    Write-Host "    (key from .env or a hidden prompt - get one at home.qwencloud.com/api-keys)"
    Write-Host "    Full guide: docs\DOCKER.md`n"
    exit 0
}

# ===========================================================================
#  RUN   ->  .\setup.ps1 run C:\path\to\case  [-DryRun]
# ===========================================================================
if ($Mode -eq 'run') {
    Write-Host "Sentinel Ensemble - one-line Docker run" -ForegroundColor White
    Test-Docker

    if (-not $CasePath) {
        Bad "usage: .\setup.ps1 run [-DryRun] C:\path\to\case-folder"
        exit 2
    }
    if (-not (Test-Path -LiteralPath $CasePath -PathType Container)) {
        Bad "case folder not found: $CasePath"
        Say "  Point it at the FOLDER holding this case's memory + disk images."
        exit 2
    }
    $Case = (Resolve-Path -LiteralPath $CasePath).Path
    $CaseName = Split-Path -Leaf $Case

    # Build the full toolchain image on first use.
    docker image inspect sentinel-qwen *> $null
    if ($LASTEXITCODE -ne 0) {
        Sec "Building the full toolchain image (one time, ~15 min)"
        docker build -t sentinel-qwen .
        if ($LASTEXITCODE -ne 0) { Bad "build failed (see above)"; exit 1 }
    }
    Ok "image ready: sentinel-qwen"

    # Config: .env first, then verified-run defaults for anything unset.
    $envmap = Import-DotEnv
    foreach ($kv in @{
        'SIFT_LLM_PROVIDER'  = 'qwen'
        'SIFT_DEFAULT_MODEL' = 'qwen3.7-max'
        'SIFT_HTTP_TIMEOUT'  = '600'
        'SIFT_ALLOW_YARA'    = '1'
    }.GetEnumerator()) {
        if (-not $envmap.ContainsKey($kv.Key) -and -not (Get-Item "env:$($kv.Key)" -ErrorAction SilentlyContinue)) {
            $envmap[$kv.Key] = $kv.Value
        }
    }
    # Environment variables win over .env (same precedence as findevil.sh).
    foreach ($e in Get-ChildItem env: | Where-Object { $_.Name -match '^(SIFT|DASHSCOPE|QWEN|ANTHROPIC)_' }) {
        $envmap[$e.Name] = $e.Value
    }

    # Key: ask once (hidden) if provider is qwen and none is set (unless dry-run).
    $provider = $envmap['SIFT_LLM_PROVIDER']
    $haveKey  = $envmap['DASHSCOPE_API_KEY'] -or $envmap['QWEN_API_KEY']
    if ($provider -eq 'qwen' -and -not $haveKey -and -not $DryRun) {
        $secure = Read-Host "  DashScope API key (hidden; home.qwencloud.com/api-keys)" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try   { $envmap['DASHSCOPE_API_KEY'] = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    # Assemble -e args (never baked into the image).
    $envArgs = @()
    foreach ($k in $envmap.Keys) {
        if ($envmap[$k]) { $envArgs += @('-e', "$k=$($envmap[$k])") }
    }
    $envArgs += @('-e', 'SIFT_PERSIST_DIR=/out')

    # Where results land on YOUR machine.
    $Out = Join-Path $RepoDir "sentinel-results\$CaseName"
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    Note "results will be saved to: $Out"

    $pass = @(); if ($DryRun) { $pass += '--dry-run' }

    Sec "Launching the agent on your case (evidence mounted read-only)"
    # Docker Desktop's Linux backend needs the FUSE capabilities to mount .E01
    # disks (harmless for memory-only). Evidence and results are bind-mounted.
    docker run --rm -it `
        --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined `
        @envArgs `
        -v "${Case}:/evidence:ro" `
        -v "${Out}:/out" `
        sentinel-qwen @pass /evidence
    $rc = $LASTEXITCODE

    if ((Test-Path (Join-Path $Out 'report.md')) -or (Get-ChildItem $Out -Filter 'incident_report_*.md' -ErrorAction SilentlyContinue)) {
        Write-Host "`n  OK  Report saved on your machine: $Out" -ForegroundColor Green
        Write-Host "     open report.md (narrative) or summary_report_*.html (one-page view)`n"
    }
    exit $rc
}

# ===========================================================================
#  HELP
# ===========================================================================
Write-Host "Sentinel Ensemble - Windows launcher" -ForegroundColor White
Write-Host ""
Write-Host "  .\setup.ps1 docker                 zero-cost demo - no key, no evidence (~30 s)"
Write-Host "  .\setup.ps1 run C:\path\to\case    real investigation - one line does everything"
Write-Host "  .\setup.ps1 run -DryRun C:\path\to\case   onboarding + plan only, nothing executed"
Write-Host ""
Write-Host "  Needs Docker Desktop: https://www.docker.com/products/docker-desktop/"
Write-Host "  Full guide: docs\DOCKER.md"
exit 0
