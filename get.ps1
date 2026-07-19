# =============================================================================
# get.ps1 - the ONE command (Windows PowerShell).
#
#   irm https://raw.githubusercontent.com/3sk1nt4n/Sentinel-Ensemble-Qwen/master/get.ps1 | iex
#
# Installs Git if it is missing (winget), clones (or updates) the repo, then
# hands off to the guided walkthrough (.\setup.cmd) where every step asks you:
# what to drop in the evidence folder, case card, depth, hidden API-key paste.
# Safe to re-run any time. Short on purpose - read it before you run it.
# =============================================================================
$ErrorActionPreference = 'Stop'

$repoUrl = 'https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git'
$dir     = 'Sentinel-Ensemble-Qwen'

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host 'Installing Git ...'
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements
        # Pick up the fresh PATH without restarting the shell.
        $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                    [Environment]::GetEnvironmentVariable('Path','User')
    } else {
        Write-Host 'ERROR: winget not available - install Git from https://git-scm.com/download/win, then re-run.' -ForegroundColor Red
        return
    }
}

if (Test-Path "$dir\.git") {
    # Appliance-style update: force the repo to byte-exact latest published
    # code (as good as a fresh clone). Your key (.env / API_KEY.txt), results
    # (sentinel-results\) and evidence stay untouched - they are untracked.
    Write-Host "Updating $dir to the latest published version ..."
    git -C $dir fetch --quiet origin master
    if ($LASTEXITCODE -eq 0) { git -C $dir reset --hard --quiet origin/master }
    if ($LASTEXITCODE -eq 0) { Write-Host '  up to date - repo files now match the latest release exactly' }
    else { Write-Host '  (update failed - continuing with what you have)' }
} else {
    # core.longpaths: some test-fixture filenames exceed the legacy 260-char
    # Windows path limit when cloned into a deep folder.
    git -c core.longpaths=true clone $repoUrl $dir
    if ($LASTEXITCODE -ne 0) { Write-Host 'ERROR: clone failed (see above).' -ForegroundColor Red; return }
}
Set-Location $dir

# Testing hook: stop before the interactive hand-off.
if ($env:SENTINEL_GET_NO_LAUNCH) { Write-Host "READY: $PWD (launch skipped)"; return }

.\setup.cmd @args
