@echo off
REM Sentinel Qwen Ensemble - Windows launcher (no PowerShell execution-policy change needed).
REM
REM   .\setup.cmd                       guided: shows the walkthrough, asks for your evidence
REM   .\setup.cmd docker                zero-cost demo (no key, no evidence, ~30 s)
REM   .\setup.cmd run C:\path\to\case   real investigation - one line does everything
REM
REM It forwards to setup.ps1 with the execution policy bypassed for this run, and
REM always runs from THIS repo folder (%~dp0), so results always land in the same
REM place (sentinel-results\ here) no matter where you launched it from.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
REM If you double-clicked this file (no arguments), keep the window open so you
REM can read the output instead of it vanishing.
if "%~1"=="" pause
