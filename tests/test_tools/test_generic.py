"""Tests for generic tool runners: run_volatility_plugin, list_volatility_plugins,
run_sleuthkit, run_yara, run_bulk_extractor, run_exiftool, run_ssdeep,
run_foremost, run_log2timeline, run_regripper, run_strings.
All subprocess calls are mocked."""

import json
from unittest.mock import patch, MagicMock, mock_open

import pytest

from sift_sentinel.tools.generic import (
    run_volatility_plugin,
    list_volatility_plugins,
    run_sleuthkit,
    run_yara,
    run_bulk_extractor,
    run_exiftool,
    run_ssdeep,
    run_foremost,
    run_log2timeline,
    run_regripper,
    run_strings,
)

DUMMY_IMAGE = "/synthetic/evidence/memory.img"


class TestRunVolatilityPlugin:
    def test_valid_plugin_returns_envelope(self):
        """Valid windows plugin with JSON output returns standard envelope."""
        mock_data = [{"PID": 4, "ImageFileName": "System"}]
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(mock_data)
        mock_result.stderr = ""

        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result):
            result = run_volatility_plugin(DUMMY_IMAGE, "windows.pstree.PsTree")

        assert result["tool_name"] == "vol_windows.pstree.PsTree"
        assert result["record_count"] == 1
        assert result["output"] == mock_data
        assert isinstance(result["execution_time_ms"], int)

    def test_non_windows_plugin_returns_error(self):
        """Non-windows plugin is rejected without running subprocess."""
        result = run_volatility_plugin(DUMMY_IMAGE, "linux.bash.Bash")
        assert "error" in result
        assert "Only windows.* plugins allowed" in result["error"]
        assert result["output"] == []
        assert result["record_count"] == 0

    def test_timeout_returns_error(self):
        """Subprocess timeout returns error dict, not exception."""
        import subprocess
        with patch("sift_sentinel.tools.generic.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="vol", timeout=300)):
            result = run_volatility_plugin(DUMMY_IMAGE, "windows.pstree.PsTree")

        assert "error" in result
        assert "timed out" in result["error"]
        assert result["output"] == []

    def test_bad_json_returns_error(self):
        """Non-JSON stdout returns error dict."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "NOT VALID JSON {{"
        mock_result.stderr = ""

        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result):
            result = run_volatility_plugin(DUMMY_IMAGE, "windows.pstree.PsTree")

        assert "error" in result
        assert "not parseable" in result["error"]
        assert result["output"] == []


    def test_json_empty_csv_fallback(self):
        """JSON returns [] -> CSV fallback fires and returns records."""
        json_result = MagicMock(returncode=0, stdout="[]", stderr="")
        csv_output = "Index,Address,Module\n0,0xf800,ntoskrnl\n1,0xf801,win32k\n"
        csv_result = MagicMock(returncode=0, stdout=csv_output, stderr="")

        with patch("sift_sentinel.tools.generic.subprocess.run",
                   side_effect=[json_result, csv_result]):
            result = run_volatility_plugin(DUMMY_IMAGE, "windows.ssdt.SSDT")

        assert result["record_count"] == 2
        assert result["output"][0]["Module"] == "ntoskrnl"


class TestListVolatilityPlugins:
    def test_parses_help_output(self):
        """Extracts windows.* plugin names from vol --help output."""
        help_text = (
            "Volatility 3 Framework\n"
            "  windows.pstree.PsTree    Process tree\n"
            "  windows.netscan.NetScan  Network connections\n"
            "  windows.malfind.Malfind  Injected code\n"
            "  linux.bash.Bash          Bash history\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = help_text

        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result):
            plugins = list_volatility_plugins()

        assert len(plugins) == 3
        assert "windows.malfind.Malfind" in plugins
        assert "windows.netscan.NetScan" in plugins
        assert "windows.pstree.PsTree" in plugins
        # linux plugins excluded
        assert "linux.bash.Bash" not in plugins


class TestRunSleuthkit:
    def test_allowed_command_returns_output(self):
        """Allowed sleuthkit command returns envelope with parsed lines."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "r/r 100:\tfile1.txt\nr/r 101:\tfile2.txt\n"
        mock_result.stderr = ""

        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result):
            result = run_sleuthkit("fls", DUMMY_IMAGE)

        assert result["tool_name"] == "sleuthkit_fls"
        assert result["record_count"] == 2
        assert len(result["output"]) == 2

    def test_disallowed_command_returns_error(self):
        """Commands not in ALLOWED set are rejected."""
        result = run_sleuthkit("rm", DUMMY_IMAGE)
        assert "error" in result
        assert "not allowed" in result["error"]
        assert result["output"] == []


class TestRunYara:
    def test_valid_rules_returns_matches(self):
        """YARA scan with matches returns structured output."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "SuspiciousRule /evidence/malware.exe\nCobaltStrike /evidence/beacon.dll\n"
        mock_result.stderr = ""

        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result), \
             patch("os.path.exists", return_value=True):
            result = run_yara("/rules/test.yar", "/evidence")

        assert result["tool_name"] == "yara_scan"
        assert result["record_count"] == 2
        assert result["output"][0]["rule"] == "SuspiciousRule"
        assert result["output"][1]["rule"] == "CobaltStrike"

    def test_missing_rules_returns_error(self):
        """Non-existent rules file returns error without running yara."""
        with patch("os.path.exists", return_value=False):
            result = run_yara("/nonexistent/rules.yar", "/evidence")

        assert "error" in result
        assert "not found" in result["error"]
        assert result["output"] == []


class TestSleuthkitAllowedExpanded:
    """Verify new Sleuthkit commands are accepted."""

    @pytest.mark.parametrize("cmd", ["sorter", "sigfind", "img_stat", "img_cat", "tsk_recover", "tsk_loaddb"])
    def test_sleuthkit_allows_new_commands(self, cmd):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "output line\n"
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result):
            result = run_sleuthkit(cmd, DUMMY_IMAGE)
        assert "error" not in result
        assert result["tool_name"] == f"sleuthkit_{cmd}"


class TestRunBulkExtractor:
    def test_rejects_missing_image(self):
        with patch("os.path.exists", return_value=False):
            result = run_bulk_extractor("/no/such/image.img")
        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_counts(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        email_data = "user@example.com\nadmin@test.org\n"
        url_data = "http://evil.com\n"
        domain_data = "# comment\nevil.com\ngood.com\nbad.com\n"

        def fake_exists(p):
            return True

        def fake_isdir(p):
            return False

        file_contents = {
            "/tmp/sift-sentinel-tools/bulk_out/email.txt": email_data,
            "/tmp/sift-sentinel-tools/bulk_out/url.txt": url_data,
            "/tmp/sift-sentinel-tools/bulk_out/domain.txt": domain_data,
        }

        def fake_open(path, *a, **kw):
            from io import StringIO
            return StringIO(file_contents.get(path, ""))

        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result), \
             patch("os.path.exists", side_effect=fake_exists), \
             patch("os.path.isdir", side_effect=fake_isdir), \
             patch("os.makedirs"), \
             patch("builtins.open", side_effect=fake_open):
            result = run_bulk_extractor(DUMMY_IMAGE)

        assert result["tool_name"] == "bulk_extractor"
        assert result["output"][0]["emails"] == 2
        assert result["output"][0]["urls"] == 1
        assert result["output"][0]["domains"] == 3
        # 31X-LITE COVERAGE FIX: record_count is len(output) (==1 summary
        # record), not the sum of carved features. The carved total is
        # preserved as data inside the summary record.
        assert result["record_count"] == 1
        assert len(result["output"]) == 1
        assert result["output"][0]["carved_feature_total"] == 6


class TestRunExiftool:
    def test_rejects_missing_file(self):
        with patch("os.path.exists", return_value=False):
            result = run_exiftool("/no/such/file.jpg")
        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_metadata(self):
        meta = [{"FileName": "test.jpg", "FileSize": "1024"}]
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(meta)
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result), \
             patch("os.path.exists", return_value=True):
            result = run_exiftool("/evidence/test.jpg")
        assert result["tool_name"] == "exiftool"
        assert result["record_count"] == 1
        assert result["output"][0]["FileName"] == "test.jpg"


class TestRunSsdeep:
    def test_rejects_missing_file(self):
        with patch("os.path.exists", return_value=False):
            result = run_ssdeep("/no/such/file.exe")
        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_hash(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "ssdeep,1.1--blocksize:hash:hash,filename\n96:abc:def,/evidence/mal.exe\n"
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result), \
             patch("os.path.exists", return_value=True):
            result = run_ssdeep("/evidence/mal.exe")
        assert result["tool_name"] == "ssdeep"
        assert result["record_count"] == 1
        assert "hash" in result["output"][0]
        assert result["output"][0]["file"] == "/evidence/mal.exe"


class TestRunForemost:
    def test_rejects_missing_image(self):
        with patch("os.path.exists", return_value=False):
            result = run_foremost("/no/such/image.dd")
        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_carved_count(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        audit_text = "Foremost audit\nFILES EXTRACTED: 17\n"

        def fake_exists(p):
            return True

        def fake_isdir(p):
            return False

        def fake_open(path, *a, **kw):
            from io import StringIO
            return StringIO(audit_text)

        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result), \
             patch("os.path.exists", side_effect=fake_exists), \
             patch("os.path.isdir", side_effect=fake_isdir), \
             patch("os.makedirs"), \
             patch("builtins.open", side_effect=fake_open):
            result = run_foremost(DUMMY_IMAGE)

        assert result["tool_name"] == "foremost"
        assert result["record_count"] == 17


class TestRunLog2timeline:
    def test_rejects_missing_image(self):
        with patch("os.path.exists", return_value=False):
            result = run_log2timeline("/no/such/image.E01")
        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_complete_status(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result), \
             patch("os.path.exists", return_value=True):
            result = run_log2timeline("/evidence/disk.E01")
        assert result["tool_name"] == "log2timeline"
        assert result["output"][0]["status"] == "complete"
        assert result["output"][0]["output"] == "/tmp/plaso.dump"


class TestRunRegripper:
    def test_rejects_missing_hive(self):
        with patch("os.path.exists", return_value=False):
            result = run_regripper("/no/such/SYSTEM")
        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_parsed_output(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "ComputerName = TEST-HOST-01\nProductName = Windows 10\n"
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result), \
             patch("os.path.exists", return_value=True):
            result = run_regripper("/evidence/SYSTEM", plugin="compname")
        assert result["tool_name"] == "regripper"
        assert result["record_count"] == 2

    def test_no_plugin_omits_flag(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "line1\n"
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result) as mock_run, \
             patch("os.path.exists", return_value=True):
            run_regripper("/evidence/SYSTEM")
        cmd = mock_run.call_args[0][0]
        assert "-p" not in cmd


class TestRunStrings:
    def test_rejects_missing_file(self):
        with patch("os.path.exists", return_value=False):
            result = run_strings("/no/such/binary.exe")
        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_strings_unicode(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "MalwareString\nC2Server\nhttp://evil.com\n"
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result) as mock_run, \
             patch("os.path.exists", return_value=True):
            result = run_strings("/evidence/mal.exe", encoding="unicode")
        assert result["tool_name"] == "strings"
        assert result["record_count"] == 3
        cmd = mock_run.call_args[0][0]
        assert "-e" in cmd and "l" in cmd

    def test_ascii_mode_no_encoding_flag(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "hello\n"
        mock_result.stderr = ""
        with patch("sift_sentinel.tools.generic.subprocess.run", return_value=mock_result) as mock_run, \
             patch("os.path.exists", return_value=True):
            run_strings("/evidence/file.bin", encoding="ascii")
        cmd = mock_run.call_args[0][0]
        assert "-e" not in cmd
