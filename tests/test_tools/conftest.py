"""Shared fixtures for tool tests.

Memory tools: mocked run_volatility returns fixture data.
Disk tools: SIFT_DRY_RUN=1 uses sample_data for disk tools only.
"""

import pytest


# ── Minimal Volatility fixture data ─────────────────────────────────────
# Small, schema-correct records for unit tests. No dependency on external files.

FIXTURE_DATA = {
    "vol_pstree": [
        {"PID": 4, "PPID": 0, "ImageFileName": "System",
         "CreateTime": "2018-07-11 17:15:00", "Path": "",
         "__children": [
             {"PID": 388, "PPID": 4, "ImageFileName": "smss.exe",
              "CreateTime": "2018-07-11 17:15:01", "Path": "\\SystemRoot\\System32\\smss.exe",
              "__children": [
                  {"PID": 500, "PPID": 388, "ImageFileName": "csrss.exe",
                   "CreateTime": "2018-07-11 17:15:02", "Path": "C:\\Windows\\system32\\csrss.exe",
                   "__children": []},
              ]},
             {"PID": 600, "PPID": 4, "ImageFileName": "svchost.exe",
              "CreateTime": "2018-07-11 17:16:00", "Path": "C:\\Windows\\system32\\svchost.exe",
              "__children": []},
         ]},
    ],
    "vol_netscan": [
        {"PID": 4, "LocalAddr": "0.0.0.0", "LocalPort": 445,
         "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING",
         "Proto": "TCPv4", "Owner": "System", "__children": []},
        {"PID": 600, "LocalAddr": "192.0.2.111", "LocalPort": 49152,
         "ForeignAddr": "192.0.2.129", "ForeignPort": 443, "State": "ESTABLISHED",
         "Proto": "TCPv4", "Owner": "svchost.exe", "__children": []},
        {"PID": 388, "LocalAddr": "0.0.0.0", "LocalPort": 135,
         "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING",
         "Proto": "TCPv4", "Owner": "smss.exe", "__children": []},
    ],
    "vol_malfind": [
        {"PID": 600, "Process": "svchost.exe", "Protection": "PAGE_EXECUTE_READWRITE",
         "Start VPN": "0x400000", "End VPN": "0x401000",
         "Hexdump": "4d5a9000", "Tag": "VadS", "__children": []},
        {"PID": 388, "Process": "smss.exe", "Protection": "PAGE_EXECUTE_READWRITE",
         "Start VPN": "0x500000", "End VPN": "0x501000",
         "Hexdump": "4d5a9000", "Tag": "VadS", "__children": []},
        {"PID": 500, "Process": "csrss.exe", "Protection": "PAGE_EXECUTE_READWRITE",
         "Start VPN": "0x600000", "End VPN": "0x601000",
         "Hexdump": "4d5a9000", "Tag": "VadS", "__children": []},
    ],
    "vol_cmdline": [
        {"PID": 4, "Process": "System", "Args": "", "__children": []},
        {"PID": 388, "Process": "smss.exe", "Args": "\\SystemRoot\\System32\\smss.exe",
         "__children": []},
        {"PID": 500, "Process": "csrss.exe", "Args": "%SystemRoot%\\system32\\csrss.exe",
         "__children": []},
        {"PID": 600, "Process": "svchost.exe", "Args": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
         "__children": []},
    ],
    "vol_dlllist": [
        {"PID": 388, "Process": "smss.exe", "Name": "ntdll.dll",
         "Path": "C:\\Windows\\SYSTEM32\\ntdll.dll", "Base": "0x77000000",
         "Size": "0x1a9000", "__children": []},
        {"PID": 388, "Process": "smss.exe", "Name": "smss.exe",
         "Path": "C:\\Windows\\System32\\smss.exe", "Base": "0x00400000",
         "Size": "0x10000", "__children": []},
        {"PID": 600, "Process": "svchost.exe", "Name": "ntdll.dll",
         "Path": "C:\\Windows\\SYSTEM32\\ntdll.dll", "Base": "0x77000000",
         "Size": "0x1a9000", "__children": []},
        {"PID": 600, "Process": "svchost.exe", "Name": "kernel32.dll",
         "Path": "C:\\Windows\\system32\\kernel32.dll", "Base": "0x76000000",
         "Size": "0x11f000", "__children": []},
    ],
    "vol_psscan": [
        {"PID": 4, "PPID": 0, "ImageFileName": "System",
         "Offset(V)": "0xfa800000", "CreateTime": "2018-07-11 17:15:00",
         "ExitTime": "N/A", "__children": []},
        {"PID": 388, "PPID": 4, "ImageFileName": "smss.exe",
         "Offset(V)": "0xfa801000", "CreateTime": "2018-07-11 17:15:01",
         "ExitTime": "N/A", "__children": []},
        {"PID": 500, "PPID": 388, "ImageFileName": "csrss.exe",
         "Offset(V)": "0xfa802000", "CreateTime": "2018-07-11 17:15:02",
         "ExitTime": "N/A", "__children": []},
    ],
    "vol_handles": [
        {"PID": 4, "Process": "System", "Offset": "0xfff000",
         "HandleValue": "0x4", "Type": "Key",
         "GrantedAccess": "0x20019", "Name": "\\REGISTRY\\MACHINE\\SYSTEM",
         "__children": []},
        {"PID": 4, "Process": "System", "Offset": "0xfff001",
         "HandleValue": "0x8", "Type": "File",
         "GrantedAccess": "0x100001", "Name": "\\Device\\HarddiskVolume1",
         "__children": []},
        {"PID": 600, "Process": "svchost.exe", "Offset": "0xfff002",
         "HandleValue": "0xc", "Type": "Mutant",
         "GrantedAccess": "0x1f0001", "Name": "\\Sessions\\1\\BaseNamedObjects",
         "__children": []},
    ],
    "vol_envars": [
        {"PID": 600, "Process": "svchost.exe", "Block": "Peb",
         "Variable": "PATH", "Value": "C:\\Windows\\system32",
         "__children": []},
        {"PID": 600, "Process": "svchost.exe", "Block": "Peb",
         "Variable": "USERNAME", "Value": "SYSTEM",
         "__children": []},
        {"PID": 2360, "Process": "explorer.exe", "Block": "Peb",
         "Variable": "USERNAME", "Value": "tuser-r",
         "__children": []},
    ],
    "vol_getsids": [
        {"PID": 4, "Process": "System",
         "SID": "S-1-5-18", "Name": "Local System",
         "__children": []},
        {"PID": 600, "Process": "svchost.exe",
         "SID": "S-1-5-20", "Name": "NT AUTHORITY\\NETWORK SERVICE",
         "__children": []},
    ],
    "vol_privileges": [
        {"PID": 4, "Process": "System", "Value": 20,
         "Privilege": "SeDebugPrivilege",
         "Attributes": "Enabled, Default", "Description": "Debug programs",
         "__children": []},
        {"PID": 600, "Process": "svchost.exe", "Value": 23,
         "Privilege": "SeImpersonatePrivilege",
         "Attributes": "Enabled, Default",
         "Description": "Impersonate a client after authentication",
         "__children": []},
    ],
    "vol_svcscan": [
        {"Binary": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
         "Display": "Background Intelligent Transfer Service",
         "Dll": "", "Name": "BITS", "Offset": "0xf8a00300",
         "Order": 1, "PID": 600, "Start": "SERVICE_AUTO_START",
         "State": "SERVICE_RUNNING", "Type": "SERVICE_WIN32_SHARE_PROCESS",
         "__children": []},
        {"Binary": "C:\\Windows\\system32\\spoolsv.exe",
         "Display": "Print Spooler", "Dll": "", "Name": "Spooler",
         "Offset": "0xf8a00400", "Order": 2, "PID": 1200,
         "Start": "SERVICE_AUTO_START", "State": "SERVICE_RUNNING",
         "Type": "SERVICE_WIN32_OWN_PROCESS", "__children": []},
    ],
    "vol_sessions": [
        {"Create Time": "2018-07-11 17:15:00", "Process": "System",
         "Process ID": 4, "Session ID": 0,
         "Session Type": "Console", "User Name": "NT AUTHORITY\\SYSTEM",
         "__children": []},
        {"Create Time": "2018-07-11 17:16:00", "Process": "svchost.exe",
         "Process ID": 600, "Session ID": 0,
         "Session Type": "Console", "User Name": "NT AUTHORITY\\SYSTEM",
         "__children": []},
        {"Create Time": "2018-07-11 17:20:00", "Process": "explorer.exe",
         "Process ID": 2360, "Session ID": 1,
         "Session Type": "Console", "User Name": "YOURPC\\tuser-r",
         "__children": []},
    ],
    "vol_ssdt": [
        {"Address": "0xfffff80003e81c00", "Index": 0,
         "Module": "ntoskrnl", "Symbol": "NtAccessCheck",
         "__children": []},
        {"Address": "0xfffff80003e82000", "Index": 1,
         "Module": "ntoskrnl", "Symbol": "NtAddAtom",
         "__children": []},
        {"Address": "0xfffff80003e83000", "Index": 2,
         "Module": "ntoskrnl", "Symbol": "NtAddBootEntry",
         "__children": []},
    ],
    "vol_filescan": [
        {"Name": "\\Windows\\System32\\ntdll.dll",
         "Offset": "0x3e409070", "__children": []},
        {"Name": "\\Windows\\System32\\config\\SYSTEM",
         "Offset": "0x3e40a000", "__children": []},
        {"Name": "\\Users\\tuser-r\\Desktop\\sqlsvc.exe",
         "Offset": "0x3e40b000", "__children": []},
    ],
    "vol_reg_hivelist": [
        {"File output": "Disabled", "FileFullPath": "\\REGISTRY\\MACHINE\\SYSTEM",
         "Offset": "0xfffff8a000024010", "__children": []},
        {"File output": "Disabled", "FileFullPath": "\\REGISTRY\\MACHINE\\SOFTWARE",
         "Offset": "0xfffff8a000100010", "__children": []},
        {"File output": "Disabled",
         "FileFullPath": "\\SystemRoot\\System32\\Config\\SAM",
         "Offset": "0xfffff8a000200010", "__children": []},
    ],
}


def _fake_run_volatility(tool_name, image_path):
    """Return fixture data for any Volatility plugin."""
    data = FIXTURE_DATA.get(tool_name)
    if data is None:
        raise ValueError(f"No Volatility plugin mapped for {tool_name}")
    return data


@pytest.fixture(autouse=True)
def _dry_run_env(monkeypatch):
    """Set SIFT_DRY_RUN=1 for disk tool tests (memory tools ignore this)."""
    monkeypatch.setenv("SIFT_DRY_RUN", "1")


@pytest.fixture(autouse=True)
def _mock_run_volatility(monkeypatch):
    """Mock run_volatility in ALL modules that import it."""
    monkeypatch.setattr(
        "sift_sentinel.tools.common.run_volatility", _fake_run_volatility,
    )
    monkeypatch.setattr(
        "sift_sentinel.tools.memory.run_volatility", _fake_run_volatility,
    )
    monkeypatch.setattr(
        "sift_sentinel.tools.memory_extended.run_volatility", _fake_run_volatility,
    )
    monkeypatch.setattr(
        "sift_sentinel.tools.memory_extended2.run_volatility", _fake_run_volatility,
    )


# ----------------------------------------------------------------
# C32: autouse fixture to init tool_health tracker for all tests
# in this directory. Mirrors tests/test_pipeline/conftest.py pattern.
# Required because C32 added get_tool_health() call inside
# call_mcp_tool (mcp_client.py), which enforces Rule 5 structurally:
# new_tool_health() must be called before any get_tool_health().
# Tests that need to assert uninitialized behavior can monkeypatch
# _tool_health back to None after this fixture runs.
# ----------------------------------------------------------------

import pytest


@pytest.fixture(autouse=True)
def _init_tool_health_for_all_tools_tests():
    """Initialize per-run tool health tracker for every test in this
    directory. Sibling to tests/test_pipeline/conftest.py fixture of
    the same purpose. Preserves backward compatibility for tests that
    exercise call_mcp_tool or run_tool directly without pipeline setup."""
    from sift_sentinel.coordinator import new_tool_health
    new_tool_health()
    yield
