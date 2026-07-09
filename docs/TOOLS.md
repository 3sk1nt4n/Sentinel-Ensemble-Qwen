# 🧰 The 195 typed tools - full inventory

The Custom MCP server ([`src/server.py`](../src/server.py)) advertises **195
typed tools**, each with a Pydantic-validated JSON contract and **zero shell
access**. The count is **186 dynamically discovered** forensic tools (from
`_TOOL_REGISTRY`) **+ 9 hardcoded core/meta** functions = **195**,
with **no overlap** (verified). This page is generated from the code, so it never
drifts; regenerate with the snippet at the bottom.

| Group | Count |
|---|---|
| Volatility 3 plugins (`vol_*`) | **138** |
| Other dynamic forensic tools (disk / registry / timeline / carving / etc.) | **48** |
| Dynamic subtotal (`_TOOL_REGISTRY`) | **186** |
| Core / meta (hardcoded `@mcp.tool()`) | **9** |
| **Total advertised** | **195** |

## 1. Volatility 3 memory-forensics plugins (138)

- `vol_amcache`
- `vol_bash`
- `vol_bigpools`
- `vol_boottime`
- `vol_cachedump`
- `vol_callbacks`
- `vol_capabilities`
- `vol_certificates`
- `vol_checkafinfo`
- `vol_checkcreds`
- `vol_checkidt`
- `vol_checkmodules`
- `vol_checksyscall`
- `vol_checksysctl`
- `vol_checktraptable`
- `vol_cmdline`
- `vol_cmdscan`
- `vol_consoles`
- `vol_crashinfo`
- `vol_debugregisters`
- `vol_deskscan`
- `vol_desktops`
- `vol_devicetree`
- `vol_directsystemcalls`
- `vol_dlllist`
- `vol_dmesg`
- `vol_driverirp`
- `vol_drivermodule`
- `vol_driverscan`
- `vol_dumpfiles`
- `vol_ebpf`
- `vol_elfs`
- `vol_envars`
- `vol_etwpatch`
- `vol_fbdev`
- `vol_filescan`
- `vol_ftrace`
- `vol_getcellroutine`
- `vol_getservicesids`
- `vol_getsids`
- `vol_handles`
- `vol_hashdump`
- `vol_hiddenmodules`
- `vol_hivescan`
- `vol_hollowprocesses`
- `vol_iat`
- `vol_ifconfig`
- `vol_indirectsystemcalls`
- `vol_info`
- `vol_iomem`
- `vol_ip`
- `vol_joblinks`
- `vol_kallsyms`
- `vol_kauthlisteners`
- `vol_kauthscopes`
- `vol_kevents`
- `vol_keyboardnotifiers`
- `vol_kmsg`
- `vol_kpcrs`
- `vol_kthreads`
- `vol_ldrmodules`
- `vol_librarylist`
- `vol_listfiles`
- `vol_lsadump`
- `vol_lsmod`
- `vol_lsof`
- `vol_malfind`
- `vol_mbrscan`
- `vol_memmap`
- `vol_mftscan`
- `vol_modscan`
- `vol_moduleextract`
- `vol_modules`
- `vol_modxview`
- `vol_mount`
- `vol_mountinfo`
- `vol_mutantscan`
- `vol_netfilter`
- `vol_netscan`
- `vol_netstat`
- `vol_orphankernelthreads`
- `vol_pagecache`
- `vol_pebmasquerade`
- `vol_pedump`
- `vol_perfevents`
- `vol_pesymbols`
- `vol_pidhashtable`
- `vol_poolscanner`
- `vol_printkey`
- `vol_privileges`
- `vol_proc`
- `vol_processghosting`
- `vol_procmaps`
- `vol_psaux`
- `vol_pscallstack`
- `vol_pslist`
- `vol_psscan`
- `vol_pstree`
- `vol_psxview`
- `vol_ptrace`
- `vol_reg_hivelist`
- `vol_scheduledtasks`
- `vol_sessions`
- `vol_shimcachemem`
- `vol_skeletonkeycheck`
- `vol_socketfilters`
- `vol_sockstat`
- `vol_ssdt`
- `vol_statistics`
- `vol_strings`
- `vol_suspendedthreads`
- `vol_suspiciousthreads`
- `vol_svcdiff`
- `vol_svclist`
- `vol_svcscan`
- `vol_symlinkscan`
- `vol_thrdscan`
- `vol_threads`
- `vol_timers`
- `vol_tracepoints`
- `vol_truecrypt`
- `vol_trustedbsd`
- `vol_ttycheck`
- `vol_unhookedsystemcalls`
- `vol_unloadedmodules`
- `vol_userassist`
- `vol_vadinfo`
- `vol_vadregexscan`
- `vol_vadwalk`
- `vol_vadyarascan`
- `vol_verinfo`
- `vol_vfsevents`
- `vol_virtmap`
- `vol_vmaregexscan`
- `vol_vmayarascan`
- `vol_vmcoreinfo`
- `vol_windows`
- `vol_windowstations`

## 2. Other dynamic forensic tools (48)

Disk (Sleuth Kit), registry (EZ Tools / RegRipper), timeline (Plaso / MFT),
event logs (EvtxECmd), artifact parsers, carving (foremost / bulk_extractor),
YARA, and string/IOC extractors:

- `decode_base64_strings`
- `extract_mft_timeline`
- `extract_network_iocs`
- `get_amcache`
- `parse_event_logs`
- `parse_powershell_transcripts`
- `parse_prefetch`
- `parse_rdp_artifacts`
- `parse_registry_persistence`
- `parse_scheduled_tasks_disk`
- `parse_usb_devices`
- `parse_userassist`
- `parse_wmi_subscription`
- `run_amcacheparser`
- `run_appcompatcacheparser`
- `run_bulk_extractor`
- `run_evtx_dump`
- `run_evtxecmd`
- `run_exiftool`
- `run_foremost`
- `run_jlecmd`
- `run_lecmd`
- `run_memprocfs`
- `run_mftecmd`
- `run_pffexport`
- `run_rbcmd`
- `run_recmd`
- `run_sbecmd`
- `run_srumecmd`
- `run_ssdeep`
- `run_strings`
- `run_vshadowmount`
- `run_wxtcmd`
- `run_yara`
- `sleuthkit_blkstat`
- `sleuthkit_ffind`
- `sleuthkit_fls`
- `sleuthkit_fsstat`
- `sleuthkit_icat`
- `sleuthkit_ifind`
- `sleuthkit_img_cat`
- `sleuthkit_img_stat`
- `sleuthkit_mactime`
- `sleuthkit_mmls`
- `sleuthkit_sigfind`
- `sleuthkit_sorter`
- `sleuthkit_tsk_loaddb`
- `sleuthkit_tsk_recover`

## 3. Core / meta functions (9, hardcoded in `server.py`)

Generic dispatchers (run any Volatility / Sleuth Kit command by name) and the
tool-recommendation meta-tools:

- `tool_parse_shellbags`
- `tool_run_log2timeline`
- `tool_run_regripper`
- `tool_get_investigation_categories`
- `tool_get_tools_for_category`
- `tool_recommend_tools`
- `tool_run_volatility`
- `tool_list_volatility_plugins`
- `tool_run_sleuthkit`

---

**Regenerate this list** (authoritative, from the running registry):

```bash
PYTHONPATH=src python3 -c "
from sift_sentinel.coordinator import _TOOL_REGISTRY
import re
reg=sorted(_TOOL_REGISTRY)
hard=re.findall(r'@mcp\\.tool\\(\\)\\s*\\ndef\\s+(\\w+)',open('src/server.py').read())
print(len(reg),'dynamic +',len(hard),'core =',len(reg)+len(hard))
"
```
