"""Generic tool runners that expose ALL SIFT capabilities via MCP."""

import csv
import subprocess
import json
import logging
import os
import shutil
from sift_sentinel.tools.common import _parse_vol_csv, make_envelope, start_timer

_SAFE_OUTPUT_BASE = "/tmp/sift-sentinel-tools"

logger = logging.getLogger(__name__)


def _parse_eztools_csv(output_csv: str, max_records: int = 50000) -> list[dict]:
    """Parse EZTools CSV output into records. Returns [] if file missing/empty.
    
    Handles EZTools BOM (utf-8-sig) and large files via record cap.
    """
    if not os.path.exists(output_csv):
        return []
    records: list[dict] = []
    try:
        with open(output_csv, newline="", encoding="utf-8-sig", errors="ignore") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_records:
                    logger.warning(f"EZTools CSV: hit {max_records} record cap, stopping")
                    break
                records.append(dict(row))
    except Exception as exc:
        logger.warning(f"EZTools CSV parse error for {output_csv}: {exc}")
        return []
    return records


def list_volatility_plugins() -> list[str]:
    """Return all available Volatility 3 windows plugins."""
    try:
        r = subprocess.run(["vol", "--help"], capture_output=True, text=True, timeout=15)
        plugins = []
        for line in r.stdout.split("\n"):
            stripped = line.strip()
            if stripped.startswith("windows."):
                plugin = stripped.split()[0]
                plugins.append(plugin)
        return sorted(set(plugins))
    except Exception as exc:
        logger.error("Failed to list Vol plugins: %s", exc)
        return []

def run_volatility_plugin(image_path: str, plugin: str, extra_args: list = None) -> dict:
    """Run ANY Volatility 3 plugin and return structured JSON output."""
    ms = start_timer()
    if not plugin.startswith("windows."):
        return {"error": f"Only windows.* plugins allowed, got: {plugin}", "output": [], "record_count": 0}
    cmd = ["vol", "-f", image_path, "-r", "json", plugin]
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            logger.debug("Vol3 detail for %s (rc=%d): %s",
                          plugin, result.returncode, result.stderr[:500])
            return {"error": f"{plugin}: unavailable on this evidence "
                    "(Vol3 plugin limitation -- not a pipeline error)",
                    "output": [], "record_count": 0}
        data = json.loads(result.stdout)
        records = data if isinstance(data, list) else [data]
        # CSV fallback: some plugins return [] in JSON mode
        if isinstance(records, list) and len(records) == 0:
            logger.info("run_volatility_plugin: %s JSON empty, retrying CSV", plugin)
            try:
                csv_cmd = ["vol", "-f", image_path, "-r", "csv", plugin]
                if extra_args:
                    csv_cmd.extend(extra_args)
                csv_result = subprocess.run(
                    csv_cmd, capture_output=True, text=True, timeout=300,
                )
                if csv_result.returncode == 0 and csv_result.stdout.strip():
                    records = _parse_vol_csv(csv_result.stdout)
                    logger.info("run_volatility_plugin: %s CSV fallback -> %d records", plugin, len(records))
            except (subprocess.TimeoutExpired, Exception) as csv_exc:
                logger.debug("Vol3 CSV fallback detail for %s: %s", plugin, csv_exc)
                logger.warning("run_volatility_plugin: %s CSV fallback also unavailable", plugin)
        return make_envelope(f"vol_{plugin}", image_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": f"{plugin}: timed out after 300s", "output": [], "record_count": 0}
    except json.JSONDecodeError as exc:
        logger.debug("Vol3 JSON parse detail for %s: %s", plugin, exc)
        return {"error": f"{plugin}: output not parseable (Vol3 JSON error)",
                "output": [], "record_count": 0}

# Slot 31J-beta: build SleuthKit CLI args with tsk_recover image-before-output_dir.
def _build_sleuthkit_command(command: str, image_path: str, args: list | None = None) -> list[str]:
    cli_args = [str(arg) for arg in (args or [])]
    if command == "tsk_recover" and cli_args:
        return [command, str(image_path), *cli_args]
    return [command, *cli_args, str(image_path)]


def run_sleuthkit(command: str, image_path: str, args: list = None) -> dict:
    """Run Sleuthkit tools (fls, icat, mmls, etc) on disk evidence."""
    ms = start_timer()
    from sift_sentinel.coordinator import _SLEUTHKIT_COMMANDS
    ALLOWED = set(_SLEUTHKIT_COMMANDS)
    if command not in ALLOWED:
        return {
            "error": f"Command {command} not allowed. Use: {sorted(ALLOWED)}",
            "failure_mode": "command_not_allowed",
            "output": [],
            "record_count": 0,
        }
    cmd = _build_sleuthkit_command(command, image_path, args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        # 31G-TSK-RECOVER-TYPED-FLOW:
        # tsk_recover writes recovered files into output_dir; stdout is often
        # empty even on success. Inventory the output directory so recovered
        # artifacts can flow into EvidenceDB as typed facts.
        if command == "tsk_recover":
            import hashlib
            import os

            output_dir = str(args[0]) if args else ""
            max_records = int(os.environ.get("SIFT_TSK_RECOVER_MAX_RECORDS", "2000") or "2000")
            hash_max = int(os.environ.get("SIFT_TSK_RECOVER_HASH_MAX_BYTES", str(50 * 1024 * 1024)) or str(50 * 1024 * 1024))
            records = []
            truncated = False

            def _sha256_file(path: str) -> str:
                h = hashlib.sha256()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
                return h.hexdigest()

            if output_dir and os.path.isdir(output_dir):
                for root, dirs, files in os.walk(output_dir):
                    dirs.sort()
                    files.sort()
                    for name in files:
                        full_path = os.path.join(root, name)
                        try:
                            st = os.stat(full_path)
                        except OSError:
                            continue

                        rel_path = os.path.relpath(full_path, output_dir)
                        rec = {
                            "path": rel_path.replace(os.sep, "/"),
                            "recovered_path": full_path,
                            "name": name,
                            "size": int(st.st_size),
                            "source": "tsk_recover",
                        }

                        if st.st_size <= hash_max:
                            try:
                                rec["sha256"] = _sha256_file(full_path)
                            except OSError:
                                rec["sha256"] = ""
                                rec["hash_error"] = "read_failed"
                        else:
                            rec["sha256"] = ""
                            rec["hash_skipped"] = "size_exceeds_limit"

                        records.append(rec)
                        if len(records) >= max_records:
                            truncated = True
                            break
                    if truncated:
                        break

            envelope = make_envelope(f"sleuthkit_{command}", image_path, records, ms)
            envelope["returncode"] = result.returncode
            envelope["output_dir"] = output_dir
            if truncated:
                envelope["truncated"] = True
                envelope["max_records"] = max_records
            if result.stderr:
                envelope["stderr_excerpt"] = result.stderr[:500]
            if result.returncode != 0:
                envelope["failure_mode"] = "runtime_error"
                envelope["error"] = result.stderr[:500] or f"{command} exited with code {result.returncode}"
            return envelope

        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
        envelope = make_envelope(f"sleuthkit_{command}", image_path, lines, ms)
        envelope["returncode"] = result.returncode
        if result.stderr:
            envelope["stderr_excerpt"] = result.stderr[:500]
        if result.returncode != 0:
            envelope["failure_mode"] = "runtime_error"
            envelope["error"] = result.stderr[:500] or f"{command} exited with code {result.returncode}"
        elif not lines and result.stderr.strip():
            envelope["failure_mode"] = "stderr_no_records"
            envelope["error"] = result.stderr[:500]
        return envelope
    except subprocess.TimeoutExpired:
        return {
            "tool_name": f"sleuthkit_{command}",
            "error": f"{command} timed out",
            "failure_mode": "timeout",
            "output": [],
            "record_count": 0,
        }


def run_yara(rules_path: str, target_path: str) -> dict:
    """Run YARA rules against files or directories with rule-load observability."""
    ms = start_timer()
    rule_suffixes = (".yar", ".yara", ".rule", ".rules")

    def _rule_files(path: str) -> list[str]:
        if os.path.isfile(path):
            return [path]
        if os.path.isdir(path):
            discovered: list[str] = []
            for root, _dirs, files in os.walk(path):
                for name in files:
                    if name.lower().endswith(rule_suffixes):
                        discovered.append(os.path.join(root, name))
            return sorted(discovered)
        if os.path.exists(path):
            return [path]
        return []

    def _annotate_yara_envelope(envelope: dict, *, rule_count: int, match_count: int) -> dict:
        loaded = rule_count > 0
        envelope.update(
            {
                "rules_path": rules_path,
                "rules_file_count": rule_count,
                "rules_loaded_count": rule_count,
                "rules_loaded": loaded,
                "yara_rules_loaded_gate": "PASS" if loaded else "FAIL",
                "yara_match_count": match_count,
                "zero_result_meaning": (
                    "rules_loaded_no_matches"
                    if loaded and match_count == 0
                    else "rules_loaded_matches_found"
                    if loaded
                    else "rules_not_loaded"
                ),
            }
        )
        return envelope

    if not os.path.exists(rules_path):
        envelope = make_envelope("yara_scan", target_path, [], ms)
        envelope.update(
            {
                "error": f"Rules file not found: {rules_path}",
                "failure_mode": "rules_path_invalid",
            }
        )
        return _annotate_yara_envelope(envelope, rule_count=0, match_count=0)

    rule_files = _rule_files(rules_path)
    rule_count = len(rule_files)

    if rule_count == 0:
        envelope = make_envelope("yara_scan", target_path, [], ms)
        envelope.update(
            {
                "error": f"No YARA rule files found: {rules_path}",
                "failure_mode": "no_rules_loaded",
            }
        )
        return _annotate_yara_envelope(envelope, rule_count=0, match_count=0)

    try:
        # 31AQ-fix: pass actual rule files (already discovered by _rule_files),
        # not the directory path. YARA expects rule-file args; passing a dir caused
        # "error: input in flex scanner failed" + 7ms silent failures.
        cmd = ["yara", "-r"] + rule_files + [target_path]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=300
        )
        matches = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split(" ", 1)
                matches.append({"rule": parts[0], "target": parts[1] if len(parts) > 1 else ""})
        envelope = make_envelope("yara_scan", target_path, matches, ms)
        return _annotate_yara_envelope(envelope, rule_count=rule_count, match_count=len(matches))
    except subprocess.TimeoutExpired:
        envelope = make_envelope("yara_scan", target_path, [], ms)
        envelope.update({"error": "YARA scan timed out", "failure_mode": "timeout"})
        return _annotate_yara_envelope(envelope, rule_count=rule_count, match_count=0)



def _safe_output_dir(requested: str, default_subdir: str) -> str:
    """Ensure output_dir is under _SAFE_OUTPUT_BASE. Never rmtree arbitrary paths."""
    resolved = os.path.realpath(requested)
    safe_base = os.path.realpath(_SAFE_OUTPUT_BASE)
    if not resolved.startswith(safe_base + os.sep) and resolved != safe_base:
        resolved = os.path.join(safe_base, default_subdir)
    return resolved



# 31G-BULK-SAMPLES: bounded feature samples for bulk_extractor summary output.
# bulk_extractor remains summary-only (record_count == 1); samples are small,
# deterministic, and are used only as traceable context/corroboration.
def _bulk_extractor_count_and_sample_feature_file(path: str, max_samples: int) -> tuple[int, list[str]]:
    count = 0
    samples: list[str] = []
    seen: set[str] = set()
    try:
        cap = max(0, int(max_samples))
    except (TypeError, ValueError):
        cap = 0

    if not os.path.exists(path):
        return 0, samples

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip() or line.startswith("#"):
                    continue
                count += 1

                if len(samples) >= cap:
                    continue

                # bulk_extractor feature files are generally:
                # offset<TAB>feature<TAB>context. Keep feature only; never
                # persist the surrounding context blob.
                parts = line.rstrip("\n\r").split("\t")
                value = parts[1] if len(parts) >= 2 else parts[0]
                value = value.replace("\x00", "")
                value = "".join(ch for ch in value if ch.isprintable()).strip()
                if not value:
                    continue
                value = value[:500]
                if value in seen:
                    continue
                seen.add(value)
                samples.append(value)
    except OSError:
        return count, samples

    return count, samples


# 31G-BULK-DAG: bulk_extractor histogram files ("n=COUNT<TAB>VALUE") are the
# deduplicated, frequency-RANKED aggregation of a flat feature file -- the
# "which URLs/domains actually recur" view, far more useful than arbitrary
# first-N raw samples. Returns (top_items_by_count, distinct_total). Universal:
# pure parse, no case/value list.
def _bulk_extractor_histogram_top(path: str, max_items: int) -> tuple[list[dict], int]:
    try:
        cap = max(0, int(max_items))
    except (TypeError, ValueError):
        cap = 0
    if not os.path.exists(path):
        return [], 0
    items: list[tuple[int, str]] = []
    distinct = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.startswith("n="):
                    continue
                parts = line.rstrip("\n\r").split("\t")
                try:
                    n = int(parts[0][2:])
                except (ValueError, IndexError):
                    continue
                value = parts[1] if len(parts) >= 2 else ""
                value = value.replace("\x00", "")
                value = "".join(ch for ch in value if ch.isprintable()).strip()[:500]
                if not value:
                    continue
                distinct += 1
                items.append((n, value))
    except OSError:
        return [], distinct
    items.sort(key=lambda t: t[0], reverse=True)
    return [{"value": v, "count": n} for n, v in items[:cap]], distinct


def _mask_ccn(value: str) -> str:
    """PCI-style mask for a carved credit-card feature: keep only the last 4 digits.
    The COUNT of carved cards is the data-leakage signal; raw card numbers are never
    persisted into the audit trail."""
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    if len(digits) < 4:
        return "****"
    return "*" * (len(digits) - 4) + digits[-4:]

def run_bulk_extractor(image_path: str, output_dir: str = "/tmp/sift-sentinel-tools/bulk_out") -> dict:
    """Run bulk_extractor to carve emails, URLs, domains from disk/memory image."""
    ms = start_timer()
    if not os.path.exists(image_path):
        return {"error": f"Image not found: {image_path}", "output": [], "record_count": 0}
    output_dir = _safe_output_dir(output_dir, "bulk_out")
    os.makedirs(_SAFE_OUTPUT_BASE, exist_ok=True)
    # Remove stale output dir (bulk_extractor refuses to overwrite)
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir)
    # Bound the carve: Step 6 waits for the slowest tool, so an unbounded
    # bulk_extractor (the old hardcoded 600 s) can dominate wall-clock while
    # returning little -- extract_network_iocs already covers the network-IOC
    # value cheaply. Default 180 s; operators raise SIFT_BULK_EXTRACTOR_TIMEOUT
    # for an exhaustive carve.
    try:
        _be_timeout = max(1, int(os.environ.get("SIFT_BULK_EXTRACTOR_TIMEOUT", "180") or "180"))
    except (TypeError, ValueError):
        _be_timeout = 180
    try:
        result = subprocess.run(
            ["bulk_extractor", "-o", output_dir, image_path],
            capture_output=True, text=True, timeout=_be_timeout,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        counts: dict[str, int] = {}
        def _bulk_sample_cap(env_name: str, default: int) -> int:
            try:
                return max(0, int(os.environ.get(env_name, str(default))))
            except (TypeError, ValueError):
                return default

        sample_caps = {
            "email": _bulk_sample_cap("SIFT_BULK_EMAIL_SAMPLE_MAX", 10),
            "url": _bulk_sample_cap("SIFT_BULK_URL_SAMPLE_MAX", 25),
            "domain": _bulk_sample_cap("SIFT_BULK_DOMAIN_SAMPLE_MAX", 25),
            # 31G-BULK-IOC-PII: IP network IOCs + carved PII (credit cards / phones)
            # are first-class data-leakage signals -- the COUNT is the exfil indicator.
            "ip": _bulk_sample_cap("SIFT_BULK_IP_SAMPLE_MAX", 25),
            "ccn": _bulk_sample_cap("SIFT_BULK_CCN_SAMPLE_MAX", 10),
            "telephone": _bulk_sample_cap("SIFT_BULK_TELEPHONE_SAMPLE_MAX", 10),
        }
        for name in ("email", "url", "domain", "ip", "ccn", "telephone"):
            path = os.path.join(output_dir, f"{name}.txt")
            count, sample = _bulk_extractor_count_and_sample_feature_file(
                path, sample_caps[name])
            counts[f"{name}s"] = count
            # PCI: never persist raw carved card numbers -- mask to last 4.
            if name == "ccn":
                sample = [_mask_ccn(s) for s in sample]
            counts[f"{name}s_sample"] = sample

        # 31G-BULK-HISTOGRAM: replace arbitrary first-N URL/domain samples with the
        # deduplicated, frequency-RANKED top features from bulk_extractor's own
        # histogram files -- "which URLs/domains actually recur" (significant IOC
        # candidates), plus the true distinct cardinality. Universal.
        hist_caps = {
            "url": _bulk_sample_cap("SIFT_BULK_URL_TOP_MAX", 25),
            "domain": _bulk_sample_cap("SIFT_BULK_DOMAIN_TOP_MAX", 25),
        }
        for name in ("url", "domain"):
            top, distinct = _bulk_extractor_histogram_top(
                os.path.join(output_dir, f"{name}_histogram.txt"), hist_caps[name])
            counts[f"{name}s_top"] = top
            counts[f"{name}s_distinct"] = distinct

        # 31G-BULK-DGA: flag algorithmically-generated (DGA) C2 domains in the carved
        # set by STRUCTURE alone (entropy / low-vowel / consonant-run / digits -- no
        # domain blocklist, so it generalizes to a held-out box). DGA domains are each
        # individually low-frequency, so scan the FULL deduplicated histogram, not the
        # top-by-count. The count is a strong malware-C2 indicator.
        all_domains, _domain_distinct = _bulk_extractor_histogram_top(
            os.path.join(output_dir, "domain_histogram.txt"), 100000)
        from sift_sentinel.analysis.dga_detection import flag_dga_domains
        dga_suspects, dga_count = flag_dga_domains(
            all_domains, _bulk_sample_cap("SIFT_BULK_DGA_SAMPLE_MAX", 25))
        counts["dga_suspected_domains"] = dga_count
        counts["dga_suspected_sample"] = dga_suspects

        # 31X-LITE COVERAGE FIX: bulk_extractor emits ONE summary record.
        # record_count MUST equal len(output) (==1) so the coverage gate
        # sees the truth: this is a summary-only tool, not 151k typed
        # facts. The carved totals stay as DATA inside the summary
        # record under "carved_feature_total" alongside the per-feature
        # counts. Coverage gate treats bulk_extractor as summary-only
        # by design (see drift_gate._SUMMARY_ONLY_TOOLS).
        counts["carved_feature_total"] = sum(
            v for k, v in counts.items()
            if k in ("emails", "urls", "domains", "ips", "ccns", "telephones")
        )
        return make_envelope("bulk_extractor", image_path, [counts], ms)
    except subprocess.TimeoutExpired:
        return {"error": "bulk_extractor timed out after %ss" % _be_timeout,
                "output": [], "record_count": 0}


def run_exiftool(file_path: str) -> dict:
    """Run exiftool to extract file metadata as JSON."""
    ms = start_timer()
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}", "output": [], "record_count": 0}
    try:
        result = subprocess.run(
            ["exiftool", "-json", file_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        data = json.loads(result.stdout)
        records = data if isinstance(data, list) else [data]
        return make_envelope("exiftool", file_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "exiftool timed out after 30s", "output": [], "record_count": 0}
    except json.JSONDecodeError as exc:
        return {"error": f"JSON parse failed: {exc}", "output": [], "record_count": 0}


def run_ssdeep(file_path: str) -> dict:
    """Run ssdeep fuzzy hashing on a file."""
    ms = start_timer()
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}", "output": [], "record_count": 0}
    try:
        result = subprocess.run(
            ["ssdeep", file_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and not l.startswith("ssdeep,")]
        hash_line = lines[0] if lines else ""
        records = [{"hash": hash_line, "file": file_path}]
        return make_envelope("ssdeep", file_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "ssdeep timed out after 30s", "output": [], "record_count": 0}


def _not_applicable_no_target(kind: str) -> dict:
    """Universal: an image/file-consumer tool resolved to NO target (None/empty)
    -- e.g. a memory-image consumer on a disk-only run -- reports a clean
    not_applicable, the same honest shape SRUM/Prefetch use when their artifact
    is absent. NOT an error (which reads as a tool failure). Keyed on
    target-is-None; no case data."""
    return {
        "output": [], "record_count": 0, "status": "not_applicable",
        "not_applicable_reason": f"no {kind} target resolved for this evidence",
    }


def run_foremost(image_path: str, output_dir: str = "/tmp/sift-sentinel-tools/foremost_out") -> dict:
    """Run foremost file carver on a disk/memory image."""
    ms = start_timer()
    if not image_path:
        return _not_applicable_no_target("image")
    if not os.path.exists(image_path):
        return {"error": f"Image not found: {image_path}", "output": [], "record_count": 0}
    output_dir = _safe_output_dir(output_dir, "foremost_out")
    os.makedirs(_SAFE_OUTPUT_BASE, exist_ok=True)
    # Remove stale output dir (foremost refuses to overwrite)
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir)
    try:
        result = subprocess.run(
            ["foremost", "-i", image_path, "-o", output_dir],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        audit_path = os.path.join(output_dir, "audit.txt")
        files_carved = 0
        if os.path.exists(audit_path):
            with open(audit_path) as f:
                for line in f:
                    if "FILES EXTRACTED" in line.upper():
                        # Parse "Files Extracted: 42" style lines
                        parts = line.split(":")
                        if len(parts) >= 2:
                            try:
                                files_carved = int(parts[-1].strip())
                            except ValueError:
                                pass
        records = [{"files_carved": files_carved}]
        env = make_envelope("foremost", image_path, records, ms)
        env["record_count"] = files_carved
        return env
    except subprocess.TimeoutExpired:
        return {"error": "foremost timed out after 600s", "output": [], "record_count": 0}


def run_log2timeline(image_path: str, output_file: str = "/tmp/plaso.dump") -> dict:
    """Run log2timeline (Plaso) to generate super-timeline from evidence."""
    ms = start_timer()
    if not os.path.exists(image_path):
        return {"error": f"Image not found: {image_path}", "output": [], "record_count": 0}
    try:
        result = subprocess.run(
            ["log2timeline.py", "--parsers", "all", output_file, image_path],
            capture_output=True, text=True, timeout=1800,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = [{"status": "complete", "output": output_file}]
        return make_envelope("log2timeline", image_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "log2timeline timed out after 1800s", "output": [], "record_count": 0}


def run_regripper(hive_path: str, plugin: str = None) -> dict:
    """Run RegRipper on a registry hive, optionally with a specific plugin."""
    ms = start_timer()
    if not os.path.exists(hive_path):
        return {"error": f"Hive not found: {hive_path}", "output": [], "record_count": 0}
    cmd = ["rip.pl", "-r", hive_path]
    if plugin:
        cmd.extend(["-p", plugin])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
        return make_envelope("regripper", hive_path, lines, ms)
    except subprocess.TimeoutExpired:
        return {"error": "regripper timed out after 60s", "output": [], "record_count": 0}


def run_strings(file_path: str, encoding: str = "unicode") -> dict:
    """Run strings on a file. encoding: 'unicode' for -el, 'ascii' for default."""
    ms = start_timer()
    if not file_path:
        return _not_applicable_no_target("file")
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}", "output": [], "record_count": 0}
    cmd = ["strings"]
    if encoding == "unicode":
        cmd.extend(["-e", "l"])
    cmd.append(file_path)
    # Budget control: a full-image strings scan is the historic slow tool. Its
    # wall time is bounded by SIFT_STRINGS_TIMEOUT (default 120s) so an operator
    # can cap its share of the pipeline budget; output is separately capped by
    # SIFT_STRINGS_MAX records. Dataset-agnostic.
    try:
        _strings_timeout = int(os.environ.get("SIFT_STRINGS_TIMEOUT", "120") or "120")
    except (TypeError, ValueError):
        _strings_timeout = 120
    _sift_strings_cap = int(os.environ.get("SIFT_STRINGS_MAX", "5000") or "5000")
    _timed_out = False
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_strings_timeout)
        _out = result.stdout or ""
    except subprocess.TimeoutExpired as _te:
        # SALVAGE: on a big image `strings` can exceed the cap, but the bytes it
        # already emitted are valid strings. Keep them (up to SIFT_STRINGS_MAX)
        # instead of dropping the whole result to zero. Dataset-agnostic: no case
        # content, just "use what was produced before the wall-clock bound."
        _timed_out = True
        _out = _te.stdout or ""
        if isinstance(_out, (bytes, bytearray)):
            _out = _out.decode("utf-8", "replace")
    lines = [l for l in _out.strip().split("\n") if l.strip()]
    capped = lines if _sift_strings_cap <= 0 else lines[:_sift_strings_cap]
    env = make_envelope("strings", file_path, capped, ms)
    if _timed_out and isinstance(env, dict):
        # Flag partiality for the record; the salvaged strings still flow to the DB.
        env["partial"] = True
        env["partial_reason"] = f"strings exceeded {_strings_timeout}s; kept {len(capped)} strings emitted before the cap"
    return env


def run_mftecmd(mft_path: str, output_csv: str = "/tmp/sift-sentinel-tools/mft.csv") -> dict:
    """Run MFTECmd to parse $MFT + $J + $LogFile into CSV."""
    ms = start_timer()
    if not os.path.exists(mft_path):
        return {"error": f"MFT not found: {mft_path}", "output": [], "record_count": 0}
    if os.path.isdir(mft_path):
        # A directory (e.g. the mount root) is never a valid -f input: MFTECmd
        # produces no CSV rows and the 'complete_no_data' placeholder then
        # masquerades as '1 record'. Fail honestly; callers resolve a real
        # file via disk.resolve_mft_source().
        return {"error": "MFT path is a directory (mount root?); MFTECmd "
                         f"needs the $MFT file: {mft_path}",
                "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        result = subprocess.run(
            ["MFTECmd", "-f", mft_path, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv)],
            capture_output=True, text=True, timeout=1800,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = _parse_eztools_csv(output_csv)
        if not records:
            records = [{"status": "complete_no_data", "output": output_csv, "stderr": result.stderr[:200]}]
        return make_envelope("MFTECmd", mft_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "MFTECmd timed out", "output": [], "record_count": 0}


def run_recmd(hive_path: str, output_csv: str = "/tmp/sift-sentinel-tools/recmd.csv", batch_file: str = "/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb") -> dict:
    """Run RECmd to parse registry hives with Kroll_Batch.reb (4000+ records typical)."""
    ms = start_timer()
    if not os.path.exists(hive_path):
        return {"error": f"Hive not found: {hive_path}", "output": [], "record_count": 0}
    if not os.path.exists(batch_file):
        return {"error": f"Batch file not found: {batch_file}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        flag = "-d" if os.path.isdir(hive_path) else "-f"
        result = subprocess.run(
            ["RECmd", flag, hive_path, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv), "--bn", batch_file],
            capture_output=True, text=True, timeout=1800,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = _parse_eztools_csv(output_csv)
        if not records:
            records = [{"status": "complete_no_data", "output": output_csv, "stderr": result.stderr[:200]}]
        return make_envelope("RECmd", hive_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "RECmd timed out", "output": [], "record_count": 0}


def run_evtxecmd(evtx_path: str, output_csv: str = "/tmp/sift-sentinel-tools/evtx.csv") -> dict:
    """Run EvtxECmd to parse EVTX files to CSV."""
    ms = start_timer()
    if not os.path.exists(evtx_path):
        return {"error": f"EVTX path not found: {evtx_path}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        flag = "-d" if os.path.isdir(evtx_path) else "-f"
        result = subprocess.run(
            ["EvtxECmd", flag, evtx_path, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv)],
            capture_output=True, text=True, timeout=1800,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = _parse_eztools_csv(output_csv)
        if not records:
            records = [{"status": "complete_no_data", "output": output_csv, "stderr": result.stderr[:200]}]
        return make_envelope("EvtxECmd", evtx_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "EvtxECmd timed out", "output": [], "record_count": 0}


def run_amcacheparser(hive_path: str, output_csv: str = "/tmp/sift-sentinel-tools/amcache.csv") -> dict:
    """Run AmcacheParser to parse Amcache.hve."""
    ms = start_timer()
    if not os.path.exists(hive_path):
        return {"error": f"Hive not found: {hive_path}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        result = subprocess.run(
            ["AmcacheParser", "-f", hive_path, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv)],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        # AmcacheParser writes multiple CSVs: {basename}_UnassociatedFileEntries.csv, etc.
        import glob
        base_no_ext = output_csv.rsplit(".csv", 1)[0]
        csv_files = glob.glob(f"{base_no_ext}_*.csv")
        records = []
        for csv_file in csv_files:
            file_records = _parse_eztools_csv(csv_file)
            for rec in file_records:
                rec["_csv_source"] = os.path.basename(csv_file)
                records.append(rec)
        if not records:
            records = [{"status": "complete_no_data", "output": output_csv, "csv_files_found": csv_files, "stderr": result.stderr[:200]}]
        return make_envelope("AmcacheParser", hive_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "AmcacheParser timed out", "output": [], "record_count": 0}


def run_appcompatcacheparser(hive_path: str, output_csv: str = "/tmp/sift-sentinel-tools/shimcache.csv") -> dict:
    """Run AppCompatCacheParser to parse SYSTEM hive ShimCache."""
    ms = start_timer()
    if not os.path.exists(hive_path):
        return {"error": f"Hive not found: {hive_path}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        result = subprocess.run(
            ["AppCompatCacheParser", "-f", hive_path, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv)],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = _parse_eztools_csv(output_csv)
        if not records:
            records = [{"status": "complete_no_data", "output": output_csv, "stderr": result.stderr[:200]}]
        return make_envelope("AppCompatCacheParser", hive_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "AppCompatCacheParser timed out", "output": [], "record_count": 0}



# 31K-SRUM-SURFACE-RESOLVER: SRUM wrapper. SRUM is aggregate
# app/user/resource/network-usage telemetry. It is artifact-gated by
# high_value_tool_args before Step 6, but this wrapper also fails closed
# when called directly.
# 31AG-D1b: Linux-native SRUM (SRUDB.dat) parsing via pyesedb. SrumECmd is
# Windows-only ("Non-Windows platforms not supported due to ... ESI specific
# Windows libraries") and yields 0 on the SIFT Linux box for every dataset,
# where the pipeline then masks SRUM as benign ok_no_records. These helpers
# decode the ESE database natively and emit rows keyed for the existing
# srum_usage_fact compiler. Dataset-agnostic: pure ESE/SID/OLE-date decoding.
def _srum_format_sid(blob) -> str:
    """Binary SID -> 'S-1-..' string. '' on malformed/short input."""
    try:
        if not blob or len(blob) < 8:
            return ""
        import struct as _struct
        rev = blob[0]
        sub_count = blob[1]
        authority = int.from_bytes(blob[2:8], "big")
        subs = []
        for k in range(sub_count):
            off = 8 + 4 * k
            if off + 4 > len(blob):
                break
            subs.append(_struct.unpack_from("<I", blob, off)[0])
        return "S-%d-%d%s" % (rev, authority, "".join("-%d" % s for s in subs))
    except Exception:
        return ""


def _srum_decode_idmap_blob(id_type, blob) -> str:
    """SruDbIdMapTable IdBlob -> string. IdType 3 = user SID (binary); else
    app/service identity (UTF-16LE). Dataset-agnostic."""
    if not blob:
        return ""
    try:
        if int(id_type) == 3:
            return _srum_format_sid(blob)
    except Exception:
        pass
    try:
        return blob.decode("utf-16-le", "replace").rstrip("\x00").strip()
    except Exception:
        return ""


def _srum_ole_to_iso(value) -> str:
    """OLE-automation date (days since 1899-12-30) -> ISO8601. '' for
    null/implausible values (guards non-date columns)."""
    try:
        days = float(value)
    except (TypeError, ValueError):
        return ""
    if not (1000.0 < days < 200000.0):
        return ""
    from datetime import datetime as _dt, timedelta as _td
    try:
        return (_dt(1899, 12, 30) + _td(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, ValueError):
        return ""


def _srum_build_idmap(f) -> dict:
    """IdIndex(int) -> resolved app/SID string from SruDbIdMapTable."""
    idmap = {}
    for ti in range(f.get_number_of_tables()):
        t = f.get_table(ti)
        if t.get_name() != "SruDbIdMapTable":
            continue
        ci = {t.get_column(j).get_name(): j
              for j in range(t.get_number_of_columns())}
        try:
            nrec = t.get_number_of_records()
        except Exception:
            return idmap
        for ri in range(nrec):
            try:
                r = t.get_record(ri)
                ix = r.get_value_data_as_integer(ci["IdIndex"])
                if ix is None:
                    continue
                idmap[ix] = _srum_decode_idmap_blob(
                    r.get_value_data_as_integer(ci["IdType"]),
                    r.get_value_data(ci["IdBlob"]))
            except Exception:
                continue
        break
    return idmap


def _srum_extract_row(record, ci, idmap, table_name, srum_path) -> dict:
    """One usage-table record -> dict keyed for the srum_usage_fact compiler."""
    import struct as _struct
    appid = record.get_value_data_as_integer(ci["AppId"]) if "AppId" in ci else None
    app = idmap.get(appid, "") or ("AppId:%s" % appid if appid else "")
    out = {"_srum_table": table_name, "ApplicationName": app,
           "TimeStamp": "", "SourceFile": srum_path}
    if "UserId" in ci:
        uid = record.get_value_data_as_integer(ci["UserId"])
        usr = idmap.get(uid, "") if uid is not None else ""
        if usr.startswith("S-1-"):
            out["UserSid"] = usr
        elif usr:
            out["UserName"] = usr
    if "TimeStamp" in ci:
        tsb = record.get_value_data(ci["TimeStamp"])
        if tsb and len(tsb) >= 8:
            out["TimeStamp"] = _srum_ole_to_iso(_struct.unpack("<d", tsb[:8])[0])
    if "BytesSent" in ci:
        out["BytesSent"] = record.get_value_data_as_integer(ci["BytesSent"]) or 0
    if "BytesRecvd" in ci:
        out["BytesReceived"] = record.get_value_data_as_integer(ci["BytesRecvd"]) or 0
    return out


def _srum_accumulate(agg: dict, row: dict) -> None:
    """Fold one SRUM row into per-(table, app, user) aggregates: sum bytes, count
    events, keep the latest timestamp. Collapses tens of thousands of per-event
    rows to a few hundred meaningful per-app groups -- prevents the raw SRUM
    volume from flooding the candidate pipeline while preserving per-app egress
    totals (the right unit for the exfil-outlier signal)."""
    key = (row.get("_srum_table", ""), row.get("ApplicationName", ""),
           row.get("UserSid") or row.get("UserName") or "")
    a = agg.get(key)
    if a is None:
        a = {
            "_srum_table": row.get("_srum_table", ""),
            "ApplicationName": row.get("ApplicationName", ""),
            "TimeStamp": row.get("TimeStamp", ""),
            "SourceFile": row.get("SourceFile", ""),
            "BytesSent": 0, "BytesReceived": 0, "event_count": 0,
        }
        if row.get("UserSid"):
            a["UserSid"] = row["UserSid"]
        if row.get("UserName"):
            a["UserName"] = row["UserName"]
        agg[key] = a
    try:
        a["BytesSent"] += int(row.get("BytesSent", 0) or 0)
        a["BytesReceived"] += int(row.get("BytesReceived", 0) or 0)
    except (TypeError, ValueError):
        pass
    a["event_count"] += 1
    ts = row.get("TimeStamp", "")
    if ts and ts > (a.get("TimeStamp") or ""):
        a["TimeStamp"] = ts


def _srum_parse_pyesedb(srum_path: str, cap: int = 50000):
    """Linux-native SRUM parse via pyesedb. Returns a list of compiler-keyed
    rows, or None if pyesedb is unavailable / the DB cannot be opened (caller
    then falls back to SrumECmd). Tolerates dirty per-table page errors. Iterates
    every GUID-named provider table with AppId+TimeStamp -> universal."""
    try:
        import pyesedb as _ese
    except Exception:
        return None
    try:
        f = _ese.file()
        f.open(srum_path)
    except Exception:
        return None
    agg: dict = {}
    try:
        idmap = _srum_build_idmap(f)
        for ti in range(f.get_number_of_tables()):
            t = f.get_table(ti)
            name = t.get_name()
            if not name.startswith("{"):
                continue
            ci = {t.get_column(j).get_name(): j
                  for j in range(t.get_number_of_columns())}
            if "AppId" not in ci or "TimeStamp" not in ci:
                continue
            try:
                nrec = t.get_number_of_records()
            except Exception:
                continue
            for ri in range(nrec):
                try:
                    _srum_accumulate(agg, _srum_extract_row(
                        t.get_record(ri), ci, idmap, name, srum_path))
                except Exception:
                    continue
    finally:
        try:
            f.close()
        except Exception:
            pass
    # Aggregated per-(app,user,table) rows -- a few hundred, not tens of
    # thousands of per-event rows (cap is a final safety bound).
    return list(agg.values())[:cap]


def _resolve_srudb_path(hint_path: str):
    """Find SRUDB.dat case-insensitively near a coordinator-supplied hint path.

    Returns the hint itself when it exists (fast path). Otherwise estimates
    the mount root (3 ancestors above the hint — parents[3]) and walks from
    there depth-bounded to 8, returning the first file whose name is
    'srudb.dat' (case-insensitive) that sits inside a path containing both
    'system32' and 'sru' directory tokens.

    Universal: no hardcoded mount layouts, no case-specific paths. Covers:
    - Standard layout:      mount/Windows/System32/sru/SRUDB.dat
    - Case-variant layout:  mount/windows/system32/sru/SRUDB.dat
    - Drive-letter layout:  mount/C/Windows/System32/sru/SRUDB.dat
      (parent[3] = C/; walk finds Windows/System32/sru/SRUDB.dat at depth 3)
    Returns None if the file cannot be located.
    """
    import os as _os
    from pathlib import Path as _Path
    raw = str(hint_path or "").strip()
    if not raw:
        return None
    p = _Path(raw)
    if p.exists():
        return str(p)
    # Only attempt glob when the hint looks like a Windows SRU path (contains
    # 'system32' and/or '/sru/' tokens). Bare paths like /tmp/SRUDB.dat must
    # fail cleanly — the walk must NOT traverse upward into system temp dirs.
    hint_lower = raw.lower().replace("\\", "/")
    if "system32" not in hint_lower and "/sru/" not in hint_lower:
        return None
    # Use parents[3] = mount root for standard layout.
    # For drive-letter layout (mount/C/Windows/...) parents[3] = C/; the
    # bounded walk still finds Windows/System32/sru/SRUDB.dat inside it.
    if 3 >= len(p.parents):
        return None
    root = p.parents[3]
    if not root.is_dir():
        return None
    for dirpath, dirs, files in _os.walk(str(root)):
        rel_depth = len(_Path(dirpath).relative_to(root).parts)
        if rel_depth > 8:
            dirs.clear()
            continue
        for fname in files:
            if fname.lower() != "srudb.dat":
                continue
            tail = [x.lower() for x in _Path(dirpath).parts[-4:]]
            if any("system32" in x for x in tail) and "sru" in tail:
                return _os.path.join(dirpath, fname)
    return None


def run_srumecmd(srum_path: str, output_csv: str = "/tmp/sift-sentinel-tools/srum.csv") -> dict:
    """Run SrumECmd against SRUDB.dat and return normalized CSV rows.

    SRUM rows are not process-creation proof and do not inherently prove
    peer IPs. They are disk-side resource/network usage context.
    """
    import csv as _csv
    import glob as _glob
    import os as _os
    import signal as _signal
    import shutil as _shutil
    import subprocess as _subprocess
    import tempfile as _tempfile
    import time as _time

    ms = start_timer()
    srum_path = str(srum_path or "").strip()

    # Path-robustness: if the canonical hint path doesn't exist, try to
    # locate SRUDB.dat via case-insensitive walk under the estimated mount
    # root. Universal: standard + case-variant + drive-letter layouts.
    _resolved = _resolve_srudb_path(srum_path)
    if _resolved and _resolved != srum_path:
        logger.info("SRUM: resolved SRUDB.dat %r -> %r", srum_path, _resolved)
        srum_path = _resolved

    if not srum_path or not _os.path.exists(srum_path):
        return {
            "tool_name": "run_srumecmd",
            "error": f"SRUM database not found: {srum_path}",
            "output": [],
            "record_count": 0,
            "failure_mode": "artifact_missing",
        }

    # 31AG-D1b: pyesedb is the cross-platform primary parser. SrumECmd is
    # Windows-only and yields nothing on Linux (masking SRUM as benign). Use
    # pyesedb whenever it can open the DB; fall back to SrumECmd only if it
    # cannot (pyesedb absent / unreadable DB).
    _pye = _srum_parse_pyesedb(srum_path)
    if _pye is not None:
        env = make_envelope("SRUM-pyesedb", srum_path, _pye, ms)
        env["bounded_scope"] = "single_srudb"
        env["source_file"] = srum_path
        env["parser"] = "pyesedb"
        return env

    exe = (
        _shutil.which("SrumECmd")
        or _shutil.which("SrumECmd.exe")
        or _shutil.which("srumecmd")
        or _shutil.which("srumecmd.exe")
    )
    if not exe:
        return {
            "tool_name": "run_srumecmd",
            "error": "SrumECmd binary not installed",
            "output": [],
            "record_count": 0,
            "failure_mode": "binary_missing",
        }

    tmpdir = _tempfile.mkdtemp(prefix="sift-srumecmd-")
    cmd = [exe, "-f", srum_path, "--csv", tmpdir]

    proc = None
    try:
        proc = _subprocess.Popen(
            cmd,
            stdout=_subprocess.PIPE,
            stderr=_subprocess.PIPE,
            text=True,
            preexec_fn=_os.setsid,
        )
        try:
            stdout, stderr = proc.communicate(timeout=120)
        except _subprocess.TimeoutExpired:
            try:
                _os.killpg(proc.pid, _signal.SIGTERM)
                _time.sleep(1.0)
                if proc.poll() is None:
                    _os.killpg(proc.pid, _signal.SIGKILL)
            except Exception:
                pass
            return {
                "tool_name": "run_srumecmd",
                "error": "SrumECmd timed out after 120s",
                "output": [],
                "record_count": 0,
                "failure_mode": "timeout",
            }

        records = []
        for csv_path in sorted(_glob.glob(_os.path.join(tmpdir, "*.csv"))):
            table_name = _os.path.splitext(_os.path.basename(csv_path))[0]
            try:
                with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as fh:
                    for row in _csv.DictReader(fh):
                        if not isinstance(row, dict):
                            continue
                        clean = dict(row)
                        clean.setdefault("SourceFile", srum_path)
                        clean["_srum_table"] = table_name
                        clean["_srum_csv"] = csv_path
                        records.append(clean)
            except Exception as exc:
                records.append({
                    "SourceFile": srum_path,
                    "_srum_table": table_name,
                    "_srum_csv": csv_path,
                    "_csv_read_error": repr(exc),
                })

        if proc.returncode != 0 and not records:
            return {
                "tool_name": "run_srumecmd",
                "error": ((stderr or stdout or "")[:800] or f"SrumECmd returncode={proc.returncode}"),
                "output": [],
                "record_count": 0,
                "failure_mode": "runtime_error",
            }

        env = make_envelope("SrumECmd", srum_path, records, ms)
        env["bounded_scope"] = "single_srudb"
        env["source_file"] = srum_path
        env["srum_csv_dir"] = tmpdir
        if proc.returncode != 0:
            env["warnings"] = [((stderr or stdout or "")[:800] or f"SrumECmd returncode={proc.returncode}")]
        return env

    except Exception as exc:
        return {
            "tool_name": "run_srumecmd",
            "error": f"SrumECmd wrapper failed: {type(exc).__name__}: {exc}",
            "output": [],
            "record_count": 0,
            "failure_mode": "runtime_error",
        }



def run_sbecmd(shellbags_path: str, output_csv: str = "/tmp/sift-sentinel-tools/shellbags.csv") -> dict:
    """Run SBECmd to parse Shellbags (UsrClass.dat + NTUSER.DAT)."""
    ms = start_timer()
    if not os.path.exists(shellbags_path):
        return {"error": f"Path not found: {shellbags_path}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        result = subprocess.run(
            ["SBECmd", "-d", shellbags_path, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv)],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = [{"status": "complete", "output": output_csv}]
        return make_envelope("SBECmd", shellbags_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "SBECmd timed out", "output": [], "record_count": 0}



# 31K-EZ-BOUNDED-LNKJL: Zimmerman LNK/JumpList wrappers must never recurse
# over the full Users tree in Step 6. Full Users was observed leaving
# LECmd/JLECmd dotnet children alive for >25 minutes. These helpers bound
# Users-root invocations to high-value Recent/Desktop/JumpList artifact dirs
# and hard-kill parser process groups on timeout.
def _31k_csv_records(path: str) -> list[dict]:
    # 31K-JLECMD-SUFFIX-CSV: JLECmd rewrites --csvf names to
    # <stem>_AutomaticDestinations.csv / <stem>_CustomDestinations.csv.
    # Read the exact path when present, plus any same-directory stem*.csv.
    import csv as _csv
    import glob as _glob

    if not path:
        return []

    candidates = []
    if os.path.exists(path):
        candidates.append(path)

    out_dir = os.path.dirname(path) or "."
    stem = os.path.splitext(os.path.basename(path))[0]
    if stem:
        for p in sorted(_glob.glob(os.path.join(out_dir, stem + "*.csv"))):
            if p not in candidates:
                candidates.append(p)

    records: list[dict] = []
    for candidate in candidates:
        try:
            with open(candidate, newline="", encoding="utf-8-sig", errors="replace") as fh:
                for row in _csv.DictReader(fh):
                    if isinstance(row, dict):
                        records.append(dict(row))
        except Exception:
            continue
    return records


def _31k_write_csv(path: str, records: list[dict]) -> None:
    import csv as _csv
    if not path or not records:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = []
    seen = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        for key in rec.keys():
            if key not in seen:
                seen.add(key)
                fields.append(key)
    if not fields:
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = _csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for rec in records:
            if isinstance(rec, dict):
                w.writerow(rec)


def _31k_has_file(root: str, suffixes: tuple[str, ...], max_depth: int = 2) -> bool:
    if not root or not os.path.isdir(root):
        return False
    root = os.path.abspath(root)
    root_depth = root.rstrip(os.sep).count(os.sep)
    try:
        for cur, dirs, files in os.walk(root, followlinks=False):
            depth = cur.rstrip(os.sep).count(os.sep) - root_depth
            if depth >= max_depth:
                dirs[:] = []
            for name in files:
                low = name.lower()
                if any(low.endswith(suf) for suf in suffixes):
                    return True
    except Exception:
        return False
    return False


def _31k_users_children(users_root: str) -> list[str]:
    out = []
    skip = {"all users", "default user", "default.migrated"}
    try:
        for ent in os.scandir(users_root):
            if not ent.is_dir(follow_symlinks=False):
                continue
            if ent.name.strip().lower() in skip:
                continue
            out.append(ent.path)
    except Exception:
        return []
    return sorted(set(out))


def _31k_lnk_targets(lnk_path: str) -> list[str]:
    if not lnk_path:
        return []
    if os.path.isfile(lnk_path):
        return [lnk_path]
    if not os.path.isdir(lnk_path):
        return []

    base = os.path.basename(os.path.normpath(lnk_path)).lower()
    if base != "users":
        return [lnk_path] if _31k_has_file(lnk_path, (".lnk",), max_depth=2) else []

    targets = []
    rels = (
        "AppData/Roaming/Microsoft/Windows/Recent",
        "AppData/Roaming/Microsoft/Office/Recent",
        "Desktop",
    )
    for user_dir in _31k_users_children(lnk_path):
        for rel in rels:
            cand = os.path.join(user_dir, *rel.split("/"))
            if _31k_has_file(cand, (".lnk",), max_depth=2):
                targets.append(cand)

    # Public/Desktop is often useful even when Public was skipped/deduped.
    pub = os.path.join(lnk_path, "Public", "Desktop")
    if _31k_has_file(pub, (".lnk",), max_depth=2):
        targets.append(pub)

    return sorted(dict.fromkeys(targets))


def _31k_jumplist_targets(jumplist_path: str) -> list[str]:
    suffixes = (".automaticdestinations-ms", ".customdestinations-ms")
    if not jumplist_path:
        return []
    if os.path.isfile(jumplist_path):
        return [jumplist_path]
    if not os.path.isdir(jumplist_path):
        return []

    base = os.path.basename(os.path.normpath(jumplist_path)).lower()
    if base != "users":
        return [jumplist_path] if _31k_has_file(jumplist_path, suffixes, max_depth=1) else []

    targets = []
    rels = (
        "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
        "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations",
    )
    for user_dir in _31k_users_children(jumplist_path):
        for rel in rels:
            cand = os.path.join(user_dir, *rel.split("/"))
            if _31k_has_file(cand, suffixes, max_depth=1):
                targets.append(cand)
    return sorted(dict.fromkeys(targets))


def _31k_run_csv_tool(cmd: list[str], csv_path: str, timeout_s: int) -> tuple[list[dict], str | None]:
    import signal as _signal
    import subprocess as _subprocess

    try:
        proc = _subprocess.Popen(
            cmd,
            stdout=_subprocess.PIPE,
            stderr=_subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            out, err = proc.communicate(timeout=timeout_s)
        except _subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, _signal.SIGTERM)
                proc.wait(timeout=2)
            except Exception:
                try:
                    os.killpg(proc.pid, _signal.SIGKILL)
                except Exception:
                    pass
            return [], "timeout_after_%ss:%s" % (timeout_s, " ".join(cmd[:4]))

        records = _31k_csv_records(csv_path)
        if proc.returncode != 0 and not records:
            return [], "returncode_%s:%s" % (proc.returncode, (err or out or "")[:300])
        return records, None
    except Exception as exc:
        return [], "exception_%s:%s" % (type(exc).__name__, str(exc)[:300])


def run_jlecmd(jumplist_path: str, output_csv: str = "/tmp/sift-sentinel-tools/jumplists.csv") -> dict:
    """Run JLECmd safely.

    Users-root input is converted to bounded JumpList destination directories.
    This prevents full-tree recursion through user profiles/junctions while
    preserving high-value JumpList evidence.
    """
    import hashlib as _hashlib
    import tempfile as _tempfile

    ms = start_timer()
    targets = _31k_jumplist_targets(jumplist_path)
    max_targets = int(os.getenv("SIFT_JLECMD_MAX_TARGET_DIRS", "40") or "40")
    timeout_s = int(os.getenv("SIFT_JLECMD_PER_TARGET_TIMEOUT_S", "45") or "45")

    tmpdir = _tempfile.mkdtemp(prefix="sift-jlecmd-")
    all_records: list[dict] = []
    warnings: list[str] = []

    for idx, target in enumerate(targets[:max_targets]):
        flag = "-f" if os.path.isfile(target) else "-d"
        digest = _hashlib.sha1(target.encode("utf-8", "ignore")).hexdigest()[:10]
        csvf = "jumplists_%03d_%s.csv" % (idx, digest)
        csv_path = os.path.join(tmpdir, csvf)
        cmd = ["JLECmd", flag, target, "--csv", tmpdir, "--csvf", csvf, "-q"]
        records, err = _31k_run_csv_tool(cmd, csv_path, timeout_s)
        all_records.extend(records)
        if err:
            warnings.append("%s => %s" % (target, err))

    _31k_write_csv(output_csv, all_records)
    env = make_envelope("JLECmd", jumplist_path, all_records, ms)
    env["bounded_scope"] = "priority_jumplist_dirs"
    env["target_count"] = len(targets)
    env["processed_target_count"] = min(len(targets), max_targets)
    if warnings:
        env["warnings"] = warnings[:10]
    return env



def run_lecmd(lnk_path: str, output_csv: str = "/tmp/sift-sentinel-tools/lnk.csv") -> dict:
    """Run LECmd safely.

    Users-root input is converted to bounded Recent/Desktop directories.
    This preserves high-value LNK evidence while avoiding full Users traversal,
    which was observed to hang dotnet LECmd for >25 minutes.
    """
    import hashlib as _hashlib
    import tempfile as _tempfile

    ms = start_timer()
    targets = _31k_lnk_targets(lnk_path)
    max_targets = int(os.getenv("SIFT_LECMD_MAX_TARGET_DIRS", "40") or "40")
    timeout_s = int(os.getenv("SIFT_LECMD_PER_TARGET_TIMEOUT_S", "30") or "30")

    tmpdir = _tempfile.mkdtemp(prefix="sift-lecmd-")
    all_records: list[dict] = []
    warnings: list[str] = []

    for idx, target in enumerate(targets[:max_targets]):
        flag = "-f" if os.path.isfile(target) else "-d"
        digest = _hashlib.sha1(target.encode("utf-8", "ignore")).hexdigest()[:10]
        csvf = "lnk_%03d_%s.csv" % (idx, digest)
        csv_path = os.path.join(tmpdir, csvf)
        cmd = ["LECmd", flag, target, "--csv", tmpdir, "--csvf", csvf, "-q"]
        records, err = _31k_run_csv_tool(cmd, csv_path, timeout_s)
        all_records.extend(records)
        if err:
            warnings.append("%s => %s" % (target, err))

    _31k_write_csv(output_csv, all_records)
    env = make_envelope("LECmd", lnk_path, all_records, ms)
    env["bounded_scope"] = "priority_lnk_dirs"
    env["target_count"] = len(targets)
    env["processed_target_count"] = min(len(targets), max_targets)
    if warnings:
        env["warnings"] = warnings[:10]
    return env


def run_rbcmd(recycle_path: str, output_csv: str = "/tmp/sift-sentinel-tools/recyclebin.csv") -> dict:
    """Run RBCmd to parse Recycle Bin $I / INFO2 files."""
    ms = start_timer()
    if not os.path.exists(recycle_path):
        return {"error": f"Path not found: {recycle_path}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        result = subprocess.run(
            ["RBCmd", "-d", recycle_path, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv)],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = [{"status": "complete", "output": output_csv}]
        return make_envelope("RBCmd", recycle_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "RBCmd timed out", "output": [], "record_count": 0}


def run_wxtcmd(activity_db: str, output_csv: str = "/tmp/sift-sentinel-tools/timeline.csv") -> dict:
    """Run WxTCmd to parse Windows Timeline ActivitiesCache.db."""
    ms = start_timer()
    if not os.path.exists(activity_db):
        return {"error": f"Path not found: {activity_db}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    try:
        result = subprocess.run(
            ["WxTCmd", "-f", activity_db, "--csv", os.path.dirname(output_csv), "--csvf", os.path.basename(output_csv)],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = [{"status": "complete", "output": output_csv}]
        return make_envelope("WxTCmd", activity_db, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "WxTCmd timed out", "output": [], "record_count": 0}


def run_evtx_dump(evtx_path: str, output_file: str = "/tmp/sift-sentinel-tools/evtx_dump.json") -> dict:
    """Run evtx_dump (Rust) to convert EVTX to JSONL."""
    ms = start_timer()
    if not os.path.exists(evtx_path):
        return {"error": f"EVTX not found: {evtx_path}", "output": [], "record_count": 0}
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, "w") as f:
            result = subprocess.run(
                ["evtx_dump", "-o", "jsonl", evtx_path],
                capture_output=True, text=True, timeout=1800,
            )
            f.write(result.stdout)
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = [{"status": "complete", "output": output_file}]
        return make_envelope("evtx_dump", evtx_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "evtx_dump timed out", "output": [], "record_count": 0}


def run_vshadowmount(image_path: str, mount_point: str = "/tmp/sift-sentinel-tools/vss_mount") -> dict:
    """Run vshadowmount to mount Volume Shadow Copies for parallel analysis."""
    ms = start_timer()
    if not os.path.exists(image_path):
        return {"error": f"Image not found: {image_path}", "output": [], "record_count": 0}
    os.makedirs(mount_point, exist_ok=True)
    try:
        result = subprocess.run(
            ["vshadowmount", image_path, mount_point],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = [{"status": "mounted", "output": mount_point}]
        return make_envelope("vshadowmount", image_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "vshadowmount timed out", "output": [], "record_count": 0}


def run_pffexport(pst_path: str, output_dir: str = "/tmp/sift-sentinel-tools/pff_out") -> dict:
    """Run pffexport to extract PST/OST mailbox contents."""
    ms = start_timer()
    if not os.path.exists(pst_path):
        return {"error": f"PST not found: {pst_path}", "output": [], "record_count": 0}
    os.makedirs(output_dir, exist_ok=True)
    try:
        result = subprocess.run(
            ["pffexport", "-t", output_dir, pst_path],
            capture_output=True, text=True, timeout=1800,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "output": [], "record_count": 0}
        records = [{"status": "complete", "output": output_dir}]
        return make_envelope("pffexport", pst_path, records, ms)
    except subprocess.TimeoutExpired:
        return {"error": "pffexport timed out", "output": [], "record_count": 0}


# ======================================================================
# Slot 31C.2 -- MemProcFS wrapper restored from 1c82295.
# Dataset-agnostic forensic-mode memory analyzer.
# Paths derive from memory_image_path input only.
# ======================================================================

# Slot 31C.2 MemProcFS aliased imports restored from 1c82295.
import csv as _a18_csv
import os as _a18_os
import subprocess as _a18_subprocess
import time as _a18_time
import tempfile
from dataclasses import dataclass as _a18_dataclass
from pathlib import Path as _A18Path



# --- restored symbol: _wait_for_memprocfs_mount_ready ---
def _wait_for_memprocfs_mount_ready(
    mount_point: str,
    timeout_sec: float,
) -> bool:
    """A7a: poll mount_point for VFS readiness.

    Returns True when at least one of MemProcFS top-level VFS
    directories appears (forensic, sys, pid, registry, files),
    False on timeout. FUSE mounts populate asynchronously after
    the mount syscall returns.
    """
    import os
    import time
    expected_roots = ("forensic", "sys", "pid", "registry", "files")
    deadline = time.time() + timeout_sec
    poll_interval = 0.25
    while time.time() < deadline:
        try:
            entries = set(os.listdir(mount_point))
        except OSError:
            entries = set()
        if entries & set(expected_roots):
            return True
        time.sleep(poll_interval)
    return False


# --- restored symbol: _walk_memprocfs_vfs ---
def _walk_memprocfs_vfs(
    mount_root: str,
    record_cap: int,
) -> tuple[list[dict], list[str]]:
    """A7a: bounded walk of MemProcFS forensic VFS roots.

    Tries documented forensic root first, then sys/forensic
    fallback. Emits metadata-only records (no raw content reads).
    """
    import os
    candidate_roots = [
        ("forensic", os.path.join(mount_root, "forensic"), "memprocfs_forensic_vfs_findings"),
        ("forensic_legacy", os.path.join(mount_root, "sys", "forensic"), "memprocfs_forensic_vfs_findings"),
    ]
    records: list[dict] = []
    warnings: list[str] = []
    seen_roots = 0
    for root_label, root_path, family in candidate_roots:
        if not os.path.isdir(root_path):
            warnings.append("memprocfs_root_missing:" + root_label)
            continue
        seen_roots += 1
        for entry in sorted(os.listdir(root_path)):
            if len(records) >= record_cap:
                warnings.append(
                    "memprocfs_record_cap_applied:" + str(record_cap)
                )
                return records, warnings
            entry_path = os.path.join(root_path, entry)
            records.append({
                "source_tool": "run_memprocfs",
                "artifact_family": "memory_forensic",
                "memprocfs_family": family,
                "vfs_root": root_label,
                "vfs_path": os.path.relpath(entry_path, mount_root),
                "name": entry,
            })
    if seen_roots == 0:
        warnings.append("memprocfs_no_forensic_roots_found")
    return records, warnings


# --- restored symbol: _terminate_memprocfs_process ---
def _terminate_memprocfs_process(proc) -> None:
    """A7a: ensure the FUSE process exits cleanly."""
    import time
    if proc.poll() is None:
        proc.terminate()
        for _ in range(20):
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        if proc.poll() is None:
            proc.kill()


# --- restored symbol: _unmount_memprocfs ---
def _unmount_memprocfs(mount_point: str) -> bool:
    """A7a: best-effort fusermount -u; never raises."""
    import subprocess
    try:
        subprocess.run(
            ["fusermount", "-u", mount_point],
            capture_output=True,
            timeout=15,
        )
        return True
    except Exception:
        return False


# --- restored symbol: _MEMPROCFS_INSTALL_DIR_DEFAULT ---
_MEMPROCFS_INSTALL_DIR_DEFAULT = "/opt/zimmermantools/MemProcFS"


# --- restored symbol: _MEMPROCFS_BINARY_NAME ---
_MEMPROCFS_BINARY_NAME = "memprocfs"


# --- restored symbol: _MEMPROCFS_VMM_SO_NAME ---
_MEMPROCFS_VMM_SO_NAME = "vmm.so"


# --- restored symbol: _MEMPROCFS_FORENSIC_DIR ---
_MEMPROCFS_FORENSIC_DIR = "forensic"


# --- restored symbol: _MEMPROCFS_CSV_SUBDIR ---
_MEMPROCFS_CSV_SUBDIR = "csv"


# --- restored symbol: _MEMPROCFS_PROGRESS_FILE ---
_MEMPROCFS_PROGRESS_FILE = "progress_percent.txt"


# --- restored symbol: _MEMPROCFS_OVERSIZED_CSV_SKIPLIST ---
_MEMPROCFS_OVERSIZED_CSV_SKIPLIST: frozenset[str] = frozenset({
    "timeline_all.csv",
    "timeline_ntfs.csv",
})


# --- restored symbol: _MEMPROCFS_PRIORITY_TIER_RANK ---
_MEMPROCFS_PRIORITY_TIER_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


# --- restored symbol: _MemProcFSCsvSpec ---
@_a18_dataclass(frozen=True)
class _MemProcFSCsvSpec:
    csv_name: str
    semantic_family: str
    semantic_role: str
    priority_tier: str
    per_csv_cap: int | None
    pid_column: str | None
    process_column: str | None
    path_column: str | None
    indicator_column: str | None
    description_column: str | None
    primary_fields: tuple[str, ...]


# --- restored symbol: _ALIAS_PARENT_PID_SOURCE ---
_ALIAS_PARENT_PID_SOURCE = "PPID"


# --- restored symbol: _ALIAS_DST_ADDRESS_SOURCE ---
_ALIAS_DST_ADDRESS_SOURCE = "DstAddr"


# --- restored symbol: _ALIAS_TIMESTAMP_SOURCES ---
_ALIAS_TIMESTAMP_SOURCES = ("CreateTime", "Time", "TimeCreate", "TimeLastRun")


# --- restored symbol: _ALIAS_COMMAND_LINE_DESCRIPTION_COLUMN ---
_ALIAS_COMMAND_LINE_DESCRIPTION_COLUMN = "CommandLine"


# --- restored symbol: _ALIAS_TASK_PATH_PATH_COLUMN ---
_ALIAS_TASK_PATH_PATH_COLUMN = "TaskPath"


# --- restored symbol: _MEMPROCFS_CSV_SPECS ---
_MEMPROCFS_CSV_SPECS: tuple[_MemProcFSCsvSpec, ...] = (
    _MemProcFSCsvSpec(
        "findevil.csv", "findevil_indicators", "anomaly_indicator",
        "CRITICAL", None, "PID", "ProcessName", None, "Type",
        "Description", ("Address",),
    ),
    _MemProcFSCsvSpec(
        "yara.csv", "memory_yara_hits", "rule_match",
        "CRITICAL", None, "PID", "ProcessName", "ProcessPath",
        "RuleAuthor", "Description",
        ("Tags", "MemoryType", "MemoryBaseAddress", "User"),
    ),
    _MemProcFSCsvSpec(
        "process.csv", "memory_process_baseline", "process_listing",
        "HIGH", 200, "PID", "Name", "KernelPath", None,
        "CommandLine", ("PPID", "User", "CreateTime", "IntegrityLevel"),
    ),
    _MemProcFSCsvSpec(
        "services.csv", "memory_service_baseline", "service_listing",
        "HIGH", 300, "PID", "ServiceName", "ImagePath", "StartType",
        "DisplayName", ("State", "User"),
    ),
    _MemProcFSCsvSpec(
        "net.csv", "memory_network_state", "connection_listing",
        "HIGH", 200, "PID", "Process", "ProcessPath", "Proto",
        None, ("State", "SrcAddr", "SrcPort", "DstAddr", "DstPort", "Time"),
    ),
    _MemProcFSCsvSpec(
        "unloaded_modules.csv", "memory_module_anomalies", "unloaded_module",
        "HIGH", 300, "PID", "Process", None, "ModuleName",
        None, ("UnloadTime", "Wow64", "Size"),
    ),
    _MemProcFSCsvSpec(
        "timeline_process.csv", "memory_timeline_process", "process_event",
        "HIGH", 200, "PID", None, None, "Action",
        "Text", ("Time", "Type"),
    ),
    _MemProcFSCsvSpec(
        "tasks.csv", "memory_persistence", "scheduled_task",
        "MEDIUM", 200, None, "TaskName", "TaskPath", None,
        "CommandLine", ("User", "TimeCreate", "TimeLastRun"),
    ),
    _MemProcFSCsvSpec(
        "prefetch.csv", "memory_execution_history", "execution_record",
        "MEDIUM", 200, None, "Process", "PrefetchFile", None,
        None, ("RunCount", "FileCount"),
    ),
    _MemProcFSCsvSpec(
        "netdns.csv", "memory_dns_resolution", "dns_listing",
        "MEDIUM", 400, None, None, None, "Type",
        "Name", ("Address", "TTL", "Data"),
    ),
    _MemProcFSCsvSpec(
        "timeline_task.csv", "memory_timeline_task", "task_event",
        "MEDIUM", 300, "PID", None, None, "Action",
        "Text", ("Time", "Type"),
    ),
    _MemProcFSCsvSpec(
        "modules.csv", "memory_module_listing", "module_load",
        "LOW", 300, "PID", "Process", "Path", "Name",
        "VerFileDescription", ("Wow64", "Size"),
    ),
    _MemProcFSCsvSpec(
        "handles.csv", "memory_handle_listing", "handle_enumeration",
        "LOW", 300, "PID", None, None, "Type",
        "Description", ("Handle", "Object", "Access"),
    ),
)


# --- restored symbol: _MountReadiness ---
@_a18_dataclass(frozen=True)
class _MountReadiness:
    state: str
    elapsed_sec: float
    progress_percent: int | None
    findevil_csv_present: bool
    process_csv_present: bool
    forensic_csv_dir_present: bool


# --- restored symbol: _memprocfs_install_dir ---
def _memprocfs_install_dir() -> _A18Path:
    return _A18Path(
        _a18_os.environ.get(
            "SIFT_MEMPROCFS_HOME",
            _MEMPROCFS_INSTALL_DIR_DEFAULT,
        )
    )


# --- restored symbol: _memprocfs_binary_path ---
def _memprocfs_binary_path() -> _A18Path:
    explicit = _a18_os.environ.get("SIFT_MEMPROCFS_BIN")
    if explicit:
        return _A18Path(explicit)
    return _memprocfs_install_dir() / _MEMPROCFS_BINARY_NAME


def memprocfs_binary_available() -> bool:
    """FIX D (#3): True when the MemProcFS binary is present on this host.

    A cheap existence probe (no subprocess, no mount) used by the memory-only
    selection floor so run_memprocfs is injected only where it can actually run.
    On a judge box without MemProcFS this returns False and the floor is a clean
    no-op -- never a phantom selection or error envelope. Never raises."""
    try:
        return _memprocfs_binary_path().is_file()
    except Exception:
        return False


# --- restored symbol: _build_subprocess_env ---
def _build_subprocess_env() -> dict[str, str]:
    env = dict(_a18_os.environ)
    install_dir = str(_memprocfs_install_dir())
    existing_ld = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = (
        f"{install_dir}:{existing_ld}" if existing_ld else install_dir
    )
    return env


# --- restored symbol: _ldd_dependency_missing ---
def _ldd_dependency_missing(binary_path: _A18Path, env: dict[str, str]) -> bool:
    """Return True when ldd reports unresolved shared libraries.

    If ldd itself cannot inspect the file, do not fail synthetic unit tests.
    Runtime launch failures are still captured by process readiness checks.
    """
    try:
        result = _a18_subprocess.run(
            ["ldd", str(binary_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
    except Exception:
        return False
    combined = f"{result.stdout}\n{result.stderr}".lower()
    return "not found" in combined


# --- restored symbol: _assert_memprocfs_install_or_envelope ---
def _assert_memprocfs_install_or_envelope(memory_image_path: str) -> list[str]:
    """Return typed error codes. Empty list means install looks usable."""
    errors: list[str] = []
    install_dir = _memprocfs_install_dir()
    binary_path = _memprocfs_binary_path()
    vmm_so_path = install_dir / _MEMPROCFS_VMM_SO_NAME

    if not install_dir.is_dir():
        errors.append("install_dir_missing")
        return errors
    if not binary_path.is_file():
        errors.append("binary_missing")
    if not vmm_so_path.is_file():
        errors.append("vmm_so_missing")
    if not _a18_os.path.exists(memory_image_path):
        errors.append("image_path_not_found")
    if not errors and _ldd_dependency_missing(binary_path, _build_subprocess_env()):
        errors.append("ldd_dependency_missing")
    return errors


# --- restored symbol: _wait_for_memprocfs_csv_readiness ---
def _wait_for_memprocfs_csv_readiness(
    mount_point: str,
    process,
    *,
    max_wait_sec: float,
    poll_interval_sec: float = 2.0,
) -> _MountReadiness:
    """Wait for forensic CSV readiness without assuming one version layout."""
    start = _a18_time.monotonic()
    forensic_dir = _a18_os.path.join(mount_point, _MEMPROCFS_FORENSIC_DIR)
    csv_dir = _a18_os.path.join(forensic_dir, _MEMPROCFS_CSV_SUBDIR)
    progress_path = _a18_os.path.join(forensic_dir, _MEMPROCFS_PROGRESS_FILE)
    findevil_csv = _a18_os.path.join(csv_dir, "findevil.csv")
    process_csv = _a18_os.path.join(csv_dir, "process.csv")
    last_progress: int | None = None

    while True:
        elapsed = _a18_time.monotonic() - start
        if process.poll() is not None:
            return _MountReadiness(
                "PROCESS_DIED", elapsed, last_progress,
                _a18_os.path.isfile(findevil_csv),
                _a18_os.path.isfile(process_csv),
                _a18_os.path.isdir(csv_dir),
            )
        if elapsed >= max_wait_sec:
            return _MountReadiness(
                "TIMEOUT", elapsed, last_progress,
                _a18_os.path.isfile(findevil_csv),
                _a18_os.path.isfile(process_csv),
                _a18_os.path.isdir(csv_dir),
            )

        if _a18_os.path.isfile(progress_path):
            try:
                raw = _A18Path(progress_path).read_text(
                    encoding="utf-8",
                    errors="replace",
                ).strip()
                if raw.isdigit():
                    last_progress = int(raw)
            except (OSError, ValueError):
                pass

        if last_progress == 100 or (
            _a18_os.path.isfile(findevil_csv)
            and _a18_os.path.isfile(process_csv)
        ):
            _a18_time.sleep(2.0)
            return _MountReadiness(
                "READY",
                _a18_time.monotonic() - start,
                last_progress,
                _a18_os.path.isfile(findevil_csv),
                _a18_os.path.isfile(process_csv),
                _a18_os.path.isdir(csv_dir),
            )

        _a18_time.sleep(poll_interval_sec)


# --- restored symbol: _build_process_path_lookup ---
def _build_process_path_lookup(csv_dir: _A18Path) -> dict[str, str]:
    process_csv = csv_dir / "process.csv"
    lookup: dict[str, str] = {}
    if not process_csv.is_file():
        return lookup
    try:
        with process_csv.open(
            "r",
            newline="",
            encoding="utf-8",
            errors="replace",
        ) as fh:
            reader = _a18_csv.DictReader(fh)
            for row in reader:
                pid = (row.get("PID") or "").strip()
                kernel_path = (row.get("KernelPath") or "").strip()
                user_path = (row.get("UserPath") or "").strip()
                if pid:
                    lookup[pid] = kernel_path or user_path or ""
    except (OSError, _a18_csv.Error):
        return {}
    return lookup


# --- restored symbol: _extract_csv_rows_to_records ---
def _extract_csv_rows_to_records(
    csv_path: _A18Path,
    spec: _MemProcFSCsvSpec,
    process_path_lookup: dict[str, str],
) -> tuple[list[dict], int]:
    records: list[dict] = []
    total_rows_seen = 0
    if not csv_path.is_file():
        return records, total_rows_seen

    try:
        with csv_path.open(
            "r",
            newline="",
            encoding="utf-8",
            errors="replace",
        ) as fh:
            reader = _a18_csv.DictReader(fh)
            for row_index, row in enumerate(reader):
                total_rows_seen += 1
                if (
                    spec.per_csv_cap is not None
                    and len(records) >= spec.per_csv_cap
                ):
                    continue

                pid_value = (
                    (row.get(spec.pid_column) or "").strip()
                    if spec.pid_column else ""
                )
                process_value = (
                    (row.get(spec.process_column) or "").strip()
                    if spec.process_column else ""
                )
                path_value = (
                    (row.get(spec.path_column) or "").strip()
                    if spec.path_column else ""
                )
                indicator_value = (
                    (row.get(spec.indicator_column) or "").strip()
                    if spec.indicator_column else ""
                )
                description_value = (
                    (row.get(spec.description_column) or "").strip()
                    if spec.description_column else ""
                )
                joined_path = process_path_lookup.get(pid_value, "") if pid_value else ""
                csv_stem = spec.csv_name.removesuffix(".csv")
                fields = {
                    field: (row.get(field) or "").strip()
                    for field in spec.primary_fields
                }
                record = {
                    "source_tool": "run_memprocfs",
                    "source_csv": spec.csv_name,
                    "memprocfs_subsystem": "forensic_csv",
                    "semantic_family": spec.semantic_family,
                    "semantic_role": spec.semantic_role,
                    "families": ["memory", spec.semantic_family],
                    "priority_tier": spec.priority_tier,
                    "evidence_id": f"memprocfs:{csv_stem}:{row_index:04d}",
                    "pid": pid_value or None,
                    "process": process_value or None,
                    "anchors": {
                        "pid": pid_value or None,
                        "process_name": process_value or None,
                        "process_path": path_value or joined_path or None,
                    },
                    "indicator_type": indicator_value or None,
                    "description": description_value or None,
                    "fields": fields,
                    "source_csv_row_index": row_index,
                }

                # --- A18-ε.2 alias emission (spec-gated, record-driven) ---
                _anchors = record.get("anchors") if isinstance(record.get("anchors"), dict) else {}
                _fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}

                # path: from already-derived process_path anchor (record-driven, broader than spec.path_column)
                _process_path_value = _anchors.get("process_path")
                if _process_path_value:
                    record["path"] = _process_path_value

                # command_line: when spec emits CommandLine as description column
                if spec.description_column == _ALIAS_COMMAND_LINE_DESCRIPTION_COLUMN:
                    _description_value = record.get("description")
                    if _description_value:
                        record["command_line"] = _description_value

                # parent_pid: when spec primary_fields include PPID
                if _ALIAS_PARENT_PID_SOURCE in spec.primary_fields:
                    _parent_pid_value = _fields.get(_ALIAS_PARENT_PID_SOURCE)
                    if _parent_pid_value:
                        record["parent_pid"] = _parent_pid_value

                # timestamp: first nonempty in declared precedence (CreateTime > Time > TimeCreate > TimeLastRun)
                for _time_key in _ALIAS_TIMESTAMP_SOURCES:
                    if _time_key in spec.primary_fields:
                        _time_value = _fields.get(_time_key)
                        if _time_value:
                            record["timestamp"] = _time_value
                            break

                # dst_address: when spec primary_fields include DstAddr
                if _ALIAS_DST_ADDRESS_SOURCE in spec.primary_fields:
                    _dst_value = _fields.get(_ALIAS_DST_ADDRESS_SOURCE)
                    if _dst_value:
                        record["dst_address"] = _dst_value

                # task_path: when spec.path_column is TaskPath, surface the already-derived process_path
                if spec.path_column == _ALIAS_TASK_PATH_PATH_COLUMN and _process_path_value:
                    record["task_path"] = _process_path_value
                # --- end A18-ε.2 alias emission ---

                records.append(record)
    except (OSError, _a18_csv.Error):
        return records, total_rows_seen
    return records, total_rows_seen


# --- restored symbol: _walk_memprocfs_csv_outputs ---
def _walk_memprocfs_csv_outputs(
    mount_point: str,
    *,
    record_cap: int,
) -> tuple[list[dict], dict[str, object], list[str]]:
    warnings: list[str] = []
    csv_dir = (
        _A18Path(mount_point)
        / _MEMPROCFS_FORENSIC_DIR
        / _MEMPROCFS_CSV_SUBDIR
    )
    if not csv_dir.is_dir():
        return [], {
            "csvs_inspected": 0,
            "csvs_in_priority_spec": len(_MEMPROCFS_CSV_SPECS),
            "csvs_parsed": 0,
            "csvs_missing": [],
            "csvs_skipped_oversized": sorted(_MEMPROCFS_OVERSIZED_CSV_SKIPLIST),
            "csvs_empty": [],
            "rows_seen_by_csv": {},
            "rows_returned_by_csv": {},
            "rows_by_priority_tier": {},
            "rows_by_semantic_family": {},
            "rows_by_indicator_type": {},
            "global_record_cap": record_cap,
            "global_cap_applied": False,
            "per_csv_cap_applied_for": [],
        }, ["forensic_csv_dir_missing"]

    inspected = sorted(path.name for path in csv_dir.iterdir() if path.is_file())
    process_path_lookup = _build_process_path_lookup(csv_dir)
    specs = sorted(
        _MEMPROCFS_CSV_SPECS,
        key=lambda spec: (
            _MEMPROCFS_PRIORITY_TIER_RANK.get(spec.priority_tier, 99),
            spec.csv_name,
        ),
    )

    all_records: list[dict] = []
    rows_seen_by_csv: dict[str, int] = {}
    rows_returned_by_csv: dict[str, int] = {}
    csvs_parsed: list[str] = []
    csvs_missing: list[str] = []
    csvs_empty: list[str] = []
    per_csv_cap_applied_for: list[str] = []
    global_cap_applied = False

    for spec in specs:
        if spec.csv_name in _MEMPROCFS_OVERSIZED_CSV_SKIPLIST:
            continue
        csv_path = csv_dir / spec.csv_name
        if not csv_path.is_file():
            csvs_missing.append(spec.csv_name)
            continue

        records, rows_seen = _extract_csv_rows_to_records(
            csv_path,
            spec,
            process_path_lookup,
        )
        rows_seen_by_csv[spec.csv_name] = rows_seen
        if rows_seen == 0:
            csvs_empty.append(spec.csv_name)
            csvs_parsed.append(spec.csv_name)
            rows_returned_by_csv[spec.csv_name] = 0
            continue

        if spec.per_csv_cap is not None and rows_seen > spec.per_csv_cap:
            per_csv_cap_applied_for.append(spec.csv_name)

        remaining = max(0, record_cap - len(all_records))
        if len(records) > remaining:
            records = records[:remaining]
            global_cap_applied = True

        all_records.extend(records)
        rows_returned_by_csv[spec.csv_name] = len(records)
        csvs_parsed.append(spec.csv_name)

        if len(all_records) >= record_cap:
            global_cap_applied = True
            break

    rows_by_priority_tier: dict[str, int] = {}
    rows_by_semantic_family: dict[str, int] = {}
    rows_by_indicator_type: dict[str, int] = {}
    for record in all_records:
        tier = str(record.get("priority_tier") or "UNKNOWN")
        family = str(record.get("semantic_family") or "unknown")
        indicator = str(record.get("indicator_type") or "")
        rows_by_priority_tier[tier] = rows_by_priority_tier.get(tier, 0) + 1
        rows_by_semantic_family[family] = rows_by_semantic_family.get(family, 0) + 1
        if indicator:
            rows_by_indicator_type[indicator] = rows_by_indicator_type.get(indicator, 0) + 1

    summary: dict[str, object] = {
        "csvs_inspected": len(inspected),
        "csvs_in_priority_spec": len(_MEMPROCFS_CSV_SPECS),
        "csvs_parsed": len(csvs_parsed),
        "csvs_missing": csvs_missing,
        "csvs_skipped_oversized": sorted(_MEMPROCFS_OVERSIZED_CSV_SKIPLIST),
        "csvs_empty": csvs_empty,
        "rows_seen_by_csv": rows_seen_by_csv,
        "rows_returned_by_csv": rows_returned_by_csv,
        "rows_by_priority_tier": rows_by_priority_tier,
        "rows_by_semantic_family": rows_by_semantic_family,
        "rows_by_indicator_type": rows_by_indicator_type,
        "global_record_cap": record_cap,
        "global_cap_applied": global_cap_applied,
        "per_csv_cap_applied_for": per_csv_cap_applied_for,
    }
    return all_records, summary, warnings


# --- restored symbol: run_memprocfs ---
def run_memprocfs(
    memory_image_path: str,
    *,
    mount_point: str | None = None,
    forensic_mode: int = 1,
    mount_ready_timeout_sec: float = 120.0,
    process_timeout_sec: float = 240.0,
    record_cap: int = 2000,
) -> dict:
    """A18: MemProcFS forensic-mode CSV semantic extraction."""
    import shutil
    import tempfile

    envelope: dict = {
        "tool_name": "run_memprocfs",
        "output": [],
        "records": [],
        "record_count": 0,
        "returned_record_count": 0,
        "total_record_count": 0,
        "cap_policy": "priority_tier_then_per_csv_then_global",
        "cap_applied": False,
        "cap_total": 0,
        "cap_returned": 0,
        "warnings": [],
        "errors": [],
        "mount_readiness": {},
        "extraction_summary": {},
    }

    install_errors = _assert_memprocfs_install_or_envelope(memory_image_path)
    if install_errors:
        # 31K-MEMPROCFS-ZERO-ERROR: zero records from a failed MemProcFS
        # setup is an error envelope, not a successful empty result.
        envelope["errors"].extend(install_errors)
        envelope["status"] = "error"
        envelope["failure_mode"] = "install_error"
        envelope["error"] = "; ".join(str(x) for x in install_errors)[:500]
        return envelope

    owns_mount_dir = mount_point is None
    if owns_mount_dir:
        mount_point = tempfile.mkdtemp(prefix="sift-memprocfs-")
    else:
        _a18_os.makedirs(mount_point, exist_ok=True)

    proc = None
    try:
        proc = _a18_subprocess.Popen(
            [
                str(_memprocfs_binary_path()),
                "-device", str(memory_image_path),
                "-forensic", str(forensic_mode),
                "-mount", str(mount_point),
            ],
            cwd=str(_memprocfs_install_dir()),
            env=_build_subprocess_env(),
            stdout=_a18_subprocess.PIPE,
            stderr=_a18_subprocess.PIPE,
            text=True,
        )
        readiness = _wait_for_memprocfs_csv_readiness(
            str(mount_point),
            proc,
            max_wait_sec=mount_ready_timeout_sec,
        )
        envelope["mount_readiness"] = {
            "state": readiness.state,
            "elapsed_sec": round(readiness.elapsed_sec, 2),
            "progress_percent": readiness.progress_percent,
            "findevil_csv_present": readiness.findevil_csv_present,
            "process_csv_present": readiness.process_csv_present,
            "forensic_csv_dir_present": readiness.forensic_csv_dir_present,
        }
        if readiness.state != "READY":
            if readiness.state == "PROCESS_DIED":
                envelope["errors"].append("process_died_before_ready")
            elif readiness.state == "TIMEOUT":
                envelope["errors"].append("mount_timeout")
            else:
                envelope["errors"].append("forensic_mode_unavailable")
            _err = envelope["errors"][-1] if envelope["errors"] else "memprocfs_not_ready"
            envelope["status"] = "error"
            envelope["failure_mode"] = _err
            envelope["error"] = _err
            return envelope

        records, summary, walk_warnings = _walk_memprocfs_csv_outputs(
            str(mount_point),
            record_cap=record_cap,
        )
        envelope["warnings"].extend(walk_warnings)
        summary["wait_state"] = readiness.state
        summary["forensic_completion_sec"] = round(readiness.elapsed_sec, 2)

        total = sum(
            int(value)
            for value in (summary.get("rows_seen_by_csv") or {}).values()
        )
        envelope["output"] = records
        envelope["records"] = records
        envelope["record_count"] = len(records)
        envelope["returned_record_count"] = len(records)
        envelope["total_record_count"] = total
        envelope["cap_total"] = total
        envelope["cap_returned"] = len(records)
        envelope["cap_applied"] = bool(summary.get("global_cap_applied"))
        envelope["extraction_summary"] = summary
        if not records:
            if "memprocfs_csv_outputs_empty" not in envelope["warnings"]:
                envelope["warnings"].append("memprocfs_csv_outputs_empty")
            envelope["status"] = "error"
            envelope["failure_mode"] = "empty_csv_outputs"
            envelope["error"] = "memprocfs_csv_outputs_empty"
        return envelope
    except Exception as exc:
        _err = f"unexpected_exception:{type(exc).__name__}"
        envelope["errors"].append(_err)
        envelope["warnings"].append(str(exc)[:300])
        envelope["status"] = "error"
        envelope["failure_mode"] = _err
        envelope["error"] = str(exc)[:500]
        return envelope
    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=process_timeout_sec)
                except _a18_subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
        try:
            _a18_subprocess.run(
                ["fusermount", "-u", str(mount_point)],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except Exception:
            pass
        if owns_mount_dir:
            try:
                shutil.rmtree(mount_point, ignore_errors=True)
            except Exception:
                pass

# RUN17_ZERO_RECORD_REASON_SRUM_WRAPPER_V1
#
# Universal zero-record contract for SRUM parsing.
# SRUDB.dat absence is not a failure; it must be explicit.
def _sift_srum_zr_count_v1(result):
    if not isinstance(result, dict):
        return 0
    rc = result.get("record_count")
    if isinstance(rc, int):
        return rc
    out = result.get("output")
    return len(out) if isinstance(out, list) else 0


def _sift_srum_zr_has_reason_v1(result):
    if not isinstance(result, dict):
        return False
    for key in ("reason", "zero_record_reason", "not_applicable_reason", "error"):
        if result.get(key) not in (None, ""):
            return True
    return False


def _sift_srum_zr_with_reason_v1(result, *, status, reason):
    if not isinstance(result, dict):
        return result
    if _sift_srum_zr_count_v1(result) != 0:
        return result
    out = dict(result)
    out.setdefault("status", status)
    out.setdefault("reason", reason)
    out.setdefault(
        "zero_record_reason",
        {
            "status": out.get("status") or status,
            "reason": out.get("reason") or reason,
        },
    )
    return out


from functools import wraps as _sift_srum_wraps_v1

if "_sift_run_srumecmd_without_zr_reason_v1" not in globals():
    _sift_run_srumecmd_without_zr_reason_v1 = run_srumecmd

    @_sift_srum_wraps_v1(_sift_run_srumecmd_without_zr_reason_v1)
    def run_srumecmd(*args, **kwargs):
        result = _sift_run_srumecmd_without_zr_reason_v1(*args, **kwargs)
        if not isinstance(result, dict) or _sift_srum_zr_count_v1(result) != 0:
            return result
        if _sift_srum_zr_has_reason_v1(result):
            return result

        return _sift_srum_zr_with_reason_v1(
            result,
            status="no_records",
            reason="SRUM parser returned zero rows for the supplied SRUM database",
        )

# RUN17_ZERO_RECORD_REASON_SRUM_WRAPPER_V2_REPAIR
#
# Repair over V1:
# Existing run_srumecmd can return {"error": ..., "record_count": 0}
# without status. Preserve the error, but normalize status/reason for the
# universal zero-record gate.
def _sift_srum_zr_count_v2(result):
    if not isinstance(result, dict):
        return 0
    rc = result.get("record_count")
    if isinstance(rc, int):
        return rc
    out = result.get("output")
    return len(out) if isinstance(out, list) else 0


def _sift_srum_zr_reason_text_v2(result):
    if not isinstance(result, dict):
        return ""
    zr = result.get("zero_record_reason")
    if isinstance(zr, dict):
        for key in ("reason", "message", "error"):
            if zr.get(key) not in (None, ""):
                return str(zr.get(key))
    for key in ("reason", "not_applicable_reason", "error", "message"):
        if result.get(key) not in (None, ""):
            return str(result.get(key))
    return ""


def _sift_srum_zr_status_v2(result):
    if isinstance(result, dict) and result.get("status") not in (None, ""):
        return str(result.get("status"))
    text = _sift_srum_zr_reason_text_v2(result).lower()
    failure_mode = str((result or {}).get("failure_mode") or "").lower() if isinstance(result, dict) else ""
    if "not found" in text or "missing" in text or "absent" in text or failure_mode in {
        "artifact_missing",
        "missing_artifact",
        "not_applicable",
    }:
        return "not_applicable"
    if isinstance(result, dict) and result.get("error") not in (None, ""):
        return "error"
    return "no_records"


def _sift_srum_zr_with_reason_v2(result, reason="SRUM parser returned zero rows"):
    if not isinstance(result, dict):
        return result
    if _sift_srum_zr_count_v2(result) != 0:
        return result
    out = dict(result)
    reason_text = _sift_srum_zr_reason_text_v2(out) or reason
    status = _sift_srum_zr_status_v2(out)
    out["status"] = status
    out["reason"] = reason_text
    out["zero_record_reason"] = {
        "status": status,
        "reason": reason_text,
    }
    return out


from functools import wraps as _sift_srum_wraps_v2

if "_sift_run_srumecmd_core_without_zr_reason_v2" not in globals():
    _sift_run_srumecmd_core_without_zr_reason_v2 = globals().get(
        "_sift_run_srumecmd_without_zr_reason_v1",
        run_srumecmd,
    )


@_sift_srum_wraps_v2(_sift_run_srumecmd_core_without_zr_reason_v2)
def run_srumecmd(*args, **kwargs):
    result = _sift_run_srumecmd_core_without_zr_reason_v2(*args, **kwargs)
    if not isinstance(result, dict) or _sift_srum_zr_count_v2(result) != 0:
        return result
    return _sift_srum_zr_with_reason_v2(result)

