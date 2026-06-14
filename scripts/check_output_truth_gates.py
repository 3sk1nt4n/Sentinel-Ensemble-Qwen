#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_gate(argv: list[str], marker: str) -> bool:
    print("+ " + " ".join(argv), flush=True)
    proc = subprocess.run(
        argv,
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    ok = proc.returncode == 0 and marker in proc.stdout
    if not ok:
        print(f"{marker}=FAIL rc={proc.returncode} missing_marker={marker!r}")
    return ok


def main(argv: list[str]) -> int:
    if not argv:
        print("OUTPUT_TRUTH_GATES=FAIL reason=no_state_dir")
        return 2

    state = Path(argv[0])
    repair = "--repair" in argv[1:]

    if not state.exists():
        print(f"OUTPUT_TRUTH_GATES=FAIL reason=missing_state state={state}")
        return 2

    py = sys.executable
    gates: list[tuple[str, list[str], str]] = []

    def add(label: str, script: str, marker: str, repairable: bool = False, required: bool = True) -> None:
        path = ROOT / script
        if not path.exists():
            if required:
                gates.append((label, [py, str(path), str(state)], marker))
            return
        cmd = [py, str(path), str(state)]
        if repair and repairable:
            cmd.append("--repair")
        gates.append((label, cmd, marker))

    add("PROVENANCE_TAXONOMY_GATE", "scripts/check_provenance_taxonomy_gate.py", "PROVENANCE_TAXONOMY_GATE=PASS", True)
    add("FINAL_FINDING_PROVENANCE_SANITIZER_GATE", "scripts/check_final_finding_provenance_sanitizer_gate.py", "FINAL_FINDING_PROVENANCE_SANITIZER_GATE=PASS", True)
    add("TOOL_HIT_INTEGRITY_GATE", "scripts/check_tool_hit_integrity_gate.py", "TOOL_HIT_INTEGRITY_GATE=PASS", True)
    add("ZERO_INFERENCE_CONTRACT_GATE", "scripts/check_zero_inference_contract_gate.py", "ZERO_INFERENCE_CONTRACT_GATE=PASS", True)
    add("VALIDATION_FAMILY_WIRING_GATE", "scripts/check_validation_family_wiring_gate.py", "VALIDATION_FAMILY_WIRING_GATE=PASS", False)
    add("PATH_FIDELITY_GATE", "scripts/postrun_path_fidelity_gate.py", "PATH_FIDELITY_GATE=PASS", False)
    add("CUSTOMER_TABLE_ZERO_HIT_TOOL_GATE", "scripts/check_customer_table_zero_hit_tools_gate.py", "CUSTOMER_TABLE_ZERO_HIT_TOOL_GATE=PASS", False)
    add("TOOL_CONTRIBUTION_GATE", "scripts/summarize_tool_contribution.py", "TOOL_CONTRIBUTION_GATE=PASS", False)

    failed: list[str] = []
    for label, cmd, marker in gates:
        if not run_gate(cmd, marker):
            failed.append(label)

    if failed:
        print(f"OUTPUT_TRUTH_GATES=FAIL failed={','.join(failed)} state={state}")
        return 1

    print(f"OUTPUT_TRUTH_GATES=PASS state={state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# SIFT_SSDT_HEALTH_OUTPUT_TRUTH_TODO check_ssdt_health_gate.py must be included in output truth gates.
