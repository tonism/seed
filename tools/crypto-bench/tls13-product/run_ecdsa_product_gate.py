#!/usr/bin/env python3
"""Run the complete offline and exact-VM gate for the 286 ECDSA module."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
OFFLINE = HERE / "check_ecdsa_product_module.py"
RUN_286 = HERE / "run_286_gate.py"
BENCH = HERE / "ecdsa_product_module_bench.asm"
REPORT = BUILD / "tls13-286-ecdsa-product-gate.json"
MAX_ECDSA_TICKS = 52


def run_json(command: list[str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def main() -> None:
    offline = run_json([sys.executable, str(OFFLINE)])
    vm = run_json(
        [
            sys.executable,
            str(RUN_286),
            "--asm",
            str(BENCH),
            "--mhz",
            "6",
            "--timeout",
            "600",
            "--expect",
            "TABLEGEN=0001",
            "--expect",
            "ECDSAPROD=0001",
            "--expect",
            "CHECK=0001",
            "--json",
        ]
    )
    result = vm.get("result")
    if not isinstance(result, dict) or not result.get("passed"):
        raise AssertionError("exact 6 MHz / 512 KiB 86Box ECDSA gate failed")
    operations = result.get("operations")
    if not isinstance(operations, dict):
        raise AssertionError("86Box gate omitted operation metrics")
    ecdsa = operations.get("ECDSAPROD")
    tablegen = operations.get("TABLEGEN")
    if not isinstance(ecdsa, dict) or not isinstance(tablegen, dict):
        raise AssertionError("86Box gate omitted ECDSA/tablegen metrics")
    ecdsa_ticks = ecdsa.get("ticks")
    if not isinstance(ecdsa_ticks, int) or ecdsa_ticks > MAX_ECDSA_TICKS:
        raise AssertionError(
            f"ECDSA product call took {ecdsa_ticks} ticks; "
            f"budget is {MAX_ECDSA_TICKS}"
        )

    report = {
        "offline": offline,
        "exact_86box": vm,
        "timing_contract": {
            "cpu": "Intel 80286",
            "mhz": 6,
            "conventional_kib": 512,
            "ecdsa_ticks": ecdsa_ticks,
            "ecdsa_seconds": ecdsa.get("seconds_per_iteration"),
            "ecdsa_max_ticks": MAX_ECDSA_TICKS,
            "two_table_generation_ticks_off_window": tablegen.get("ticks"),
            "provider_window_includes_table_generation": False,
        },
        "passed": True,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
