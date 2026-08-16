#!/usr/bin/env python3
"""Execute the exact HELLO timing wrapper semantically without 86Box."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"
SOURCE = HERE / "hello_product_timing_bench.asm"
FIXTURE_BUILDER = HERE / "build_286_flight_timing_fixtures.py"
HELLO_RAW = BUILD / "tls13-286-hello.bin"
LOAD = 0x1000
HELLO_LOAD = 0x1800
SEMANTIC_MAGIC = b"H286SEM1"
INSTRUCTION_LIMIT = 20_000_000


def main() -> None:
    subprocess.run(
        [sys.executable, str(FIXTURE_BUILDER)],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    with tempfile.TemporaryDirectory(
        prefix="seed-286-hello-timing-check-", dir=BUILD
    ) as raw:
        image_path = Path(raw) / "hello-timing-semantic.bin"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-DHELLO_TIMING_SEMANTIC=1",
                "-Itargets/ibm_pc_5150/boot/",
                "-Itools/crypto-bench/",
                "-o",
                str(image_path),
                str(SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        image = image_path.read_bytes()

    hello = HELLO_RAW.read_bytes()
    embedded = image[HELLO_LOAD - LOAD : HELLO_LOAD - LOAD + len(hello)]
    if embedded != hello:
        raise AssertionError("semantic harness did not embed the current HELLO")
    marker = image.find(SEMANTIC_MAGIC)
    if marker < 0 or image.find(SEMANTIC_MAGIC, marker + 1) >= 0:
        raise AssertionError("semantic result marker is absent or ambiguous")

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 1024 * 1024)
    machine.mem_write(LOAD, image)
    instructions = 0
    halted = False
    exhausted = False

    def code(uc: Uc, address: int, _size: int, _data: object) -> None:
        nonlocal instructions, halted, exhausted
        instructions += 1
        if instructions > INSTRUCTION_LIMIT:
            exhausted = True
            uc.emu_stop()
            return
        if bytes(uc.mem_read(address, 1)) == b"\xf4":
            halted = True
            uc.emu_stop()

    machine.hook_add(UC_HOOK_CODE, code)
    machine.emu_start(LOAD, 1024 * 1024)
    if exhausted:
        raise AssertionError("HELLO timing semantic harness exceeded limit")
    if not halted:
        raise AssertionError("HELLO timing semantic harness did not halt")
    result = bytes(machine.mem_read(LOAD + marker + len(SEMANTIC_MAGIC), 1))
    if result != b"\x01":
        raise AssertionError("HELLO timing semantic harness failed")

    report = {
        "schema": "seed-tls13-286-hello-timing-semantic-v1",
        "source": str(SOURCE.relative_to(ROOT)),
        "current_hello": str(HELLO_RAW.relative_to(ROOT)),
        "current_hello_sha256": hashlib.sha256(hello).hexdigest(),
        "harness_bytes": len(image),
        "harness_sha256": hashlib.sha256(image).hexdigest(),
        "instructions": instructions,
        "checks": {
            "acquisition_full_tx_rx_wrapper": True,
            "resumption_full_tx_rx_wrapper": True,
            "exact_six_fragment_client_hellos": True,
            "split_record_header_and_pending_suffix": True,
            "current_hello_byte_identity": True,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
