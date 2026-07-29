#!/usr/bin/env python3
"""Bounded 86Box v9001 runner for Seed's standalone 8086 benchmarks.

The runner deliberately separates two facts:

* timing environment: IBM PC 5150, 4.772728 MHz 8088, 64 KiB installed;
* address contract: the assembled benchmark image starts at 0x1000 and may be
  statically constrained to the 16 KiB ceiling (0x4000) by its own NASM
  assertions.

A literal 16 KiB IBM PC cannot enter through the BIOS boot path because the
boot sector executes at 0000:7c00.  The extra emulated RAM permits BIOS boot;
it does not make an image that stays below 0x4000 execute faster.

86Box 9001 moved serial passthrough to its virtual-console stdout backend.  The
tracked vm-crypto-bench config is therefore replaced temporarily with a
minimal ``serial1_device = stdio`` / ``mode = 0`` profile, then restored
byte-for-byte in ``finally`` after the child process has stopped.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run86box as rb  # type: ignore


DEFAULT_ASM = HERE / "flight_bench.asm"
CONFIG_PATH = rb.VM_PATH / "86box.cfg"
CPU_HZ = 4_772_728
TIMING_RAM_KIB = 64
STATIC_16K_CEILING = 0x4000
LOAD_ADDRESS = 0x1000


class StdoutCapture:
    """Continuously drain 86Box stdout without waiting for process exit."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            raise RuntimeError("86Box stdout was not piped")
        self._thread = threading.Thread(
            target=self._read,
            args=(process.stdout,),
            daemon=True,
        )
        self._thread.start()

    def _read(self, stream) -> None:
        try:
            for line in iter(stream.readline, ""):
                with self._lock:
                    self._parts.append(line)
        except (OSError, ValueError):
            pass

    def text(self) -> str:
        with self._lock:
            return "".join(self._parts)

    def finish(self) -> None:
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def temporary_config(image: Path) -> str:
    """Return the complete v9001-compatible 8088 timing profile."""

    return f"""[General]
emu_build_num = 9001
sound_muted = 1
vid_renderer = qt_software
video_filter_method = 0

[Machine]
machine = ibmpc
cpu_family = 8088
cpu_multi = 1
cpu_speed = {CPU_HZ}
cpu_use_dynarec = 0
fpu_type = 8087
mem_size = {TIMING_RAM_KIB}

[Video]
gfxcard = cga

[Input devices]
keyboard_type = keyboard_pc_xt
mouse_type = none

[Ports (COM & LPT)]
serial1_device = stdio

[Storage controllers]
cassette_enabled = 1
fdc = fdc_xt

[Floppy and CD-ROM drives]
fdd_01_fn = {image}
fdd_01_type = 525_1dd
fdd_02_type = none

[Virtual Console (COM) #1]
mode = 0
"""


def build(bench_asm: Path) -> tuple[Path, int]:
    """Assemble and wrap a benchmark using the established harness helpers."""

    if not bench_asm.is_file():
        raise SystemExit(f"benchmark source not found: {bench_asm}")
    rb.BENCH_BUILD.mkdir(parents=True, exist_ok=True)
    core = rb.BENCH_BUILD / "bench.bin"
    size = rb.assemble(bench_asm, core)
    rb.build_image(core)
    return rb.IMAGE, size


def stop_process(process: subprocess.Popen[str]) -> None:
    """Stop only the 86Box instance started by this runner."""

    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            pass


def run(
    bench_asm: Path,
    *,
    timeout: float,
    done_token: str,
) -> dict[str, object]:
    image, size = build(bench_asm)
    load_end = LOAD_ADDRESS + size
    image_within_16k = load_end <= STATIC_16K_CEILING

    original_config = CONFIG_PATH.read_bytes()
    process: subprocess.Popen[str] | None = None
    capture = StdoutCapture()
    started = time.monotonic()
    done = False
    try:
        CONFIG_PATH.write_text(temporary_config(image))
        process = subprocess.Popen(
            [
                rb.emulator_path(),
                "--vmpath",
                str(rb.VM_PATH),
                "--image",
                f"A:{image}",
            ],
            cwd=rb.ROOT,
            env={**os.environ, "SEED_NO_IMAGE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        capture.start(process)
        deadline = started + timeout
        while time.monotonic() < deadline:
            if done_token in capture.text():
                done = True
                break
            if process.poll() is not None:
                break
            time.sleep(0.25)
        if done:
            time.sleep(0.25)
    finally:
        if process is not None:
            stop_process(process)
        capture.finish()
        CONFIG_PATH.write_bytes(original_config)

    if CONFIG_PATH.read_bytes() != original_config:
        raise RuntimeError("failed to restore vm-crypto-bench config byte-for-byte")

    serial_text = capture.text()
    serial_path = rb.BENCH_BUILD / f"{bench_asm.stem}.serial.txt"
    serial_path.write_text(serial_text)
    return {
        "done": done,
        "timeout_seconds": timeout,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "source": str(bench_asm),
        "image": str(image),
        "image_bytes": size,
        "image_sectors": (size + 511) // 512,
        "load_start": f"0x{LOAD_ADDRESS:04x}",
        "load_end": f"0x{load_end:04x}",
        "image_within_16k_ceiling": image_within_16k,
        "timing_environment": {
            "machine": "IBM PC 5150",
            "cpu": "8088",
            "cpu_hz": CPU_HZ,
            "installed_ram_kib": TIMING_RAM_KIB,
            "dynarec": False,
        },
        "static_address_contract": {
            "ceiling": f"0x{STATIC_16K_CEILING:04x}",
            "literal_16k_bios_boot": False,
            "note": (
                "Image-range check only; benchmark NASM assertions remain "
                "authoritative for fixed scratch and stack-guard placement."
            ),
        },
        "ops": rb.parse_results(serial_text),
        "serial_path": str(serial_path),
        "serial_text": serial_text,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a standalone Seed benchmark on 86Box v9001's stdout serial console."
    )
    parser.add_argument(
        "--asm",
        type=Path,
        default=DEFAULT_ASM,
        help=f"benchmark source (default: {DEFAULT_ASM.relative_to(rb.ROOT)})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="hard wall-clock bound in seconds (default: 180)",
    )
    parser.add_argument(
        "--done-token",
        default="DONE",
        help="stdout token that ends capture (default: DONE)",
    )
    args = parser.parse_args()
    if not 1.0 <= args.timeout <= 900.0:
        parser.error("--timeout must be between 1 and 900 seconds")
    if not args.done_token:
        parser.error("--done-token must not be empty")

    bench_asm = args.asm
    if not bench_asm.is_absolute():
        bench_asm = (rb.ROOT / bench_asm).resolve()

    print(
        "timing environment: IBM PC 5150, 8088 @ 4.772728 MHz, "
        "64 KiB installed, dynarec off"
    )
    print(
        "static contract: 16 KiB ceiling is checked for the loaded image; "
        "literal 16 KiB BIOS boot is impossible because entry is at 0000:7c00"
    )
    result = run(
        bench_asm,
        timeout=args.timeout,
        done_token=args.done_token,
    )
    print("--- captured stdout/serial ---")
    print(result["serial_text"] or "(none)")
    print("--- result ---")
    printable = dict(result)
    printable.pop("serial_text")
    print(json.dumps(printable, indent=2))
    if not result["done"]:
        raise SystemExit(
            f"benchmark did not emit {args.done_token!r} within {args.timeout:g} seconds"
        )
    if not result["image_within_16k_ceiling"]:
        raise SystemExit("assembled image crosses the static 16 KiB address ceiling")


if __name__ == "__main__":
    main()
