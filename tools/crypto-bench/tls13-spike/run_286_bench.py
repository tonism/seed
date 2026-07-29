#!/usr/bin/env python3
"""Generic 86Box v9001-safe runner for standalone 286 crypto benches.

The input assembly must boot as the SEED.SYS payload loaded by
``tools/crypto-bench/bench_boot.asm`` and terminate its serial report with
``DONE``.  The runner:

* builds a raw 360 KiB floppy with the fixed 28-sector benchmark loader;
* runs the IBM AT at one or more requested clocks;
* selects 86Box's virtual-console ``mode = 0`` so COM1 reaches stdout;
* parses the conventional ``TAG N=<n> dt=<ticks> ck=<hex>`` records; and
* restores the tracked VM configuration and generated CMOS state in ``finally``.

Example:

    python3 tools/crypto-bench/tls13-spike/run_286_bench.py \
        --asm tools/crypto-bench/tls13-spike/hkdf_bench.asm \
        --mhz 6 8 \
        --expect HKFULL=2D5F --expect VFULL=0001 \
        --expect HKHOT=2D5F --expect VHOT=0001
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run86box as rb  # type: ignore


AT_NVR_NAME = "ibm5170_111585.nvr"
GUEST_AUX_RE = re.compile(r"^(?:TAG|SHA|OPS|CHECK)\b|^DONE$")


class OutputCapture(rb.ComCapture):
    """Read both v9001 mode-0 stdout and the legacy PTY banner if present."""

    def __init__(self) -> None:
        super().__init__()
        self.stdout_buf = bytearray()

    def _read_stdout(self, process) -> None:
        try:
            for line in iter(process.stdout.readline, ""):
                if self.stop_event.is_set():
                    break
                with self.lock:
                    self.stdout_buf.extend(line.encode("utf-8", errors="replace"))
                match = rb.PTY_PATH_RE.search(line)
                if match and self.pty_path is None:
                    self.pty_path = match.group(1)
                    threading.Thread(target=self._read_pty, daemon=True).start()
        except (ValueError, OSError):
            pass

    def text(self) -> str:
        with self.lock:
            combined = bytes(self.stdout_buf) + bytes(self.buf)
        return combined.decode("ascii", errors="replace")


def assemble_image(
    asm_path: Path, include_dirs: list[Path], nasm_defines: list[str]
) -> tuple[Path, int, int]:
    """Assemble one benchmark and wrap it in the fixed 360 KiB raw image."""
    asm_path = asm_path.resolve()
    if not asm_path.is_file():
        raise SystemExit(f"benchmark assembly not found: {asm_path}")
    rb.BENCH_BUILD.mkdir(parents=True, exist_ok=True)
    stem = asm_path.stem
    boot_path = rb.BENCH_BUILD / f"{stem}-286-boot.bin"
    bench_path = rb.BENCH_BUILD / f"{stem}-286.bin"
    image_path = rb.BENCH_BUILD / f"{stem}-286-360.img"

    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-o",
            str(boot_path),
            "tools/crypto-bench/bench_boot.asm",
        ],
        check=True,
        cwd=rb.ROOT,
    )
    nasm_command = ["nasm", "-f", "bin"]
    nasm_command.extend(
        f"-I{directory.resolve()}{os.sep}" for directory in include_dirs
    )
    nasm_command.extend(f"-D{definition}" for definition in nasm_defines)
    nasm_command.extend(
        [
            "-Itargets/ibm_pc_5150/boot/",
            "-Itools/crypto-bench/",
            "-o",
            str(bench_path),
            str(asm_path),
        ]
    )
    subprocess.run(
        nasm_command,
        check=True,
        cwd=rb.ROOT,
    )
    boot = boot_path.read_bytes()
    bench = bench_path.read_bytes()
    if len(boot) != 512:
        raise SystemExit(f"benchmark boot sector is {len(boot)} bytes, expected 512")
    sectors = (len(bench) + 511) // 512
    if sectors > 28:
        raise SystemExit(
            f"{asm_path.name} is {len(bench)} bytes / {sectors} sectors; "
            "bench_boot.asm loads at most 28"
        )
    image = bytearray(368640)
    image[:512] = boot
    image[512 : 512 + len(bench)] = bench
    image_path.write_bytes(image)
    return image_path, len(bench), sectors


def at_cmos() -> bytes:
    cmos = bytearray(64)
    cmos[0x0A] = 0x26
    cmos[0x0B] = 0x02
    cmos[0x0D] = 0x80
    cmos[0x04] = 0x12
    cmos[0x07] = 0x01
    cmos[0x08] = 0x06
    cmos[0x09] = 0x26
    cmos[0x10] = 0x10
    cmos[0x14] = 0x21
    cmos[0x15] = 0x00
    cmos[0x16] = 0x02
    checksum = sum(cmos[0x10:0x2E]) & 0xFFFF
    cmos[0x2E] = (checksum >> 8) & 0xFF
    cmos[0x2F] = checksum & 0xFF
    return bytes(cmos)


def write_config(image_path: Path, mhz: int) -> None:
    (rb.VM_PATH / "86box.cfg").write_text(
        f"""[General]
emu_build_num = 9001
sound_muted = 1
vid_renderer = qt_software
video_filter_method = 0
[Machine]
machine = ibmat
cpu_family = 286
cpu_multi = 1
cpu_speed = {mhz * 1000000}
cpu_use_dynarec = 0
fpu_type = none
mem_size = 512
[Video]
gfxcard = cga
[Input devices]
keyboard_type = keyboard_at
mouse_type = none
[Ports (COM & LPT)]
serial1_device = stdio
[Storage controllers]

[Floppy and CD-ROM drives]
fdd_01_fn = {image_path}
fdd_01_type = 525_2dd
fdd_02_type = none
[Virtual Console (COM) #1]
mode = 0
"""
    )


def guest_lines(serial_text: str) -> list[str]:
    lines: list[str] = []
    for line in serial_text.splitlines():
        stripped = line.strip()
        if rb.RESULT_RE.match(stripped) or GUEST_AUX_RE.match(stripped):
            lines.append(stripped)
    return lines


def parsed_operations(serial_text: str) -> dict[str, dict[str, int | float | str]]:
    operations: dict[str, dict[str, int | float | str]] = {}
    for line in serial_text.splitlines():
        match = rb.RESULT_RE.match(line.strip())
        if match is None:
            continue
        tag = match.group(1)
        iterations = int(match.group(2))
        ticks = int(match.group(3))
        checksum = match.group(4).upper()
        seconds = ticks * rb.TICK_MS / 1000.0
        operations[tag] = {
            "iterations": iterations,
            "ticks": ticks,
            "checksum": checksum,
            "seconds_total": seconds,
            "seconds_per_iteration": seconds / iterations if iterations else 0.0,
        }
    return operations


def run_vm(image_path: Path, mhz: int, timeout: int) -> dict[str, object]:
    config_path = rb.VM_PATH / "86box.cfg"
    original_config = config_path.read_bytes()
    nvr_dir = rb.VM_PATH / "nvr"
    nvr_path = nvr_dir / AT_NVR_NAME
    nvr_dir_existed = nvr_dir.exists()
    nvr_existed = nvr_path.exists()
    original_nvr = nvr_path.read_bytes() if nvr_existed else None
    process: subprocess.Popen[str] | None = None
    capture: OutputCapture | None = None

    try:
        nvr_dir.mkdir(parents=True, exist_ok=True)
        nvr_path.write_bytes(at_cmos())
        write_config(image_path, mhz)
        subprocess.run(["pkill", "-f", str(rb.VM_PATH)], capture_output=True)
        time.sleep(1)

        capture = OutputCapture()
        process = subprocess.Popen(
            [
                rb.emulator_path(),
                "--vmpath",
                str(rb.VM_PATH),
                "--image",
                f"A:{image_path}",
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
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if "DONE" in capture.text():
                break
            time.sleep(0.5)
        serial_text = capture.text()
        lines = guest_lines(serial_text)
        operations = parsed_operations(serial_text)
        checks = [
            line.split(maxsplit=1)[1]
            for line in lines
            if line.startswith("CHECK ")
        ]
        return {
            "mhz": mhz,
            "done": "DONE" in lines,
            "operations": operations,
            "checks": checks,
            "guest_lines": lines,
        }
    finally:
        if capture is not None:
            capture.finish()
        if process is not None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        subprocess.run(["pkill", "-f", str(rb.VM_PATH)], capture_output=True)
        config_path.write_bytes(original_config)
        if nvr_existed:
            assert original_nvr is not None
            nvr_path.write_bytes(original_nvr)
        elif nvr_path.exists():
            nvr_path.unlink()
        if not nvr_dir_existed and nvr_dir.exists():
            try:
                nvr_dir.rmdir()
            except OSError:
                pass


def parse_expectations(values: list[str]) -> dict[str, str]:
    expected: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--expect must be TAG=HEX, got {value!r}")
        tag, checksum = value.split("=", 1)
        tag = tag.strip().upper()
        checksum = checksum.strip().upper()
        if not tag or not re.fullmatch(r"[0-9A-F]+", checksum):
            raise SystemExit(f"bad --expect value: {value!r}")
        expected[tag] = checksum
    return expected


def check_result(
    result: dict[str, object], expected: dict[str, str], required: list[str]
) -> list[str]:
    failures: list[str] = []
    if not result["done"]:
        failures.append("guest did not emit DONE")
    operations = result["operations"]
    assert isinstance(operations, dict)
    for tag, checksum in expected.items():
        operation = operations.get(tag)
        if not isinstance(operation, dict):
            failures.append(f"missing operation {tag}")
        elif operation.get("checksum") != checksum:
            failures.append(
                f"{tag} checksum {operation.get('checksum')} != {checksum}"
            )
    lines = result["guest_lines"]
    assert isinstance(lines, list)
    joined = "\n".join(str(line) for line in lines)
    for text in required:
        if text not in joined:
            failures.append(f"missing required guest text {text!r}")
    if "CHECK FAIL" in joined:
        failures.append("guest emitted CHECK FAIL")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asm", type=Path, required=True)
    parser.add_argument("--mhz", nargs="+", type=int, default=[6])
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--expect", action="append", default=[], metavar="TAG=HEX")
    parser.add_argument("--require", action="append", default=[], metavar="TEXT")
    parser.add_argument(
        "--include-dir",
        action="append",
        default=[],
        type=Path,
        metavar="PATH",
        help="prepend a NASM include directory (repeatable)",
    )
    parser.add_argument(
        "--nasm-define",
        action="append",
        default=[],
        metavar="NAME[=VALUE]",
        help="pass a NASM -D definition to the benchmark (repeatable)",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    expected = parse_expectations(args.expect)
    image_path, image_bytes, sectors = assemble_image(
        args.asm, args.include_dir, args.nasm_define
    )
    results: list[dict[str, object]] = []
    for mhz in args.mhz:
        result = run_vm(image_path, mhz, args.timeout)
        failures = check_result(result, expected, args.require)
        result["passed"] = not failures
        result["failures"] = failures
        results.append(result)

    report = {
        "asm": str(args.asm),
        "image": str(image_path),
        "payload_bytes": image_bytes,
        "payload_sectors": sectors,
        "include_dirs": [str(path) for path in args.include_dir],
        "nasm_defines": args.nasm_define,
        "results": results,
        "passed": all(bool(result["passed"]) for result in results),
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"{args.asm}: {image_bytes} B / {sectors} sectors in "
            f"{image_path.name}"
        )
        for result in results:
            print(f"286@{result['mhz']} MHz:")
            for line in result["guest_lines"]:
                print(f"  {line}")
            for tag, operation in result["operations"].items():
                print(
                    f"  {tag}: {operation['ticks']} ticks = "
                    f"{operation['seconds_per_iteration']:.4f} s/iteration"
                )
            verdict = "PASS" if result["passed"] else "FAIL"
            print(f"  [{verdict}]")
            for failure in result["failures"]:
                print(f"    {failure}")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
