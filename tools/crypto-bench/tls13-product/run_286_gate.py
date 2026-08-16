#!/usr/bin/env python3
"""Run an exact standalone crypto benchmark on the 6 MHz / 512 KiB 286 gate.

86Box 9001's stdout console is not reliable for this AT profile on macOS.  The
earlier generic harness booted the payload but eventually reported an empty
serial stream.  This runner uses a fixed Unix FIFO COM transport, while still
saving and restoring the tracked benchmark profile and CMOS image byte-for-byte.

The benchmark image format, serial parser, and correctness expectations are
shared with ``tls13-spike/run_286_bench.py``.
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
SPIKE_DIR = HERE.parent / "tls13-spike"
sys.path.insert(0, str(SPIKE_DIR))
import run_286_bench as base  # type: ignore


rb = base.rb
PIPE_BASE = rb.BENCH_BUILD / "tls13-product-com"
BOOT_SOURCE = HERE / "bench_boot.asm"
MAX_PAYLOAD_SECTORS = 103
PLAIN_METRIC_RE = re.compile(r"^([A-Z0-9]+)\s+N=(\d+)\s+dt=(\d+)$")
GUEST_LINE_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:\s|$)")


class PipeCapture:
    """Capture the guest's COM1 writes from 86Box's fixed FIFO device."""

    def __init__(self, base_path: Path) -> None:
        self.input_path = Path(f"{base_path}.in")
        self.output_path = Path(f"{base_path}.out")
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.fd: int | None = None

    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        for path in (self.input_path, self.output_path):
            path.unlink(missing_ok=True)
            os.mkfifo(path, 0o600)
        self.fd = os.open(
            self.output_path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY,
        )
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        assert self.fd is not None
        while not self.stop_event.is_set():
            try:
                chunk = os.read(self.fd, 4096)
            except BlockingIOError:
                chunk = b""
            except OSError:
                break
            if chunk:
                with self.lock:
                    self.buf.extend(chunk)
            else:
                time.sleep(0.02)

    def text(self) -> str:
        with self.lock:
            return bytes(self.buf).decode("ascii", errors="replace")

    def finish(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        for path in (self.input_path, self.output_path):
            path.unlink(missing_ok=True)


def configure_pipe_serial(config_path: Path) -> None:
    """Replace the temporary stdio serial device with a fixed FIFO."""
    text = config_path.read_text()
    text = text.replace("serial1_device = stdio", "serial1_device = pipe")
    text += (
        "\n[Named Pipe (COM) #1]\n"
        f"path = {PIPE_BASE}\n"
        "mode = 1\n"
        "reconnect = 1\n"
    )
    config_path.write_text(text)


def assemble_image(
    asm_path: Path, include_dirs: list[Path], nasm_defines: list[str]
) -> tuple[Path, int, int]:
    """Assemble a benchmark and a boot sector sized to its exact payload."""
    asm_path = asm_path.resolve()
    if not asm_path.is_file():
        raise SystemExit(f"benchmark assembly not found: {asm_path}")
    rb.BENCH_BUILD.mkdir(parents=True, exist_ok=True)
    stem = asm_path.stem
    boot_path = rb.BENCH_BUILD / f"{stem}-286-product-boot.bin"
    bench_path = rb.BENCH_BUILD / f"{stem}-286-product.bin"
    image_path = rb.BENCH_BUILD / f"{stem}-286-product-360.img"

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
    subprocess.run(nasm_command, check=True, cwd=rb.ROOT)
    bench = bench_path.read_bytes()
    sectors = (len(bench) + 511) // 512
    if not 1 <= sectors <= MAX_PAYLOAD_SECTORS:
        raise SystemExit(
            f"{asm_path.name} is {len(bench)} bytes / {sectors} sectors; "
            f"product gate limit is {MAX_PAYLOAD_SECTORS}"
        )
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-DBENCH_SECTORS={sectors}",
            "-o",
            str(boot_path),
            str(BOOT_SOURCE),
        ],
        check=True,
        cwd=rb.ROOT,
    )
    boot = boot_path.read_bytes()
    if len(boot) != 512:
        raise SystemExit(f"benchmark boot sector is {len(boot)} bytes, expected 512")
    image = bytearray(368640)
    image[:512] = boot
    image[512 : 512 + len(bench)] = bench
    image_path.write_bytes(image)
    return image_path, len(bench), sectors


def guest_lines(serial_text: str) -> list[str]:
    return [
        line.strip()
        for line in serial_text.splitlines()
        if GUEST_LINE_RE.match(line.strip()) and not line.startswith("VK_")
    ]


def parsed_operations(
    serial_text: str,
) -> dict[str, dict[str, int | float | str]]:
    operations = base.parsed_operations(serial_text)
    for line in serial_text.splitlines():
        match = PLAIN_METRIC_RE.match(line.strip())
        if match is None:
            continue
        tag = match.group(1)
        iterations = int(match.group(2))
        ticks = int(match.group(3))
        operations[tag] = {
            "iterations": iterations,
            "ticks": ticks,
            "checksum": "",
            "seconds_total": ticks * rb.TICK_MS / 1000.0,
            "seconds_per_iteration": (
                ticks * rb.TICK_MS / 1000.0 / iterations if iterations else 0.0
            ),
        }
    return operations


def matching_pids() -> set[int]:
    """Return 86Box processes launched with this benchmark VM path."""
    result = subprocess.run(
        ["ps", "-axo", "pid=,command="],
        capture_output=True,
        text=True,
        check=True,
    )
    match = str(rb.VM_PATH)
    pids: set[int] = set()
    for line in result.stdout.splitlines():
        pid_text, _, command = line.strip().partition(" ")
        if pid_text.isdigit() and "86Box" in command and match in command:
            pids.add(int(pid_text))
    return pids


def stop_pids(pids: set[int]) -> None:
    """Stop only the 86Box processes created for this gate."""
    for pid in sorted(pids):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        alive = matching_pids() & pids
        if not alive:
            return
        time.sleep(0.1)
    for pid in sorted(matching_pids() & pids):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_vm(image_path: Path, mhz: int, timeout: int) -> dict[str, object]:
    """Run one benchmark and restore every persistent profile input."""
    config_path = rb.VM_PATH / "86box.cfg"
    original_config = config_path.read_bytes()
    nvr_dir = rb.VM_PATH / "nvr"
    nvr_path = nvr_dir / base.AT_NVR_NAME
    nvr_dir_existed = nvr_dir.exists()
    nvr_existed = nvr_path.exists()
    original_nvr = nvr_path.read_bytes() if nvr_existed else None
    spawned_pids: set[int] = set()
    process: subprocess.Popen[bytes] | None = None
    capture = PipeCapture(PIPE_BASE)

    try:
        nvr_dir.mkdir(parents=True, exist_ok=True)
        nvr_path.write_bytes(base.at_cmos())
        base.write_config(image_path, mhz)
        configure_pipe_serial(config_path)
        subprocess.run(["pkill", "-f", str(rb.VM_PATH)], capture_output=True)
        time.sleep(1)

        capture.start()
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
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        spawned_pids = {process.pid}

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            captured = capture.text()
            if "DONE" in captured or "\nFAIL" in captured or captured.startswith("FAIL"):
                break
            if process.poll() is not None:
                break
            time.sleep(0.25)

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
            "raw_serial": serial_text,
        }
    finally:
        stop_pids(spawned_pids)
        capture.finish()
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asm", type=Path, required=True)
    parser.add_argument("--mhz", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--expect", action="append", default=[], metavar="TAG=HEX")
    parser.add_argument("--require", action="append", default=[], metavar="TEXT")
    parser.add_argument(
        "--include-dir", action="append", default=[], type=Path, metavar="PATH"
    )
    parser.add_argument(
        "--nasm-define", action="append", default=[], metavar="NAME[=VALUE]"
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    expected = base.parse_expectations(args.expect)
    image_path, image_bytes, sectors = assemble_image(
        args.asm, args.include_dir, args.nasm_define
    )
    result = run_vm(image_path, args.mhz, args.timeout)
    failures = base.check_result(result, expected, args.require)
    result["passed"] = not failures
    result["failures"] = failures
    report = {
        "asm": str(args.asm),
        "image": str(image_path),
        "payload_bytes": image_bytes,
        "payload_sectors": sectors,
        "result": result,
        "passed": not failures,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"{args.asm}: {image_bytes} B / {sectors} sectors")
        for line in result["guest_lines"]:
            print(f"  {line}")
        for tag, operation in result["operations"].items():
            print(
                f"  {tag}: {operation['ticks']} ticks = "
                f"{operation['seconds_per_iteration']:.4f} s/iteration"
            )
        print("  [PASS]" if not failures else "  [FAIL]")
        for failure in failures:
            print(f"    {failure}")
        if failures and result["raw_serial"]:
            print(f"  raw serial: {result['raw_serial']!r}")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
