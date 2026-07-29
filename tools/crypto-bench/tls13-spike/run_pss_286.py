#!/usr/bin/env python3
"""Boot and time the TLS 1.3 RSA-PSS decoder on the lowest 6 MHz 286.

The timed operation includes the 130-byte CertificateVerify signed-content
hash plus EMSA-PSS decode/MGF1.  It excludes RSA-2048 modular exponentiation,
which remains covered by ``../run_rsa_286.py``.
"""

from __future__ import annotations

import argparse
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


EXPECTED_CODE_BYTES = 272
EXPECTED_SCRATCH_BYTES = 74


class OutputCapture(rb.ComCapture):
    """Accept both old PTY passthrough and 86Box 9001's stdio migration."""

    def __init__(self) -> None:
        super().__init__()
        self.stdout_buf = bytearray()

    def _read_stdout(self, process) -> None:
        try:
            for line in iter(process.stdout.readline, ""):
                if self.stop_event.is_set():
                    break
                encoded = line.encode("utf-8", errors="replace")
                with self.lock:
                    self.stdout_buf.extend(encoded)
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


def build_image() -> Path:
    rb.BENCH_BUILD.mkdir(parents=True, exist_ok=True)
    boot_path = rb.BENCH_BUILD / "pss-bench-boot.bin"
    bench_path = rb.BENCH_BUILD / "pss-decode.bin"
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
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-Itargets/ibm_pc_5150/boot/",
            "-Itools/crypto-bench/",
            "-o",
            str(bench_path),
            "tools/crypto-bench/tls13-spike/pss_decode_bench.asm",
        ],
        check=True,
        cwd=rb.ROOT,
    )
    boot = boot_path.read_bytes()
    bench = bench_path.read_bytes()
    sectors = (len(bench) + 511) // 512
    if sectors > 28:
        raise SystemExit(f"pss-decode.bin is {sectors} sectors; loader limit is 28")
    image = bytearray(368640)
    image[0:512] = boot
    image[512 : 512 + len(bench)] = bench
    image_path = rb.BENCH_BUILD / "pss-decode-360.img"
    image_path.write_bytes(image)
    print(f"pss-decode.bin {len(bench)} B ({sectors} sectors)")
    return image_path


def craft_cmos() -> None:
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
    (rb.VM_PATH / "nvr").mkdir(parents=True, exist_ok=True)
    (rb.VM_PATH / "nvr" / "ibm5170_111585.nvr").write_bytes(bytes(cmos))


def write_config(image_path: Path, mhz: int) -> None:
    (rb.VM_PATH / "86box.cfg").write_text(
        f"""[General]
emu_build_num = 8200
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


def run(mhz: int, timeout: int) -> dict[str, int | float | str | bool]:
    image_path = build_image()
    config_path = rb.VM_PATH / "86box.cfg"
    original_config = config_path.read_bytes()
    try:
        craft_cmos()
        write_config(image_path, mhz)
        return run_configured(image_path, mhz, timeout)
    finally:
        config_path.write_bytes(original_config)


def run_configured(
    image_path: Path, mhz: int, timeout: int
) -> dict[str, int | float | str | bool]:
    subprocess.run(["pkill", "-f", "86Box"], capture_output=True)
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
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if "DONE" in capture.text():
                break
            time.sleep(1)
    finally:
        capture.finish()
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        subprocess.run(
            ["pkill", "-f", str(rb.VM_PATH)],
            capture_output=True,
        )

    serial_text = capture.text()
    match = re.search(
        r"PSSDEC\s+N=(\d+)\s+dt=(\d+)\s+ok=([0-9A-Fa-f]{4})"
        r"\s+code=([0-9A-Fa-f]{4})\s+scratch=([0-9A-Fa-f]{4})",
        serial_text,
    )
    if not match:
        raise SystemExit(f"no PSSDEC result parsed from serial output: {serial_text!r}")
    iterations = int(match.group(1))
    ticks = int(match.group(2))
    accepted = int(match.group(3), 16)
    code_bytes = int(match.group(4), 16)
    scratch_bytes = int(match.group(5), 16)
    seconds_per_iteration = ticks * rb.TICK_MS / 1000.0 / iterations
    passed = (
        accepted == iterations
        and code_bytes == EXPECTED_CODE_BYTES
        and scratch_bytes == EXPECTED_SCRATCH_BYTES
    )
    return {
        "mhz": mhz,
        "iterations": iterations,
        "ticks": ticks,
        "accepted": accepted,
        "code_bytes": code_bytes,
        "scratch_bytes": scratch_bytes,
        "seconds_per_iteration": seconds_per_iteration,
        "serial_text": serial_text,
        "passed": passed,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mhz", nargs="?", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    result = run(args.mhz, args.timeout)
    verdict = "PASS" if result["passed"] else "FAIL"
    print(f"raw: {result['serial_text']!r}")
    print(
        f"286@{args.mhz}MHz: TLS 1.3 CV post-RSA = "
        f"{result['ticks']} ticks / {result['iterations']} = "
        f"{result['seconds_per_iteration']:.3f} s; "
        f"code={result['code_bytes']} B scratch={result['scratch_bytes']} B "
        f"[{verdict}]"
    )
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
