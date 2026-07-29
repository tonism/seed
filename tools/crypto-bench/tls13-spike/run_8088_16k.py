#!/usr/bin/env python3
"""Run a standalone 8086 spike on a literal 16 KiB IBM PC 5150.

The normal standalone benchmark runner boots through a sector at 0000:7c00,
so it must configure at least 64 KiB even when the benchmark itself remains
below 0000:4000.  This runner uses Seed's established ROM BASIC sidecar entry:

* ROM BASIC runs from ROM on an actual 16 KiB profile;
* a small BASIC program installs the floppy reader at 0000:3a00;
* the reader loads the benchmark from drive B: to 0000:1000; and
* the benchmark reports through COM1.

The generated floppy, loader, BASIC program, and serial capture live under
``build/crypto-bench/tls13-16k``.  Product sources and release images are not
modified.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / "build/crypto-bench/tls13-16k"
HARNESS_PATH = ROOT / "tools/run-basic-bootstrap-86box.py"
BOOTSTRAP_ASM = ROOT / "targets/ibm_pc_5150/basic/bootstrap.asm"
BUILD_BASIC = ROOT / "tools/build-basic-bootstrap.py"
DEFAULT_ASM = HERE / "hkdf_bench.asm"
DEFAULT_PROFILE = "vm-net-ne2k8"

LOAD_ADDR = 0x1000
BOOTSTRAP_ADDR = 0x3A00
RAM_TOP = 0x4000
STACK_GUARD = 0x0100
CORE_START_LBA = 11
SECTOR_SIZE = 512
FLOPPY_BYTES = 160 * 1024
CPU_HZ = 4_772_728
LOADER_STATUS_TEXT = "POC LOADER..."
GUEST_RESULT_RE = re.compile(
    r"^(?!VK_)[A-Z][A-Z0-9_]{1,15}(?:\s+N=\d+|\s+(?:PASS|FAIL)|$)"
)


class StdoutCapture:
    """Continuously drain 86Box's v9001 virtual COM/stdout stream."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path
        self.parts: list[str] = []
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def start(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            raise RuntimeError("86Box stdout was not piped")
        self.thread = threading.Thread(
            target=self._read,
            args=(process.stdout,),
            daemon=True,
        )
        self.thread.start()

    def _read(self, stream) -> None:
        try:
            for line in iter(stream.readline, ""):
                with self.lock:
                    self.parts.append(line)
        except (OSError, ValueError):
            pass

    def text(self) -> str:
        with self.lock:
            return "".join(self.parts)

    def finish(self) -> None:
        if self.thread is not None:
            self.thread.join(timeout=2.0)
        data = self.text()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(data)


class PipeSerialCapture:
    """Capture COM1 from 86Box's fixed Unix FIFO character device."""

    def __init__(self, output_path: Path, base_path: Path) -> None:
        self.output_path = output_path
        self.base_path = base_path
        self.input_path = Path(f"{base_path}.in")
        self.output_fifo = Path(f"{base_path}.out")
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.fd: int | None = None

    def start(self) -> None:
        self.base_path.parent.mkdir(parents=True, exist_ok=True)
        for path in (self.input_path, self.output_fifo):
            path.unlink(missing_ok=True)
            os.mkfifo(path, 0o600)
        # Opening the read side first lets 86Box open its nonblocking writer
        # immediately during device initialization.
        self.fd = os.open(
            self.output_fifo,
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
        data = self.text().encode("ascii", errors="replace")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_bytes(data)
        for path in (self.input_path, self.output_fifo):
            path.unlink(missing_ok=True)


def load_basic_harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "seed_basic_bootstrap_harness",
        HARNESS_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load harness module: {HARNESS_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def checked_run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True, text=True)


def all_86box_pids() -> set[int]:
    """Return 86Box application PIDs, including manager-only processes."""

    result = subprocess.run(
        ["ps", "-axo", "pid=,command="],
        capture_output=True,
        text=True,
        check=True,
    )
    pids: set[int] = set()
    for line in result.stdout.splitlines():
        pid_text, _, command = line.strip().partition(" ")
        if not pid_text.isdigit():
            continue
        executable = command.split(" ", 1)[0]
        if executable.endswith("/86Box") or executable == "86Box":
            pids.add(int(pid_text))
    return pids


def stop_spawned_86box_pids(preexisting: set[int]) -> None:
    """Close only 86Box processes created during this harness invocation."""

    spawned = all_86box_pids() - preexisting
    for pid in sorted(spawned):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        remaining = (all_86box_pids() - preexisting) & spawned
        if not remaining:
            return
        time.sleep(0.1)
    for pid in sorted((all_86box_pids() - preexisting) & spawned):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def build_artifacts(
    bench_asm: Path,
    defines: list[str],
    *,
    resident_sectors: int | None = None,
) -> dict[str, object]:
    BUILD.mkdir(parents=True, exist_ok=True)
    core = BUILD / "bench.bin"
    loader = BUILD / "loader.bin"
    basic = BUILD / "BENCH16.BAS"
    floppy = BUILD / "bench-160k.img"

    nasm = [
        "nasm",
        "-Itargets/ibm_pc_5150/boot/",
        "-Itools/crypto-bench/",
        "-Ibuild/ibm_pc_5150/",
    ]
    for define in defines:
        nasm.append(f"-D{define}")
    checked_run([*nasm, "-f", "bin", "-o", str(core), str(bench_asm)])

    core_bytes = core.read_bytes()
    if not core_bytes:
        raise SystemExit("assembled benchmark is empty")
    total_sectors = math.ceil(len(core_bytes) / SECTOR_SIZE)
    if resident_sectors is None:
        resident_sectors = total_sectors
    if not 1 <= resident_sectors <= total_sectors:
        raise SystemExit(
            "--resident-sectors must be between 1 and the assembled image's "
            f"{total_sectors} sectors"
        )
    loaded_end = LOAD_ADDR + resident_sectors * SECTOR_SIZE
    if loaded_end > BOOTSTRAP_ADDR:
        raise SystemExit(
            "benchmark load extent collides with the ROM BASIC sidecar: "
            f"{resident_sectors} resident sectors load through 0x{loaded_end:04x}, "
            f"limit is 0x{BOOTSTRAP_ADDR:04x}"
        )

    checked_run(
        [
            "nasm",
            f"-DBASIC_BOOTSTRAP_ADDR=0x{BOOTSTRAP_ADDR:04x}",
            f"-DSEED_CORE_START_LBA={CORE_START_LBA}",
            f"-DSEED_CORE_SECTORS={resident_sectors}",
            f"-DSEED_RAM_TOP=0x{RAM_TOP:04x}",
            "-DSEED_BOOT_DRIVE=1",
            "-f",
            "bin",
            "-o",
            str(loader),
            str(BOOTSTRAP_ASM),
        ]
    )
    checked_run(
        [
            sys.executable,
            str(BUILD_BASIC),
            "--input",
            str(loader),
            "--output",
            str(basic),
            "--load-addr",
            f"0x{BOOTSTRAP_ADDR:04x}",
            "--clear-top",
            str(BOOTSTRAP_ADDR - 1),
            "--max-addr",
            f"0x{RAM_TOP:04x}",
        ]
    )
    basic_text = basic.read_text(encoding="ascii").replace("\r\n", "\n")
    call_lines = re.findall(r"(?m)^([0-9]+) DEF USR0=", basic_text)
    if len(call_lines) != 1:
        raise RuntimeError("generated BASIC sidecar has no unique USR0 call line")
    call_line_no = int(call_lines[0])
    status_line_no = call_line_no - 5
    if (
        status_line_no <= 0
        or re.search(rf"(?m)^{status_line_no} ", basic_text)
    ):
        raise RuntimeError(
            "generated BASIC sidecar has no free status line before USR0"
        )
    call_line = f"{call_line_no} DEF USR0="
    basic.write_text(
        basic_text.replace(
            call_line,
            f'{status_line_no} PRINT "{LOADER_STATUS_TEXT}"\n{call_line}',
            1,
        ),
        encoding="ascii",
    )

    image = bytearray(FLOPPY_BYTES)
    offset = CORE_START_LBA * SECTOR_SIZE
    if offset + len(core_bytes) > len(image):
        raise SystemExit("benchmark phase container exceeds the 160 KiB harness image")
    image[offset : offset + len(core_bytes)] = core_bytes
    floppy.write_bytes(image)

    return {
        "core": core,
        "loader": loader,
        "basic": basic,
        "floppy": floppy,
        "core_bytes": len(core_bytes),
        "core_sha256": hashlib.sha256(core_bytes).hexdigest(),
        "core_sectors": total_sectors,
        "resident_sectors": resident_sectors,
        "loaded_end": loaded_end,
    }


def captured_bytes(capture) -> bytes:
    return capture.text().encode("utf-8", errors="replace")


def extract_guest_output(stdout_text: str) -> str:
    """Trim emulator diagnostics before the benchmark's result stream."""

    lines = stdout_text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if GUEST_RESULT_RE.match(line.strip()):
            start = index
            break
    if start is None:
        return ""
    return "\n".join(lines[start:]) + "\n"


def configure_stdio_serial(config: Path) -> None:
    """Select 86Box v9001's stdout-backed virtual serial console."""

    source = config.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_ports = False
    in_virtual = False
    saw_ports = False
    saw_serial = False
    saw_virtual = False
    saw_mode = False

    def finish_ports() -> None:
        nonlocal saw_serial
        if in_ports and not saw_serial:
            out.append("serial1_device = stdio")
            saw_serial = True

    def finish_virtual() -> None:
        nonlocal saw_mode
        if in_virtual and not saw_mode:
            out.append("mode = 0")
            saw_mode = True

    for line in source:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            finish_ports()
            finish_virtual()
            in_ports = stripped == "[Ports (COM & LPT)]"
            in_virtual = stripped == "[Virtual Console (COM) #1]"
            if in_ports:
                saw_ports = True
                saw_serial = False
            if in_virtual:
                saw_virtual = True
                saw_mode = False
            out.append(line)
            continue
        if in_ports and (
            stripped.startswith("serial1_device")
            or stripped.startswith("serial1_passthrough_enabled")
        ):
            if not saw_serial:
                out.append("serial1_device = stdio")
                saw_serial = True
            continue
        if in_virtual and stripped.startswith("mode ="):
            out.append("mode = 0")
            saw_mode = True
            continue
        out.append(line)

    finish_ports()
    finish_virtual()
    if not saw_ports:
        if out and out[-1].strip():
            out.append("")
        out.extend(["[Ports (COM & LPT)]", "serial1_device = stdio"])
    if not saw_virtual:
        if out and out[-1].strip():
            out.append("")
        out.extend(["[Virtual Console (COM) #1]", "mode = 0"])
    config.write_text("\n".join(out) + "\n", encoding="utf-8")


def configure_pipe_serial(config: Path, base_path: Path) -> None:
    """Select 86Box's fixed Unix FIFO COM device for LaunchServices runs."""

    source = config.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_ports = False
    in_pipe = False
    saw_ports = False
    saw_serial = False
    saw_pipe = False
    saw_path = False
    saw_mode = False
    saw_reconnect = False

    def finish_ports() -> None:
        nonlocal saw_serial
        if in_ports and not saw_serial:
            out.append("serial1_device = pipe")
            saw_serial = True

    def finish_pipe() -> None:
        nonlocal saw_path, saw_mode, saw_reconnect
        if not in_pipe:
            return
        if not saw_path:
            out.append(f"path = {base_path}")
            saw_path = True
        if not saw_mode:
            out.append("mode = 1")
            saw_mode = True
        if not saw_reconnect:
            out.append("reconnect = 1")
            saw_reconnect = True

    for line in source:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            finish_ports()
            finish_pipe()
            in_ports = stripped == "[Ports (COM & LPT)]"
            in_pipe = stripped == "[Named Pipe (COM) #1]"
            if in_ports:
                saw_ports = True
                saw_serial = False
            if in_pipe:
                saw_pipe = True
                saw_path = saw_mode = saw_reconnect = False
            out.append(line)
            continue
        if in_ports and (
            stripped.startswith("serial1_device")
            or stripped.startswith("serial1_passthrough_enabled")
        ):
            if not saw_serial:
                out.append("serial1_device = pipe")
                saw_serial = True
            continue
        if in_pipe and stripped.startswith("path ="):
            out.append(f"path = {base_path}")
            saw_path = True
            continue
        if in_pipe and stripped.startswith("mode ="):
            out.append("mode = 1")
            saw_mode = True
            continue
        if in_pipe and stripped.startswith("reconnect ="):
            out.append("reconnect = 1")
            saw_reconnect = True
            continue
        out.append(line)

    finish_ports()
    finish_pipe()
    if not saw_ports:
        if out and out[-1].strip():
            out.append("")
        out.extend(["[Ports (COM & LPT)]", "serial1_device = pipe"])
    if not saw_pipe:
        if out and out[-1].strip():
            out.append("")
        out.extend(
            [
                "[Named Pipe (COM) #1]",
                f"path = {base_path}",
                "mode = 1",
                "reconnect = 1",
            ]
        )
    config.write_text("\n".join(out) + "\n", encoding="utf-8")


def run_literal_16k(
    harness: ModuleType,
    artifacts: dict[str, object],
    *,
    profile: str,
    timeout: float,
    done_token: bytes,
    start_token: bytes | None,
    start_timeout: float,
    startup_delay: float,
    type_delay: float,
    line_delay: float,
    floppy_read_only: bool,
) -> dict[str, object]:
    vm_path = ROOT / "targets/ibm_pc_5150/86box" / profile
    if not vm_path.is_dir():
        raise SystemExit(f"missing 86Box profile: {vm_path}")
    config = vm_path / "86box.cfg"
    original_config = config.read_bytes()
    restore_nvr = None
    process = None
    capture_path = BUILD / "bench.serial.txt"
    startup_failure_screenshot = BUILD / "startup-timeout.png"
    capture_path.unlink(missing_ok=True)
    startup_failure_screenshot.unlink(missing_ok=True)
    pipe_base = BUILD / "bench-com"
    capture = PipeSerialCapture(capture_path, pipe_base)
    preexisting_86box_pids = all_86box_pids()
    started = time.monotonic()
    done = False
    start_seen = start_token is None
    start_timeout_hit = False
    start_elapsed_wall_seconds: float | None = None
    floppy = artifacts["floppy"]
    original_floppy_mode = stat.S_IMODE(floppy.stat().st_mode)
    floppy_hash_before = hashlib.sha256(floppy.read_bytes()).hexdigest()
    floppy_hash_after = ""
    read_only_open_denied = False
    try:
        if floppy_read_only:
            floppy.chmod(0o444)
            try:
                descriptor = os.open(floppy, os.O_WRONLY)
            except PermissionError:
                read_only_open_denied = True
            else:
                os.close(descriptor)
                raise RuntimeError("read-only floppy still permits a write open")
        harness.validate_vm_ram_override(vm_path, 16)
        harness.stop_matching_86box_pids(vm_path)
        harness.rewrite_vm_config(
            config,
            16,
            artifacts["floppy"],
            True,
            com_passthrough=False,
            muted=True,
        )
        configure_pipe_serial(config, pipe_base)
        restore_nvr = harness.prepare_vm_nvr(vm_path, 16)
        capture.start()
        process = harness.launch_86box(
            vm_path,
            capture_stdout=False,
            background=True,
        )
        harness.wait_for_86box_window_or_identity_dialog(profile, process.pid)
        time.sleep(startup_delay)

        basic_text = (
            artifacts["basic"]
            .read_text(encoding="ascii")
            .replace("\r\n", "\n")
            .rstrip()
            + "\n"
        )
        harness.type_basic_pid_keycodes(
            process.pid,
            basic_text,
            type_delay,
            line_delay,
        )
        time.sleep(max(1.0, line_delay * 2))
        harness.type_basic_pid_keycodes(
            process.pid,
            "RUN\n",
            type_delay,
            line_delay,
        )

        deadline = started + timeout
        run_started = time.monotonic()
        start_deadline = run_started + start_timeout
        while time.monotonic() < deadline:
            output = captured_bytes(capture)
            if not start_seen and start_token in output:
                start_seen = True
                start_elapsed_wall_seconds = round(
                    time.monotonic() - run_started,
                    3,
                )
            if done_token in output:
                done = True
                break
            if not start_seen and time.monotonic() >= start_deadline:
                start_timeout_hit = True
                try:
                    harness.screenshot_86box_window_or_screen(
                        startup_failure_screenshot,
                        profile,
                        process.pid,
                    )
                except Exception:
                    startup_failure_screenshot.unlink(missing_ok=True)
                break
            if process.poll() is not None:
                break
            time.sleep(0.1)
        if done:
            time.sleep(0.25)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        capture.finish()
        stop_spawned_86box_pids(preexisting_86box_pids)
        config.write_bytes(original_config)
        if restore_nvr is not None:
            restore_nvr[0].write_bytes(restore_nvr[1])
        floppy_hash_after = hashlib.sha256(floppy.read_bytes()).hexdigest()
        floppy.chmod(original_floppy_mode)

    if config.read_bytes() != original_config:
        raise RuntimeError("failed to restore 86Box config byte-for-byte")
    stdout_text = capture_path.read_text(errors="replace") if capture_path.exists() else ""
    serial_text = extract_guest_output(stdout_text)
    return {
        "done": done,
        "start_seen": start_seen,
        "start_timeout_hit": start_timeout_hit,
        "start_elapsed_wall_seconds": start_elapsed_wall_seconds,
        "start_timeout_seconds": start_timeout,
        "startup_failure_screenshot": (
            display_path(startup_failure_screenshot)
            if startup_failure_screenshot.is_file()
            else None
        ),
        "global_config_override": None,
        "emulator_launch": "LaunchServices --vmpath + fixed COM FIFO",
        "elapsed_wall_seconds": round(time.monotonic() - started, 3),
        "timeout_seconds": timeout,
        "serial_path": display_path(capture_path),
        "serial_text": serial_text,
        "emulator_stdout_bytes": len(stdout_text.encode("utf-8")),
        "machine": {
            "model": "IBM PC 5150",
            "cpu": "8088",
            "cpu_hz": CPU_HZ,
            "installed_ram_kib": 16,
            "dynarec": False,
            "entry": "ROM BASIC sidecar",
        },
        "floppy_media": {
            "read_only_requested": floppy_read_only,
            "mode_during_run": "0o444" if floppy_read_only else None,
            "host_write_open_denied": read_only_open_denied,
            "sha256_before": floppy_hash_before,
            "sha256_after": floppy_hash_after,
            "unchanged": floppy_hash_before == floppy_hash_after,
            "mode_restored": (
                stat.S_IMODE(floppy.stat().st_mode) == original_floppy_mode
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a standalone Seed benchmark on a literal 16 KiB 5150."
    )
    parser.add_argument("--asm", type=Path, default=DEFAULT_ASM)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--done-token", default="DONE")
    parser.add_argument(
        "--start-token",
        default=None,
        help=(
            "optional first guest token; fail early if it is not emitted within "
            "--start-timeout seconds after RUN"
        ),
    )
    parser.add_argument("--start-timeout", type=float, default=45.0)
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--startup-delay", type=float, default=10.0)
    parser.add_argument("--type-delay", type=float, default=0.01)
    parser.add_argument("--line-delay", type=float, default=0.2)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument(
        "--resident-sectors",
        type=int,
        default=None,
        help=(
            "load only this prefix through the ROM BASIC sidecar; the remaining "
            "contiguous image stays on floppy for a resident phase loader"
        ),
    )
    parser.add_argument(
        "--floppy-read-only",
        action="store_true",
        help=(
            "chmod the generated floppy image read-only for the VM run, verify "
            "a host write-open is denied, and restore its mode afterward"
        ),
    )
    args = parser.parse_args()

    if not 10.0 <= args.timeout <= 1800.0:
        parser.error("--timeout must be between 10 and 1800 seconds")
    if not args.done_token:
        parser.error("--done-token must not be empty")
    if not 5.0 <= args.start_timeout <= args.timeout:
        parser.error("--start-timeout must be between 5 seconds and --timeout")
    bench_asm = args.asm
    if not bench_asm.is_absolute():
        bench_asm = (ROOT / bench_asm).resolve()
    if not bench_asm.is_file():
        parser.error(f"benchmark source not found: {bench_asm}")

    artifacts = build_artifacts(
        bench_asm,
        args.define,
        resident_sectors=args.resident_sectors,
    )
    harness = load_basic_harness()
    result = run_literal_16k(
        harness,
        artifacts,
        profile=args.profile,
        timeout=args.timeout,
        done_token=args.done_token.encode("ascii"),
        start_token=(
            args.start_token.encode("ascii")
            if args.start_token is not None
            else None
        ),
        start_timeout=args.start_timeout,
        startup_delay=args.startup_delay,
        type_delay=args.type_delay,
        line_delay=args.line_delay,
        floppy_read_only=args.floppy_read_only,
    )
    result.update(
        {
            "source": display_path(bench_asm),
            "source_sha256": hashlib.sha256(bench_asm.read_bytes()).hexdigest(),
            "runner": display_path(Path(__file__)),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "bootstrap_source": display_path(BOOTSTRAP_ASM),
            "bootstrap_source_sha256": hashlib.sha256(
                BOOTSTRAP_ASM.read_bytes()
            ).hexdigest(),
            "basic_builder": display_path(BUILD_BASIC),
            "basic_builder_sha256": hashlib.sha256(
                BUILD_BASIC.read_bytes()
            ).hexdigest(),
            "vm_harness": display_path(HARNESS_PATH),
            "vm_harness_sha256": hashlib.sha256(
                HARNESS_PATH.read_bytes()
            ).hexdigest(),
            "image_bytes": artifacts["core_bytes"],
            "image_sha256": artifacts["core_sha256"],
            "image_sectors": artifacts["core_sectors"],
            "resident_sectors": artifacts["resident_sectors"],
            "load_start": f"0x{LOAD_ADDR:04x}",
            "loaded_end": f"0x{artifacts['loaded_end']:04x}",
            "bootstrap_start": f"0x{BOOTSTRAP_ADDR:04x}",
            "ram_top": f"0x{RAM_TOP:04x}",
            "stack_guard_bytes": STACK_GUARD,
            "loader_status_text": LOADER_STATUS_TEXT,
            "command": (
                "python3 tools/crypto-bench/tls13-spike/run_8088_16k.py "
                f"--asm {display_path(bench_asm)}"
                + (
                    f" --resident-sectors {args.resident_sectors}"
                    if args.resident_sectors is not None
                    else ""
                )
                + "".join(f" --define {define}" for define in args.define)
                + (
                    f" --start-token {args.start_token!r}"
                    if args.start_token is not None
                    else ""
                )
                + f" --start-timeout {args.start_timeout:g}"
                + (" --floppy-read-only" if args.floppy_read_only else "")
            ),
        }
    )

    print("--- captured COM1 ---")
    print(result["serial_text"] or "(none)")
    print("--- result ---")
    printable = dict(result)
    printable.pop("serial_text")
    print(json.dumps(printable, indent=2))
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    if not result["done"]:
        if result["start_timeout_hit"]:
            raise SystemExit(
                "literal 16 KiB benchmark did not reach its first guest marker "
                f"{args.start_token!r} within {args.start_timeout:g} seconds "
                "after RUN"
            )
        raise SystemExit(
            f"literal 16 KiB benchmark did not emit {args.done_token!r}"
        )


if __name__ == "__main__":
    main()
