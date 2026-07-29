#!/usr/bin/env python3
"""Build and run the automatic-floppy-entropy 16 KiB credentialed-live PoC.

The target performs 256 alternating read-only floppy reads and conditions
their PIT-measured completion timing before the first network transmission.
86Box proves the unattended mechanism and full TLS route, but its virtual
timing receives zero entropy security credit.
"""

from __future__ import annotations

import atexit
import argparse
import configparser
from dataclasses import dataclass
import functools
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILDER = HERE / "build_post_auth_live.py"
HARNESS = ROOT / "tools/run-basic-bootstrap-86box.py"
DEFAULT_BASE = ROOT / "build/crypto-bench/tls13-live-k15"
DEFAULT_BUILD = ROOT / "build/crypto-bench/tls13-live-k15-post-auth"
EXACT_PROFILE = "vm-net-ne2k8"
PROFILE_ROOT = ROOT / "targets/ibm_pc_5150/86box"

ENTROPY_START = b"ENTROPY START 256"
ENTROPY_PASS = b"ENTROPY PASS 256"
SUCCESS = b"\r\nok\r\nPASS\r\nRESULT\r\n"
FAILURE = b"\r\nFAIL\r\nRESULT\r\n"
PASS_REPORT_NAME = "credentialed-live-run.json"
RUN_LOCK_NAME = ".credentialed-live.lock"


class RunnerOwnership:
    """Exclusive ownership of one credentialed build/evidence directory."""

    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None

    def acquire(self) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            raise SystemExit(
                "credentialed-live build directory is already owned by "
                "another runner"
            ) from None
        try:
            os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        except BaseException:
            os.close(descriptor)
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            raise
        self.fd = descriptor

    def release(self) -> None:
        descriptor = self.fd
        if descriptor is None:
            return
        self.fd = None
        try:
            opened = os.fstat(descriptor)
            try:
                current = self.path.stat(follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if (
                current is not None
                and current.st_dev == opened.st_dev
                and current.st_ino == opened.st_ino
            ):
                self.path.unlink()
        finally:
            os.close(descriptor)

    def __enter__(self) -> RunnerOwnership:
        self.acquire()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.release()


def invalidate_previous_pass_report(build: Path) -> None:
    """A failed rerun must never inherit an earlier passing report."""

    (build / PASS_REPORT_NAME).unlink(missing_ok=True)


def exclusive_credentialed_run(function):
    """Hold build/evidence ownership around one fully authorized runner call."""

    @functools.wraps(function)
    def wrapped():
        preflight = argparse.ArgumentParser(add_help=False)
        preflight.add_argument("--credentialed-live", action="store_true")
        preflight.add_argument("--automatic-floppy-entropy", action="store_true")
        preflight.add_argument("--user-cfg")
        preflight.add_argument(
            "--build-dir",
            type=Path,
            default=DEFAULT_BUILD,
        )
        selected, _unknown = preflight.parse_known_args()
        if (
            not selected.credentialed_live
            or not selected.automatic_floppy_entropy
            or selected.user_cfg is None
        ):
            return function()

        build = selected.build_dir.resolve()
        build.mkdir(parents=True, exist_ok=True)
        with RunnerOwnership(build / RUN_LOCK_NAME):
            invalidate_previous_pass_report(build)
            return function()

    return wrapped


@dataclass(frozen=True)
class SerialCreditState:
    collection_started: bool
    entropy_passed: bool
    success: bool
    failure: bool


def inspect_credited_serial(serial: bytes) -> SerialCreditState:
    """Validate complete CRLF lines at the security-credit boundary."""

    parts = serial.split(b"\r\n")
    lines = parts[:-1]

    for marker in (ENTROPY_START, ENTROPY_PASS):
        for line in lines:
            if marker in line and line != marker:
                raise RuntimeError(
                    "target emitted a credited entropy marker outside an "
                    "exact CRLF-delimited line"
                )

    def indices(value: bytes) -> list[int]:
        return [index for index, line in enumerate(lines) if line == value]

    start_offsets = indices(ENTROPY_START)
    entropy_pass_offsets = indices(ENTROPY_PASS)
    ok_offsets = indices(b"ok")
    result_pass_offsets = indices(b"PASS")
    result_offsets = indices(b"RESULT")
    fail_offsets = indices(b"FAIL")
    for offsets in (
        start_offsets,
        entropy_pass_offsets,
        ok_offsets,
        result_pass_offsets,
        result_offsets,
        fail_offsets,
    ):
        if len(offsets) > 1:
            raise RuntimeError("target emitted a duplicate credited proof marker")

    if entropy_pass_offsets and (
        not start_offsets or entropy_pass_offsets[0] <= start_offsets[0]
    ):
        raise RuntimeError(
            "target entropy PASS preceded its unique START marker"
        )

    success = False
    failure = False
    if result_offsets:
        result_offset = result_offsets[0]
        success = bool(
            ok_offsets
            and result_pass_offsets
            and ok_offsets[0] + 1 == result_pass_offsets[0]
            and result_pass_offsets[0] + 1 == result_offset
        )
        failure = bool(
            fail_offsets
            and fail_offsets[0] + 1 == result_offset
        )
        if success == failure:
            raise RuntimeError(
                "target terminal proof markers were not one exact contiguous "
                "success or failure sequence"
            )
        if result_offset != len(lines) - 1 or parts[-1] != b"":
            raise RuntimeError(
                "target terminal proof sequence was not the final complete "
                "CRLF-delimited output"
            )

    if success and (
        not entropy_pass_offsets
        or ok_offsets[0] <= entropy_pass_offsets[0]
    ):
        raise RuntimeError(
            "target success preceded its unique entropy PASS marker"
        )
    if failure and success:
        raise RuntimeError("target emitted conflicting terminal proof markers")

    return SerialCreditState(
        collection_started=bool(start_offsets),
        entropy_passed=bool(entropy_pass_offsets),
        success=success,
        failure=failure,
    )


def read_serial(path: Path, maximum: int = 1024 * 1024) -> bytes:
    if not path.is_file():
        return b""
    size = path.stat().st_size
    if size > maximum:
        raise RuntimeError("target serial evidence exceeds the fixed 1 MiB limit")
    return path.read_bytes()


def stop_harness(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=20)
        return
    except subprocess.TimeoutExpired:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def validate_profile(config_path: Path, *, memory_kib: int | None) -> None:
    parser = configparser.ConfigParser(interpolation=None)
    if not parser.read(config_path, encoding="utf-8"):
        raise SystemExit("exact vm-net-ne2k8 configuration is absent")
    required = {
        ("Machine", "machine"): "ibmpc",
        ("Machine", "cpu_family"): "8088",
        ("Machine", "cpu_multi"): "1",
        ("Machine", "cpu_speed"): "4772728",
        ("Machine", "cpu_use_dynarec"): "0",
        ("Network", "net_01_card"): "ne2k8",
    }
    if memory_kib is not None:
        required[("Machine", "mem_size")] = str(memory_kib)
    for (section, option), expected in required.items():
        if parser.get(section, option, fallback=None) != expected:
            raise SystemExit(
                "vm-net-ne2k8 no longer matches the fixed original-speed "
                "8088/NE2000 proof profile"
            )


def make_exact_runtime_profile(build: Path) -> Path:
    source = PROFILE_ROOT / EXACT_PROFILE
    validate_profile(source / "86box.cfg", memory_kib=None)
    temporary_root = Path(
        tempfile.mkdtemp(prefix=".credentialed-vm-profile-", dir=build)
    )
    atexit.register(shutil.rmtree, temporary_root, True)
    destination = temporary_root / EXACT_PROFILE
    shutil.copytree(source, destination)
    config_path = destination / "86box.cfg"
    text = config_path.read_text(encoding="utf-8")
    text, replacements = re.subn(
        r"(?m)^mem_size\s*=\s*\d+\s*$",
        "mem_size = 16",
        text,
        count=1,
    )
    if replacements != 1:
        raise SystemExit("vm-net-ne2k8 memory field is absent or ambiguous")
    # A copied profile retains the source path-derived UUID.  With a configured
    # NIC, 86Box treats that mismatch as a moved/copied machine and blocks on
    # a modal dialog before the guest can accept BASIC keycodes.  An empty UUID
    # is 86Box's documented first-run state: it binds the temporary profile to
    # its canonical path without prompting or changing the copied MAC.
    text, uuid_replacements = re.subn(
        r"(?m)^uuid\s*=\s*.*$",
        "uuid =",
        text,
        count=1,
    )
    if uuid_replacements != 1:
        raise SystemExit("vm-net-ne2k8 UUID field is absent or ambiguous")
    config_path.write_text(text, encoding="utf-8")
    validate_profile(config_path, memory_kib=16)
    return destination


def image_digest(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
    return digest.digest()


def verify_host_read_only(path: Path) -> None:
    if stat.S_IMODE(path.stat().st_mode) != 0o444:
        raise AssertionError("credentialed floppy image is not mode 0444")
    try:
        descriptor = os.open(path, os.O_WRONLY)
    except PermissionError:
        return
    else:
        os.close(descriptor)
        raise AssertionError("host write-open unexpectedly succeeded")


@exclusive_credentialed_run
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentialed-live", action="store_true")
    parser.add_argument(
        "--automatic-floppy-entropy",
        action="store_true",
        help=(
            "run the unattended read-only floppy-timing collector; virtual "
            "timing receives zero security credit"
        ),
    )
    parser.add_argument("--user-cfg", type=Path)
    parser.add_argument("--base-build", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument(
        "--profile",
        choices=[EXACT_PROFILE],
        default=EXACT_PROFILE,
        help="fixed security-credit profile (no alternate profiles accepted)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=7200,
        help="maximum seconds to wait for target completion (default: 7200)",
    )
    parser.add_argument(
        "--start-timeout",
        type=int,
        default=180,
        help=(
            "maximum seconds after harness launch to observe the target's "
            "unique entropy-start marker (default: 180)"
        ),
    )
    args = parser.parse_args()

    # Refuse before resolving, opening, or statting a caller-selected config.
    if not args.credentialed_live:
        raise SystemExit("runner requires explicit --credentialed-live")
    if not args.automatic_floppy_entropy:
        raise SystemExit(
            "runner requires --automatic-floppy-entropy"
        )
    if args.user_cfg is None:
        raise SystemExit("runner requires --user-cfg")
    if args.timeout < 60:
        raise SystemExit("--timeout must be at least 60 seconds")
    if not 30 <= args.start_timeout < args.timeout:
        raise SystemExit(
            "--start-timeout must be at least 30 seconds and below --timeout"
        )

    selected_config = args.user_cfg.resolve()
    if not selected_config.is_file():
        raise SystemExit("the explicitly selected USER.CFG is not a file")
    size = selected_config.stat().st_size
    if not 1 <= size <= 512:
        raise SystemExit("credentialed-live USER.CFG must occupy 1..512 bytes")

    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".credentialed-runner-input-",
        dir=build,
    ) as input_name:
        opaque_config = Path(input_name) / "USER.CFG"
        try:
            os.link(selected_config, opaque_config)
        except OSError:
            raise SystemExit(
                "unable to stage the credential through an opaque "
                "same-filesystem hard link"
            ) from None
        built = subprocess.run(
            [
                sys.executable,
                str(BUILDER),
                "--credentialed-live",
                "--automatic-floppy-entropy",
                "--user-cfg",
                str(opaque_config),
                "--base-build",
                str(args.base_build.resolve()),
                "--build-dir",
                str(build),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if built.returncode:
        # Builder output is contractually free of credential contents and the
        # original path; its only input path was the opaque hard link above.
        sys.stdout.write(built.stdout)
        raise SystemExit(built.returncode)
    sys.stdout.write(built.stdout)

    manifest_path = build / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mode = manifest.get("mode")
    if (
        not isinstance(mode, dict)
        or mode.get("credentialed_live") is not True
        or mode.get("automatic_floppy_entropy") is not True
        or mode.get("entropy_values_accepted_by_cli_or_environment")
        is not False
    ):
        raise AssertionError(
            "builder did not publish the automatic-floppy-entropy contract"
        )
    output = manifest.get("output")
    if not isinstance(output, dict):
        raise AssertionError("builder manifest lacks output paths")
    image = Path(str(output.get("image", "")))
    basic_loader = Path(str(output.get("basic_loader", "")))
    basic = Path(str(output.get("basic_program", "")))
    if (
        not image.is_file()
        or not basic_loader.is_file()
        or not basic.is_file()
    ):
        raise AssertionError(
            "credentialed-live image/BASIC loader/sidecar is absent"
        )
    if (
        output.get("basic_sidecar_rebuilt_and_base_compared") is not True
        or output.get("basic_loader_bytes") != basic_loader.stat().st_size
        or output.get("basic_program_bytes") != basic.stat().st_size
        or output.get("basic_loader_sha256")
        != hashlib.sha256(basic_loader.read_bytes()).hexdigest()
        or output.get("basic_program_sha256")
        != hashlib.sha256(basic.read_bytes()).hexdigest()
    ):
        raise AssertionError("BASIC loader/sidecar manifest binding drifted")
    verify_host_read_only(image)
    image_before = image_digest(image)
    runtime_profile = make_exact_runtime_profile(build)

    serial_path = build / "credentialed-live.serial.log"
    harness_path = build / "credentialed-live.harness.log"
    pcap_path = build / "credentialed-live.pcap"
    serial_path.unlink(missing_ok=True)
    harness_path.unlink(missing_ok=True)
    pcap_path.unlink(missing_ok=True)
    command = [
        sys.executable,
        "-u",
        str(HARNESS),
        "--profile",
        args.profile,
        "--vm-path",
        str(runtime_profile),
        "--entry",
        "basic",
        "--ram-kib",
        "16",
        "--basic",
        str(basic),
        "--basic-loader",
        str(basic_loader),
        "--floppy",
        str(image),
        "--no-build",
        "--type-delay",
        "0.05",
        "--line-delay",
        "0.5",
        "--capture-delay",
        str(args.timeout),
        "--com-capture",
        str(serial_path),
        "--pcap",
        str(pcap_path),
        "--pcap-filter",
        "tcp port 443",
        "--pcap-max-lines",
        "40",
        "--no-screenshot",
    ]
    collection_started = False
    entropy_passed = False
    success = False
    stable_success_serial: bytes | None = None
    started = time.monotonic()
    with harness_path.open("wb") as harness_log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=harness_log,
            stderr=subprocess.STDOUT,
            # Keep a terminal Ctrl-C on this proof runner from racing the
            # harness's own VM/pcap cleanup.  stop_harness() delivers the
            # single intentional SIGINT to the isolated child.
            start_new_session=True,
        )
        try:
            while time.monotonic() - started < args.timeout:
                serial = read_serial(serial_path)
                credit = inspect_credited_serial(serial)
                if not collection_started and credit.collection_started:
                    collection_started = True
                    print(
                        "Target started 256 automatic read-only floppy timing "
                        "samples.",
                        flush=True,
                    )
                if (
                    not collection_started
                    and time.monotonic() - started >= args.start_timeout
                ):
                    raise RuntimeError(
                        "target did not emit its unique entropy START marker "
                        f"within {args.start_timeout} seconds"
                    )
                if not entropy_passed and credit.entropy_passed:
                    entropy_passed = True
                    print(
                        "Target reported ENTROPY PASS 256; waiting for the "
                        "fresh-resumption secure path.",
                        flush=True,
                    )
                if credit.failure:
                    raise RuntimeError("target reported FAIL / RESULT")
                if credit.success:
                    if not collection_started or not entropy_passed:
                        raise RuntimeError(
                            "target reached success without the ordered "
                            "START / PASS entropy collection"
                        )
                    if stable_success_serial == serial:
                        success = True
                        break
                    stable_success_serial = serial
                else:
                    stable_success_serial = None
                code = process.poll()
                if code is not None:
                    raise RuntimeError(
                        f"86Box harness exited before target completion ({code})"
                    )
                time.sleep(1)
        finally:
            stop_harness(process)

    if not success:
        raise SystemExit("timed out before exact ok / PASS / RESULT")
    verify_host_read_only(image)
    if image_digest(image) != image_before:
        raise AssertionError("credentialed floppy image changed during target run")
    report = {
        "schema": "seed-live-k14-credentialed-run-v1",
        "status": "pass",
        "profile": args.profile,
        "ram_kib": 16,
        "machine_gate": {
            "machine": "IBM PC 5150",
            "cpu": "8088",
            "clock_hz": 4772728,
            "memory_kib": 16,
            "dynarec": False,
            "nic": "NE2000 8-bit",
            "exact_profile_required": True,
        },
        "automatic_target_entropy": {
            "source": (
                "256 alternating read-only floppy completion timings "
                "measured by PIT channel 0"
            ),
            "collection_started": collection_started,
            "pass_observed": entropy_passed,
            "strict_start_pass_success_order": True,
            "unique_credited_markers": True,
            "entropy_values_accepted_by_runner": False,
            "entropy_values_logged_by_runner": False,
            "emulator_security_credit_bits": 0,
            "physical_security_credit": (
                "pending representative real-drive min-entropy "
                "characterization"
            ),
            "collection_before_first_network_transmission": True,
        },
        "credential_privacy": {
            "contents_logged": False,
            "path_logged": False,
            "size_logged": False,
            "hash_logged": False,
        },
        "read_only_media": {
            "mode": "0444",
            "host_write_open_denied": True,
            "before_after_digest_equal": True,
            "digest_logged": False,
        },
        "wire_evidence": {
            "pcap_required": False,
            "reason": (
                "the target emits the exact success marker only after K14 "
                "authenticates the resumed HEAD drain and final OpenAI "
                "response records; packet capture cannot prove plaintext "
                "authentication"
            ),
        },
        "result": "exact authenticated ok then PASS / RESULT",
    }
    report_path = build / PASS_REPORT_NAME
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("credentialed-live 16 KiB target proof: PASS")
    print(f"  report={report_path}")
    print("  entropy samples and USER.CFG contents/path/size/hash=NOT LOGGED")


if __name__ == "__main__":
    main()
