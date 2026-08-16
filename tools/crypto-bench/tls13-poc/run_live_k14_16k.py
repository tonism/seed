#!/usr/bin/env python3
"""Run the credential-free logical-K14 TLS 1.3 canary on a 16 KiB 5150.

This is the live counterpart to ``build_live_k15.py`` (whose filename is
historical).  It requires an explicit ``--run`` flag before it will launch
86Box or tcpdump.  ``--dry-run`` performs only local artifact, manifest,
profile, and offline-controller checks.

The live path uses the proven ROM BASIC mechanics from ``run_8088_16k.py``:
LaunchServices 86Box startup, PID-targeted BASIC injection, fixed-FIFO COM1,
and byte-for-byte VM config/NVR restoration.  tcpdump starts after the BASIC
program is installed but before ``RUN`` is typed.  After the first exact
``RESULT`` line after the RAM-only HEAD/ticket canary, the harness leaves the
VM and capture alive for a short,
explicit observation grace so an already-completed emulated NIC transmit can
cross the host bridge.  This grace is outside the measured wire deadline.
Afterward, ``live_k15_pcap.py`` provides the authoritative wire verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEFAULT_BUILD = ROOT / "build/crypto-bench/tls13-live-k15"
DEFAULT_PROFILE = "vm-net-ne2k8"
PROFILE_BASE_RAM_KIB = 32
SPIKE_RUNNER = HERE.parent / "tls13-spike/run_8088_16k.py"
HARNESS_PATH = ROOT / "tools/run-basic-bootstrap-86box.py"
OFFLINE_CHECK = HERE / "live_k15_check.py"
OFFLINE_SECURE_CHECK = HERE / "live_k15_secure_fo_check.py"
PCAP_ANALYZER = HERE / "live_k15_pcap.py"

RAM_KIB = 16
START_MARKER = "K15 net ready"
SECURE_START_MARKER = "K15 local ready"
RESULT_MARKER = "RESULT"
PASS_MARKER = "PASS"
FAIL_MARKER = "FAIL"
DEADLINE_MARKER = "DEADLINE PASS"
HEAD_TX_MARKER = "HEAD TX"
HEAD_COMPLETE_MARKER = "HEAD OK"
TICKET_MARKER = "TICKET"
CANARY_MARKER = "CANARY COMMIT"
AUTH_BEGIN_MARKER = "AUTH BEGIN"
IDENTITY_MARKER = "IDENTITY PASS"
FO_BEGIN_MARKER = "FO BEGIN"
KEM_VALID_MARKER = "KEM VALID"
ENTROPY_START_MARKER = "ENTROPY START 256"
ENTROPY_PASS_MARKER = "ENTROPY PASS 256"
SUCCESS_PREFIX_MARKERS = (
    START_MARKER,
    "preflight cache",
    "offline keygen",
    "live connect",
    HEAD_TX_MARKER,
)
SECURE_SUCCESS_PREFIX_MARKERS = (
    SECURE_START_MARKER,
    ENTROPY_START_MARKER,
    ENTROPY_PASS_MARKER,
    "preflight cache",
    "offline keygen",
    "live connect",
    HEAD_TX_MARKER,
)
SUCCESS_POST_HEAD_ORDERS = (
    (HEAD_COMPLETE_MARKER, TICKET_MARKER),
    (TICKET_MARKER, HEAD_COMPLETE_MARKER),
)
SUCCESS_SUFFIX_MARKERS = (
    CANARY_MARKER,
    PASS_MARKER,
    RESULT_MARKER,
)
DEFAULT_PCAP_FILTER = "tcp port 443 or arp or udp port 53"
EXPECTED_MACHINE_SETTINGS = {
    "machine": "ibmpc",
    "cpu_family": "8088",
    "cpu_speed": "4772728",
    "cpu_multi": "1",
    "cpu_use_dynarec": "0",
}

# Keep this exact mirror synchronized with build_live_k15.py.  Rechecking the
# actual core and floppy here prevents a stale or substituted live artifact
# from bypassing the builder's credential/request literal gate.
FORBIDDEN_LITERALS = (
    b"authorization",
    b"bearer ",
    b"content-type:",
    b"openai-beta",
    b"x-api-key",
    b"api-key",
    b"post ",
    b"get /",
    b"/v1/",
    b'"input"',
    b'"model"',
    b"sk-",
)
CANARY_HEAD_REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"\r\n"
)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load Python module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def root_path(path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (ROOT / path).resolve()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines()]


def completed_exact_lines(text: str) -> list[str]:
    """Return only newline-terminated COM1 lines from a live capture."""

    lines = text.splitlines()
    if text and not text.endswith(("\n", "\r")):
        lines = lines[:-1]
    return [line.strip() for line in lines]


def result_seen(text: str) -> bool:
    return RESULT_MARKER in exact_lines(text)


def markers_in_order(text: str, markers: tuple[str, ...]) -> bool:
    lines = exact_lines(text)
    cursor = 0
    for marker in markers:
        try:
            cursor = lines.index(marker, cursor) + 1
        except ValueError:
            return False
    return True


def success_markers_in_order(
    text: str,
    *,
    identity: bool = False,
    secure: bool = False,
) -> bool:
    if secure:
        suffix = (
            FO_BEGIN_MARKER,
            KEM_VALID_MARKER,
            AUTH_BEGIN_MARKER,
            IDENTITY_MARKER,
            PASS_MARKER,
            RESULT_MARKER,
        )
    elif identity:
        suffix = (
            AUTH_BEGIN_MARKER,
            IDENTITY_MARKER,
            PASS_MARKER,
            RESULT_MARKER,
        )
    else:
        suffix = SUCCESS_SUFFIX_MARKERS
    prefix = SECURE_SUCCESS_PREFIX_MARKERS if secure else SUCCESS_PREFIX_MARKERS
    return any(
        markers_in_order(
            text, prefix + post_head + suffix,
        )
        for post_head in SUCCESS_POST_HEAD_ORDERS
    )


def extract_live_serial(stdout_text: str) -> str:
    start = re.search(
        (
            rf"(?m)^(?:{re.escape(START_MARKER)}|"
            rf"{re.escape(SECURE_START_MARKER)})\r?(?:\n|$)"
        ),
        stdout_text,
    )
    if start is None:
        return ""
    # Preserve whether the final COM1 line is actually terminated.  The live
    # FIFO often exposes a few bytes of a UART burst before the rest arrives;
    # manufacturing a newline here made that partial prefix look complete and
    # prevented marker-driven keyboard input from seeing the finished line.
    return (
        stdout_text[start.start() :]
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )


def terminal_status(serial_text: str) -> str | None:
    lines = exact_lines(serial_text)
    try:
        result_index = lines.index(RESULT_MARKER)
    except ValueError:
        return None
    for line in reversed(lines[:result_index]):
        if line in {PASS_MARKER, FAIL_MARKER}:
            return line
    return None


def scan_no_request_or_credentials(name: str, value: bytes) -> None:
    lowered = value.lower()
    exact = CANARY_HEAD_REQUEST.lower()
    if lowered.count(exact) != 1:
        raise AssertionError(
            f"{name} does not contain exactly one compiled canary HEAD"
        )
    at = lowered.index(exact)
    lowered = lowered[:at] + bytes(len(exact)) + lowered[at + len(exact) :]
    found = [token for token in FORBIDDEN_LITERALS if token in lowered]
    if found:
        rendered = ", ".join(repr(token) for token in found)
        raise AssertionError(
            f"{name} contains forbidden request/credential literals: {rendered}"
        )


def validate_artifacts(build: Path) -> dict[str, Any]:
    paths = {
        "manifest": build / "manifest.json",
        "core": build / "SEED.SYS",
        "floppy": build / "floppy-160k-live-k15.img",
        "basic": build / "LIVEK15.BAS",
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise SystemExit(
            "missing live K14 artifact(s):\n  "
            + "\n  ".join(missing)
            + "\nRun the offline build/check commands in live_k15_README.md first."
        )

    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    variant = manifest.get("crypto_memory_variant", {})
    if (
        variant.get("logical_variant") != "K14"
        or variant.get("is_15_sector_k_memory_proof") is not False
    ):
        raise AssertionError("manifest is not the logical-K14 live artifact")
    secure_checkpoint = manifest.get("secure_fo_checkpoint")
    if secure_checkpoint is not None:
        if (
            not isinstance(secure_checkpoint, dict)
            or secure_checkpoint.get("enabled") is not True
            or secure_checkpoint.get("marker_order")
            != [
                FO_BEGIN_MARKER,
                KEM_VALID_MARKER,
                AUTH_BEGIN_MARKER,
                IDENTITY_MARKER,
                PASS_MARKER,
                RESULT_MARKER,
            ]
            or secure_checkpoint.get("success_requires_exact_marker_order")
            is not True
            or secure_checkpoint.get("identity_only_is_success") is not False
        ):
            raise AssertionError("secure FO success contract drifted")
        entropy = manifest.get("entropy_ceremony")
        if (
            not isinstance(entropy, dict)
            or entropy.get("enabled") is not True
            or entropy.get("public_fixture_phase_present") is not False
            or entropy.get("disk_writes") != 0
            or entropy.get("read_only_floppy_compatible") is not True
            or not isinstance(entropy.get("source_model"), dict)
            or entropy["source_model"].get("samples") != 256
            or entropy["source_model"].get("credited_entropy_bits") != 0
            or not isinstance(entropy.get("operational_mode"), dict)
            or entropy["operational_mode"].get(
                "manual_operator_entry_required"
            )
            is not False
            or entropy["operational_mode"].get(
                "unattended_collection"
            )
            is not True
            or entropy["operational_mode"].get(
                "collection_before_first_network_transmission"
            )
            is not True
            or entropy["operational_mode"].get(
                "automated_security_credit_bits"
            )
            != 0
            or entropy["operational_mode"].get("physical_security_credit_pending")
            is not True
        ):
            raise AssertionError("secure entropy ceremony contract drifted")

    literal_gate = manifest.get("literal_gate", {})
    expected_forbidden = [
        token.decode("ascii", errors="strict") for token in FORBIDDEN_LITERALS
    ]
    if literal_gate.get("forbidden") != expected_forbidden:
        raise AssertionError("runner/builder forbidden-literal contracts drifted")
    if (
        literal_gate.get("forbidden_hits") != 0
        or literal_gate.get("credential_files_packaged") is not False
        or literal_gate.get("credential_free_canary_request_compiled") is not True
        or literal_gate.get("exact_allowed_head_occurrences") != 1
        or literal_gate.get("allowed_head_sha256")
        != hashlib.sha256(CANARY_HEAD_REQUEST).hexdigest()
        or literal_gate.get("files_packaged")
        != ["SEED.SYS", "SEED/DRIVERS/NE.DRV"]
    ):
        raise AssertionError("manifest does not prove a credential-free image")

    output = manifest.get("output", {})
    for name, bytes_key, hash_key in (
        ("core", "core_bytes", "core_sha256"),
        ("floppy", "image_bytes", "image_sha256"),
    ):
        path = paths[name]
        expected_bytes = output.get(bytes_key)
        expected_hash = output.get(hash_key)
        if path.stat().st_size != expected_bytes:
            raise AssertionError(
                f"{name} size drifted: {path.stat().st_size} != {expected_bytes}"
            )
        actual_hash = sha256(path)
        if actual_hash != expected_hash:
            raise AssertionError(
                f"{name} hash drifted: {actual_hash} != {expected_hash}"
            )
        scan_no_request_or_credentials(name, path.read_bytes())

    core = paths["core"].read_bytes()
    if core.lower().count(b"api.openai.com") != 3:
        raise AssertionError(
            "live core must contain endpoint-DNS, ClientHello-SNI, and HEAD hosts"
        )

    basic_text = paths["basic"].read_text(encoding="ascii").replace("\r\n", "\n")
    required_basic = (
        "10 CLEAR ,14847:DEF SEG=0:P=14848\n",
        "60 DEF USR0=14848:A=USR0(0)\n",
    )
    for line in required_basic:
        if basic_text.count(line) != 1:
            raise AssertionError(f"BASIC sidecar contract drifted: {line.strip()}")
    if re.search(r"(?m)^\s*RUN\s*$", basic_text):
        raise AssertionError("BASIC artifact unexpectedly embeds RUN")

    return {
        "paths": paths,
        "manifest": manifest,
        "provenance": {
            "core": display_path(paths["core"]),
            "core_bytes": paths["core"].stat().st_size,
            "core_sha256": sha256(paths["core"]),
            "floppy": display_path(paths["floppy"]),
            "floppy_bytes": paths["floppy"].stat().st_size,
            "floppy_sha256": sha256(paths["floppy"]),
        },
        "credential_free": True,
    }


def run_offline_check(
    build: Path,
    *,
    identity: bool = False,
    secure: bool = False,
) -> None:
    command = [
        sys.executable,
        str(OFFLINE_SECURE_CHECK if secure else OFFLINE_CHECK),
        "--build-dir",
        str(build),
    ]
    if identity and not secure:
        command.append("--identity")
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if completed.returncode:
        raise SystemExit(
            "offline live-controller gate failed:\n"
            f"{completed.stdout}{completed.stderr}"
        )
    print("preflight: offline live-controller gate PASS")


def machine_settings(config: Path) -> dict[str, str]:
    settings: dict[str, str] = {}
    in_machine = False
    for raw_line in config.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_machine = line == "[Machine]"
            continue
        if not in_machine or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in settings:
            raise RuntimeError(
                f"{config}: duplicate [Machine] setting {key!r}"
            )
        settings[key] = value
    return settings


def require_exact_vm_config(
    config: Path,
    *,
    ram_kib: int,
    phase: str,
) -> dict[str, str]:
    expected = {
        **EXPECTED_MACHINE_SETTINGS,
        "mem_size": str(ram_kib),
    }
    actual = machine_settings(config)
    mismatches = [
        f"{key}={actual.get(key)!r} (expected {value!r})"
        for key, value in expected.items()
        if actual.get(key) != value
    ]
    if mismatches:
        raise RuntimeError(
            f"{phase} exact {DEFAULT_PROFILE} profile check failed: "
            + "; ".join(mismatches)
        )
    return {key: actual[key] for key in expected}


def validate_profile(harness: ModuleType, profile: str) -> tuple[Path, Path]:
    if profile != DEFAULT_PROFILE:
        raise SystemExit(
            f"this live runner requires the exact {DEFAULT_PROFILE} profile"
        )
    vm_path = ROOT / "targets/ibm_pc_5150/86box" / profile
    if not vm_path.is_dir():
        raise SystemExit(f"missing 86Box profile: {vm_path}")
    config = vm_path / "86box.cfg"
    if not config.is_file():
        raise SystemExit(f"missing 86Box config: {config}")
    harness.validate_vm_ram_override(vm_path, RAM_KIB)
    try:
        require_exact_vm_config(
            config,
            ram_kib=PROFILE_BASE_RAM_KIB,
            phase="pre-rewrite",
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    return vm_path, config


def stop_process(process: Any | None) -> int | None:
    if process is None:
        return None
    returncode = process.poll()
    if returncode is not None:
        return returncode
    process.kill()
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        returncode = process.poll()
        if returncode is None:
            pid = getattr(process, "pid", "unknown")
            raise RuntimeError(
                f"86Box process {pid} did not stop after SIGKILL"
            ) from exc
        return returncode


def cleanup_live_state(
    *,
    pcap_capture: Any | None,
    pcap_started: bool,
    process: Any | None,
    capture: Any,
    config: Path,
    original_config: bytes,
    restore_nvr: tuple[Path, bytes] | None,
    floppy: Path,
    original_floppy_mode: int,
) -> dict[str, Any]:
    errors: list[str] = []
    missing = object()

    def attempt(label: str, operation: Any) -> Any:
        try:
            return operation()
        except Exception as exc:  # Continue so every restoration is attempted.
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            return missing

    if pcap_started and pcap_capture is not None:
        attempt("stop pcap", pcap_capture.stop)
    stopped_returncode = attempt(
        "stop launched 86Box process",
        lambda: stop_process(process),
    )
    attempt("finish serial capture", capture.finish)
    attempt(
        "restore 86Box config",
        lambda: config.write_bytes(original_config),
    )
    if restore_nvr is not None:
        attempt(
            "restore 86Box NVR",
            lambda: restore_nvr[0].write_bytes(restore_nvr[1]),
        )

    floppy_hash_after = attempt("hash floppy after run", lambda: sha256(floppy))
    attempt(
        "restore floppy mode",
        lambda: floppy.chmod(original_floppy_mode),
    )

    config_after = attempt("verify 86Box config", config.read_bytes)
    if config_after is not missing and config_after != original_config:
        errors.append("verify 86Box config: byte-for-byte mismatch")
    if restore_nvr is not None:
        nvr_after = attempt("verify 86Box NVR", restore_nvr[0].read_bytes)
        if nvr_after is not missing and nvr_after != restore_nvr[1]:
            errors.append("verify 86Box NVR: byte-for-byte mismatch")

    floppy_mode_after = attempt(
        "verify floppy mode",
        lambda: stat.S_IMODE(floppy.stat().st_mode),
    )
    if (
        floppy_mode_after is not missing
        and floppy_mode_after != original_floppy_mode
    ):
        errors.append(
            "verify floppy mode: "
            f"0o{floppy_mode_after:o} != 0o{original_floppy_mode:o}"
        )

    if errors:
        raise RuntimeError(
            "live-run cleanup failed:\n  - " + "\n  - ".join(errors)
        )
    return {
        "process_returncode": (
            None if stopped_returncode is missing else stopped_returncode
        ),
        "floppy_hash_after": floppy_hash_after,
        "floppy_mode_after": floppy_mode_after,
    }


def floppy_media_integrity_passed(media: dict[str, Any]) -> bool:
    sha256_before = media.get("sha256_before")
    sha256_after = media.get("sha256_after")
    return bool(
        media.get("read_only_requested")
        and media.get("mode_during_run") == "0o444"
        and media.get("host_write_open_denied")
        and isinstance(sha256_before, str)
        and len(sha256_before) == 64
        and sha256_before == sha256_after
        and media.get("unchanged")
        and media.get("mode_restored")
    )


def run_live(
    harness: ModuleType,
    spike: ModuleType,
    *,
    profile: str,
    floppy: Path,
    basic: Path,
    stdout_path: Path,
    serial_path: Path,
    pcap_path: Path,
    timeout: float,
    start_timeout: float,
    window_timeout: float,
    startup_delay: float,
    type_delay: float,
    line_delay: float,
    post_result_delay: float,
    pcap_filter: str,
    pcap_iface: str,
    identity: bool = False,
    secure: bool = False,
) -> dict[str, Any]:
    vm_path, config = validate_profile(harness, profile)
    original_config = config.read_bytes()
    restore_nvr: tuple[Path, bytes] | None = None
    process: Any | None = None
    pcap_capture = None
    pcap_started = False
    stopped_returncode: int | None = None
    pipe_base = stdout_path.parent / "live-com-fifo"
    capture = spike.PipeSerialCapture(stdout_path, pipe_base)
    launch_started = time.monotonic()
    run_started: float | None = None
    saw_result = False
    saw_start = False
    start_timeout_hit = False
    start_elapsed: float | None = None
    reported_lines = 0
    timeout_hit = False
    early_returncode: int | None = None
    marker_elapsed: dict[str, float] = {}
    original_floppy_mode = stat.S_IMODE(floppy.stat().st_mode)
    floppy_hash_before = sha256(floppy)
    floppy_hash_after = ""
    floppy_mode_after = original_floppy_mode
    read_only_open_denied = False
    effective_vm_settings: dict[str, str] | None = None

    stdout_path.unlink(missing_ok=True)
    serial_path.unlink(missing_ok=True)
    pcap_path.unlink(missing_ok=True)

    try:
        floppy.chmod(0o444)
        try:
            descriptor = os.open(floppy, os.O_WRONLY)
        except PermissionError:
            read_only_open_denied = True
        else:
            os.close(descriptor)
            raise RuntimeError("read-only floppy still permits a write open")

        harness.stop_matching_86box_pids(vm_path)
        harness.rewrite_vm_config(
            config,
            RAM_KIB,
            floppy,
            True,
            com_passthrough=False,
            muted=True,
        )
        spike.configure_pipe_serial(config, pipe_base)
        effective_vm_settings = require_exact_vm_config(
            config,
            ram_kib=RAM_KIB,
            phase="post-rewrite",
        )
        restore_nvr = harness.prepare_vm_nvr(vm_path, RAM_KIB)

        capture.start()
        process = harness.launch_86box(
            vm_path,
            capture_stdout=False,
            background=True,
        )
        if not harness.wait_for_86box_window_or_identity_dialog(
            profile,
            process.pid,
            window_timeout,
        ):
            raise RuntimeError(
                f"86Box window did not appear within {window_timeout:g} seconds"
            )
        time.sleep(startup_delay)

        basic_text = (
            basic.read_text(encoding="ascii")
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

        pcap_capture = harness.PcapCapture(
            pcap_path,
            pcap_filter,
            pcap_iface,
            None,
            0,
        )
        pcap_capture.start()
        pcap_started = True

        # The capture is live before this is typed.  BASIC installation itself
        # performs no guest networking.
        run_started = time.monotonic()
        start_deadline = run_started + start_timeout
        harness.type_basic_pid_keycodes(
            process.pid,
            "RUN\n",
            type_delay,
            line_delay,
        )

        deadline = run_started + timeout
        while time.monotonic() < deadline:
            serial_now = extract_live_serial(capture.text())
            lines_now = completed_exact_lines(serial_now)
            if len(lines_now) > reported_lines:
                observed_at = round(time.monotonic() - run_started, 3)
                for line in lines_now[reported_lines:]:
                    print(f"guest: {line}", flush=True)
                    if line and line not in marker_elapsed:
                        marker_elapsed[line] = observed_at
                reported_lines = len(lines_now)
            expected_start = SECURE_START_MARKER if secure else START_MARKER
            if not saw_start and expected_start in lines_now:
                saw_start = True
                start_elapsed = round(time.monotonic() - run_started, 3)
            if result_seen(serial_now):
                saw_result = True
                break
            if not saw_start and time.monotonic() >= start_deadline:
                start_timeout_hit = True
                break
            early_returncode = process.poll()
            if early_returncode is not None:
                break
            time.sleep(0.1)
        else:
            timeout_hit = True
        if saw_result:
            time.sleep(post_result_delay)
    finally:
        cleanup = cleanup_live_state(
            pcap_capture=pcap_capture,
            pcap_started=pcap_started,
            process=process,
            capture=capture,
            config=config,
            original_config=original_config,
            restore_nvr=restore_nvr,
            floppy=floppy,
            original_floppy_mode=original_floppy_mode,
        )
        stopped_returncode = cleanup["process_returncode"]
        floppy_hash_after = cleanup["floppy_hash_after"]
        floppy_mode_after = cleanup["floppy_mode_after"]

    if effective_vm_settings is None:
        raise RuntimeError("effective VM profile was not verified before launch")

    stdout_text = (
        stdout_path.read_text(encoding="utf-8", errors="replace")
        if stdout_path.is_file()
        else ""
    )
    serial_text = extract_live_serial(stdout_text)
    serial_path.parent.mkdir(parents=True, exist_ok=True)
    serial_path.write_text(serial_text, encoding="utf-8")
    status = terminal_status(serial_text)
    historical_deadline_marker_seen = (
        DEADLINE_MARKER in exact_lines(serial_text)
    )
    if secure:
        completion_markers = (
            HEAD_TX_MARKER,
            HEAD_COMPLETE_MARKER,
            TICKET_MARKER,
            FO_BEGIN_MARKER,
            KEM_VALID_MARKER,
            AUTH_BEGIN_MARKER,
            IDENTITY_MARKER,
        )
    elif identity:
        completion_markers = (
            HEAD_TX_MARKER,
            HEAD_COMPLETE_MARKER,
            TICKET_MARKER,
            AUTH_BEGIN_MARKER,
            IDENTITY_MARKER,
        )
    else:
        completion_markers = (
            HEAD_TX_MARKER,
            HEAD_COMPLETE_MARKER,
            TICKET_MARKER,
            CANARY_MARKER,
        )
    canary_markers_seen = all(
        marker in exact_lines(serial_text)
        for marker in completion_markers
    )
    success_markers_ordered = success_markers_in_order(
        serial_text, identity=identity, secure=secure
    )
    fo_duration = (
        round(
            marker_elapsed[KEM_VALID_MARKER]
            - marker_elapsed[FO_BEGIN_MARKER],
            3,
        )
        if (
            FO_BEGIN_MARKER in marker_elapsed
            and KEM_VALID_MARKER in marker_elapsed
        )
        else None
    )
    identity_duration = (
        round(
            marker_elapsed[IDENTITY_MARKER]
            - marker_elapsed[AUTH_BEGIN_MARKER],
            3,
        )
        if (
            AUTH_BEGIN_MARKER in marker_elapsed
            and IDENTITY_MARKER in marker_elapsed
        )
        else None
    )
    floppy_media = {
        "read_only_requested": True,
        "mode_during_run": "0o444",
        "host_write_open_denied": read_only_open_denied,
        "sha256_before": floppy_hash_before,
        "sha256_after": floppy_hash_after,
        "unchanged": floppy_hash_before == floppy_hash_after,
        "mode_restored": floppy_mode_after == original_floppy_mode,
    }
    floppy_media["integrity_gate_passed"] = floppy_media_integrity_passed(
        floppy_media
    )
    return {
        "result_seen": saw_result,
        "start_seen": saw_start,
        "start_timeout_hit": start_timeout_hit,
        "start_elapsed_after_run_seconds": start_elapsed,
        "start_timeout_seconds": start_timeout,
        "timeout_hit": timeout_hit,
        "terminal_status": status,
        "deadline_marker_seen": historical_deadline_marker_seen,
        "runtime_deadline_marker_required": False,
        "canary_markers_seen": canary_markers_seen,
        "identity_checkpoint": identity,
        "secure_fo_checkpoint": secure,
        "entropy_ceremony": (
            {
                "mode": "automatic-floppy",
                "start_seen": ENTROPY_START_MARKER in exact_lines(serial_text),
                "pass_seen": ENTROPY_PASS_MARKER in exact_lines(serial_text),
                "samples": 256,
                "unattended": True,
                "collection_before_first_network_transmission": True,
                "emulator_security_credit_bits": 0,
                "physical_security_credit": "pending hardware characterization",
            }
            if secure
            else None
        ),
        "required_success_marker_order": (
            list(
                SECURE_SUCCESS_PREFIX_MARKERS
                if secure
                else SUCCESS_PREFIX_MARKERS
            )
            + ["HEAD OK/TICKET in either order"]
            + (
                [
                    FO_BEGIN_MARKER,
                    KEM_VALID_MARKER,
                    AUTH_BEGIN_MARKER,
                    IDENTITY_MARKER,
                    PASS_MARKER,
                    RESULT_MARKER,
                ]
                if secure
                else (
                    [
                        AUTH_BEGIN_MARKER,
                        IDENTITY_MARKER,
                        PASS_MARKER,
                        RESULT_MARKER,
                    ]
                    if identity
                    else list(SUCCESS_SUFFIX_MARKERS)
                )
            )
        ),
        "marker_observed_elapsed_seconds": marker_elapsed,
        "fo_observed_duration_seconds": fo_duration,
        "identity_observed_duration_seconds": identity_duration,
        "success_markers_ordered": success_markers_ordered,
        "guest_passed": (
            status == PASS_MARKER
            and canary_markers_seen
            and success_markers_ordered
        ),
        "process_returncode_before_stop": early_returncode,
        "process_returncode_after_stop": stopped_returncode,
        "pcap_started_before_run": pcap_started and run_started is not None,
        "elapsed_after_run_seconds": (
            None
            if run_started is None
            else round(time.monotonic() - run_started, 3)
        ),
        "elapsed_total_seconds": round(time.monotonic() - launch_started, 3),
        "timeout_seconds": timeout,
        "stdout": display_path(stdout_path),
        "stdout_bytes": len(stdout_text.encode("utf-8")),
        "serial": display_path(serial_path),
        "serial_bytes": len(serial_text.encode("utf-8")),
        "serial_text": serial_text,
        "pcap": display_path(pcap_path),
        "pcap_bytes": pcap_path.stat().st_size if pcap_path.is_file() else 0,
        "vm": {
            "profile": profile,
            "model": "IBM PC 5150",
            "machine": effective_vm_settings["machine"],
            "cpu": effective_vm_settings["cpu_family"],
            "cpu_hz": int(effective_vm_settings["cpu_speed"]),
            "cpu_multiplier": int(effective_vm_settings["cpu_multi"]),
            "dynarec_enabled": (
                effective_vm_settings["cpu_use_dynarec"] != "0"
            ),
            "ram_kib": int(effective_vm_settings["mem_size"]),
            "exact_profile_verified": True,
            "entry": "ROM BASIC sidecar",
            "emulator_launch": "LaunchServices --vmpath",
            "serial1_device": "pipe",
            "serial_transport": "fixed Unix FIFO",
        },
        "floppy_media": floppy_media,
    }


def run_analyzer(
    pcap: Path,
    wire_json: Path,
    server_ip: str | None,
) -> tuple[int, dict[str, Any] | None]:
    if not pcap.is_file() or pcap.stat().st_size == 0:
        print("wire analyzer: pcap is missing or empty", file=sys.stderr)
        return 1, None
    wire_json.parent.mkdir(parents=True, exist_ok=True)
    wire_json.unlink(missing_ok=True)
    command = [
        sys.executable,
        str(PCAP_ANALYZER),
        str(pcap),
        "--json-out",
        str(wire_json),
    ]
    if server_ip is not None:
        command.extend(["--server-ip", server_ip])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    result = (
        json.loads(wire_json.read_text(encoding="utf-8"))
        if wire_json.is_file()
        else None
    )
    return completed.returncode, result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--run",
        action="store_true",
        help="explicitly authorize the live 86Box, network, and pcap run",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="perform only local static/artifact/controller checks",
    )
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--timeout", type=float, default=420.0)
    parser.add_argument("--start-timeout", type=float, default=120.0)
    parser.add_argument("--window-timeout", type=float, default=15.0)
    parser.add_argument("--startup-delay", type=float, default=10.0)
    parser.add_argument("--type-delay", type=float, default=0.01)
    parser.add_argument("--line-delay", type=float, default=0.2)
    parser.add_argument("--post-result-delay", type=float, default=2.0)
    parser.add_argument("--pcap-filter", default=DEFAULT_PCAP_FILTER)
    parser.add_argument("--pcap-iface", default="en0")
    parser.add_argument("--server-ip")
    parser.add_argument("--stdout-out", type=Path)
    parser.add_argument("--serial-out", type=Path)
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--wire-json", type=Path)
    parser.add_argument("--json-out", type=Path)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not 30.0 <= args.timeout <= 1800.0:
        parser.error("--timeout must be between 30 and 1800 seconds")
    if not 5.0 <= args.start_timeout <= args.timeout:
        parser.error("--start-timeout must be between 5 seconds and --timeout")
    if not 5.0 <= args.window_timeout <= 60.0:
        parser.error("--window-timeout must be between 5 and 60 seconds")
    if not 0.0 <= args.startup_delay <= 60.0:
        parser.error("--startup-delay must be between 0 and 60 seconds")
    if not 0.001 <= args.type_delay <= 0.1:
        parser.error("--type-delay must be between 0.001 and 0.1 seconds")
    if not 0.01 <= args.line_delay <= 2.0:
        parser.error("--line-delay must be between 0.01 and 2 seconds")
    if not 0.5 <= args.post_result_delay <= 10.0:
        parser.error("--post-result-delay must be between 0.5 and 10 seconds")
    if not args.pcap_filter.strip():
        parser.error("--pcap-filter must not be empty")

    build = root_path(args.build_dir)
    stdout_path = root_path(
        args.stdout_out or (build / "live-stdout.txt")
    )
    serial_path = root_path(
        args.serial_out or (build / "live-com.txt")
    )
    pcap_path = root_path(args.pcap or (build / "live.pcap"))
    wire_json = root_path(
        args.wire_json or (build / "live-wire.json")
    )
    run_json = root_path(args.json_out or (build / "live-run.json"))

    artifacts = validate_artifacts(build)
    identity = bool(
        artifacts["manifest"].get("identity_checkpoint", {}).get("enabled")
    )
    secure = bool(
        artifacts["manifest"].get("secure_fo_checkpoint", {}).get("enabled")
    )
    if secure and not identity:
        raise AssertionError("secure FO artifact must include identity checkpoint")
    run_offline_check(build, identity=identity, secure=secure)
    spike = load_module(SPIKE_RUNNER, "seed_tls13_spike_16k_runner")
    harness = spike.load_basic_harness()
    vm_path, config = validate_profile(harness, args.profile)

    plan = {
        "mode": "dry-run" if args.dry_run else "live",
        "credential_free_artifacts": True,
        "identity_checkpoint": identity,
        "secure_fo_checkpoint": secure,
        "entropy_ceremony": (
            {
                "mode": "automatic-floppy",
                "samples": 256,
                "unattended": True,
                "collection_before_first_network_transmission": True,
                "emulator_security_credit_bits": 0,
                "physical_security_credit": "pending hardware characterization",
            }
            if secure
            else None
        ),
        "required_success_marker_order": (
            [
                ENTROPY_START_MARKER,
                ENTROPY_PASS_MARKER,
                "preflight cache",
                "offline keygen",
                "live connect",
                FO_BEGIN_MARKER,
                KEM_VALID_MARKER,
                AUTH_BEGIN_MARKER,
                IDENTITY_MARKER,
                PASS_MARKER,
                RESULT_MARKER,
            ]
            if secure
            else None
        ),
        "logical_variant": "K14",
        "historical_artifact_name": "live_k15",
        "profile": args.profile,
        "vm_path": display_path(vm_path),
        "config": display_path(config),
        "vm_harness": display_path(HARNESS_PATH),
        "machine": EXPECTED_MACHINE_SETTINGS["machine"],
        "cpu": EXPECTED_MACHINE_SETTINGS["cpu_family"],
        "cpu_hz": int(EXPECTED_MACHINE_SETTINGS["cpu_speed"]),
        "cpu_multiplier": int(EXPECTED_MACHINE_SETTINGS["cpu_multi"]),
        "dynarec_enabled": False,
        "ram_kib": RAM_KIB,
        "floppy": display_path(artifacts["paths"]["floppy"]),
        "floppy_media_policy": (
            "host-enforced mode 0o444 during every live run; write-open denial "
            "plus unchanged before/after hash and restored mode gate success"
        ),
        "basic": display_path(artifacts["paths"]["basic"]),
        "pcap": display_path(pcap_path),
        "pcap_filter": args.pcap_filter,
        "pcap_iface": args.pcap_iface,
        "timeout_seconds": args.timeout,
        "start_timeout_seconds": args.start_timeout,
        "timings": {
            "startup_delay_seconds": args.startup_delay,
            "type_delay_seconds": args.type_delay,
            "line_delay_seconds": args.line_delay,
            "post_result_observation_seconds": args.post_result_delay,
        },
        "execution_order": [
            "LaunchServices 86Box launch",
            "fixed Unix FIFO / serial1_device=pipe",
            "wait for window or identity dialog",
            "inject BASIC",
            "start pcap",
            "type RUN",
            "wait for exact RESULT or timeout",
            "retain pcap and VM for the post-RESULT observation grace",
            "stop pcap and VM",
            "restore config and NVR",
            "run live_k15_pcap analyzer",
        ],
        "launch_performed": False,
        "network_performed": False,
    }
    if args.dry_run:
        print("live K14 16 KiB runner dry-run: PASS")
        print(json.dumps(plan, indent=2))
        return 0

    result = run_live(
        harness,
        spike,
        profile=args.profile,
        floppy=artifacts["paths"]["floppy"],
        basic=artifacts["paths"]["basic"],
        stdout_path=stdout_path,
        serial_path=serial_path,
        pcap_path=pcap_path,
        timeout=args.timeout,
        start_timeout=args.start_timeout,
        window_timeout=args.window_timeout,
        startup_delay=args.startup_delay,
        type_delay=args.type_delay,
        line_delay=args.line_delay,
        post_result_delay=args.post_result_delay,
        pcap_filter=args.pcap_filter,
        pcap_iface=args.pcap_iface,
        identity=identity,
        secure=secure,
    )
    analyzer_returncode, wire_result = run_analyzer(
        pcap_path,
        wire_json,
        args.server_ip,
    )
    plan["launch_performed"] = True
    plan["network_performed"] = True
    record = {
        "schema": "seed-live-k14-16k-run-v2",
        "plan": plan,
        "runner": display_path(Path(__file__)),
        "runner_sha256": sha256(Path(__file__)),
        "manifest": display_path(artifacts["paths"]["manifest"]),
        "manifest_sha256": sha256(artifacts["paths"]["manifest"]),
        "artifact": artifacts["provenance"],
        "guest": result,
        "wire_analyzer": {
            "path": display_path(PCAP_ANALYZER),
            "returncode": analyzer_returncode,
            "json": display_path(wire_json),
            "result": wire_result,
        },
    }
    run_json.parent.mkdir(parents=True, exist_ok=True)
    run_json.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    print("--- captured COM1 ---")
    print(result["serial_text"] or "(none)")
    print("--- run result ---")
    printable = dict(result)
    printable.pop("serial_text")
    print(json.dumps(printable, indent=2))
    print(f"run record: {display_path(run_json)}")

    if not result["floppy_media"]["integrity_gate_passed"]:
        raise SystemExit(
            "live K14 floppy-media integrity gate failed: require write-open "
            "denial, unchanged SHA-256, and restored original mode"
        )
    if not result["result_seen"]:
        if result["start_timeout_hit"]:
            raise SystemExit(
                "live K14 guest did not emit its first exact marker within "
                f"{args.start_timeout:g} seconds"
            )
        if result["timeout_hit"]:
            raise SystemExit(
                f"live K14 guest did not emit RESULT within {args.timeout:g} seconds"
            )
        raise SystemExit("86Box exited before the live K14 guest emitted RESULT")
    if not result["guest_passed"]:
        expected = (
            "DEADLINE/HEAD/TICKET/FO/KEM/AUTH/IDENTITY/PASS"
            if secure
            else (
                "DEADLINE/HEAD/TICKET/AUTH/IDENTITY/PASS"
                if identity
                else "DEADLINE/HEAD/TICKET/CANARY/PASS"
            )
        )
        raise SystemExit(
            "live K14 guest reached RESULT without the complete "
            f"{expected} milestone contract"
        )
    if analyzer_returncode != 0:
        raise SystemExit("live K14 wire deadline analyzer failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
