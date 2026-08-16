#!/usr/bin/env python3
"""Run the serialized exact-floor TLS 1.3 286 CPU timing gate.

Each primitive remains an independently target-executed correctness gate on
the exact 6 MHz / 512 KiB 286 profile.  The report maps those measurements into
the route's two real provider-deadline windows:

* acquisition uses the measured ML-KEM candidate operation, X25519, hardened
  pack transition proxy, full post-connect HELLO TX/RX CPU wrapper, current
  flight decode, and exact protected-flight controller through Finished + the
  credential-free HEAD; authenticated response/ticket export remains
  separately measured post-dialogue work;
* uncached full ML-KEM FO and partially measured X.509/hostname/UTC/CV/table
  work then run offline;
* before final no-0RTT PSK-DHE resumption, the public A^T matrix is generated;
  that connection charges cached full ML-KEM decapsulation (with zero matrix
  SHAKE128 permutations), X25519, the pack transition proxy, full HELLO TX/RX
  CPU wrapper, current flight decode, and the exact resumed protected-flight
  controller through Finished, credential-free HEAD, a complete authenticated
  NST plus allowed HTTP status, and sequence-preserving application
  publication.  Charging this post-HEAD dialogue is deliberately conservative
  for the initial-silence deadline.

Every measured component aligns its timer to a BIOS tick edge.  Summing those
separately rounded readings within each window is intentionally conservative
and avoids hiding a slow primitive behind another component's partial tick.

The ``complete`` and ``passed`` fields describe only this conservative
two-window CPU model.  The exact controller measurements use the current
ordinary-Certificate acquisition and no-0RTT PSK-DHE resumption fixtures.
Resident controller-load/connect CPU, physical I/O latency, the complete
offline authentication controller, and live-provider evidence remain outside
this command's measurement/provenance boundary; therefore current-product CPU
completeness and product acceptance stay false here.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPIKE = HERE.parent / "tls13-spike"
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
REPORT = BUILD / "tls13-286-serialized-gate.json"
FROZEN_INCLUDE = BUILD / "tls13-product-head-includes"
FROZEN_CORE_FILES = (
    "layout.inc",
    "data.inc",
    "chacha20.inc",
    "poly1305.inc",
    "sha256.inc",
    "p256.inc",
)
DEADLINE_SECONDS = 15.0
SOURCE_SUFFIXES = {".asm", ".inc", ".py"}


def prepare_canonical_report(full_run: bool) -> None:
    """Invalidate stale canonical evidence before a complete gate attempt."""
    if full_run:
        REPORT.unlink(missing_ok=True)


def publish_canonical_report(
    report: dict[str, object], full_run: bool
) -> None:
    """Atomically publish a completed full-run report; partial runs are inert."""
    if not full_run:
        return
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        os.replace(temporary, REPORT)
    finally:
        temporary.unlink(missing_ok=True)


def timing_input_paths() -> tuple[Path, ...]:
    """Return every source/generated input that can shape a timed payload."""
    paths: set[Path] = {ROOT / "Makefile"}
    for base in (
        ROOT / "targets/ibm_pc_5150/boot",
        ROOT / "tools/crypto-bench",
    ):
        paths.update(
            path
            for path in base.rglob("*")
            if path.is_file()
            and path.suffix in SOURCE_SUFFIXES
            and "__pycache__" not in path.parts
        )

    generated_root = BUILD.parent
    paths.update(
        path
        for path in generated_root.glob("tls13-286-*")
        if path.is_file()
    )
    generated_crypto = BUILD
    paths.update(
        path
        for path in generated_crypto.rglob("tls13-286-*")
        if path.is_file()
        and "-286-product" not in path.name
        and path != REPORT
    )
    for directory in generated_crypto.glob("tls13-286-*"):
        if directory.is_dir():
            paths.update(path for path in directory.rglob("*") if path.is_file())
    for name in ("x25519_unrolled_bench.asm", "width7-ecdsa-g.bin"):
        path = generated_crypto / name
        if path.is_file():
            paths.add(path)
    paths.update(path for path in FROZEN_INCLUDE.rglob("*") if path.is_file())
    return tuple(sorted(paths))


def timing_input_manifest() -> dict[str, object]:
    entries: list[dict[str, object]] = []
    aggregate = hashlib.sha256()
    for path in timing_input_paths():
        contents = path.read_bytes()
        relative = str(path.relative_to(ROOT))
        digest = hashlib.sha256(contents).hexdigest()
        entries.append(
            {"path": relative, "bytes": len(contents), "sha256": digest}
        )
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(bytes.fromhex(digest))
    return {
        "schema": "seed-tls13-286-timing-input-manifest-v1",
        "sha256": aggregate.hexdigest(),
        "file_count": len(entries),
        "files": entries,
    }


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = load_module(HERE / "run_286_gate.py", "seed_tls13_product_runner")
TICK_MS = runner.rb.TICK_MS


@dataclass(frozen=True)
class Component:
    name: str
    asm: Path
    critical_operations: tuple[str, ...]
    expected: dict[str, str]
    required: tuple[str, ...] = ()
    off_window_operations: tuple[str, ...] = ()


def build_generated_sources() -> None:
    for script in (
        "build_286_module_pack.py",
        "build_286_hello_controller.py",
        "build_286_flight_sym.py",
        "build_286_flight.py",
        "build_286_flight_timing_fixtures.py",
        "check_286_hello_timing_bench.py",
    ):
        subprocess.run(
            [sys.executable, str(HERE / script)],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )


def materialize_source_core() -> tuple[str, str, bool]:
    """Freeze and identify the current source snapshot for one gate run."""
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    core_dir = FROZEN_INCLUDE / "core"
    core_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    for name in FROZEN_CORE_FILES:
        path = ROOT / "targets/ibm_pc_5150/boot/core" / name
        contents = path.read_bytes()
        (core_dir / name).write_bytes(contents)
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(contents)
    dirty = bool(
        subprocess.run(
            [
                "git",
                "status",
                "--porcelain",
                "--",
                *[
                    f"targets/ibm_pc_5150/boot/core/{name}"
                    for name in FROZEN_CORE_FILES
                ],
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    return commit, digest.hexdigest(), dirty


def components() -> tuple[Component, ...]:
    return (
        Component(
            "mlkem768_product_modules",
            HERE / "mlkem_product_modules_bench.asm",
            ("MLKMODCD", "MLKMODCA"),
            {"CHECK": "0001"},
            off_window_operations=(
                "MLKMODKG",
                "MLKMODMX",
                "MLKMODDC",
                "MLKMODIR",
            ),
        ),
        Component(
            "x25519_product_module",
            HERE / "x25519_product_module_bench.asm",
            ("XMODSS",),
            {"CHECK": "0001"},
            off_window_operations=("XMODKG",),
        ),
        Component(
            "deadline_product_transitions",
            HERE / "deadline_transition_product_bench.asm",
            ("PACKMX", "FLIGHTDC"),
            {
                "PACKMX": "0001",
                "FLIGHTDC": "0001",
                "CHECK": "0001",
            },
        ),
        Component(
            "product_cached_pack_loader",
            HERE / "pack_loader_product_bench.asm",
            (),
            {"CHECK": "0001"},
        ),
        Component(
            "p256_width7_product_tablegen",
            HERE / "p256_tablegen_product_module_bench.asm",
            (),
            {"CHECK": "0001"},
            off_window_operations=("TABLEGEN",),
        ),
        Component(
            "product_server_hello_controllers",
            HERE / "hello_product_timing_bench.asm",
            ("HELLOACQ", "HELLORES"),
            {"HELLOACQ": "0001", "HELLORES": "0001", "CHECK": "0001"},
        ),
        Component(
            "product_protected_flight_controllers",
            HERE / "flight_product_timing_bench.asm",
            ("ACQHEAD", "RESFLIGHT"),
            {"CHECK": "0001"},
            off_window_operations=("ACQPOST", "ACQFLIGHT"),
        ),
        Component(
            "pinned_ecdsa_certificate_verify",
            HERE / "ecdsa_product_module_bench.asm",
            ("ECDSAPROD",),
            {"TABLEGEN": "0001", "ECDSAPROD": "0001", "CHECK": "0001"},
            off_window_operations=("TABLEGEN",),
        ),
    )


def run_component(component: Component, timeout: int) -> dict[str, object]:
    image, payload_bytes, payload_sectors = runner.assemble_image(
        component.asm, [FROZEN_INCLUDE], []
    )
    measured_image = image.read_bytes()
    measured_payload = measured_image[512 : 512 + payload_bytes]
    result = runner.run_vm(image, 6, timeout)
    failures = runner.base.check_result(
        result, component.expected, list(component.required)
    )
    operations = result["operations"]
    for operation in (
        component.critical_operations + component.off_window_operations
    ):
        if operation not in operations:
            failures.append(f"missing timed operation {operation}")
    if failures:
        lines = "\n".join(f"  {line}" for line in result["guest_lines"])
        raise RuntimeError(
            f"{component.name} failed: {'; '.join(failures)}"
            + (f"\n{lines}" if lines else "")
        )
    critical = {
        name: {
            "ticks": int(operations[name]["ticks"]),
            "seconds": int(operations[name]["ticks"]) * TICK_MS / 1000.0,
        }
        for name in component.critical_operations
    }
    off_window = {
        name: {
            "ticks": int(operations[name]["ticks"]),
            "seconds": int(operations[name]["ticks"]) * TICK_MS / 1000.0,
        }
        for name in component.off_window_operations
    }
    ticks = sum(int(item["ticks"]) for item in critical.values())
    return {
        "name": component.name,
        "asm": str(component.asm.relative_to(ROOT)),
        "critical_operations": critical,
        "off_window_operations": off_window,
        "ticks": ticks,
        "seconds": ticks * TICK_MS / 1000.0,
        "payload_bytes": payload_bytes,
        "payload_sectors": payload_sectors,
        "payload_sha256": hashlib.sha256(measured_payload).hexdigest(),
        "floppy_image_sha256": hashlib.sha256(measured_image).hexdigest(),
        "guest_lines": result["guest_lines"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="run only a named component (disables the complete-budget verdict)",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--research-only",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    full_run = not args.only
    prepare_canonical_report(full_run)

    source_commit, source_snapshot_sha256, source_snapshot_dirty = (
        materialize_source_core()
    )
    build_generated_sources()
    input_manifest = timing_input_manifest()
    selected = components()
    if args.only:
        wanted = set(args.only)
        selected = tuple(component for component in selected if component.name in wanted)
        missing = wanted - {component.name for component in selected}
        if missing:
            raise SystemExit(f"unknown component(s): {', '.join(sorted(missing))}")

    results: list[dict[str, object]] = []
    for component in selected:
        if not args.json:
            print(f"[RUN] {component.name}", flush=True)
        result = run_component(component, args.timeout)
        results.append(result)
        if not args.json:
            print(
                f"[PASS] {component.name}: {result['ticks']} ticks = "
                f"{result['seconds']:.4f} s",
                flush=True,
            )

    input_manifest_after = timing_input_manifest()
    if input_manifest_after != input_manifest:
        raise RuntimeError(
            "serialized timing inputs changed while measurements were running"
        )

    result_by_name = {
        str(result["name"]): result
        for result in results
    }

    def measurement(
        component_name: str,
        operation: str,
        bucket: str,
    ) -> dict[str, object] | None:
        component = result_by_name.get(component_name)
        if component is None:
            return None
        operations = component[bucket]
        if not isinstance(operations, dict) or operation not in operations:
            return None
        item = operations[operation]
        if not isinstance(item, dict):
            return None
        ticks = int(item["ticks"])
        return {
            "component": component_name,
            "operation": operation,
            "ticks": ticks,
            "seconds": ticks * TICK_MS / 1000.0,
        }

    candidate = measurement(
        "mlkem768_product_modules",
        "MLKMODCA",
        "critical_operations",
    )
    resumed_cached_fo = measurement(
        "mlkem768_product_modules",
        "MLKMODCD",
        "critical_operations",
    )
    offline_uncached_fo = measurement(
        "mlkem768_product_modules",
        "MLKMODDC",
        "off_window_operations",
    )
    matrix_precompute = measurement(
        "mlkem768_product_modules",
        "MLKMODMX",
        "off_window_operations",
    )
    x25519_shared = measurement(
        "x25519_product_module",
        "XMODSS",
        "critical_operations",
    )
    pack_transition = measurement(
        "deadline_product_transitions",
        "PACKMX",
        "critical_operations",
    )
    flight_decode = measurement(
        "deadline_product_transitions",
        "FLIGHTDC",
        "critical_operations",
    )
    acquisition_hello = measurement(
        "product_server_hello_controllers",
        "HELLOACQ",
        "critical_operations",
    )
    resumed_hello = measurement(
        "product_server_hello_controllers",
        "HELLORES",
        "critical_operations",
    )
    acquisition_controller = measurement(
        "product_protected_flight_controllers",
        "ACQHEAD",
        "critical_operations",
    )
    acquisition_post = measurement(
        "product_protected_flight_controllers",
        "ACQPOST",
        "off_window_operations",
    )
    acquisition_lifecycle = measurement(
        "product_protected_flight_controllers",
        "ACQFLIGHT",
        "off_window_operations",
    )
    resumed_controller = measurement(
        "product_protected_flight_controllers",
        "RESFLIGHT",
        "critical_operations",
    )
    certificate_verify = measurement(
        "pinned_ecdsa_certificate_verify",
        "ECDSAPROD",
        "critical_operations",
    )
    g_table = measurement(
        "p256_width7_product_tablegen",
        "TABLEGEN",
        "off_window_operations",
    )
    auth_tables = measurement(
        "pinned_ecdsa_certificate_verify",
        "TABLEGEN",
        "off_window_operations",
    )

    def window(
        operations: dict[str, dict[str, object] | None],
    ) -> dict[str, object]:
        complete = all(item is not None for item in operations.values())
        ticks = (
            sum(int(item["ticks"]) for item in operations.values() if item is not None)
            if complete
            else None
        )
        seconds = ticks * TICK_MS / 1000.0 if ticks is not None else None
        return {
            "operations": operations,
            "complete": complete,
            "ticks": ticks,
            "seconds": seconds,
            "budget_seconds": DEADLINE_SECONDS,
            "margin_seconds": (
                DEADLINE_SECONDS - seconds
                if seconds is not None
                else None
            ),
            "passed": (
                seconds <= DEADLINE_SECONDS
                if seconds is not None
                else False
            ),
        }

    acquisition_window = window(
        {
            "mlkem_candidate": candidate,
            "x25519_shared": x25519_shared,
            "hardened_m_x_pack_transition": pack_transition,
            "post_connect_clienthello_tx_serverhello_rx": acquisition_hello,
            "flight_component_decode_crc": flight_decode,
            "finished_and_credential_free_head": acquisition_controller,
        }
    )
    final_resumption_window = window(
        {
            "mlkem_cached_full_fo_decapsulation": resumed_cached_fo,
            "x25519_shared": x25519_shared,
            "hardened_m_x_pack_transition": pack_transition,
            "post_connect_clienthello_tx_serverhello_rx": resumed_hello,
            "flight_component_decode_crc": flight_decode,
            "resumed_finished_head_response_and_application_publication": (
                resumed_controller
            ),
        }
    )
    serialized_measurement_ticks = sum(
        int(result["ticks"])
        for result in results
    )
    serialized_measurement_seconds = (
        serialized_measurement_ticks * TICK_MS / 1000.0
    )
    all_components = full_run and len(results) == len(components())
    timing_passed = (
        all_components
        and bool(acquisition_window["passed"])
        and bool(final_resumption_window["passed"])
    )
    product_blockers = [
        (
            "the HELLOACQ/HELLORES measurements start after the resident TCP "
            "connect entry returns; controller-phase loading, connect-wrapper "
            "CPU, NIC wait/transmit/receive, and resident TCP parser CPU are "
            "not charged by the deterministic wrapper gate"
        ),
        (
            "the exact FLIGHTDC CPU measurement starts after the staged "
            "component is resident in low RAM; the product's BIOS floppy "
            "read and resident TCP/NIC wall time remain live-pcap evidence"
        ),
        (
            "offline authentication timing is partial: the exact serialized "
            "X.509/hostname/UTC controller, its module-load transitions, and "
            "both required ECDSA verifications are not yet measured as one "
            "current product path"
        ),
        (
            "this timing command does not ingest or bind the separate live "
            "exact-floor 6 MHz / 512 KiB pcap and screen evidence for "
            "acquisition, offline authentication, final no-0RTT PSK-DHE "
            "resumption, authenticated OpenAI application data, reuse, and "
            "bounded reconnect"
        ),
    ]
    product_complete = False
    report = {
        "schema": "seed-tls13-286-serialized-cpu-gate-v4",
        "gate_scope": (
            "two serialized exact-floor CPU deadline windows with current "
            "acquisition/resumption HELLO and protected-flight controllers"
        ),
        "claim_boundary": (
            "passed/complete cover only conservative sums of independently "
            "target-executed operations mapped into acquisition and final "
            "resumption windows. Current deterministic controller fixtures "
            "prove target CPU work and exact bytes/state. They do not measure "
            "BIOS read latency, live provider behavior, NIC transmit, or "
            "entropy; it also omits named resident HELLO/connect and offline "
            "authentication CPU, so it cannot establish complete product CPU "
            "timing, standards conformance, or product acceptance"
        ),
        "machine": "Intel 80286, 6 MHz, 512 KiB RAM",
        "source_commit": source_commit,
        "frozen_core_include_snapshot_sha256": source_snapshot_sha256,
        "frozen_core_include_snapshot_dirty": source_snapshot_dirty,
        "timing_input_manifest": input_manifest,
        "timing_model": (
            "sum of separately tick-edge-aligned target operations within "
            "each provider connection; acquisition charges through successful "
            "Finished + credential-free HEAD, while response/NST/close and "
            "offline work are measured separately; final resumption "
            "conservatively charges its authenticated HEAD response/NST even "
            "though successful HEAD transmission ends initial silence"
        ),
        "deadline_composition": {
            "PACKMX": (
                "conservative transition proxy: the hardened loader validates/"
                "decodes M, uses the X decode transition to wipe M, validates/"
                "decodes X, and uses a rejected decode to retire X; this is "
                "not the exact live wrapper call sequence"
            ),
            "PRODUCT_MODULE_OPERATION_BENCHES": (
                "standalone product-module benches execute the selected real "
                "descriptor operation plus their benchmark one-shot cleanup/"
                "stack scan. They do not repeat PACKMX decode/CRC/header work, "
                "but the composition is intentionally conservative rather "
                "than an instruction-exact live wrapper trace"
            ),
            "HELLOACQ_HELLORES": (
                "start after resident TCP connect returns, then execute the "
                "shipped six-fragment ClientHello builder/stager/transcript "
                "hash and hostile split record-header ServerHello receive/"
                "pending-suffix wrapper through begin/feed/finish. Stub "
                "callbacks remove network latency and byte-compare every "
                "ClientHello fragment"
            ),
            "FLIGHTDC": (
                "executes current flight LZ4/header/CRC decode after staging; "
                "the preceding BIOS read is deliberately excluded"
            ),
            "ACQHEAD_RESFLIGHT": (
                "start at the already-decoded FLIGHT entry, so they do not "
                "repeat FLIGHTDC; they include symmetric relocation, key "
                "schedule, authenticated records, and the named publication; "
                "RESFLIGHT additionally includes exact credential-free HEAD "
                "send, complete authenticated NST plus allowed HTTP status, "
                "and advanced-sequence publication without requiring the "
                "response header-tail terminator"
            ),
        },
        "tick_ms": TICK_MS,
        "components": results,
        "deadline_windows": {
            "acquisition_candidate_head": acquisition_window,
            "final_no_0rtt_psk_dhe_resumption": final_resumption_window,
        },
        "offline_between_connections": {
            "deadline_applies": False,
            "timing_complete": False,
            "mlkem_uncached_full_fo_decapsulation": offline_uncached_fo,
            "p256_g_table_generation": g_table,
            "p256_auth_table_generation_proxy": auth_tables,
            "one_pinned_certificate_verify_proxy": certificate_verify,
            "unmeasured_current_path": [
                "serialized X.509/hostname/UTC parsing and policy",
                "exact table/module load transitions",
                "the second required ECDSA verification",
            ],
            "policy": (
                "full FO and certificate/hostname/UTC/CV/table work complete "
                "before the tentative ticket may be promoted; executable "
                "offline gates prove semantics, while this report measures "
                "only the listed timing proxies"
            ),
        },
        "post_dialogue_acquisition_lifecycle": {
            "deadline_applies": False,
            "response_nst_close_retire": acquisition_post,
            "full_flight_lifecycle": acquisition_lifecycle,
            "policy": (
                "ACQHEAD ends at the successful 58-byte Finished plus "
                "72-byte credential-free HEAD send; ACQPOST partitions the "
                "authenticated response, tentative NST export, close, and "
                "symmetric retirement from the full ACQFLIGHT measurement"
            ),
        },
        "offline_before_final_resumption_tcp": {
            "deadline_applies": False,
            "mlkem_public_matrix_precompute": matrix_precompute,
            "cache_bytes": 4608,
            "cache_polynomials": 9,
            "cache_order": "row-major rho || row || col",
            "cached_decapsulation_matrix_shake128_permutations": 0,
        },
        "serialized_unique_measurement_sum_ticks": serialized_measurement_ticks,
        "serialized_unique_measurement_sum_seconds": (
            serialized_measurement_seconds
        ),
        "final_resumption_ticks": final_resumption_window["ticks"],
        "final_resumption_seconds": final_resumption_window["seconds"],
        "final_resumption_budget_seconds": DEADLINE_SECONDS,
        "final_resumption_margin_seconds": (
            final_resumption_window["margin_seconds"]
        ),
        "timing_components_complete": all_components,
        "timing_passed": timing_passed,
        "current_product_cpu_timing_complete": False,
        "current_product_timing_complete": False,
        "product_acceptance_complete": product_complete,
        "complete": all_components,
        "passed": timing_passed,
        "product_blockers": product_blockers,
        "separate_executable_integration_gates": {
            "hello_timing_wrapper": {
                "gate": (
                    "tools/crypto-bench/tls13-product/"
                    "check_286_hello_timing_bench.py"
                ),
                "executed_by_this_timing_command": True,
                "scope": (
                    "Unicorn executes both exact post-connect HELLO TX/RX "
                    "wrappers, validates six ClientHello fragments, hostile "
                    "split ServerHello records, transcript/share publication, "
                    "and the quarantined protected suffix before VM timing"
                ),
            },
            "live_certificate_verify_wiring": {
                "gate": (
                    "tools/crypto-bench/tls13-product/check_286_flight.py"
                ),
                "cryptographic_module_gate": (
                    "tools/crypto-bench/tls13-product/check_286_auth.py"
                ),
                "scope": (
                    "acquisition CV digest, strict-DER signature, and distinct "
                    "G/leaf table spans are passed in one ECDSA descriptor; "
                    "the separate target auth gate generates the real tables "
                    "and executes the real ECDSA module"
                ),
            },
            "client_finished_resident_callback": {
                "gate": (
                    "tools/crypto-bench/tls13-product/check_286_flight.py"
                ),
                "binding_generator": (
                    "tools/crypto-bench/tls13-product/"
                    "build_286_runtime_abi.py"
                ),
                "scope": (
                    "the exact 58-byte Client Finished is passed through the "
                    "generated resident tcp_send_payload callback, followed "
                    "by the exact 72-byte credential-free HEAD on both "
                    "connection modes; either callback failure aborts before "
                    "application publication"
                ),
            },
            "flight_and_auth_gates_executed_by_this_timing_command": False,
        },
        "certificate_policy": {
            "acquisition_connection": (
                "target uses the measured ML-KEM candidate to authenticate the "
                "protected flight and server Finished provisionally, captures "
                "ordinary Certificate/CV, sends Finished plus the immutable "
                "credential-free HEAD, retains one tentative ticket, and closes"
            ),
            "final_resumption_in_window": (
                "target offers psk_dhe_ke with one final-position "
                "pre_shared_key, no early_data, fresh ML-KEM/X25519 material, "
                "performs full ML-KEM decapsulation before Finished, then "
                "sends and authenticates the credential-free HEAD dialogue "
                "before publishing application keys and consumed sequences"
            ),
            "offline_authentication": (
                "full ML-KEM FO, local chain/WE1, hostname, UTC validity, "
                "CertificateVerify, and table work remain inside the security "
                "boundary but outside either provider connection deadline; "
                "only success promotes the tentative ticket"
            ),
            "timing_fixture_scope": (
                "the shipped HELLO send wrapper builds/stages/hashes and "
                "byte-compares each exact current ClientHello, while the "
                "receive wrapper handles the hostile split TLS header, exact "
                "ServerHello, and pending protected suffix; the shipped "
                "FLIGHT coordinator and "
                "relocated symmetric image execute current ordinary-"
                "Certificate acquisition and no-0RTT resumption fixtures"
            ),
            "read_only_media": (
                "acquisition state is same-boot RAM; a restart repeats "
                "acquisition and never requires a writable floppy"
            ),
        },
        "timed_operation_matrix": {
            "acquisition_post_connect_clienthello_tx_serverhello_rx": True,
            "resumption_post_connect_clienthello_tx_serverhello_rx": True,
            "hello_client_fragment_count": 6,
            "hello_split_record_header_and_pending_suffix": True,
            "hello_resident_connect_and_tcp_parser_cpu": False,
            "acquisition_mlkem_candidate_in_window_ticks": (
                int(candidate["ticks"]) if candidate is not None else None
            ),
            "acquisition_full_fo_in_window": False,
            "offline_uncached_full_fo_before_ticket_promotion": True,
            "final_resumption_cached_full_fo_in_window": True,
            "public_matrix_precompute_before_acquisition_tcp": False,
            "public_matrix_precompute_before_final_resumption_tcp": True,
            "cached_full_fo_matrix_shake128_permutations": 0,
            "x25519_rfc7748": True,
            "hardened_m_x_pack_decode_crc_header_and_retire": True,
            "flight_component_lz4_header_crc_decode": True,
            "flight_component_bios_read_latency": False,
            "protected_flight_aead_and_transcript": True,
            "live_pre_cv_transcript_and_signed_input_hash": True,
            "acquisition_certificate_and_cv_capture": True,
            "offline_x509_hostname_utc_and_cv_semantics": True,
            "offline_x509_hostname_utc_and_cv_complete_timing": False,
            "both_offline_ecdsa_verifications_timed": False,
            "credential_free_finished_and_head_exact_timing": True,
            "authenticated_response_nst_close_exact_post_timing": True,
            "full_acquisition_lifecycle_exact_timing": True,
            "final_psk_dhe_resumed_controller_exact_timing": True,
            "final_resumption_credential_free_head_exact_timing": True,
            "final_resumption_authenticated_response_before_publication": True,
            "final_resumption_sequence_preserving_publication": True,
            "strict_flight_shape_and_signature_scheme_parse": True,
            "p256_certificate_verify_equation": True,
            "server_finished_live_extract_and_constant_time_compare": True,
            "client_finished_hmac_and_aead_seal": True,
            "early_data": False,
            "real_tcp_nic_transmit": False,
            "live_provider_deadline_pcap": False,
            "fixed_origin_descriptor_driven_module_calls": True,
            "target_width7_table_generation": True,
        },
        "secure_floor_open_gates": [
            (
                "physical RTC/PIT entropy characterization remains separate; "
                "86Box receives zero entropy credit"
            )
        ],
    }
    if all_components:
        publish_canonical_report(report, full_run)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        verdict = (
            "TWO-WINDOW CURRENT-CONTROLLER CPU TIMING PASS; LIVE PRODUCT ACCEPTANCE OPEN"
            if timing_passed
            else ("PARTIAL" if not all_components else "TIMING FAIL")
        )
        if all_components:
            acquisition_ticks = int(acquisition_window["ticks"])
            acquisition_seconds = float(acquisition_window["seconds"])
            acquisition_margin = float(acquisition_window["margin_seconds"])
            resumption_ticks = int(final_resumption_window["ticks"])
            resumption_seconds = float(final_resumption_window["seconds"])
            resumption_margin = float(
                final_resumption_window["margin_seconds"]
            )
            print(
                f"{verdict}: acquisition {acquisition_ticks} ticks = "
                f"{acquisition_seconds:.4f} s, margin "
                f"{acquisition_margin:.4f} s; final resumption "
                f"{resumption_ticks} ticks = {resumption_seconds:.4f} s, "
                f"margin {resumption_margin:.4f} s"
            )
        else:
            print(f"{verdict}: partial run; no two-window budget verdict")
        if all_components:
            for blocker in product_blockers:
                print(f"  LIVE ACCEPTANCE OPEN: {blocker}")
    if all_components and not timing_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
