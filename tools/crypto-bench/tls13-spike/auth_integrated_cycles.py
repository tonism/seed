#!/usr/bin/env python3
"""Executed-trace 8088 cycle model for the integrated authentication gate.

This is the timing fallback when the 86Box ROM-BASIC runner cannot start its
known-good control VM.  It is not relabeled as physical timing: the result is
the repository's calibrated static-ish ``cycles8088.py`` model over the exact
instruction/data trace that already passes the independent target checker.

Besides aggregate time, this script records the boundaries needed for the
25-second liveness architecture: scalar preparation, each complete Straus
digit iteration, final affine normalization/check, individual point/table
generation, and the 706-byte resumable checkpoint.
"""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
import tempfile
from pathlib import Path

from unicorn import UC_HOOK_CODE, Uc
from unicorn.x86_const import (
    UC_X86_REG_EFLAGS,
    UC_X86_REG_SP,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BENCH_TOOLS = ROOT / "tools/crypto-bench"
sys.path.insert(0, str(BENCH_TOOLS))

from cycles8088 import Cycle8088  # noqa: E402


def load_checker():
    path = HERE / "auth_integrated_check.py"
    spec = importlib.util.spec_from_file_location(
        "seed_auth_integrated_checker_for_cycles", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load integrated authentication checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECK = load_checker()
CPU_HZ = 4_772_728


class TraceCycle8088(Cycle8088):
    """Normalize mnemonics emitted by this host's Capstone build.

    Unicorn calls the code hook once per REP iteration (plus the terminal
    zero-CX visit), so the string operation must remain a normal per-visit
    instruction here instead of using Cycle8088's one-hook REP shortcut.
    """

    def _decode(self, machine: Uc, address: int):
        info = super()._decode(machine, address)
        (
            mnemonic,
            size,
            eu,
            ea,
            memory_bytes,
            is_branch,
            branch_cost,
            is_rep,
            rep_mnemonic,
        ) = info
        replacements = {
            "cdq": ("cwd", 5),
            "rep movsw": ("movsw", 18),
            "rep stosw": ("stosw", 11),
        }
        if mnemonic not in replacements:
            return info
        normalized, normalized_eu = replacements[mnemonic]
        self.unknown.discard(mnemonic)
        corrected = (
            normalized,
            size,
            normalized_eu,
            ea,
            memory_bytes,
            is_branch,
            branch_cost,
            False,
            None,
        )
        self.cache[address] = corrected
        return corrected


def seconds(cycles: int) -> float:
    return round(cycles / CPU_HZ, 6)


def invoke_cycles(
    machine: Uc,
    entry: int,
    *,
    event_addresses: dict[int, list[str]] | None = None,
    instruction_limit: int = 500_000_000,
) -> dict[str, object]:
    machine.reg_write(UC_X86_REG_SP, CHECK.STACK_TOP - 2)
    machine.mem_write(
        CHECK.STACK_TOP - 2,
        struct.pack("<H", CHECK.RETURN_SENTINEL),
    )
    model = TraceCycle8088()
    instructions = 0
    events: list[tuple[str, int]] = []

    def trace(
        emulator: Uc, address: int, size: int, _data: object
    ) -> None:
        nonlocal instructions
        instructions += 1
        model.hook(emulator, address, size, None)
        if event_addresses and address in event_addresses:
            for name in event_addresses[address]:
                events.append((name, model.cycles))

    hook = machine.hook_add(UC_HOOK_CODE, trace)
    try:
        machine.emu_start(
            entry,
            CHECK.RETURN_SENTINEL,
            count=instruction_limit,
        )
    finally:
        machine.hook_del(hook)
    model.finish()
    if machine.reg_read(UC_X86_REG_SP) != CHECK.STACK_TOP:
        raise AssertionError("cycle trace did not return before instruction cap")
    return {
        "cycles": model.cycles,
        "seconds": seconds(model.cycles),
        "instructions": instructions,
        "carry": bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
        "unknown_mnemonics": sorted(model.unknown),
        "events": events,
    }


def segment(events: list[tuple[str, int]], start: str, end: str) -> int:
    starts = [cycles for name, cycles in events if name == start]
    ends = [cycles for name, cycles in events if name == end]
    if len(starts) != 1 or len(ends) != 1:
        raise AssertionError(f"missing unique trace boundary {start}->{end}")
    if ends[0] < starts[0]:
        raise AssertionError(f"backward trace boundary {start}->{end}")
    return ends[0] - starts[0]


def ecdsa_breakdown(trace: dict[str, object]) -> dict[str, object]:
    events = trace["events"]
    assert isinstance(events, list)
    scalar = segment(
        events,
        "scalar_prep_start",
        "scalar_prep_end",
    )
    parse_digest = segment(
        events,
        "scalar_prep_start",
        "n_inverse_start",
    )
    inverse = segment(events, "n_inverse_start", "n_inverse_end")
    multiply_z = segment(events, "n_mul_z_start", "n_mul_z_end")
    multiply_r = segment(events, "n_mul_r_start", "n_mul_r_end")
    recode = segment(events, "n_mul_r_end", "scalar_prep_end")
    straus = segment(events, "straus_start", "straus_end")
    affine = segment(events, "affine_start", "affine_end")
    checkpoints = [
        cycles for name, cycles in events if name == "straus_checkpoint"
    ]
    end = [cycles for name, cycles in events if name == "straus_end"]
    if not checkpoints or len(end) != 1:
        raise AssertionError("missing Straus checkpoint trace")
    iterations = [
        right - left
        for left, right in zip(checkpoints, checkpoints[1:] + end)
    ]
    if any(value <= 0 for value in iterations):
        raise AssertionError("non-positive Straus iteration trace")
    return {
        "total_cycles": trace["cycles"],
        "total_seconds": trace["seconds"],
        "instructions": trace["instructions"],
        "scalar_prep": {
            "cycles": scalar,
            "seconds": seconds(scalar),
            "signature_parse_and_digest_load": {
                "cycles": parse_digest,
                "seconds": seconds(parse_digest),
            },
            "mod_n_inverse": {
                "cycles": inverse,
                "seconds": seconds(inverse),
            },
            "mod_n_multiply_z": {
                "cycles": multiply_z,
                "seconds": seconds(multiply_z),
            },
            "mod_n_multiply_r": {
                "cycles": multiply_r,
                "seconds": seconds(multiply_r),
            },
            "two_scalar_recodes": {
                "cycles": recode,
                "seconds": seconds(recode),
            },
        },
        "straus": {
            "cycles": straus,
            "seconds": seconds(straus),
            "digit_iterations": len(iterations),
            "max_iteration_cycles": max(iterations),
            "max_iteration_seconds": seconds(max(iterations)),
        },
        "affine_and_x_check": {
            "cycles": affine,
            "seconds": seconds(affine),
        },
        "unknown_mnemonics": trace["unknown_mnemonics"],
    }


def main() -> None:
    fixture = CHECK.ORACLE.make_fixture()
    with tempfile.TemporaryDirectory(
        prefix="seed-auth-integrated-cycles-"
    ) as temp:
        image, listing = CHECK.assemble(Path(temp))

    labels = (
        "auth_prepare",
        "auth_verify_certificate",
        "auth_build_leaf_table",
        "auth_verify_certificate_verify",
        "auth_validate_point",
        "p256_w_build_table",
        "p256_affine_x_ptr",
        "p256_affine_y_ptr",
        "auth_generator_x",
        "auth_generator_y",
        "auth_anchor_x",
        "auth_anchor_y",
        "auth_leaf_x",
        "auth_leaf_y",
        "auth_ecdsa_scalar_prep_start",
        "auth_ecdsa_scalar_prep_end",
        "auth_ecdsa_n_inverse_start",
        "auth_ecdsa_n_inverse_end",
        "auth_ecdsa_n_mul_z_start",
        "auth_ecdsa_n_mul_z_end",
        "auth_ecdsa_n_mul_r_start",
        "auth_ecdsa_n_mul_r_end",
        "auth_ecdsa_straus_start",
        "auth_ecdsa_straus_checkpoint",
        "auth_ecdsa_straus_end",
        "auth_ecdsa_affine_start",
        "auth_ecdsa_affine_end",
    )
    addresses = {
        label: CHECK.label_address(listing, label)
        for label in labels
    }
    boundary_names = {
        "auth_ecdsa_scalar_prep_start": "scalar_prep_start",
        "auth_ecdsa_scalar_prep_end": "scalar_prep_end",
        "auth_ecdsa_n_inverse_start": "n_inverse_start",
        "auth_ecdsa_n_inverse_end": "n_inverse_end",
        "auth_ecdsa_n_mul_z_start": "n_mul_z_start",
        "auth_ecdsa_n_mul_z_end": "n_mul_z_end",
        "auth_ecdsa_n_mul_r_start": "n_mul_r_start",
        "auth_ecdsa_n_mul_r_end": "n_mul_r_end",
        "auth_ecdsa_straus_start": "straus_start",
        "auth_ecdsa_straus_checkpoint": "straus_checkpoint",
        "auth_ecdsa_straus_end": "straus_end",
        "auth_ecdsa_affine_start": "affine_start",
        "auth_ecdsa_affine_end": "affine_end",
    }
    event_addresses: dict[int, list[str]] = {}
    for label, name in boundary_names.items():
        event_addresses.setdefault(addresses[label], []).append(name)

    # Measure point validation and each cold table independently so each
    # monolithic precompute has its own <25 s bound.
    point_results: dict[str, object] = {}
    table_results: dict[str, object] = {}
    for name in ("generator", "anchor", "leaf"):
        x_address = addresses[f"auth_{name}_x"]
        y_address = addresses[f"auth_{name}_y"]
        point_machine = CHECK.new_machine(image)
        point_machine.reg_write(CHECK.UC_X86_REG_SI, x_address)
        point_machine.reg_write(CHECK.UC_X86_REG_DI, y_address)
        point_trace = invoke_cycles(
            point_machine,
            addresses["auth_validate_point"],
        )
        if point_trace["carry"]:
            raise AssertionError(f"{name} point validation failed")
        point_results[name] = {
            key: point_trace[key]
            for key in ("cycles", "seconds", "instructions")
        }

        table_machine = CHECK.new_machine(image)
        table_machine.mem_write(
            addresses["p256_affine_x_ptr"],
            struct.pack("<H", x_address),
        )
        table_machine.mem_write(
            addresses["p256_affine_y_ptr"],
            struct.pack("<H", y_address),
        )
        table_trace = invoke_cycles(
            table_machine,
            addresses["p256_w_build_table"],
        )
        table_results[name] = {
            key: table_trace[key]
            for key in ("cycles", "seconds", "instructions")
        }

    machine = CHECK.new_machine(image)
    prepare = invoke_cycles(machine, addresses["auth_prepare"])
    if prepare["carry"]:
        raise AssertionError("authentication preparation failed")
    certificate_trace = invoke_cycles(
        machine,
        addresses["auth_verify_certificate"],
        event_addresses=event_addresses,
    )
    if certificate_trace["carry"]:
        raise AssertionError("certificate ECDSA trace failed")
    leaf_build = invoke_cycles(
        machine,
        addresses["auth_build_leaf_table"],
    )
    cv_trace = invoke_cycles(
        machine,
        addresses["auth_verify_certificate_verify"],
        event_addresses=event_addresses,
    )
    if cv_trace["carry"]:
        raise AssertionError("CertificateVerify trace failed")

    certificate = ecdsa_breakdown(certificate_trace)
    certificate_verify = ecdsa_breakdown(cv_trace)
    nonyieldable = {
        "point_validation": max(
            value["cycles"] for value in point_results.values()
        ),
        "one_width4_table_generation": max(
            value["cycles"] for value in table_results.values()
        ),
        "mod_n_inverse": max(
            certificate["scalar_prep"]["mod_n_inverse"]["cycles"],
            certificate_verify["scalar_prep"]["mod_n_inverse"]["cycles"],
        ),
        "one_mod_n_multiply": max(
            certificate["scalar_prep"]["mod_n_multiply_z"]["cycles"],
            certificate["scalar_prep"]["mod_n_multiply_r"]["cycles"],
            certificate_verify["scalar_prep"]["mod_n_multiply_z"]["cycles"],
            certificate_verify["scalar_prep"]["mod_n_multiply_r"]["cycles"],
        ),
        "signature_parse_and_digest_load": max(
            certificate["scalar_prep"][
                "signature_parse_and_digest_load"
            ]["cycles"],
            certificate_verify["scalar_prep"][
                "signature_parse_and_digest_load"
            ]["cycles"],
        ),
        "two_scalar_recodes": max(
            certificate["scalar_prep"]["two_scalar_recodes"]["cycles"],
            certificate_verify["scalar_prep"]["two_scalar_recodes"]["cycles"],
        ),
        "one_straus_digit_iteration": max(
            certificate["straus"]["max_iteration_cycles"],
            certificate_verify["straus"]["max_iteration_cycles"],
        ),
        "affine_normalize_and_x_check": max(
            certificate["affine_and_x_check"]["cycles"],
            certificate_verify["affine_and_x_check"]["cycles"],
        ),
    }
    longest_name = max(nonyieldable, key=nonyieldable.get)
    longest_cycles = nonyieldable[longest_name]
    post_cycles = (
        certificate_trace["cycles"]
        + leaf_build["cycles"]
        + cv_trace["cycles"]
    )
    total_cycles = prepare["cycles"] + post_cycles

    result = {
        "authority": {
            "kind": "executed target trace through calibrated cycles8088.py",
            "physical_86box_timing": False,
            "reason": (
                "literal-16K runner launched both this image and a "
                "known-good HKDF control at 0 Hz with no COM1 bytes"
            ),
            "cpu_hz": CPU_HZ,
            "model_source": str(
                (BENCH_TOOLS / "cycles8088.py").relative_to(ROOT)
            ),
        },
        "source_sha256": CHECK.sha256_file(CHECK.SOURCE),
        "image_bytes": len(image),
        "prepare_g_we1_and_points": {
            key: prepare[key]
            for key in ("cycles", "seconds", "instructions")
        },
        "individual_point_validation": point_results,
        "individual_width4_table_generation": table_results,
        "leaf_under_we1": certificate,
        "leaf_table_between_signatures": {
            key: leaf_build[key]
            for key in ("cycles", "seconds", "instructions")
        },
        "tls_certificate_verify": certificate_verify,
        "post_finished_two_signature_cycles": post_cycles,
        "post_finished_two_signature_seconds": seconds(post_cycles),
        "cold_total_cycles": total_cycles,
        "cold_total_seconds": seconds(total_cycles),
        "cadence": {
            "head_interval_seconds": 25,
            "checkpoint_boundary": (
                "between complete Straus digit iterations"
            ),
            "resumable_bytes": 706,
            "nonyieldable_segments": {
                name: {
                    "cycles": cycles,
                    "seconds": seconds(cycles),
                }
                for name, cycles in nonyieldable.items()
            },
            "longest_segment": longest_name,
            "longest_segment_cycles": longest_cycles,
            "longest_segment_seconds": seconds(longest_cycles),
            "model_says_each_segment_below_25s": (
                seconds(longest_cycles) < 25
            ),
        },
        "fixture": {
            "certificate_signature_bytes": len(
                fixture.certificate_signature
            ),
            "certificate_verify_signature_bytes": len(
                fixture.certificate_verify_signature
            ),
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
