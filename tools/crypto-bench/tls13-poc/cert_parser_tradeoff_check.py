#!/usr/bin/env python3
"""Reproduce the uncompressed-certificate wire/timing and Brotli size ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import cert_parser_check as parser_gate


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FLIGHT_RESULTS = HERE.parent / "tls13-spike/flight_8088_results.json"
MLKEM_RESULTS = HERE.parent / "tls13-spike/mlkem768_integrated_results.json"
PARSER_RESULTS = HERE / "cert_parser_results.json"
EXPECTED_BODY_SHA256 = "20f283d58de0351f0b652c14fb929e3b068ce416d1801be0226389d89372e982"
EXPECTED_Q6_SHA256 = "0496000b2e07308b9a8dc82d3bc079a338c2c3d5ffd0c93c69adc7a058d50813"


def brotli_window_bits(stream: bytes) -> int:
    """Decode RFC 7932 WBITS from the LSB-first stream prefix."""

    bit_cursor = 0

    def take(count: int) -> int:
        nonlocal bit_cursor
        value = 0
        for index in range(count):
            byte = stream[bit_cursor // 8]
            value |= ((byte >> (bit_cursor % 8)) & 1) << index
            bit_cursor += 1
        return value

    if take(1) == 0:
        return 16
    value = take(3)
    if value:
        return 17 + value
    value = take(3)
    if value == 1:
        raise ValueError("large-window escape is not RFC 7932")
    if value:
        return 8 + value
    return 17


def compress(
    binary: str,
    body: bytes,
    quality: int,
    window: int | None = None,
    input_path: Path | None = None,
) -> bytes:
    command = [binary, "-q", str(quality), "-c"]
    if window is not None:
        command[1:1] = ["-w", str(window)]
    if input_path is not None:
        command.append(str(input_path))
        return subprocess.run(command, check=True, capture_output=True).stdout
    return subprocess.run(command, input=body, check=True, capture_output=True).stdout


def current_certificate_body() -> bytes:
    leaf = parser_gate.pem_to_der(parser_gate.LIVE_LEAF.read_bytes())
    chain_pems = parser_gate.split_pem_chain(parser_gate.TRACKED_CHAIN.read_bytes())
    chain = [parser_gate.pem_to_der(item) for item in chain_pems[1:]]
    entries = b"".join(
        parser_gate.u24(len(cert)) + cert + b"\x00\x00"
        for cert in (leaf, *chain)
    )
    body = b"\x00" + parser_gate.u24(len(entries)) + entries
    if len(body) != 2491:
        raise AssertionError("current Certificate body geometry changed")
    return body


def run() -> dict[str, object]:
    binary = shutil.which("brotli")
    if binary is None:
        raise RuntimeError("brotli CLI is required")
    version = subprocess.run(
        [binary, "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    body = current_certificate_body()
    body_sha256 = hashlib.sha256(body).hexdigest()
    if body_sha256 != EXPECTED_BODY_SHA256:
        raise AssertionError("instrumented Certificate body changed")

    expected_quality_sizes = {0: 2003, 1: 1922, 4: 1834, 6: 1787, 9: 1750, 11: 1824}
    with tempfile.TemporaryDirectory(prefix="seed-cert-brotli-") as temp_name:
        input_path = Path(temp_name) / "certificate-body.bin"
        input_path.write_bytes(body)
        quality_streams = {
            quality: compress(binary, body, quality, input_path=input_path)
            for quality in expected_quality_sizes
        }
        window_streams = {
            window: compress(
                binary, body, 6, window, input_path=input_path
            )
            for window in (10, 11, 12)
        }
    quality_sizes = {
        quality: len(stream) for quality, stream in quality_streams.items()
    }
    if quality_sizes != expected_quality_sizes:
        raise AssertionError(
            f"Brotli 1.2.0 size ledger changed: {quality_sizes!r}"
        )
    q6_sha256 = hashlib.sha256(quality_streams[6]).hexdigest()
    if q6_sha256 != EXPECTED_Q6_SHA256:
        raise AssertionError("instrumented q6 stream changed")
    for stream in quality_streams.values():
        decoded = subprocess.run(
            [binary, "-d", "-c"],
            input=stream,
            check=True,
            capture_output=True,
        ).stdout
        if decoded != body:
            raise AssertionError("Brotli round trip mismatch")

    forced_windows = {
        str(window): {
            "compressed_bytes": len(stream),
            "encoded_window_bits": brotli_window_bits(stream),
            "declared_max_backward_distance": (1 << brotli_window_bits(stream)) - 16,
            "sha256": hashlib.sha256(stream).hexdigest(),
        }
        for window, stream in window_streams.items()
    }
    if [len(window_streams[item]) for item in (10, 11, 12)] != [1801, 1787, 1787]:
        raise AssertionError("forced-window Brotli size ledger changed")

    flight = json.loads(FLIGHT_RESULTS.read_text())
    compressed = flight["profiles"]["brotli_compact_ecdsa"]
    uncompressed = flight["profiles"]["compact_ecdsa"]
    operations_delta = {
        key: uncompressed["operations"][key] - compressed["operations"][key]
        for key in compressed["operations"]
    }
    component_delta = {
        key: {
            "ticks": (
                uncompressed["timings"][key]["ticks"]
                - compressed["timings"][key]["ticks"]
            ),
            "seconds": round(
                uncompressed["timings"][key]["seconds"]
                - compressed["timings"][key]["seconds"],
                4,
            ),
        }
        for key in ("CHAXOR", "POLY", "SHAFLT", "FLIGHT")
    }
    if operations_delta != {
        "chacha_blocks_including_otk": 10,
        "poly1305_blocks": 43,
        "sha256_blocks": 11,
    }:
        raise AssertionError("flight operation delta changed")
    if component_delta["FLIGHT"]["ticks"] != 44:
        raise AssertionError("flight timing delta changed")

    mlkem = json.loads(MLKEM_RESULTS.read_text())
    candidate = next(
        item
        for item in mlkem["literal_86box_runs"]
        if item["name"] == "provisional candidate repeated"
    )
    candidate_seconds = candidate["seconds_per_operation"]
    compressed_fixed = compressed["timings"]["FLIGHT"]["seconds"]
    critical_hkdf = flight["critical_hkdf_seconds"]
    uncompressed_extra = component_delta["FLIGHT"]["seconds"]
    compressed_with_candidate = compressed_fixed + critical_hkdf + candidate_seconds
    uncompressed_with_candidate = compressed_with_candidate + uncompressed_extra

    parser_results = json.loads(PARSER_RESULTS.read_text())
    coexistence = parser_results["live_integration_gate"]
    mutable_work = coexistence["current_symmetric_mutable_k_work"]
    naive_layout = coexistence["naive_linked_k14_layout"]
    expected_coexistence = {
        "current_symmetric_image_bytes": 6142,
        "current_symmetric_mutable_k_work": {
            "start": "0x3000",
            "end": "0x33f8",
            "bytes": 1016,
        },
        "free_after_symmetric_mutable_k_work_bytes": 8,
        "naive_link_overflow_past_0x3400_bytes": 744,
    }
    actual_coexistence = {
        "current_symmetric_image_bytes": coexistence[
            "current_symmetric_image_bytes"
        ],
        "current_symmetric_mutable_k_work": mutable_work,
        "free_after_symmetric_mutable_k_work_bytes": coexistence[
            "free_after_symmetric_mutable_k_work_bytes"
        ],
        "naive_link_overflow_past_0x3400_bytes": naive_layout[
            "overflow_past_0x3400_bytes"
        ],
    }
    if actual_coexistence != expected_coexistence:
        raise AssertionError(
            f"current K14 callback coexistence ledger changed: {actual_coexistence!r}"
        )

    certificate_message_bytes = 4 + len(body)
    compressed_certificate_message_bytes = 4 + 2 + 3 + 3 + quality_sizes[6]
    message_delta = certificate_message_bytes - compressed_certificate_message_bytes
    if message_delta != 696:
        raise AssertionError("Certificate message delta changed")

    return {
        "schema": "seed-tls13-cert-parser-tradeoff-v1",
        "status": "pass",
        "scope": "host reconstruction plus existing literal 4.77 MHz 8088 timing; no VM run",
        "artifacts": {
            "checker": Path(__file__).name,
            "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "flight_results": str(FLIGHT_RESULTS.relative_to(ROOT)),
            "flight_results_sha256": hashlib.sha256(
                FLIGHT_RESULTS.read_bytes()
            ).hexdigest(),
            "mlkem_results": str(MLKEM_RESULTS.relative_to(ROOT)),
            "mlkem_results_sha256": hashlib.sha256(
                MLKEM_RESULTS.read_bytes()
            ).hexdigest(),
            "cert_parser_results": str(PARSER_RESULTS.relative_to(ROOT)),
            "cert_parser_results_sha256": hashlib.sha256(
                PARSER_RESULTS.read_bytes()
            ).hexdigest(),
        },
        "fixture": {
            "certificate_body_bytes": len(body),
            "certificate_body_sha256": body_sha256,
            "brotli_cli": version,
            "raw_live_compressed_payload_retained": False,
            "reencode_caveat": (
                "The exact current decoded body was re-encoded with Brotli 1.2.0; "
                "the q6 length matches the live 1787-byte payload, but byte identity "
                "to that unretained live payload is not claimed."
            ),
        },
        "wire": {
            "fixed_seed_client_hello_with_compression_bytes": 1376,
            "fixed_seed_client_hello_without_compression_bytes": 1369,
            "client_hello_saving_bytes": 7,
            "compressed_certificate_handshake_bytes": compressed_certificate_message_bytes,
            "uncompressed_certificate_handshake_bytes": certificate_message_bytes,
            "protected_record_wire_bytes_compressed": 1945,
            "protected_record_wire_bytes_uncompressed_projected": 2641,
            "protected_record_delta_bytes": message_delta,
            "mss_384_chunks_compressed": 6,
            "mss_384_chunks_uncompressed": 7,
        },
        "brotli_reencode": {
            "quality_sizes": {str(key): value for key, value in quality_sizes.items()},
            "q6_default": {
                "bytes": len(quality_streams[6]),
                "encoded_window_bits": brotli_window_bits(quality_streams[6]),
                "declared_max_backward_distance": (
                    1 << brotli_window_bits(quality_streams[6])
                )
                - 16,
                "sha256": hashlib.sha256(quality_streams[6]).hexdigest(),
            },
            "forced_windows_q6": forced_windows,
        },
        "literal_8088_critical_delta": {
            "operation_delta": operations_delta,
            "component_delta": component_delta,
            "extra_fixed_work_ticks": component_delta["FLIGHT"]["ticks"],
            "extra_fixed_work_seconds": uncompressed_extra,
            "compressed_fixed_plus_critical_hkdf_seconds": round(
                compressed_fixed + critical_hkdf, 4
            ),
            "uncompressed_fixed_plus_critical_hkdf_seconds": round(
                compressed_fixed + critical_hkdf + uncompressed_extra, 4
            ),
            "provisional_mlkem_candidate_seconds": round(candidate_seconds, 4),
            "compressed_plus_candidate_seconds": round(compressed_with_candidate, 4),
            "uncompressed_plus_candidate_seconds": round(uncompressed_with_candidate, 4),
            "uncompressed_margin_to_15s_before_other_omissions": round(
                15 - uncompressed_with_candidate, 4
            ),
            "omitted_from_margin": compressed["fixed_work_only"]
            if isinstance(compressed["fixed_work_only"], list)
            else compressed["omitted_from_margin"],
        },
        "instrumented_q6_reencode_observation": {
            "provenance": (
                "One-off instrumentation of official google/brotli v1.2.0 "
                "source tarball SHA-256 "
                "816c96e8e8f193b40151dad7e8ff37b1221d019dbcb9c35cd3fadbfe6477dfec"
            ),
            "instrumented_stream_sha256": q6_sha256,
            "encoded_window_bits": 12,
            "declared_max_backward_distance": 4080,
            "observed_max_backward_distance": 1705,
            "max_copy_length": 74,
            "commands": 80,
            "static_dictionary_references": 0,
            "official_decoder_ring_bytes": 4096,
            "official_decoder_write_ahead_slack_bytes": 542,
            "official_decoder_state_bytes_arm64": 5744,
            "official_decoder_peak_dynamic_bytes_arm64": 32827,
            "official_decoder_allocations_bytes": [
                5744,
                1408,
                12336,
                1,
                64,
                4,
                2536,
                4328,
                1768,
                4638,
            ],
            "homebrew_arm64_static_archive_reference": {
                "libbrotlidec_text_bytes": 32292,
                "libbrotlicommon_text_bytes_including_static_dictionary": 126985,
                "comparability_caveat": (
                    "These are host compiler/archive sections, not an 8086 "
                    "target-size estimate; they only expose the breadth of the "
                    "general decoder and dictionary implementation."
                ),
            },
            "restricted_stream_ring_conclusion": (
                "A bytewise custom decoder with an explicit actual-distance cap "
                "would need a 2048-byte circular history for this re-encoded "
                "command stream. This is not a bound for a future server stream: "
                "the default stream advertises WBITS=12 and legally permits 4080."
            ),
        },
        "decision": {
            "target_brotli_decoder_implemented": False,
            "k14_callback_coexistence": {
                **actual_coexistence,
                "standalone_capture_callback_bytes": coexistence[
                    "standalone_capture_prefix_bytes"
                ],
                "coexistence_proven": False,
                "low_relocation_conflict": (
                    "The former 0x0d00..0x0fec candidate conflicts with the "
                    "live protected-flight scatter at 0x0d00..0x0eff and its "
                    "adjacent loader schedule beginning at 0x0f00."
                ),
            },
            "reason": (
                "RFC 8879 negotiates only the compression algorithm, not a window "
                "or restricted command profile. Safe arbitrary Brotli needs the "
                "meta-block, block-switch, canonical Huffman, context-map, "
                "insert/copy/distance, history-window, and static-dictionary paths. "
                "The observed restricted stream is too weak a compatibility contract."
            ),
            "recommended_poc_path": (
                "Omit certificate compression and use the checked streaming "
                "uncompressed parser as the parser/profile direction. This is not "
                "yet a K14 integration path: the 748-byte live callback cannot "
                "coexist below 0x3400 with the current 6,142-byte symmetric image "
                "and its 1,016-byte mutable K work at 0x3000..0x33f8. Only 8 "
                "bytes remain, and the naive aligned link overflows by 744 bytes. "
                "The former 0x0d00..0x0fec relocation conflicts with the live "
                "scatter/loader schedule. "
                "Treat a restricted Brotli decoder as a later optional optimization "
                "only after raw provider streams and target timing/code/workspace "
                "are gated."
            ),
        },
    }


def main() -> int:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--json", action="store_true")
    args = argument_parser.parse_args()
    result = run()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "certificate tradeoff gate: pass; "
            f"+{result['wire']['protected_record_delta_bytes']} wire B, "
            f"+{result['literal_8088_critical_delta']['extra_fixed_work_seconds']} s"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
