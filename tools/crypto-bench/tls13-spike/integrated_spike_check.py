#!/usr/bin/env python3
"""Audit the frozen evidence behind the 16 KiB TLS 1.3 architecture decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
POC = HERE.parent / "tls13-poc"
FROZEN = HERE / "integrated_spike_results.json"


def load(name: str, directory: Path = HERE) -> dict[str, Any]:
    with (directory / name).open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise AssertionError(f"{name}: top level is not an object")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_close(actual: float, expected: float, label: str) -> None:
    require(
        math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-9),
        f"{label}: expected {expected!r}, got {actual!r}",
    )


def require_hash(path: Path, expected: str, label: str) -> None:
    actual = sha256(path)
    require(actual == expected, f"{label}: SHA-256 {actual}, expected {expected}")


def require_sha256_literal(value: Any, label: str) -> None:
    require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        f"{label}: invalid SHA-256 literal",
    )


def audit_source_hashes(
    mlkem: dict[str, Any],
    auth: dict[str, Any],
    tls: dict[str, Any],
    ticket: dict[str, Any],
    entropy: dict[str, Any],
    phase_chain: dict[str, Any],
    live_k14: dict[str, Any],
) -> None:
    mlkem_paths = {
        "mlkem768_integrated_candidate.asm": HERE
        / "mlkem768_integrated_candidate.asm",
        "mlkem768_integrated_keygen.asm": HERE / "mlkem768_integrated_keygen.asm",
        "mlkem768_integrated_core.inc": HERE / "mlkem768_integrated_core.inc",
        "mlkem768_integrated_vectors.inc": HERE
        / "mlkem768_integrated_vectors.inc",
        "mlkem768_integrated_check.py": HERE / "mlkem768_integrated_check.py",
        "mlkem768_integrated_keygen_check.py": HERE
        / "mlkem768_integrated_keygen_check.py",
        "mlkem768_kernels_check.py": HERE / "mlkem768_kernels_check.py",
        "run_8088_16k.py_current_replay": HERE / "run_8088_16k.py",
        "run_basic_bootstrap_86box.py": ROOT / "tools/run-basic-bootstrap-86box.py",
        "basic_bootstrap.asm": ROOT / "targets/ibm_pc_5150/basic/bootstrap.asm",
        "build_basic_bootstrap.py": ROOT / "tools/build-basic-bootstrap.py",
        "vm_profile_base_config": ROOT
        / "targets/ibm_pc_5150/86box/vm-net-ne2k8/86box.cfg",
    }
    for label, path in mlkem_paths.items():
        require_hash(path, mlkem["source_hashes"][label], f"ML-KEM {label}")

    auth_paths = {
        "auth_integrated_bench.asm": HERE / "auth_integrated_bench.asm",
        "auth_integrated_check.py": HERE / "auth_integrated_check.py",
        "auth_integrated_cycles.py": HERE / "auth_integrated_cycles.py",
        "auth_integrated_oracle.py": HERE / "auth_integrated_oracle.py",
        "auth_integrated_vectors.inc": HERE / "auth_integrated_vectors.inc",
        "p256.inc": ROOT / "targets/ibm_pc_5150/boot/core/p256.inc",
        "cycles8088.py": ROOT / "tools/crypto-bench/cycles8088.py",
        "run_8088_16k.py": HERE / "run_8088_16k.py",
        "basic_bootstrap.asm": ROOT / "targets/ibm_pc_5150/basic/bootstrap.asm",
        "build_basic_bootstrap.py": ROOT / "tools/build-basic-bootstrap.py",
        "run_basic_bootstrap_86box.py": ROOT / "tools/run-basic-bootstrap-86box.py",
        "known_good_hkdf_control.asm": HERE / "hkdf_bench.asm",
    }
    for label, path in auth_paths.items():
        require_hash(path, auth["source_hashes"][label], f"authentication {label}")

    hostile = tls["deterministic_hostile_gate"]
    require_hash(
        HERE / "tls13_integrated_oracle.py",
        hostile["oracle_sha256"],
        "TLS state-machine oracle",
    )
    require_hash(
        HERE / "tls13_integrated_checks.py",
        hostile["checks_sha256"],
        "TLS hostile checker",
    )
    require_hash(
        ROOT / ticket["provenance"]["measurement_source"],
        ticket["provenance"]["measurement_source_sha256"],
        "ticket measurement probe",
    )
    require_hash(
        ROOT / ticket["provenance"]["curation_source"],
        ticket["provenance"]["curation_source_sha256"],
        "ticket current/curation probe",
    )
    require_hash(
        ROOT / entropy["source"],
        entropy["source_sha256"],
        "entropy ratchet oracle",
    )

    phase_paths = {
        "source": "source_sha256",
        "bootstrap_source": "bootstrap_source_sha256",
        "basic_builder": "basic_builder_sha256",
        "vm_harness": "vm_harness_sha256",
    }
    for path_field, hash_field in phase_paths.items():
        require_hash(
            ROOT / phase_chain[path_field],
            phase_chain[hash_field],
            f"K14 phase-chain {path_field}",
        )
    require_hash(
        ROOT / phase_chain["runner"],
        phase_chain["runner_sha256"],
        "K14 phase-chain runner",
    )

    live_paths = {
        "builder": "builder_sha256",
        "controller_source": "controller_source_sha256",
        "runner": "runner_sha256",
        "wire_analyzer": "wire_analyzer_sha256",
        "controller_gate": "controller_gate_sha256",
        "capture_oracle": "capture_oracle_sha256",
    }
    for path_field, hash_field in live_paths.items():
        require_hash(
            ROOT / live_k14["provenance"][path_field],
            live_k14["provenance"][hash_field],
            f"live K14 {path_field}",
        )


def build_result() -> dict[str, Any]:
    mlkem_name = "mlkem768_integrated_results.json"
    auth_name = "auth_integrated_results.json"
    tls_name = "tls13_integrated_results.json"
    ticket_name = "tls13_ticket_resumption_live_results.json"
    entropy_name = "entropy_ratchet_results.json"
    liveness_name = "post_finished_dialogue_results.json"
    patience_name = "patience_results.json"
    phase_chain_name = "phase_chain_literal16k_k14_results.json"
    live_k14_name = "live_k14_16k_results.json"

    mlkem = load(mlkem_name)
    auth = load(auth_name)
    tls = load(tls_name)
    ticket = load(ticket_name)
    entropy = load(entropy_name)
    liveness = load(liveness_name)
    patience = load(patience_name)
    phase_chain = load(phase_chain_name, POC)
    live_k14 = load(live_k14_name, POC)

    require(mlkem["schema"] == "seed-mlkem768-integrated-spike-v2", "ML-KEM schema")
    require(
        mlkem["offline_correctness"]["decapsulation"]["status"] == "pass",
        "ML-KEM decapsulation correctness",
    )
    require(
        mlkem["offline_correctness"]["keygen"]["status"] == "pass",
        "ML-KEM KeyGen correctness",
    )
    runs = {run["name"]: run for run in mlkem["literal_86box_runs"]}
    require(len(runs) == 4, "four exact ML-KEM runs")
    require(all(run["status"] == "pass" for run in runs.values()), "ML-KEM run status")
    candidate = runs["provisional candidate repeated"]["seconds_per_operation"]
    decaps = runs["complete decapsulation valid repeated"]["seconds_per_operation"]
    invalid = runs[
        "complete decapsulation one-bit-invalid repeated"
    ]["seconds_per_operation"]
    keygen = runs["deterministic keygen"]["seconds_per_operation"]
    require_close(candidate, 1.9004188799361708, "ML-KEM candidate seconds")
    require_close(decaps, 24.84458978876092, "ML-KEM decapsulation seconds")
    require_close(invalid, decaps, "ML-KEM frozen invalid seconds")
    require_close(keygen, 22.02508586284406, "ML-KEM KeyGen seconds")
    require(mlkem["layout"]["decapsulation"]["matrix_cache_bytes"] == 0, "matrix cache")
    require(
        mlkem["offline_correctness"]["decapsulation"]["invalid_vector"][
            "fixed_work_evidence"
        ]
        is False,
        "invalid vector must not claim fixed work",
    )

    require(
        auth["schema"] == "seed-tls13-auth-integrated-spike-v1",
        "authentication schema",
    )
    require(auth["correctness"]["status"] == "pass", "authentication correctness")
    require(auth["fixture_identity"]["synthetic"] is True, "authentication fixture")
    require(
        auth["fixture_identity"]["live_openai_chain_bytes_exercised"] is False,
        "authentication live-chain scope",
    )
    require(auth["authority"]["physical_86box_timing"] is False, "auth timing label")
    require(
        auth["executed_trace_cycle_model"]["unknown_mnemonics"] == [],
        "authentication cycle model coverage",
    )
    require(auth["literal_16k_layout"]["content_bytes"] == 9790, "auth image size")
    require(
        auth["literal_16k_layout"]["routine_only_unicorn_stack_high_water_bytes"]
        == 74,
        "auth stack high-water",
    )
    require(
        auth["literal_16k_layout"]["resumable_straus_checkpoint_bytes"] == 706,
        "auth resumable state",
    )
    require(
        auth["cadence"]["each_candidate_segment_below_25_seconds"] is True,
        "auth candidate yield intervals",
    )
    require(
        auth["brotli_fixture"]["target_decoder_implemented"] is False,
        "target Brotli must remain an open gate",
    )

    hostile = tls["deterministic_hostile_gate"]
    require(hostile["tests"] == 28 and hostile["passed"] == 28, "TLS hostile matrix")
    require(hostile["failed"] == 0, "TLS hostile failures")
    require(
        tls["combined_live_observation"]["proofs"]["credential_loaded"] is False,
        "live probe credential quarantine",
    )
    require(
        tls["combined_live_observation"]["profile"]["provisional_pre_fo_split_exercised"]
        is False,
        "live probe scope label",
    )

    require(ticket["schema"] == "seed-tls13-ticket-live-v2", "ticket schema")
    conclusion = ticket["conclusion"]
    require(conclusion["ticket_resumption_accepted"] is True, "ticket acceptance")
    require(
        conclusion["certificate_and_certificate_verify_omitted_on_resume"] is True,
        "ticket omitted certificate authentication",
    )
    require(
        conclusion["resumed_key_share_still_required"] is True,
        "resumed key share",
    )
    require(
        conclusion["extension_message_attribution_preserved"] is False,
        "ticket extension parser scope",
    )
    require(
        ticket["provenance"]["session_psk_file_destroyed_after_probe"] is True,
        "ticket probe PSK cleanup",
    )
    require(
        ticket["provenance"]["curated_without_network_rerun"] is True
        and ticket["provenance"][
            "raw_observation_values_and_output_hashes_changed"
        ]
        is False,
        "ticket curation provenance",
    )

    require(entropy["status"] == "PASS", "entropy ratchet oracle")
    require(entropy["crash_cases_examined"] == 516, "entropy crash cases")
    require(
        entropy["successful_sequence_attempts"] == 4096,
        "entropy sequence advances",
    )
    require(
        entropy["single_byte_corruptions_rejected"] == 512,
        "entropy corruption matrix",
    )

    heads = liveness["experiments"]["complete_unauthorized_heads_long"]
    require(heads["responses"] == 7, "complete HEAD responses")
    require(heads["extended_connection"] is True, "complete HEAD liveness")
    require(
        liveness["conclusion"]["candidate_profile_transfer_is_inference"] is True,
        "HEAD candidate-profile scope",
    )
    require(liveness["conclusion"]["provider_sla"] is False, "liveness SLA label")
    require(
        patience["conclusion"]["twelve_second_hold_accepted"] is True
        and patience["conclusion"]["fifteen_second_hold_accepted"] is False,
        "observed pre-Finished close bracket",
    )
    require(
        patience["conclusion"]["candidate_profile_deadline_established"] is False,
        "candidate deadline scope",
    )

    require(
        phase_chain["machine"]["cpu"] == "8088"
        and phase_chain["machine"]["cpu_hz"] == 4_772_728
        and phase_chain["machine"]["installed_ram_kib"] == 16
        and phase_chain["machine"]["dynarec"] is False
        and phase_chain["machine"]["entry"] == "ROM BASIC sidecar",
        "K14 phase-chain machine",
    )
    require(
        phase_chain["done"] is True
        and phase_chain["status"] == "pass"
        and phase_chain["passed"] is True
        and phase_chain["failed"] is False,
        "K14 phase-chain result",
    )
    require(
        phase_chain["resident_sectors"] == 4
        and phase_chain["loaded_end"] == "0x1800"
        and phase_chain["image_bytes"] == 79_872
        and phase_chain["image_sha256"]
        == "703924e3ecaddd82f47549f3d7d0a2f1665c049f0a8aeef7a95b840226917ae0",
        "K14 phase-chain image",
    )
    require(
        phase_chain["floppy_media"]["read_only_requested"] is False
        and phase_chain["floppy_media"]["unchanged"] is False,
        "K14 durability fixture must exercise its deliberate media write",
    )
    require(
        phase_chain["serial_text"]
        == (
            "TLS13 POC\n"
            "PRE...\n"
            "PRE l=12\n"
            "ENT[D]...\n"
            "ENT t=181 w=14 r=3 load=7\n"
            "KG...\n"
            "KG t=402 load=3\n"
            "HEL...\n"
            "CF t=225\n"
            "FO...\n"
            "FO t=470 load=6\n"
            "AU...\n"
            "AU t=989 load=13\n"
            "PASS\n"
            "RESULT\n"
        ),
        "K14 phase-chain serial order",
    )
    require(
        phase_chain["phase_chain"]["physical_min_entropy_established"] is False,
        "K14 phase-chain entropy scope",
    )

    require(
        live_k14["schema"] == "seed-live-k14-16k-wire-v4"
        and live_k14["status"] == "pass",
        "live K14 schema/status",
    )
    target = live_k14["target"]
    require(
        target["cpu"] == "8088"
        and target["clock_mhz"] == 4.772728
        and target["ram_kib"] == 16
        and target["dynarec"] is False
        and target["entry"] == "ROM BASIC sidecar"
        and target["profile"] == "vm-net-ne2k8"
        and target["driver"] == "production SEED/DRIVERS/NE.DRV",
        "live K14 target",
    )
    require(
        live_k14["historical_deadline_artifact"]["core_bytes"] == 45_568
        and live_k14["historical_deadline_artifact"]["core_sectors"] == 89
        and live_k14["historical_deadline_artifact"]["resident_prefix_bytes"]
        == 2_048
        and live_k14["historical_deadline_artifact"]["logical_k_bytes"] == 7_168,
        "historical live K14 artifact layout",
    )
    controller_bytes = live_k14["historical_deadline_artifact"][
        "controller_bytes"
    ]
    require(
        controller_bytes["protected"] == 900
        and controller_bytes["protected_slot_bytes"] == 1_024
        and controller_bytes["protected_slot_slack_bytes"] == 124,
        "historical live K14 protected-controller fit",
    )
    wire = live_k14["historical_deadline_wire_contract"]
    require(
        wire["deadline_seconds"] == 15.0
        and wire["finished_record_bytes"] == 58,
        "historical live K14 wire contract",
    )
    protected_shape = wire["protected_shape"]
    require(
        protected_shape["encrypted_handshake_records"] == 1
        and protected_shape["tls_inner_plaintext_padding"] == 0
        and protected_shape["coalesced_or_already_queued_later_record"]
        == "rejected before client Finished",
        "historical live K14 strict protected shape",
    )
    trial_binding = live_k14["historical_deadline_artifact_binding"]
    historical_artifact = live_k14["historical_deadline_artifact"]
    require(
        trial_binding["curation_manifest_sha256"]
        == historical_artifact["manifest_sha256"]
        and trial_binding["curation_runner_sha256"]
        == "b24059fa64dcd17adbe185ad29c4b2ae5e27cd436b77a2057798d0c8ffb949fb"
        and trial_binding["core_sha256"]
        == historical_artifact["core_sha256"]
        and trial_binding["floppy_sha256"]
        == historical_artifact["floppy_sha256"],
        "historical live K14 curation/trial artifact binding",
    )
    require(
        trial_binding["trial_manifest_reconstructed_exactly"] is True
        and trial_binding["binary_outputs_identical"] is True
        and trial_binding["trial_run_record_embeds_binary_hashes"] is False
        and trial_binding["curation_run_record_schema"]
        == "seed-live-k14-16k-run-v2",
        "historical live K14 trial provenance scope",
    )
    require(
        [
            change["path"]
            for change in trial_binding["metadata_only_changes_after_trials"]
        ]
        == [
            "strict_server_shape.protected_flight",
            "product_input.resident_abi_offsets.parse_tcp_payload",
            "product_input.resident_abi_offsets.nic_vt_rx_fallback",
        ],
        "historical live K14 post-trial metadata-only changes",
    )
    trials = live_k14["historical_deadline_trials"]
    require(
        len(trials) == 3
        and all(trial["status"] == "pass" for trial in trials),
        "historical live K14 trials",
    )
    require(
        [trial["name"] for trial in trials] == ["repeat8", "repeat9", "repeat10"]
        and all(trial["host_capture_finished_copies"] == 1 for trial in trials),
        "historical live K14 trial identities",
    )
    require(
        all(
            trial["manifest_sha256"]
            == trial_binding["trial_manifest_sha256"]
            and trial["runner_sha256"]
            == trial_binding["trial_runner_sha256"]
            for trial in trials
        ),
        "historical live K14 per-trial manifest/runner provenance",
    )
    distribution = live_k14["historical_deadline_distribution"]
    require(distribution["trial_count"] == 3, "historical live K14 trial count")
    wire_seconds = [trial["wire_seconds"] for trial in trials]
    require_close(
        distribution["minimum_wire_seconds"],
        min(wire_seconds),
        "historical live K14 minimum wire seconds",
    )
    require_close(
        distribution["maximum_wire_seconds"],
        max(wire_seconds),
        "historical live K14 worst wire seconds",
    )
    require_close(
        distribution["mean_wire_seconds"],
        sum(wire_seconds) / len(wire_seconds),
        "historical live K14 mean wire seconds",
    )
    require_close(
        distribution["worst_margin_seconds"],
        wire["deadline_seconds"] - max(wire_seconds),
        "historical live K14 worst wire margin",
    )
    transport = live_k14["historical_transport_reliability"]
    require(
        transport["finished_transmit_attempts"] == 2
        and transport["same_tcp_sequence"] is True
        and transport["logical_sequence_advance_bytes"] == 58
        and transport["offline_second_send_failure_recovery"] is True,
        "historical live K14 Finished retry contract",
    )
    require(
        transport["host_capture_observed_finished_copies_per_trial"] == [1, 1, 1]
        and transport["second_copy_visibility_reason"].startswith(
            "not established;"
        )
        and transport["earlier_diagnostic_is_packet_loss_evidence"] is False,
        "historical live K14 capture scope",
    )
    live_gates = live_k14["historical_deadline_gates"]
    for gate_name in (
        "guest_deadline_pass_and_result_ordered",
        "host_wire_deadline_pass",
        "server_acked_finished",
        "fragmented_server_hello_and_protected_flight",
        "strict_protected_shape_positive_and_negative_matrix",
        "zero_window_phase_boundary",
        "critical_loader_fallback",
        "credential_and_api_request_literal_scan",
    ):
        require(
            live_gates[gate_name] is True,
            f"historical live K14 gate {gate_name}",
        )
    require(
        live_gates["half_open_rx_extent"] == "[0x0700,0x08b6)",
        "historical live K14 NIC RX extent",
    )
    require(
        live_gates["post_sym_extension_writes"] == 0,
        "historical live K14 post-symmetric extension writes",
    )

    canary = live_k14["current_post_finished_canary"]
    require(
        canary["name"] == "live-attempt6-hardened-canary-pass"
        and canary["frozen_artifacts_required_for_audit"] is False,
        "current post-Finished canary identity and offline audit scope",
    )
    binding = canary["artifact_run_binding"]
    expected_binding = {
        "baseline_git_head": "548053dfcdfc19b12130ce418ed24f7670c45750",
        "core_bytes": 45_568,
        "core_sha256": (
            "ccedcd8dcbdf3a87f50b6caf6c35c359642738d7cd4278fed0884d7687dc8144"
        ),
        "floppy_bytes": 163_840,
        "floppy_sha256": (
            "be79ab23ec351f2bed45fa8d0de1b199ba7fc0ae3786f20b799f36367cd1d11c"
        ),
        "manifest_sha256": (
            "b254df9143582d7ed8921a08174236c8e6608dc77804b2dc33714eb142a08b37"
        ),
        "current_offline_byte_identity_replay": {
            "date": "2026-07-26",
            "core_identical": True,
            "floppy_identical": True,
            "core_sha256": (
                "ccedcd8dcbdf3a87f50b6caf6c35c359642738d7cd4278fed0884d7687dc8144"
            ),
            "floppy_sha256": (
                "be79ab23ec351f2bed45fa8d0de1b199ba7fc0ae3786f20b799f36367cd1d11c"
            ),
            "replay_manifest_sha256": (
                "2b1ee31aee8efee6254c13ba8b3cb6e09442ec0bba467decc01f7e7a19bd603c"
            ),
            "manifest_difference_scope": "absolute output paths only",
            "network_launch_performed": False,
        },
        "run_schema": "seed-live-k14-16k-run-v2",
        "run_result_sha256": (
            "c454e630a92dc4db509b16adb4b58a123e3a7ebf910cad411855232d4dcf67e9"
        ),
        "pcap_sha256": (
            "58384f2473e9830dffefca2e343acdd03e8a634ec136c6ce119ade0db0f4593b"
        ),
        "capture_oracle_schema": "seed-live-k14-capture-oracle-v3",
        "capture_oracle_sha256": (
            "c7eb9ba8ca0944d775ac9737e0085c14072698eea02ccfcbb43d323d9e4fb775"
        ),
        "wire_result_sha256": (
            "5e7017f32837a705d1015123706ccbbcbe9a40cbe26ff15ef7c6091489437186"
        ),
    }
    require(binding == expected_binding, "current post-Finished artifact/run binding")
    for key, value in binding.items():
        if key.endswith("_sha256"):
            require_sha256_literal(value, f"current post-Finished {key}")
    replay = binding["current_offline_byte_identity_replay"]
    for key in ("core_sha256", "floppy_sha256", "replay_manifest_sha256"):
        require_sha256_literal(
            replay[key],
            f"current post-Finished byte-identity replay {key}",
        )

    canary_profile = canary["exact_profile"]
    require(
        canary_profile["machine"] == "IBM PC 5150"
        and canary_profile["machine_id"] == "ibmpc"
        and canary_profile["cpu"] == "8088"
        and canary_profile["cpu_hz"] == 4_772_728
        and canary_profile["cpu_multiplier"] == 1
        and canary_profile["dynarec"] is False
        and canary_profile["ram_kib"] == 16
        and canary_profile["entry"] == "ROM BASIC sidecar"
        and canary_profile["profile"] == "vm-net-ne2k8"
        and canary_profile["driver"] == "production SEED/DRIVERS/NE.DRV"
        and canary_profile["exact_profile_verified"] is True,
        "current post-Finished exact profile",
    )
    read_only = canary["read_only_floppy"]
    require(
        read_only["requested"] is True
        and read_only["mode_during_run"] == "0o444"
        and read_only["host_write_open_denied"] is True
        and read_only["sha256_before"] == binding["floppy_sha256"]
        and read_only["sha256_after"] == binding["floppy_sha256"]
        and read_only["unchanged"] is True
        and read_only["mode_restored"] is True
        and read_only["integrity_gate_passed"] is True,
        "current post-Finished read-only floppy gate",
    )
    client_hello = canary["client_hello"]
    require(
        client_hello["handshake_bytes"] == 1_382
        and client_hello["record_bytes"] == 1_387
        and client_hello["psk_key_exchange_mode"] == "psk_dhe_ke"
        and client_hello["pre_shared_key_offered"] is False,
        "current post-Finished ClientHello ticket-request shape",
    )
    canary_wire = canary["wire_deadline"]
    require(
        canary_wire["deadline_seconds"] == 15.0
        and canary_wire["identified_live_seed_flows"] == 1
        and canary_wire["completed_live_seed_flows"] == 1
        and canary_wire["client_retransmit_payloads"] == 0
        and canary_wire["server_retransmit_payloads"] == 0
        and canary_wire["stream_conflict"] is False
        and canary_wire["status"] == "pass",
        "current post-Finished wire gate",
    )
    require_close(
        canary_wire["server_hello_to_client_finished_seconds"],
        13.404952049255371,
        "current post-Finished wire deadline",
    )
    require_close(
        canary_wire["margin_seconds"],
        1.595047950744629,
        "current post-Finished wire margin",
    )
    oracle = canary["capture_oracle"]
    expected_oracle_timings = {
        "tcp_syn": 1785064223.212374,
        "client_finished": 1785064236.753313,
        "syn_to_client_finished_seconds": 13.540939092636108,
        "client_head": 1785064237.709358,
        "client_finished_to_head_seconds": 0.9560449123382568,
        "syn_to_head_seconds": 14.496984004974365,
        "first_post_finished_server_record": 1785064237.93114,
        "client_finished_to_first_server_record_seconds": 1.1778268814086914,
        "syn_to_first_server_record_seconds": 14.7187659740448,
        "first_server_record_to_head_seconds": -0.22178196907043457,
    }
    require(
        {
            key: oracle[key]
            for key in expected_oracle_timings
        }
        == expected_oracle_timings,
        "current post-Finished oracle timings",
    )
    require(
        oracle["server_finished_record_tag_verified"] is True
        and oracle["server_finished_verify_data_matches"] is True
        and oracle["client_finished_exact_match"] is True
        and oracle["head_tag_verified"] is True
        and oracle["head_content_bytes"] == 50
        and oracle["post_finished_record_count"] == 2
        and oracle["all_post_finished_records_tag_verified"] is True
        and oracle["post_finished_target_acceptable"] is True
        and oracle["post_finished_target_rejection_count"] == 0,
        "current post-Finished tag-verified transcript and records",
    )
    nsts = oracle["new_session_tickets"]
    require(
        nsts["count"] == 2
        and nsts["record_server_application_sequence"] == 0
        and nsts["message_bytes"] == [222, 222]
        and nsts["all_messages_within_seed_bounds"] is True
        and nsts["all_target_acceptable"] is True
        and nsts["retention"] == "RAM-only tentative ticket",
        "current post-Finished volatile NewSessionTickets",
    )
    http = oracle["http"]
    require(
        http["record_server_application_sequence"] == 1
        and http["content_bytes"] == 1_125
        and http["status_code"] == 401
        and http["header_terminator_present"] is True,
        "current post-Finished tag-verified HTTP",
    )
    guest = canary["guest"]
    require(
        guest["terminal_status"] == "PASS"
        and guest["success_markers_ordered"] is True
        and guest["markers"]
        == [
            "DEADLINE PASS",
            "HEAD TX",
            "TICKET",
            "HEAD OK",
            "CANARY COMMIT",
            "PASS",
            "RESULT",
        ]
        and guest["ticket_seen"] is True
        and guest["head_ok_seen"] is True
        and guest["canary_commit_seen"] is True
        and guest["pass_seen"] is True,
        "current post-Finished guest evidence",
    )
    hardened = canary["hardened_failure_path_gates"]
    require(
        hardened
        == {
            "protected_bad_tag_no_precommit": True,
            "protected_authenticated_tail_tamper_no_precommit": True,
            "duplicate_early_data_rejected": True,
            "sequence_exhaustion_rejected_without_wrap": True,
            "capture_oracle_record_order_and_target_compatibility": True,
        },
        "current hardened failure-path evidence",
    )

    audit_source_hashes(
        mlkem,
        auth,
        tls,
        ticket,
        entropy,
        phase_chain,
        live_k14,
    )
    require_hash(
        ROOT / liveness["provenance"]["source"],
        liveness["provenance"]["source_sha256"],
        "post-Finished liveness probe",
    )
    require_hash(
        ROOT / patience["provenance"]["source"],
        patience["provenance"]["source_sha256"],
        "held-Finished patience probe",
    )

    result_paths = {
        mlkem_name: HERE / mlkem_name,
        auth_name: HERE / auth_name,
        tls_name: HERE / tls_name,
        ticket_name: HERE / ticket_name,
        entropy_name: HERE / entropy_name,
        liveness_name: HERE / liveness_name,
        patience_name: HERE / patience_name,
        phase_chain_name: POC / phase_chain_name,
        live_k14_name: POC / live_k14_name,
    }
    artifacts = {name: sha256(path) for name, path in result_paths.items()}

    return {
        "schema": "seed-tls13-secure-floor-spike-decision-v5",
        "recorded_date": "2026-07-26",
        "baseline_git_head": auth["git_head"],
        "evidence_gate_status": "pass",
        "artifact_sha256": artifacts,
        "historical_evidence_curation": {
            "component_recorded_date": "2026-07-25",
            "current_replay_wrapper_hashes_refreshed": True,
            "historical_mlkem_auth_ticks_com_text_and_image_hashes_changed": False,
            "all_recorded_mlkem_and_auth_images_reassembled_byte_identically": True,
            "k14_phase_chain_current_target_rerun": True,
        },
        "literal_16k_evidence": {
            "address_space_scope": "the K14 fixture phase-links entropy, KeyGen, HELLO, candidate, symmetric, FO, and authentication below the literal 16 KiB ROM-BASIC ceiling; the current live sibling combines the production nucleus and NE.DRV through client Finished, credential-free HTTP and volatile ticket capture AEAD-verified under provisional traffic keys, but peer identity and full secure product coexistence are not established",
            "mlkem_timing_scope": "86Box v9001 literal 16 KiB configuration; not physical IBM hardware",
            "mlkem_keygen_seconds": keygen,
            "mlkem_candidate_seconds": candidate,
            "mlkem_complete_decapsulation_seconds": decaps,
            "mlkem_post_candidate_tail_seconds": mlkem["derived"][
                "post_candidate_tail_seconds"
            ],
            "mlkem_matrix_cache_bytes": 0,
            "authentication_content_bytes": auth["literal_16k_layout"][
                "content_bytes"
            ],
            "authentication_execution_scope": auth["authority"][
                "semantic_execution"
            ],
            "authentication_timing_authority": auth["authority"]["timing"],
            "authentication_fixture_identity": "deterministic synthetic WE1 and leaf; not live OpenAI chain bytes",
            "authentication_post_finished_seconds": auth[
                "executed_trace_cycle_model"
            ]["post_finished_two_signature_seconds"],
            "authentication_cold_seconds": auth["executed_trace_cycle_model"][
                "cold_total_seconds"
            ],
            "authentication_longest_candidate_slice_seconds": auth["cadence"][
                "longest_candidate_nonyieldable_seconds"
            ],
            "authentication_resumable_bytes": auth["literal_16k_layout"][
                "resumable_straus_checkpoint_bytes"
            ],
            "k14_logical_k_bytes": historical_artifact["logical_k_bytes"],
            "k14_resident_prefix_bytes": historical_artifact[
                "resident_prefix_bytes"
            ],
            "k14_fixture_critical_ticks": 225,
            "k14_fixture_fo_ticks": 470,
            "k14_fixture_auth_ticks": 989,
            "live_product_shaped_core_bytes": binding["core_bytes"],
        },
        "protocol_evidence": {
            "hostile_state_machine_tests": hostile["tests"],
            "hostile_state_machine_passed": hostile["passed"],
            "credential_free_head_liveness_standard_openssl_seconds": heads[
                "alive_when_client_stopped_seconds"
            ],
            "head_cadence_transfer_to_candidate_is_inference": True,
            "observed_initial_close_p256_rsa_profile_seconds": patience["conclusion"][
                "observed_close_after_hold_seconds"
            ],
            "historical_three_run_deadline_baseline": {
                "trial_count": distribution["trial_count"],
                "worst_wire_seconds": distribution["maximum_wire_seconds"],
                "worst_margin_seconds": distribution["worst_margin_seconds"],
                "all_passed": True,
            },
            "current_post_finished_canary": {
                "exact_profile_verified": canary_profile["exact_profile_verified"],
                "host_read_only_floppy_gate_passed": read_only[
                    "integrity_gate_passed"
                ],
                "host_read_only_scope": (
                    "image mode 0444, host write-open denied, image SHA-256 "
                    "unchanged, and original mode restored; not a physical "
                    "write-protect mechanism"
                ),
                "client_hello_bytes": client_hello["handshake_bytes"],
                "psk_key_exchange_mode": client_hello[
                    "psk_key_exchange_mode"
                ],
                "wire_seconds": canary_wire[
                    "server_hello_to_client_finished_seconds"
                ],
                "wire_margin_seconds": canary_wire["margin_seconds"],
                "credential_free_head_tag_verified": oracle[
                    "head_tag_verified"
                ],
                "http_response_tag_verified": True,
                "http_content_bytes": http["content_bytes"],
                "volatile_tickets_tag_verified": nsts["count"],
                "ticket_message_bytes": nsts["message_bytes"],
                "guest_markers": guest["markers"],
                "hardened_failure_path_gates": hardened,
            },
            "candidate_profile_deadline_distribution_established": False,
            "live_path_scope": "production nucleus and NE.DRV proven through verified server Finished, transmitted client Finished, and a credential-free HEAD/HTTP dialogue plus RAM-only tentative ticket capture AEAD-verified under provisional traffic keys; peer identity, credentials, and product API traffic remain absent",
            "historical_client_finished_same_sequence_retry_proven_offline": True,
            "host_observed_same_boot_ticket_resumption_accepted": conclusion[
                "ticket_resumption_accepted"
            ],
            "resumed_certificate_authentication_omitted": conclusion[
                "certificate_and_certificate_verify_omitted_on_resume"
            ],
            "resumed_fresh_key_share_required": conclusion[
                "resumed_key_share_still_required"
            ],
        },
        "restart_evidence": {
            "ratchet_oracle_passed": True,
            "crash_cases": entropy["crash_cases_examined"],
            "advances": entropy["successful_sequence_attempts"],
            "single_byte_corruptions": entropy[
                "single_byte_corruptions_rejected"
            ],
            "physical_entropy_established": False,
            "rollback_safety_established": False,
            "write_protected_fallback_established": False,
            "current_canary_host_read_only_floppy_gate_passed": read_only[
                "integrity_gate_passed"
            ],
        },
        "architecture_decision": {
            "status": "validated credential-free live path through volatile ticket capture; conditional secure-tier candidate",
            "recommended_shape": "resident nucleus plus mutually exclusive streamed security slices, credential-free quarantine, ticket-assisted close recovery, and atomic credential unlock",
            "ticket_role": "same-boot recovery after retrospective proof; not a pre-Finished deadline extension or cold-start dependency",
            "head_role": "opportunistic live-socket continuity at bounded checkpoints",
            "leaf_pinning": "leaf plus WE1 issuer proof; not current plus guessed-next leaf",
            "safe_16k_arena_context_bytes": [96, 96],
            "safe_32k_arena_context_bytes": [224, 224],
            "staged_k14_persistent_arena_context_bytes": [96, 96],
            "staged_k14_phase_owned_reclaimed_bytes": 512,
            "conditional_relinked_repacked_upper_bounds_bytes": {
                "balanced": [352, 352],
                "executable_first": [608, 96],
            },
            "conditional_relinked_repacked_upper_bounds_accepted": False,
            "phase_lifetime_link_proven_through_client_finished": True,
            "credential_free_post_finished_dialogue_proven": True,
            "volatile_ticket_capture_proven": True,
            "post_finished_secure_commit_proven": False,
            "secure_floor_proven": False,
            "product_replacement_authorized": False,
            "tls12_removal_authorized": False,
            "remaining_false_reasons": [
                "complete ML-KEM FO on the live path",
                "live Certificate and CertificateVerify authentication",
                "trusted time or an explicit no-time certificate policy",
                "physical entropy plus restart and rollback behavior",
                "atomic credential unlock after every retrospective proof",
                "target ticket resumption and close recovery",
                "full legacy and modern NIC regression matrix",
            ],
        },
        "hard_open_gates": [
            "complete ML-KEM FO on the live target path",
            "live uncompressed Certificate/CV capture linked to the checked X.509/SPKI/profile parser; bounded Brotli decoder only if compression is retained",
            "live Certificate and CertificateVerify authentication",
            "self-contained trusted-time or explicit no-time certificate policy",
            "physical entropy source, health model, restart/rollback policy, and read-only regeneration fallback",
            "atomic credential unlock without releasing quarantined state early",
            "target ticket binder/resumption and socket-close recovery",
            "full legacy and modern NIC matrix under the integrated scheduler",
            "new linked K14 phase/high-state schedule before any persistent arena growth",
            "representative invalid ML-KEM timing and side-channel review",
            "independent review of fixed-u=9, provisional pre-FO use, and deferred authentication",
            "real IBM PC timing",
        ],
        "next_gate": "complete live FO, Certificate/CertificateVerify, trusted-time, entropy/restart, and atomic credential unlock; then prove target resumption and the NIC matrix, while current TLS 1.2 remains unchanged",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="print the result object")
    args = parser.parse_args()

    result = build_result()
    with FROZEN.open("r", encoding="utf-8") as stream:
        frozen = json.load(stream)
    require(result == frozen, "integrated_spike_results.json is stale")

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("INTEGRATED SPIKE PASS")
        print("secure floor proven: no")
        print("product replacement authorized: no")
        print(f"next gate: {result['next_gate']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
