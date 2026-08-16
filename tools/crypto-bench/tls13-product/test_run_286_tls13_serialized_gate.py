#!/usr/bin/env python3
"""No-VM report-semantics checks for the serialized 286 timing gate."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "run_286_tls13_serialized_gate.py"


def load_gate():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_serialized_report_test", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SerializedReportSemanticsTest(unittest.TestCase):
    def test_timing_pass_is_not_product_acceptance(self) -> None:
        gate = load_gate()
        fixture_asm = HERE / "hello_product_timing_bench.asm"
        components = (
            gate.Component(
                "mlkem768_product_modules",
                fixture_asm,
                ("MLKMODCD", "MLKMODCA"),
                {"CHECK": "0001"},
                off_window_operations=("MLKMODMX", "MLKMODDC"),
            ),
            gate.Component(
                "x25519_product_module",
                fixture_asm,
                ("XMODSS",),
                {"CHECK": "0001"},
            ),
            gate.Component(
                "deadline_product_transitions",
                fixture_asm,
                ("PACKMX", "FLIGHTDC"),
                {"CHECK": "0001"},
            ),
            gate.Component(
                "product_cached_pack_loader",
                fixture_asm,
                (),
                {"CHECK": "0001"},
            ),
            gate.Component(
                "p256_width7_product_tablegen",
                fixture_asm,
                (),
                {"CHECK": "0001"},
                off_window_operations=("TABLEGEN",),
            ),
            gate.Component(
                "product_server_hello_controllers",
                fixture_asm,
                ("HELLOACQ", "HELLORES"),
                {"CHECK": "0001"},
            ),
            gate.Component(
                "product_protected_flight_controllers",
                fixture_asm,
                ("ACQHEAD", "RESFLIGHT"),
                {"CHECK": "0001"},
                off_window_operations=("ACQPOST", "ACQFLIGHT"),
            ),
            gate.Component(
                "pinned_ecdsa_certificate_verify",
                fixture_asm,
                ("ECDSAPROD",),
                {"CHECK": "0001"},
                off_window_operations=("TABLEGEN",),
            ),
        )
        gate.materialize_source_core = lambda: ("test-commit", "ab" * 32, True)
        gate.build_generated_sources = lambda: None
        gate.components = lambda: components

        def run_component(component, _timeout):
            critical = {
                name: {"ticks": 1, "seconds": gate.TICK_MS / 1000}
                for name in component.critical_operations
            }
            off_window = {
                name: {
                    "ticks": 2 if name == "ACQFLIGHT" else 1,
                    "seconds": (
                        (2 if name == "ACQFLIGHT" else 1)
                        * gate.TICK_MS
                        / 1000
                    ),
                }
                for name in component.off_window_operations
            }
            return {
                "name": component.name,
                "asm": "fixture.asm",
                "critical_operations": critical,
                "off_window_operations": off_window,
                "ticks": len(critical),
                "seconds": len(critical) * gate.TICK_MS / 1000,
                "payload_bytes": 1,
                "payload_sectors": 1,
                "guest_lines": ["CHECK N=1 dt=0 ck=0001", "DONE"],
            }

        gate.run_component = run_component

        with tempfile.TemporaryDirectory() as raw:
            gate.REPORT = Path(raw) / "report.json"
            saved_argv = sys.argv
            sys.argv = [str(SCRIPT), "--json"]
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    gate.main()
            finally:
                sys.argv = saved_argv
            report = json.loads(output.getvalue())
            persisted = json.loads(gate.REPORT.read_text())
            temporary_reports = list(Path(raw).glob(".report.json.*.tmp"))

        self.assertEqual(
            report["schema"], "seed-tls13-286-serialized-cpu-gate-v4"
        )
        self.assertEqual(report["machine"], "Intel 80286, 6 MHz, 512 KiB RAM")
        self.assertEqual(persisted, report)
        self.assertEqual(temporary_reports, [])
        self.assertTrue(report["complete"])
        self.assertTrue(report["passed"])
        self.assertTrue(report["timing_passed"])
        self.assertFalse(report["current_product_cpu_timing_complete"])
        self.assertFalse(report["current_product_timing_complete"])
        self.assertFalse(report["product_acceptance_complete"])
        self.assertFalse(
            report["separate_executable_integration_gates"][
                "flight_and_auth_gates_executed_by_this_timing_command"
            ]
        )
        self.assertTrue(
            report["separate_executable_integration_gates"]
            ["hello_timing_wrapper"]["executed_by_this_timing_command"]
        )
        self.assertEqual(len(report["product_blockers"]), 4)
        self.assertTrue(
            report["timed_operation_matrix"][
                "credential_free_finished_and_head_exact_timing"
            ]
        )
        self.assertTrue(
            report["timed_operation_matrix"][
                "final_resumption_authenticated_response_before_publication"
            ]
        )
        self.assertTrue(
            report["timed_operation_matrix"][
                "final_resumption_sequence_preserving_publication"
            ]
        )
        self.assertEqual(
            report["deadline_windows"]["acquisition_candidate_head"]
            ["operations"]["mlkem_candidate"]["operation"],
            "MLKMODCA",
        )
        self.assertEqual(
            report["offline_between_connections"]
            ["mlkem_uncached_full_fo_decapsulation"]["operation"],
            "MLKMODDC",
        )
        self.assertEqual(
            report["deadline_windows"]
            ["final_no_0rtt_psk_dhe_resumption"]["operations"]
            ["mlkem_cached_full_fo_decapsulation"]["operation"],
            "MLKMODCD",
        )
        self.assertEqual(
            report["deadline_windows"]
            ["final_no_0rtt_psk_dhe_resumption"]["operations"]
            ["resumed_finished_head_response_and_application_publication"]
            ["operation"],
            "RESFLIGHT",
        )
        self.assertFalse(
            report["offline_between_connections"]["timing_complete"]
        )
        self.assertIn("timing_input_manifest", report)
        self.assertEqual(
            [component["name"] for component in report["components"]],
            [component.name for component in components],
        )
        acquisition_operations = report["deadline_windows"][
            "acquisition_candidate_head"
        ]["operations"]
        final_operations = report["deadline_windows"][
            "final_no_0rtt_psk_dhe_resumption"
        ]["operations"]
        self.assertEqual(
            set(acquisition_operations),
            {
                "mlkem_candidate",
                "x25519_shared",
                "hardened_m_x_pack_transition",
                "post_connect_clienthello_tx_serverhello_rx",
                "flight_component_decode_crc",
                "finished_and_credential_free_head",
            },
        )
        self.assertEqual(
            set(final_operations),
            {
                "mlkem_cached_full_fo_decapsulation",
                "x25519_shared",
                "hardened_m_x_pack_transition",
                "post_connect_clienthello_tx_serverhello_rx",
                "flight_component_decode_crc",
                "resumed_finished_head_response_and_application_publication",
            },
        )
        for operations in (acquisition_operations, final_operations):
            component_operations = [
                (item["component"], item["operation"])
                for item in operations.values()
            ]
            self.assertEqual(
                len(component_operations),
                len(set(component_operations)),
            )
        self.assertEqual(
            report["offline_before_final_resumption_tcp"]
            ["mlkem_public_matrix_precompute"]["operation"],
            "MLKMODMX",
        )
        acquisition_lifecycle = report[
            "post_dialogue_acquisition_lifecycle"
        ]
        self.assertEqual(
            acquisition_lifecycle["full_flight_lifecycle"]["ticks"],
            acquisition_operations["finished_and_credential_free_head"][
                "ticks"
            ]
            + acquisition_lifecycle["response_nst_close_retire"]["ticks"],
        )
        encoded_report = json.dumps(report)
        for legacy in ("LZ4RACE", "HELLOHASH", "CTRLRACE", "model_input"):
            self.assertNotIn(legacy, encoded_report)

    def test_aborted_full_run_invalidates_stale_report(self) -> None:
        gate = load_gate()

        def abort_before_measurement():
            raise RuntimeError("deliberate setup abort")

        gate.materialize_source_core = abort_before_measurement
        with tempfile.TemporaryDirectory() as raw:
            gate.REPORT = Path(raw) / "report.json"
            gate.REPORT.write_text('{"passed": true}\n')
            saved_argv = sys.argv
            sys.argv = [str(SCRIPT), "--json"]
            try:
                with self.assertRaisesRegex(RuntimeError, "deliberate setup abort"):
                    gate.main()
            finally:
                sys.argv = saved_argv
            self.assertFalse(gate.REPORT.exists())

    def test_partial_run_never_changes_canonical_report(self) -> None:
        gate = load_gate()
        with tempfile.TemporaryDirectory() as raw:
            gate.REPORT = Path(raw) / "report.json"
            stale = b'{"schema":"old","passed":true}\n'
            gate.REPORT.write_bytes(stale)
            gate.prepare_canonical_report(False)
            gate.publish_canonical_report(
                {"schema": "partial", "passed": False}, False
            )
            self.assertEqual(gate.REPORT.read_bytes(), stale)


if __name__ == "__main__":
    unittest.main()
