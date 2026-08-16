from __future__ import annotations

import importlib.util
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "run_live_k14_16k.py"
SPEC = importlib.util.spec_from_file_location(
    "run_live_k14_16k_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def vm_config_text(*, ram_kib: int, cpu_speed: int = 4_772_728) -> str:
    return (
        "[General]\n"
        "sound_muted = 1\n"
        "\n"
        "[Machine]\n"
        "cpu_family = 8088\n"
        "cpu_multi = 1\n"
        f"cpu_speed = {cpu_speed}\n"
        "cpu_use_dynarec = 0\n"
        "machine = ibmpc\n"
        f"mem_size = {ram_kib}\n"
    )


class LiveK14RunnerTests(unittest.TestCase):
    def test_live_progress_ignores_partial_serial_line(self) -> None:
        self.assertEqual(
            RUNNER.completed_exact_lines("FO BEGIN\nIDE"),
            ["FO BEGIN"],
        )
        self.assertEqual(
            RUNNER.completed_exact_lines("FO BEGIN\nIDENTITY PASS\n"),
            ["FO BEGIN", "IDENTITY PASS"],
        )

    def test_extract_live_serial_starts_after_bios_only_boot(self) -> None:
        raw = (
            "86Box diagnostic\n"
            "K15 boot\n"
            "K15 net ready\r\n"
            "preflight cache\r\n"
            "DEADLINE PASS\r\n"
            "PASS\r\n"
            "RESULT\r\n"
        )
        serial = RUNNER.extract_live_serial(raw)
        self.assertEqual(
            serial,
            "K15 net ready\n"
            "preflight cache\n"
            "DEADLINE PASS\n"
            "PASS\n"
            "RESULT\n",
        )
        self.assertTrue(RUNNER.result_seen(serial))
        self.assertEqual(RUNNER.terminal_status(serial), "PASS")
        self.assertFalse(RUNNER.success_markers_in_order(serial))

    def test_extract_live_serial_does_not_complete_uart_prefix(self) -> None:
        raw = "86Box diagnostic\nK15 net ready\r\nENTRO"
        serial = RUNNER.extract_live_serial(raw)
        self.assertEqual(serial, "K15 net ready\nENTRO")
        self.assertEqual(
            RUNNER.completed_exact_lines(serial),
            ["K15 net ready"],
        )
        completed = RUNNER.extract_live_serial(
            raw + "PY START 256\r\n"
        )
        self.assertEqual(
            RUNNER.completed_exact_lines(completed),
            ["K15 net ready", "ENTROPY START 256"],
        )

    def test_success_markers_allow_either_head_ticket_order(self) -> None:
        ticket_first = (
            "K15 net ready\n"
            "preflight cache\n"
            "offline keygen\n"
            "live connect\n"
            "HEAD TX\n"
            "TICKET\n"
            "HEAD OK\n"
            "CANARY COMMIT\n"
            "PASS\n"
            "RESULT\n"
        )
        head_first = ticket_first.replace(
            "TICKET\nHEAD OK",
            "HEAD OK\nTICKET",
        )
        self.assertTrue(RUNNER.success_markers_in_order(ticket_first))
        self.assertTrue(RUNNER.success_markers_in_order(head_first))

    def test_success_markers_enforce_full_partial_order(self) -> None:
        serial = (
            "K15 net ready\n"
            "preflight cache\n"
            "offline keygen\n"
            "live connect\n"
            "DEADLINE PASS\n"
            "HEAD TX\n"
            "TICKET\n"
            "HEAD OK\n"
            "CANARY COMMIT\n"
            "PASS\n"
            "RESULT\n"
        )
        invalid = {
            "prefix order": serial.replace(
                "preflight cache\noffline keygen",
                "offline keygen\npreflight cache",
            ),
            "ticket before HEAD TX": serial.replace(
                "HEAD TX\nTICKET",
                "TICKET\nHEAD TX",
            ),
            "HEAD OK before HEAD TX": serial.replace(
                "HEAD TX\nTICKET\nHEAD OK",
                "HEAD OK\nHEAD TX\nTICKET",
            ),
            "CANARY before ticket": serial.replace(
                "TICKET\nHEAD OK\nCANARY COMMIT",
                "CANARY COMMIT\nTICKET\nHEAD OK",
            ),
            "CANARY before HEAD OK": serial.replace(
                "HEAD OK\nCANARY COMMIT",
                "CANARY COMMIT\nHEAD OK",
            ),
            "PASS before CANARY": serial.replace(
                "CANARY COMMIT\nPASS",
                "PASS\nCANARY COMMIT",
            ),
            "RESULT before PASS": serial.replace(
                "PASS\nRESULT",
                "RESULT\nPASS",
            ),
        }
        for name, reordered in invalid.items():
            with self.subTest(name=name):
                self.assertFalse(
                    RUNNER.success_markers_in_order(reordered)
                )

    def test_success_markers_must_be_exact(self) -> None:
        serial = (
            "K15 net ready\n"
            "preflight cache\n"
            "offline keygen\n"
            "live connect\n"
            "DEADLINE PASS\n"
            "HEAD TX\n"
            "TICKET\n"
            "HEAD OK\n"
            "CANARY COMMIT\n"
            "PASS\n"
            "RESULT\n"
        )
        approximate = serial.replace("live connect", "live connect...")
        self.assertFalse(RUNNER.success_markers_in_order(approximate))
        missing = serial.replace("HEAD OK\n", "")
        self.assertFalse(RUNNER.success_markers_in_order(missing))

    def test_secure_success_requires_fo_and_kem_before_identity(self) -> None:
        serial = (
            "K15 local ready\n"
            "ENTROPY START 256\n"
            "ENTROPY PASS 256\n"
            "preflight cache\n"
            "offline keygen\n"
            "live connect\n"
            "DEADLINE PASS\n"
            "HEAD TX\n"
            "HEAD OK\n"
            "TICKET\n"
            "FO BEGIN\n"
            "KEM VALID\n"
            "AUTH BEGIN\n"
            "IDENTITY PASS\n"
            "PASS\n"
            "RESULT\n"
        )
        self.assertTrue(
            RUNNER.success_markers_in_order(
                serial,
                identity=True,
                secure=True,
            )
        )
        for marker in ("FO BEGIN\n", "KEM VALID\n"):
            with self.subTest(missing=marker.strip()):
                self.assertFalse(
                    RUNNER.success_markers_in_order(
                        serial.replace(marker, ""),
                        identity=True,
                        secure=True,
                    )
                )
        reordered = serial.replace(
            "KEM VALID\nAUTH BEGIN",
            "AUTH BEGIN\nKEM VALID",
        )
        self.assertFalse(
            RUNNER.success_markers_in_order(
                reordered,
                identity=True,
                secure=True,
            )
        )
        without_entropy = serial.replace("ENTROPY PASS 256\n", "")
        self.assertFalse(
            RUNNER.success_markers_in_order(
                without_entropy,
                identity=True,
                secure=True,
            )
        )
        unsafe_preflight_order = serial.replace(
            "preflight cache\noffline keygen",
            "offline keygen\npreflight cache",
        )
        self.assertFalse(
            RUNNER.success_markers_in_order(
                unsafe_preflight_order,
                identity=True,
                secure=True,
            )
        )

    def test_identity_only_output_is_not_secure_success(self) -> None:
        serial = (
            "K15 net ready\n"
            "preflight cache\n"
            "offline keygen\n"
            "live connect\n"
            "DEADLINE PASS\n"
            "HEAD TX\n"
            "TICKET\n"
            "HEAD OK\n"
            "AUTH BEGIN\n"
            "IDENTITY PASS\n"
            "PASS\n"
            "RESULT\n"
        )
        self.assertTrue(
            RUNNER.success_markers_in_order(serial, identity=True)
        )
        self.assertFalse(
            RUNNER.success_markers_in_order(
                serial,
                identity=True,
                secure=True,
            )
        )

    def test_automatic_entropy_requires_no_keyboard_injection(self) -> None:
        source = inspect.getsource(RUNNER.run_live)
        self.assertNotIn("functional_entropy_input", source)
        self.assertNotIn("functional-auto", source)
        self.assertNotIn("automated_input_submitted", source)
        self.assertEqual(RUNNER.ENTROPY_START_MARKER, "ENTROPY START 256")
        self.assertEqual(RUNNER.ENTROPY_PASS_MARKER, "ENTROPY PASS 256")

    def test_result_before_serial_start_cannot_end_run(self) -> None:
        raw = "86Box RESULT diagnostic\nRESULT\nK15 boot\n"
        serial = RUNNER.extract_live_serial(raw)
        self.assertEqual(serial, "")
        self.assertFalse(RUNNER.result_seen(serial))

    def test_exact_profile_is_checked_before_and_after_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "86box.cfg"
            config.write_text(
                vm_config_text(ram_kib=RUNNER.PROFILE_BASE_RAM_KIB),
                encoding="utf-8",
            )
            before = RUNNER.require_exact_vm_config(
                config,
                ram_kib=RUNNER.PROFILE_BASE_RAM_KIB,
                phase="pre-rewrite",
            )
            self.assertEqual(before["cpu_speed"], "4772728")

            config.write_text(
                vm_config_text(ram_kib=RUNNER.RAM_KIB),
                encoding="utf-8",
            )
            after = RUNNER.require_exact_vm_config(
                config,
                ram_kib=RUNNER.RAM_KIB,
                phase="post-rewrite",
            )
            self.assertEqual(after["mem_size"], "16")

    def test_exact_profile_rejects_cpu_or_ram_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "86box.cfg"
            config.write_text(
                vm_config_text(ram_kib=16, cpu_speed=8_000_000),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RuntimeError,
                r"cpu_speed='8000000'.*expected '4772728'",
            ):
                RUNNER.require_exact_vm_config(
                    config,
                    ram_kib=RUNNER.RAM_KIB,
                    phase="post-rewrite",
                )

            config.write_text(vm_config_text(ram_kib=32), encoding="utf-8")
            with self.assertRaisesRegex(
                RuntimeError,
                r"mem_size='32'.*expected '16'",
            ):
                RUNNER.require_exact_vm_config(
                    config,
                    ram_kib=RUNNER.RAM_KIB,
                    phase="post-rewrite",
                )

    def test_live_runner_rejects_an_alternate_profile_name(self) -> None:
        with self.assertRaisesRegex(
            SystemExit,
            r"requires the exact vm-net-ne2k8 profile",
        ):
            RUNNER.validate_profile(mock.Mock(), "vm-net-ne1k")

    def test_post_rewrite_drift_blocks_launch_and_restores_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vm_path = root / RUNNER.DEFAULT_PROFILE
            vm_path.mkdir()
            config = vm_path / "86box.cfg"
            original_config = vm_config_text(
                ram_kib=RUNNER.PROFILE_BASE_RAM_KIB
            ).encode()
            config.write_bytes(original_config)
            floppy = root / "floppy.img"
            floppy.write_bytes(b"read-only canary")
            floppy.chmod(0o644)
            basic = root / "LIVEK15.BAS"
            basic.write_text("10 END\n", encoding="ascii")

            harness = mock.Mock()

            def drift_rewrite(*_args: object, **_kwargs: object) -> None:
                config.write_text(
                    vm_config_text(ram_kib=16, cpu_speed=8_000_000),
                    encoding="utf-8",
                )

            harness.rewrite_vm_config.side_effect = drift_rewrite
            spike = mock.Mock()
            capture = mock.Mock()
            spike.PipeSerialCapture.return_value = capture

            with (
                mock.patch.object(
                    RUNNER,
                    "validate_profile",
                    return_value=(vm_path, config),
                ),
                mock.patch.object(
                    RUNNER.os,
                    "open",
                    side_effect=PermissionError("read-only"),
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    r"post-rewrite.*cpu_speed='8000000'",
                ),
            ):
                RUNNER.run_live(
                    harness,
                    spike,
                    profile=RUNNER.DEFAULT_PROFILE,
                    floppy=floppy,
                    basic=basic,
                    stdout_path=root / "stdout.txt",
                    serial_path=root / "serial.txt",
                    pcap_path=root / "capture.pcap",
                    timeout=30.0,
                    start_timeout=5.0,
                    window_timeout=5.0,
                    startup_delay=0.0,
                    type_delay=0.01,
                    line_delay=0.1,
                    post_result_delay=0.5,
                    pcap_filter="tcp port 443",
                    pcap_iface="test0",
                )

            harness.launch_86box.assert_not_called()
            self.assertEqual(config.read_bytes(), original_config)
            self.assertEqual(floppy.stat().st_mode & 0o777, 0o644)
            capture.finish.assert_called_once_with()

    def test_cleanup_attempts_every_restore_and_aggregates_failures(self) -> None:
        pcap_capture = mock.Mock()
        pcap_capture.stop.side_effect = OSError("pcap stop blocked")
        process = mock.Mock(pid=1234)
        process.poll.return_value = None
        process.kill.side_effect = OSError("process kill blocked")
        capture = mock.Mock()
        capture.finish.side_effect = OSError("capture finish blocked")
        config = mock.Mock()
        config.write_bytes.side_effect = OSError("config write blocked")
        config.read_bytes.return_value = b"wrong config"
        nvr = mock.Mock()
        nvr.write_bytes.side_effect = OSError("NVR write blocked")
        nvr.read_bytes.return_value = b"wrong NVR"
        floppy = mock.Mock()
        floppy.read_bytes.return_value = b"unchanged contents"
        floppy.chmod.side_effect = OSError("chmod blocked")
        floppy.stat.return_value = SimpleNamespace(st_mode=0o444)

        with self.assertRaises(RuntimeError) as raised:
            RUNNER.cleanup_live_state(
                pcap_capture=pcap_capture,
                pcap_started=True,
                process=process,
                capture=capture,
                config=config,
                original_config=b"original config",
                restore_nvr=(nvr, b"original NVR"),
                floppy=floppy,
                original_floppy_mode=0o644,
            )

        message = str(raised.exception)
        for failure in (
            "stop pcap",
            "stop launched 86Box process",
            "finish serial capture",
            "restore 86Box config",
            "restore 86Box NVR",
            "restore floppy mode",
            "verify 86Box config",
            "verify 86Box NVR",
            "verify floppy mode",
        ):
            self.assertIn(failure, message)
        config.write_bytes.assert_called_once_with(b"original config")
        nvr.write_bytes.assert_called_once_with(b"original NVR")
        floppy.read_bytes.assert_called_once_with()
        floppy.chmod.assert_called_once_with(0o644)

    def test_cleanup_restores_mode_even_when_post_run_hash_fails(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 0
        capture = mock.Mock()
        config = mock.Mock()
        config.read_bytes.return_value = b"original config"
        floppy = mock.Mock()
        floppy.read_bytes.side_effect = OSError("hash read blocked")
        floppy.stat.return_value = SimpleNamespace(st_mode=0o644)

        with self.assertRaisesRegex(
            RuntimeError,
            r"hash floppy after run.*hash read blocked",
        ):
            RUNNER.cleanup_live_state(
                pcap_capture=None,
                pcap_started=False,
                process=process,
                capture=capture,
                config=config,
                original_config=b"original config",
                restore_nvr=None,
                floppy=floppy,
                original_floppy_mode=0o644,
            )

        floppy.chmod.assert_called_once_with(0o644)
        config.write_bytes.assert_called_once_with(b"original config")

    def test_floppy_integrity_is_a_success_gate(self) -> None:
        safe = {
            "read_only_requested": True,
            "mode_during_run": "0o444",
            "host_write_open_denied": True,
            "sha256_before": "a" * 64,
            "sha256_after": "a" * 64,
            "unchanged": True,
            "mode_restored": True,
        }
        self.assertTrue(RUNNER.floppy_media_integrity_passed(safe))
        for field in (
            "read_only_requested",
            "host_write_open_denied",
            "unchanged",
            "mode_restored",
        ):
            unsafe = dict(safe)
            unsafe[field] = False
            self.assertFalse(
                RUNNER.floppy_media_integrity_passed(unsafe),
                field,
            )
        hash_drift = dict(safe, sha256_after="b" * 64)
        self.assertFalse(RUNNER.floppy_media_integrity_passed(hash_drift))
        self.assertIn(
            'result["floppy_media"]["integrity_gate_passed"]',
            inspect.getsource(RUNNER.main),
        )

    def test_cleanup_has_no_global_86box_pid_sweep(self) -> None:
        source = inspect.getsource(RUNNER.run_live)
        self.assertNotIn("all_86box_pids", source)
        self.assertNotIn("stop_spawned_86box_pids", source)


if __name__ == "__main__":
    unittest.main()
