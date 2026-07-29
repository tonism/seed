from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def import_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = import_file("seed_test_run_post_auth_live", HERE / "run_post_auth_live.py")
HARNESS = import_file(
    "seed_test_run_basic_bootstrap",
    ROOT / "tools/run-basic-bootstrap-86box.py",
)


class StrictSerialCreditTests(unittest.TestCase):
    def test_exact_ordered_terminal_success(self) -> None:
        serial = (
            b"K15 local ready\r\n"
            b"ENTROPY START 256\r\n"
            b"offline work\r\n"
            b"ENTROPY PASS 256\r\n"
            b"authenticated work\r\n"
            b"ok\r\n"
            b"PASS\r\n"
            b"RESULT\r\n"
        )
        state = RUNNER.inspect_credited_serial(serial)
        self.assertTrue(state.collection_started)
        self.assertTrue(state.entropy_passed)
        self.assertTrue(state.success)
        self.assertFalse(state.failure)

    def test_partial_terminal_line_receives_no_credit(self) -> None:
        serial = (
            b"ENTROPY START 256\r\n"
            b"ENTROPY PASS 256\r\n"
            b"ok\r\n"
            b"PASS\r\n"
            b"RESULT"
        )
        state = RUNNER.inspect_credited_serial(serial)
        self.assertFalse(state.success)

    def test_prefixed_and_suffixed_entropy_markers_are_rejected(self) -> None:
        for serial in (
            b"prefix ENTROPY START 256\r\n",
            b"ENTROPY PASS 256 suffix\r\n",
        ):
            with self.subTest(serial=serial):
                with self.assertRaisesRegex(RuntimeError, "exact CRLF"):
                    RUNNER.inspect_credited_serial(serial)

    def test_duplicate_markers_are_rejected(self) -> None:
        serial = (
            b"ENTROPY START 256\r\n"
            b"ENTROPY START 256\r\n"
        )
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            RUNNER.inspect_credited_serial(serial)

    def test_out_of_order_entropy_markers_are_rejected(self) -> None:
        serial = (
            b"ENTROPY PASS 256\r\n"
            b"ENTROPY START 256\r\n"
        )
        with self.assertRaisesRegex(RuntimeError, "preceded"):
            RUNNER.inspect_credited_serial(serial)

    def test_noncontiguous_terminal_markers_are_rejected(self) -> None:
        serial = (
            b"ENTROPY START 256\r\n"
            b"ENTROPY PASS 256\r\n"
            b"ok\r\n"
            b"unexpected\r\n"
            b"PASS\r\n"
            b"RESULT\r\n"
        )
        with self.assertRaisesRegex(RuntimeError, "contiguous"):
            RUNNER.inspect_credited_serial(serial)

    def test_success_before_entropy_pass_is_rejected(self) -> None:
        serial = (
            b"ENTROPY START 256\r\n"
            b"ok\r\n"
            b"PASS\r\n"
            b"RESULT\r\n"
        )
        with self.assertRaisesRegex(RuntimeError, "preceded"):
            RUNNER.inspect_credited_serial(serial)


class RunnerOwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_argv = sys.argv

    def tearDown(self) -> None:
        sys.argv = self.old_argv

    @staticmethod
    def authorized_argv(build: Path) -> list[str]:
        return [
            "run_post_auth_live.py",
            "--credentialed-live",
            "--automatic-floppy-entropy",
            "--user-cfg",
            "opaque-test-input",
            "--build-dir",
            str(build),
        ]

    def test_failed_rerun_removes_stale_report_and_releases_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            build = Path(temporary_name)
            report = build / RUNNER.PASS_REPORT_NAME
            lock = build / RUNNER.RUN_LOCK_NAME
            report.write_text("stale pass\n", encoding="utf-8")

            @RUNNER.exclusive_credentialed_run
            def fail_after_ownership() -> None:
                self.assertFalse(report.exists())
                self.assertTrue(lock.exists())
                raise RuntimeError("intentional offline failure")

            sys.argv = self.authorized_argv(build)
            with self.assertRaisesRegex(RuntimeError, "intentional"):
                fail_after_ownership()
            self.assertFalse(report.exists())
            self.assertFalse(lock.exists())

    def test_concurrent_owner_is_rejected_without_touching_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            build = Path(temporary_name)
            report = build / RUNNER.PASS_REPORT_NAME
            lock = build / RUNNER.RUN_LOCK_NAME
            report.write_text("active evidence\n", encoding="utf-8")
            called = False

            @RUNNER.exclusive_credentialed_run
            def must_not_run() -> None:
                nonlocal called
                called = True

            sys.argv = self.authorized_argv(build)
            with RUNNER.RunnerOwnership(lock):
                with self.assertRaisesRegex(SystemExit, "already owned"):
                    must_not_run()
                self.assertFalse(called)
                self.assertEqual(
                    report.read_text(encoding="utf-8"),
                    "active evidence\n",
                )
            self.assertFalse(lock.exists())

    def test_release_does_not_unlink_replacement_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            lock = Path(temporary_name) / RUNNER.RUN_LOCK_NAME
            owner = RUNNER.RunnerOwnership(lock)
            owner.acquire()
            lock.unlink()
            lock.write_text("replacement\n", encoding="utf-8")
            owner.release()
            self.assertEqual(
                lock.read_text(encoding="utf-8"),
                "replacement\n",
            )


class FixedFifoCaptureTests(unittest.TestCase):
    def test_launch_failure_cleanup_removes_both_fifos(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            output = temporary / "serial.log"
            base = temporary / "serial.pipe"
            capture = HARNESS.ComCapture(output, base)
            capture.start()
            capture.finish()
            capture.finish()
            self.assertEqual(output.read_bytes(), b"")
            self.assertFalse(capture.input_path.exists())
            self.assertFalse(capture.output_fifo.exists())

    def test_finish_drains_queued_fifo_bytes_after_writer_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            output = temporary / "serial.log"
            base = temporary / "serial.pipe"
            payload = b"terminal bytes queued before writer teardown\r\n"
            capture = HARNESS.ComCapture(output, base)
            capture.start()
            writer = os.open(
                capture.output_fifo,
                os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY,
            )
            try:
                self.assertEqual(os.write(writer, payload), len(payload))
            finally:
                os.close(writer)
            capture.finish()
            self.assertEqual(output.read_bytes(), payload)
            self.assertFalse(capture.input_path.exists())
            self.assertFalse(capture.output_fifo.exists())

    def test_harness_launch_failure_restores_config_and_cleans_fifos(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            profile = temporary / "profile"
            profile.mkdir()
            config = profile / "86box.cfg"
            original_config = (
                "[General]\n"
                "video_filter_method = 0\n"
                "\n"
                "[Machine]\n"
                "machine = ibmpc\n"
                "mem_size = 16\n"
                "\n"
                "[Floppy and CD-ROM drives]\n"
                "fdd_01_type = 525_1dd\n"
                "fdd_01_fn =\n"
                "fdd_02_type = none\n"
                "fdd_02_fn =\n"
                "\n"
                "[Ports (COM & LPT)]\n"
                "serial1_device = none\n"
            ).encode("utf-8")
            config.write_bytes(original_config)
            floppy = temporary / "floppy.img"
            floppy.write_bytes(bytes(160 * 1024))
            basic = temporary / "BOOT.BAS"
            basic.write_text("10 REM OFFLINE CLEANUP TEST\n", encoding="ascii")
            serial = temporary / "serial.log"
            pipe_base = serial.with_suffix(serial.suffix + ".pipe")

            old_argv = sys.argv
            old_launch = HARNESS.launch_86box

            def fail_launch(*_args, **_kwargs):
                raise RuntimeError("intentional offline launch failure")

            HARNESS.launch_86box = fail_launch
            sys.argv = [
                "run-basic-bootstrap-86box.py",
                "--profile",
                "offline-cleanup",
                "--vm-path",
                str(profile),
                "--entry",
                "basic",
                "--ram-kib",
                "16",
                "--basic",
                str(basic),
                "--floppy",
                str(floppy),
                "--no-build",
                "--com-capture",
                str(serial),
                "--no-screenshot",
                "--allow-existing-86box",
            ]
            try:
                with self.assertRaisesRegex(RuntimeError, "intentional"):
                    HARNESS.main()
            finally:
                HARNESS.launch_86box = old_launch
                sys.argv = old_argv

            self.assertEqual(config.read_bytes(), original_config)
            self.assertEqual(serial.read_bytes(), b"")
            self.assertFalse(Path(f"{pipe_base}.in").exists())
            self.assertFalse(Path(f"{pipe_base}.out").exists())


if __name__ == "__main__":
    unittest.main()
