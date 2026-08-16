#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import stat
import subprocess
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
HARNESS_PATH = ROOT / "tools/run-basic-bootstrap-86box.py"
SPEC = importlib.util.spec_from_file_location("seed_basic_bootstrap_harness", HARNESS_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {HARNESS_PATH}")
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class RtcUtcConfigTests(unittest.TestCase):
    def rewrite(self, source: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "86box.cfg"
            floppy = root / "floppy-360k.img"
            config.write_text(source, encoding="utf-8")
            floppy.write_bytes(bytes(368_640))
            HARNESS.rewrite_vm_config(
                config,
                512,
                floppy,
                False,
                muted=False,
                attest_rtc_utc=True,
                floppy_read_only=True,
            )
            return config.read_text(encoding="utf-8")

    def test_replaces_existing_time_sync_and_memory(self) -> None:
        result = self.rewrite(
            "[General]\n"
            "video_filter_method = 0\n"
            "\n"
            "[Machine]\n"
            "machine = ami286\n"
            "mem_size = 2048\n"
            "time_sync = local\n"
            "time_sync = disabled\n"
            "\n"
            "[Floppy and CD-ROM drives]\n"
            "fdd_01_type = 525_2hd\n"
        )
        self.assertEqual(result.count("time_sync = utc"), 1)
        self.assertNotIn("time_sync = local", result)
        self.assertIn("mem_size = 512", result)
        self.assertIn("fdd_01_writeprot = 1", result)

    def test_inserts_missing_time_sync_inside_machine_section(self) -> None:
        result = self.rewrite(
            "[General]\n"
            "\n"
            "[Machine]\n"
            "machine = ami286\n"
            "mem_size = 512\n"
            "\n"
            "[Video]\n"
            "gfxcard = cga\n"
            "\n"
            "[Floppy and CD-ROM drives]\n"
            "fdd_01_type = 525_2hd\n"
        )
        machine = result.index("[Machine]")
        time_sync = result.index("time_sync = utc")
        video = result.index("[Video]")
        self.assertLess(machine, time_sync)
        self.assertLess(time_sync, video)

    def test_rejects_config_without_machine_section(self) -> None:
        with self.assertRaisesRegex(ValueError, r"\[Machine\]"):
            self.rewrite(
                "[General]\n"
                "\n"
                "[Floppy and CD-ROM drives]\n"
                "fdd_01_type = 525_2hd\n"
            )


class RtcUtcPromptTests(unittest.TestCase):
    def test_recognizes_only_the_ami286_memory_test_prompt(self) -> None:
        self.assertTrue(
            HARNESS.ocr_lines_suggest_ami286_memory_test(
                [
                    "286-BIOS (C)1989 American Megatrends Inc",
                    "00192 KB OK",
                    "Press {ESC} to bypass MEMORY test",
                ]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_ami286_memory_test(
                ["Press ESC to bypass memory test"]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_ami286_memory_test(
                ["American Megatrends", "RTC is set to UTC (y/n)?"]
            )
        )

    def test_memory_test_is_bypassed_once_without_waiting_for_seed_question(self) -> None:
        args = SimpleNamespace(
            ami286_memory_bypass_timeout=30.0,
            ami286_memory_bypass_interval=1.0,
            oracle_screenshot=Path("/tmp/seed-rtc-bios-oracle.png"),
            profile="vm-net-286",
            screen_ocr_timeout=1.0,
        )
        process = mock.Mock(pid=286)
        process.poll.return_value = None
        bios = [
            "286-BIOS (C)1989 American Megatrends Inc",
            "00192 KB OK",
            "Press {ESC} to bypass MEMORY test",
        ]
        seed = ["seed build 13", "How can I help you", ">"]
        with (
            mock.patch.object(
                HARNESS,
                "screenshot_86box_window_or_screen",
                return_value=True,
            ),
            mock.patch.object(
                HARNESS,
                "screen_ocr_lines",
                side_effect=[
                    ("fixture-ocr", bios),
                    ("fixture-ocr", bios),
                    ("fixture-ocr", seed),
                ],
            ),
            mock.patch.object(
                HARNESS,
                "AMI286_MEMORY_BYPASS_DELAY_SECONDS",
                0.0,
            ),
            mock.patch.object(HARNESS, "post_pid_focused_keycode") as post_key,
            mock.patch.object(HARNESS.time, "monotonic", return_value=0.0),
            mock.patch.object(HARNESS.time, "sleep"),
        ):
            self.assertTrue(HARNESS.bypass_ami286_memory_test(args, process))
        post_key.assert_called_once_with(286, 53, restore_focus=False)

    def test_recognizes_seed_greeting_without_treating_arbitrary_text_as_ready(self) -> None:
        self.assertTrue(
            HARNESS.ocr_lines_suggest_seed_greeting(
                ["seed build 13", "security note", "Hellot How can I help you"]
            )
        )
        self.assertTrue(
            HARNESS.ocr_lines_suggest_seed_greeting(
                ["seed", "RIC is set to UTC Cy/n)?", "hel", "Hellot How can I help you today?"]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_seed_greeting(
                ["the model asked how can I help", ">"]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_dpi_ready(
                ["seed build 13", "Hellot How can I help you"]
            )
        )

    def test_final_oracle_promotes_authenticated_greeting(self) -> None:
        args = SimpleNamespace(
            oracle_screenshot=Path("/tmp/seed-greeting-oracle.png"),
            profile="vm-net-ne2k8",
            no_screen_ocr=False,
            screen_ocr_timeout=1.0,
            screen_expect_text=[],
            keep_success_oracle_screenshot=True,
        )
        process = mock.Mock(pid=5150)
        with (
            mock.patch.object(
                HARNESS,
                "screenshot_86box_window_or_screen",
                return_value=True,
            ),
            mock.patch.object(
                HARNESS,
                "classify_86box_screen",
                return_value=("ambiguous", "fixture"),
            ),
            mock.patch.object(
                HARNESS,
                "screen_ocr_lines",
                return_value=(
                    "fixture-ocr",
                    ["seed build 13", "security note", "How can I help you"],
                ),
            ),
            mock.patch.object(HARNESS, "print_screen_ocr_lines"),
        ):
            verdict, detail = HARNESS.classify_running_vm(
                args,
                process,
                "fixture oracle",
            )
        self.assertEqual(verdict, "success")
        self.assertEqual(detail, "ocr_fixture-ocr_greeting")

    def test_recognizes_failure_menu_when_dim_error_line_is_missing(self) -> None:
        self.assertTrue(
            HARNESS.ocr_lines_suggest_seed_failure_menu(
                ["retry on restart?", "i, retry", "2, restart"]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_seed_failure_menu(
                ["the model said retry, then restart"]
            )
        )

    def test_failure_menu_overrides_dpi_shaped_screen(self) -> None:
        args = SimpleNamespace(
            oracle_screenshot=Path("/tmp/seed-failure-oracle.png"),
            profile="vm",
            no_screen_ocr=False,
            screen_ocr_timeout=1.0,
            screen_expect_text=[],
            keep_success_oracle_screenshot=True,
        )
        process = mock.Mock(pid=5150)
        with (
            mock.patch.object(
                HARNESS,
                "screenshot_86box_window_or_screen",
                return_value=True,
            ),
            mock.patch.object(
                HARNESS,
                "classify_86box_screen",
                return_value=("success", "dpi_prompt"),
            ),
            mock.patch.object(
                HARNESS,
                "screen_ocr_lines",
                return_value=(
                    "fixture-ocr",
                    ["retry op restart?", "1, retry", "2, restart", ">"],
                ),
            ),
            mock.patch.object(HARNESS, "print_screen_ocr_lines"),
        ):
            verdict, detail = HARNESS.classify_running_vm(
                args,
                process,
                "fixture oracle",
            )
        self.assertEqual(verdict, "clean-failure")
        self.assertEqual(detail, "ocr_fixture-ocr_failure_menu")

    def test_requires_exact_question_and_choice_shape(self) -> None:
        self.assertTrue(
            HARNESS.ocr_lines_suggest_rtc_utc_question(
                ["RTC is set to UTC (y/n)?", "> "]
            )
        )
        self.assertTrue(
            HARNESS.ocr_lines_suggest_rtc_utc_question(
                ["rtc is set to utc ( y / n ) ?"]
            )
        )
        self.assertTrue(
            HARNESS.ocr_lines_suggest_rtc_utc_question(
                ["RIC is set to UTC Cy/n)?", ">"]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_rtc_utc_question(
                ["RTC is set to UTC?", "> "]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_rtc_utc_question(
                ["Reply with only UTC", "> "]
            )
        )

    def test_recognizes_only_answer_after_question(self) -> None:
        self.assertTrue(
            HARNESS.ocr_lines_suggest_rtc_utc_answered(
                ["RTC is set to UTC (y/n)?", "", "> y"]
            )
        )
        self.assertTrue(
            HARNESS.ocr_lines_suggest_rtc_utc_answered(
                ["RTC is set", "to UTC (y/n)?", "> y"]
            )
        )
        self.assertTrue(
            HARNESS.ocr_lines_suggest_rtc_utc_answered(
                ["RIC is set to UTC Cy/n)?", "> y"]
            )
        )
        self.assertTrue(
            HARNESS.ocr_lines_suggest_rtc_utc_answered(
                ["RIC is set to UTC Cy/n)?", "dy"]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_rtc_utc_answered(
                ["y", "RTC is set to UTC (y/n)?", "> "]
            )
        )
        self.assertFalse(
            HARNESS.ocr_lines_suggest_rtc_utc_answered(
                ["RTC is set to UTC (y/n)?", "> n"]
            )
        )

    def test_submits_one_y_without_newline(self) -> None:
        with mock.patch.object(HARNESS, "post_pid_focused_keycode") as post_key:
            HARNESS.submit_rtc_utc_answer(42, 0.03, 0.3)
        post_key.assert_called_once_with(
            42,
            HARNESS.KEY_CODES["y"][0],
            restore_focus=False,
        )

    def test_recognizes_paused_zero_hz_status(self) -> None:
        def write_fixture(path: Path, glyph_x: list[int]) -> None:
            width, height = 640, 483
            pixels = bytearray(width * height * 3)
            for y in range(height):
                for x in range(width):
                    off = (y * width + x) * 3
                    shade = 48 if y >= 445 else 0
                    pixels[off : off + 3] = bytes((shade, shade, shade))
            for x0 in glyph_x + [580]:
                for y in range(462, 474):
                    for x in range(x0, x0 + 7):
                        off = (y * width + x) * 3
                        pixels[off : off + 3] = b"\xff\xff\xff"
            raw = b"".join(
                b"\0" + bytes(pixels[y * width * 3 : (y + 1) * width * 3])
                for y in range(height)
            )

            def chunk(kind: bytes, payload: bytes) -> bytes:
                body = kind + payload
                return (
                    HARNESS.struct.pack(">I", len(payload))
                    + body
                    + HARNESS.struct.pack(">I", HARNESS.zlib.crc32(body) & 0xFFFFFFFF)
                )

            path.write_bytes(
                b"\x89PNG\r\n\x1a\n"
                + chunk(
                    b"IHDR",
                    HARNESS.struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0),
                )
                + chunk(b"IDAT", HARNESS.zlib.compress(raw))
                + chunk(b"IEND", b"")
            )

        with tempfile.TemporaryDirectory() as tmp:
            paused = Path(tmp) / "paused.png"
            running = Path(tmp) / "running.png"
            write_fixture(paused, [530, 542, 553])
            write_fixture(running, [515, 525, 535, 545])
            self.assertTrue(HARNESS.image_suggests_86box_paused(paused))
            self.assertFalse(HARNESS.image_suggests_86box_paused(running))


class DenseGlyphScreenTests(unittest.TestCase):
    @staticmethod
    def write_png(path: Path, width: int, height: int, pixels: bytearray) -> None:
        raw = b"".join(
            b"\0" + bytes(pixels[y * width * 3 : (y + 1) * width * 3])
            for y in range(height)
        )

        def chunk(kind: bytes, payload: bytes) -> bytes:
            body = kind + payload
            return (
                HARNESS.struct.pack(">I", len(payload))
                + body
                + HARNESS.struct.pack(
                    ">I", HARNESS.zlib.crc32(body) & 0xFFFFFFFF
                )
            )

        path.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(
                b"IHDR",
                HARNESS.struct.pack(
                    ">IIBBBBB", width, height, 8, 2, 0, 0, 0
                ),
            )
            + chunk(b"IDAT", HARNESS.zlib.compress(raw))
            + chunk(b"IEND", b"")
        )

    def test_full_screen_binary_glyphs_are_never_shape_success(self) -> None:
        width, height = 640, 400
        pixels = bytearray(width * height * 3)
        # Fill 25 text rows and 80 columns with varied high-density glyph
        # strokes.  This is the visible shape produced when character/attribute
        # pairs from an MDA vault are scanned as text.
        for cell_y in range(25):
            for cell_x in range(80):
                for dy in range(16):
                    for dx in range(8):
                        if (dx + dy + cell_x * 3 + cell_y * 5) % 4 == 0:
                            continue
                        x = cell_x * 8 + dx
                        y = cell_y * 16 + dy
                        off = (y * width + x) * 3
                        pixels[off : off + 3] = b"\xdd\xdd\xdd"
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "dense-glyphs.png"
            self.write_png(fixture, width, height, pixels)
            verdict, detail = HARNESS.classify_86box_screen(fixture)
        self.assertEqual(verdict, "dense-glyph-screen", detail)


class PostDpiExpectedResponseTests(unittest.TestCase):
    def test_main_rejects_expectation_count_mismatch(self) -> None:
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    str(HARNESS_PATH),
                    "--post-dpi-text",
                    "reply with only mango",
                    "--post-dpi-expect-text",
                    "ORCHID-731",
                    "--post-dpi-expect-text",
                    "SECOND-RESPONSE",
                    "--screen-oracle",
                ],
            ),
            self.assertRaisesRegex(
                SystemExit,
                "--post-dpi-expect-text count must match",
            ),
        ):
            HARNESS.main()

    def test_validation_is_noop_when_expectations_are_omitted(self) -> None:
        HARNESS.validate_post_dpi_expectations(
            ["reply with only mango"],
            [],
            screen_oracle=False,
            no_screen_ocr=True,
        )

    def test_validation_rejects_prompt_echo_as_expectation(self) -> None:
        with self.assertRaisesRegex(
            SystemExit,
            "must not already appear",
        ):
            HARNESS.validate_post_dpi_expectations(
                ["reply with only mango"],
                ["mango"],
                screen_oracle=True,
                no_screen_ocr=False,
            )

    def run_prompt_gate(
        self,
        ocr_samples: list[list[str]],
        *,
        expected_response_text: str | None,
        attest_rtc_utc: bool = False,
        changed_from_crc: int | None = 0x9999,
        response_crc_samples: list[int] | None = None,
    ) -> tuple[bool, int]:
        args = SimpleNamespace(
            oracle_screenshot=Path("/tmp/seed-post-dpi-oracle.png"),
            profile="vm-net-ne2k8",
            screen_ocr_timeout=1.0,
            keep_success_oracle_screenshot=True,
            attest_rtc_utc=attest_rtc_utc,
        )
        process = mock.Mock(pid=5150)
        process.poll.return_value = None
        with (
            mock.patch.object(
                HARNESS,
                "screenshot_86box_window_or_screen",
                return_value=True,
            ),
            mock.patch.object(
                HARNESS,
                "classify_86box_screen",
                return_value=("success", "fixture"),
            ),
            mock.patch.object(
                HARNESS,
                "screen_ocr_lines",
                side_effect=[
                    ("fixture-ocr", lines) for lines in ocr_samples
                ],
            ) as ocr,
            mock.patch.object(
                HARNESS,
                "image_suggests_dpi_prompt",
                return_value=True,
            ),
            mock.patch.object(
                HARNESS,
                "image_prompt_band_crc",
                return_value=0x1234,
            ),
            mock.patch.object(
                HARNESS,
                "image_response_area_crc",
                side_effect=(
                    response_crc_samples
                    if response_crc_samples is not None
                    else [0x5678] * len(ocr_samples)
                ),
            ),
            mock.patch.object(HARNESS, "print_screen_ocr_lines"),
            mock.patch.object(HARNESS.time, "monotonic", return_value=0.0),
            mock.patch.object(HARNESS.time, "sleep"),
        ):
            result = HARNESS.wait_for_dpi_prompt(
                args,
                process,
                "fixture post-DPI gate",
                5.0,
                0.1,
                changed_from_crc=changed_from_crc,
                expected_response_text=expected_response_text,
            )
        return result, ocr.call_count

    def test_prompt_echo_does_not_satisfy_expected_response(self) -> None:
        prompt = "reply with only mango"
        response_token = "ORCHID-731"
        self.assertNotIn(response_token.casefold(), prompt.casefold())
        result, samples = self.run_prompt_gate(
            [
                [prompt, ">"],
                [prompt, ">"],
                [prompt, response_token, ">"],
            ],
            expected_response_text=response_token,
        )
        self.assertTrue(result)
        self.assertEqual(samples, 3)

    def test_omitted_expectation_preserves_existing_prompt_gate(self) -> None:
        prompt_echo = ["reply with only mango", ">"]
        result, samples = self.run_prompt_gate(
            [prompt_echo, prompt_echo],
            expected_response_text=None,
        )
        self.assertTrue(result)
        self.assertEqual(samples, 2)

    def test_rtc_question_is_not_a_dpi_prompt(self) -> None:
        rtc = ["RIC is set to UTC Cy/n)?", ">"]
        dpi = ["hello from seed", ">"]
        result, samples = self.run_prompt_gate(
            [rtc, rtc, dpi, dpi],
            expected_response_text=None,
        )
        self.assertTrue(result)
        self.assertEqual(samples, 4)

    def test_answered_rtc_question_in_scrollback_allows_dpi_prompt(self) -> None:
        answered = [
            "RIC is set to UTC Cy/n)?",
            "> y",
            "Hello! How can I help you today?",
            ">",
        ]
        result, samples = self.run_prompt_gate(
            [answered, answered],
            expected_response_text=None,
        )
        self.assertTrue(result)
        self.assertEqual(samples, 2)

class RtcUtcGuardTests(unittest.TestCase):
    def validate(self, **overrides: object) -> None:
        values: dict[str, object] = {
            "enabled": True,
            "entry": "direct",
            "ram_kib": 512,
            "machine_settings": dict(HARNESS.RTC_UTC_ATTEST_MACHINE_SETTINGS),
            "screen_ocr_disabled": False,
            "prompt_timeout": 300.0,
            "answer_timeout": 30.0,
            "interval": 1.0,
            "leave_running": False,
            "long_running": False,
        }
        values.update(overrides)
        HARNESS.validate_rtc_utc_attestation(**values)

    def test_accepts_exact_direct_ami286_shape(self) -> None:
        self.validate()

    def test_rejects_non_direct_entry(self) -> None:
        with self.assertRaisesRegex(SystemExit, "--entry direct"):
            self.validate(entry="basic")

    def test_rejects_non_ami286_machine(self) -> None:
        with self.assertRaisesRegex(SystemExit, "ami286"):
            settings = dict(HARNESS.RTC_UTC_ATTEST_MACHINE_SETTINGS)
            settings["machine"] = "ibmpc"
            self.validate(machine_settings=settings)

    def test_rejects_non_exact_cpu_floor(self) -> None:
        for key, value in (
            ("cpu_family", "386"),
            ("cpu_speed", "8000000"),
            ("cpu_multi", "2"),
            ("cpu_use_dynarec", "1"),
        ):
            with self.subTest(key=key):
                settings = dict(HARNESS.RTC_UTC_ATTEST_MACHINE_SETTINGS)
                settings[key] = value
                with self.assertRaisesRegex(SystemExit, "exactly 6 MHz"):
                    self.validate(machine_settings=settings)

    def test_rejects_non_exact_ram_floor(self) -> None:
        with self.assertRaisesRegex(SystemExit, "--ram-kib 512"):
            self.validate(ram_kib=1024)

    def test_accepts_nonterminating_modes_without_interactive_input(self) -> None:
        for field in ("leave_running", "long_running"):
            with self.subTest(field=field):
                self.validate(**{field: True})

    def test_accepts_disabled_ocr(self) -> None:
        self.validate(screen_ocr_disabled=True)

    def test_legacy_prompt_timing_arguments_are_noops(self) -> None:
        for field in ("prompt_timeout", "answer_timeout", "interval"):
            with self.subTest(field=field):
                self.validate(**{field: 0.0})


class HarnessSafetyTests(unittest.TestCase):
    def test_read_only_media_is_restored_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            floppy = Path(tmp) / "floppy.img"
            floppy.write_bytes(b"immutable acceptance media")
            floppy.chmod(0o640)
            media = HARNESS.snapshot_floppy_media(floppy)

            HARNESS.make_floppy_read_only(media)
            self.assertEqual(stat.S_IMODE(floppy.stat().st_mode), 0o444)

            HARNESS.restore_harness_state(
                com_capture=None,
                pcap_capture=None,
                restore_config=None,
                restore_nvr=None,
                floppy_media=media,
                test_lock=None,
            )
            self.assertEqual(floppy.read_bytes(), b"immutable acceptance media")
            self.assertEqual(stat.S_IMODE(floppy.stat().st_mode), 0o640)

    def test_cleanup_restores_mode_even_when_media_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            floppy = Path(tmp) / "floppy.img"
            floppy.write_bytes(b"before")
            floppy.chmod(0o600)
            media = HARNESS.snapshot_floppy_media(floppy)
            floppy.write_bytes(b"after")

            with self.assertRaisesRegex(RuntimeError, "SHA-256 changed"):
                HARNESS.restore_harness_state(
                    com_capture=None,
                    pcap_capture=None,
                    restore_config=None,
                    restore_nvr=None,
                    floppy_media=media,
                    test_lock=None,
                )
            self.assertEqual(stat.S_IMODE(floppy.stat().st_mode), 0o600)

    def test_busy_lock_fails_without_replacing_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "vm.lock"
            lock_path.write_text("other owner\n", encoding="utf-8")
            lock = HARNESS.TestLock(lock_path, "test", "profile", 0.0)
            with self.assertRaisesRegex(SystemExit, "test lock busy"):
                lock.acquire()
            self.assertEqual(lock_path.read_text(encoding="utf-8"), "other owner\n")


class HarnessMainSafetyTests(unittest.TestCase):
    @staticmethod
    def fixture(root: Path) -> tuple[Path, Path, Path, bytes, bytes, int]:
        vm_path = root / "vm-net-286"
        nvr_dir = vm_path / "nvr"
        nvr_dir.mkdir(parents=True)
        config = vm_path / "86box.cfg"
        original_config = (
            "[General]\n"
            "video_filter_method = 0\n"
            "\n"
            "[Machine]\n"
            "cpu_family = 286\n"
            "cpu_multi = 1\n"
            "cpu_speed = 6000000\n"
            "cpu_use_dynarec = 0\n"
            "machine = ami286\n"
            "mem_size = 2048\n"
            "\n"
            "[Floppy and CD-ROM drives]\n"
            "fdd_01_type = 525_2hd\n"
            "fdd_02_type = none\n"
        ).encode()
        config.write_bytes(original_config)
        nvr = nvr_dir / "ami286.nvr"
        original_nvr = b"original 286 NVR"
        nvr.write_bytes(original_nvr)
        floppy = root / "floppy-360k.img"
        floppy.write_bytes(bytes(368_640))
        original_mode = 0o640
        floppy.chmod(original_mode)
        return (
            vm_path,
            config,
            nvr,
            original_config,
            original_nvr,
            original_mode,
        )

    @staticmethod
    def argv(vm_path: Path, floppy: Path, *extra: str) -> list[str]:
        return [
            str(HARNESS_PATH),
            "--profile",
            "vm-net-286",
            "--vm-path",
            str(vm_path),
            "--floppy",
            str(floppy),
            "--entry",
            "direct",
            "--ram-kib",
            "512",
            "--attest-rtc-utc",
            "--no-build",
            "--no-screenshot",
            "--startup-delay",
            "0",
            "--capture-delay",
            "0",
            *extra,
        ]

    def assert_restored(
        self,
        *,
        vm_path: Path,
        config: Path,
        nvr: Path,
        floppy: Path,
        original_config: bytes,
        original_nvr: bytes,
        original_mode: int,
    ) -> None:
        self.assertEqual(config.read_bytes(), original_config)
        self.assertEqual(nvr.read_bytes(), original_nvr)
        self.assertEqual(stat.S_IMODE(floppy.stat().st_mode), original_mode)
        self.assertFalse((vm_path / ".seed-rtc-utc.lock").exists())

    def test_lock_precedes_stop_and_launch_exception_restores_all_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (
                vm_path,
                config,
                nvr,
                original_config,
                original_nvr,
                original_mode,
            ) = self.fixture(root)
            floppy = root / "floppy-360k.img"

            def assert_locked_before_stop(_vm_path: Path) -> None:
                self.assertTrue((vm_path / ".seed-rtc-utc.lock").is_file())
                self.assertEqual(config.read_bytes(), original_config)
                self.assertEqual(nvr.read_bytes(), original_nvr)

            def fail_after_mutation(*_args: object, **_kwargs: object) -> None:
                effective = config.read_text(encoding="utf-8")
                self.assertIn("mem_size = 512", effective)
                self.assertIn("time_sync = utc", effective)
                self.assertIn("fdd_01_writeprot = 1", effective)
                self.assertNotEqual(nvr.read_bytes(), original_nvr)
                self.assertEqual(
                    stat.S_IMODE(floppy.stat().st_mode),
                    0o444,
                )
                raise RuntimeError("launch failed")

            with (
                mock.patch.object(sys, "argv", self.argv(vm_path, floppy)),
                mock.patch.object(
                    HARNESS,
                    "stop_matching_86box_pids",
                    side_effect=assert_locked_before_stop,
                ),
                mock.patch.object(
                    HARNESS,
                    "launch_86box",
                    side_effect=fail_after_mutation,
                ),
                self.assertRaisesRegex(RuntimeError, "launch failed"),
            ):
                HARNESS.main()

            self.assert_restored(
                vm_path=vm_path,
                config=config,
                nvr=nvr,
                floppy=floppy,
                original_config=original_config,
                original_nvr=original_nvr,
                original_mode=original_mode,
            )

    def test_partial_nvr_override_exception_restores_and_unlocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (
                vm_path,
                config,
                nvr,
                original_config,
                original_nvr,
                original_mode,
            ) = self.fixture(root)
            floppy = root / "floppy-360k.img"

            def partial_nvr_write(
                restore: tuple[Path, bytes] | None,
                _ram_kib: int | None,
            ) -> None:
                assert restore is not None
                restore[0].write_bytes(b"partial NVR override")
                raise RuntimeError("NVR override failed")

            with (
                mock.patch.object(sys, "argv", self.argv(vm_path, floppy)),
                mock.patch.object(HARNESS, "stop_matching_86box_pids"),
                mock.patch.object(
                    HARNESS,
                    "apply_vm_nvr_override",
                    side_effect=partial_nvr_write,
                ),
                mock.patch.object(HARNESS, "launch_86box") as launch,
                self.assertRaisesRegex(RuntimeError, "NVR override failed"),
            ):
                HARNESS.main()

            launch.assert_not_called()
            self.assert_restored(
                vm_path=vm_path,
                config=config,
                nvr=nvr,
                floppy=floppy,
                original_config=original_config,
                original_nvr=original_nvr,
                original_mode=original_mode,
            )

    def test_post_launch_wait_timeout_restores_and_unlocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (
                vm_path,
                config,
                nvr,
                original_config,
                original_nvr,
                original_mode,
            ) = self.fixture(root)
            floppy = root / "floppy-360k.img"
            process = mock.Mock(pid=286)
            process.wait.side_effect = subprocess.TimeoutExpired("86Box", 5)

            with (
                mock.patch.object(sys, "argv", self.argv(vm_path, floppy)),
                mock.patch.object(HARNESS, "stop_matching_86box_pids"),
                mock.patch.object(HARNESS, "launch_86box", return_value=process),
                mock.patch.object(
                    HARNESS,
                    "wait_for_86box_window_or_identity_dialog",
                    return_value=True,
                ),
                mock.patch.object(
                    HARNESS,
                    "ensure_86box_running",
                    return_value=True,
                ),
                mock.patch.object(
                    HARNESS,
                    "attest_rtc_utc",
                    return_value=False,
                ),
                self.assertRaises(subprocess.TimeoutExpired),
            ):
                HARNESS.main()

            process.kill.assert_called_once_with()
            self.assert_restored(
                vm_path=vm_path,
                config=config,
                nvr=nvr,
                floppy=floppy,
                original_config=original_config,
                original_nvr=original_nvr,
                original_mode=original_mode,
            )


if __name__ == "__main__":
    unittest.main()
