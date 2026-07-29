from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "run_8088_16k.py"
SPEC = importlib.util.spec_from_file_location("run_8088_16k_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class Literal16KRunnerTests(unittest.TestCase):
    def test_extract_guest_output_drops_emulator_diagnostics(self) -> None:
        raw = (
            'Qt: version 5\n'
            '[mvk-info] Destroying VkInstance\n'
            'HKCRIT N=1 dt=24 ck=B988\n'
            'CHECK PASS\n'
            'DONE\n'
        )
        self.assertEqual(
            RUNNER.extract_guest_output(raw),
            'HKCRIT N=1 dt=24 ck=B988\nCHECK PASS\nDONE\n',
        )

    def test_configure_stdio_serial_replaces_legacy_passthrough(self) -> None:
        source = (
            '[Machine]\n'
            'mem_size = 16\n'
            '\n'
            '[Ports (COM & LPT)]\n'
            'serial1_passthrough_enabled = 1\n'
        )
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / '86box.cfg'
            config.write_text(source)
            RUNNER.configure_stdio_serial(config)
            rewritten = config.read_text()
        self.assertIn('[Ports (COM & LPT)]\nserial1_device = stdio\n', rewritten)
        self.assertIn('[Virtual Console (COM) #1]\nmode = 0\n', rewritten)
        self.assertNotIn('serial1_passthrough_enabled', rewritten)

    def test_configure_stdio_serial_is_idempotent(self) -> None:
        source = (
            '[Ports (COM & LPT)]\n'
            'serial1_device = stdio\n'
            '\n'
            '[Virtual Console (COM) #1]\n'
            'mode = 0\n'
        )
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / '86box.cfg'
            config.write_text(source)
            RUNNER.configure_stdio_serial(config)
            first = config.read_text()
            RUNNER.configure_stdio_serial(config)
            second = config.read_text()
        self.assertEqual(first, second)

    def test_configure_pipe_serial_replaces_stdio_and_sets_fixed_fifo(self) -> None:
        source = (
            '[Ports (COM & LPT)]\n'
            'serial1_device = stdio\n'
            '\n'
            '[Virtual Console (COM) #1]\n'
            'mode = 0\n'
        )
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / '86box.cfg'
            pipe = Path(temp) / 'bench-com'
            config.write_text(source)
            RUNNER.configure_pipe_serial(config, pipe)
            rewritten = config.read_text()
        self.assertIn('[Ports (COM & LPT)]\nserial1_device = pipe\n', rewritten)
        self.assertIn(
            (
                '[Named Pipe (COM) #1]\n'
                f'path = {pipe}\n'
                'mode = 1\n'
                'reconnect = 1\n'
            ),
            rewritten,
        )
        self.assertNotIn('serial1_device = stdio', rewritten)

    def test_configure_pipe_serial_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / '86box.cfg'
            pipe = Path(temp) / 'bench-com'
            config.write_text(
                (
                    '[Ports (COM & LPT)]\n'
                    'serial1_device = pipe\n'
                    '\n'
                    '[Named Pipe (COM) #1]\n'
                    f'path = {pipe}\n'
                    'mode = 1\n'
                    'reconnect = 1\n'
                )
            )
            RUNNER.configure_pipe_serial(config, pipe)
            first = config.read_text()
            RUNNER.configure_pipe_serial(config, pipe)
            second = config.read_text()
        self.assertEqual(first, second)


if __name__ == '__main__':
    unittest.main()
