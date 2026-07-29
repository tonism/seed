from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "entropy_ratchet_oracle.py"
SPEC = importlib.util.spec_from_file_location("entropy_ratchet_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RATCHET = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RATCHET
SPEC.loader.exec_module(RATCHET)


class EntropyRatchetOracleTests(unittest.TestCase):
    def test_record_round_trip_and_corruption(self) -> None:
        record = RATCHET.Record(7, bytes(range(32)))
        encoded = record.encode()
        self.assertEqual(len(encoded), RATCHET.SECTOR_BYTES)
        self.assertEqual(RATCHET.Record.decode(encoded), record)
        corrupted = bytearray(encoded)
        corrupted[100] ^= 1
        self.assertIsNone(RATCHET.Record.decode(bytes(corrupted)))

    def test_advance_is_durable_before_attempt_seed_is_returned(self) -> None:
        media = RATCHET.Media.initialized(bytes(32))
        prepared = RATCHET.prepare_attempt(media, b"timing")
        self.assertEqual(media.current()[1].generation, 0)
        RATCHET.verified_commit(media, prepared)
        self.assertEqual(media.current()[1].generation, 1)
        next_prepared = RATCHET.prepare_attempt(media, b"timing")
        self.assertNotEqual(next_prepared.attempt_seed, prepared.attempt_seed)

    def test_equal_generation_with_different_state_is_ambiguous(self) -> None:
        media = RATCHET.Media(
            [
                RATCHET.Record(9, bytes(32)).encode(),
                RATCHET.Record(9, bytes([1]) * 32).encode(),
            ]
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            media.current()

    def test_exhaustive_modeled_crash_matrix(self) -> None:
        result = RATCHET.crash_matrix()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["prefix_torn_write_cases"], 513)
        self.assertEqual(result["crash_cases_examined"], 516)
        self.assertEqual(result["single_byte_corruptions_rejected"], 512)


if __name__ == "__main__":
    unittest.main()
