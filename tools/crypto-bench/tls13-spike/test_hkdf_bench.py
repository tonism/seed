"""Offline gates for the standalone 8086 TLS 1.3 HKDF harness."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hkdf_bench


class HKDFBenchTests(unittest.TestCase):
    def test_stdlib_vector_is_frozen(self) -> None:
        no_psk_derived, outputs = hkdf_bench.schedule()
        self.assertEqual(
            no_psk_derived.hex(), hkdf_bench.EXPECTED_NO_PSK_DERIVED
        )
        self.assertEqual(len(outputs), hkdf_bench.EXPECTED_OUTPUT_LEN)
        self.assertEqual(
            hashlib.sha256(outputs).hexdigest(),
            hkdf_bench.EXPECTED_OUTPUT_SHA256,
        )
        self.assertEqual(
            hkdf_bench.word_sum(outputs), hkdf_bench.EXPECTED_WORD_SUM
        )
        critical = outputs[: hkdf_bench.EXPECTED_CRITICAL_OUTPUT_LEN]
        self.assertEqual(
            hashlib.sha256(critical).hexdigest(),
            hkdf_bench.EXPECTED_CRITICAL_OUTPUT_SHA256,
        )
        self.assertEqual(
            hkdf_bench.word_sum(critical),
            hkdf_bench.EXPECTED_CRITICAL_WORD_SUM,
        )

    def test_8086_harness_assembles_with_frozen_hash(self) -> None:
        _, outputs = hkdf_bench.schedule()
        binary = hkdf_bench.assemble()
        sizes = hkdf_bench.parse_footer(binary)
        marker = binary.find(hkdf_bench.HASH_MARKER)
        self.assertGreaterEqual(marker, 0)
        embedded = binary[
            marker + len(hkdf_bench.HASH_MARKER) :
            marker + len(hkdf_bench.HASH_MARKER) + hkdf_bench.HASH_LEN
        ]
        self.assertEqual(embedded, hashlib.sha256(outputs).digest())
        critical_marker = binary.find(hkdf_bench.CRITICAL_HASH_MARKER)
        self.assertGreaterEqual(critical_marker, 0)
        embedded_critical = binary[
            critical_marker + len(hkdf_bench.CRITICAL_HASH_MARKER) :
            critical_marker
            + len(hkdf_bench.CRITICAL_HASH_MARKER)
            + hkdf_bench.HASH_LEN
        ]
        critical = outputs[: hkdf_bench.EXPECTED_CRITICAL_OUTPUT_LEN]
        self.assertEqual(embedded_critical, hashlib.sha256(critical).digest())
        self.assertLess(sizes["tls13_code_and_constants"], 1024)
        self.assertLessEqual(sizes["scratch_bytes"], 0x900)
        self.assertEqual(
            sizes["retained_oracle_output_bytes"],
            hkdf_bench.EXPECTED_OUTPUT_LEN,
        )


if __name__ == "__main__":
    unittest.main()
