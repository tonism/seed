#!/usr/bin/env python3
"""Execute the current product's cold greeting and send-failure handoff.

The HTTP/2 composition gate runs actual R/X, encryption, flow control and
resident unwinding against an independent peer. The former HTTP/1 fixture
that supplied a prebuilt plaintext length no longer describes this handoff.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    subprocess.run([
        sys.executable,
        str(ROOT/'tools/crypto-bench/tls13-product/run_http2_gates.py'),
        '--output-dir', str(ROOT/'build/ibm_pc_5150/http2-cold-send-tests'),
        '--only', 'h2_cold_send',
    ], cwd=ROOT, check=True)
