#!/usr/bin/env python3
"""Execute guarded HTTP/2 composition against the emitted product image.

These gates use synthetic secrets, an independent HTTP/2 peer, and explicit
BIOS/NIC leaves. They establish byte-bound functional and memory invariants;
live original-speed NIC/provider validation remains a separate requirement.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import build_system_ram_product_pack as B
import prepare_http2_tests as P

HERE = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--core', type=Path, default=P.BUILD/'SEED.SYS')
    ap.add_argument('--listing', type=Path)
    ap.add_argument('--image', type=Path)
    ap.add_argument('--output-dir', type=Path, default=P.BUILD/'http2-tests')
    ap.add_argument('--only', nargs='+', help='Selected gate names for diagnosis')
    args = ap.parse_args()
    listing = args.listing or args.core.with_suffix('.SYS.lst')
    out = args.output_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='seed-http2-gates-') as raw:
        work = Path(raw)
        images = B.build_independent(work)
        slots, named = B.make_layout(images)
        B.build_dependent(work, images, named, args.core.read_bytes(), listing)
        pack = B.build_pack(work, slots)
        metadata = P.prepare(out, work, images, slots, pack,
                             core=args.core.resolve(), listing=listing.resolve())
    if args.image:
        # Q validates the actual FAT chains and byte identity of SEED.SYS.
        # The test uses synthetic runtime credentials; nothing logs config.
        (out/'floppy-160k.img').write_bytes(args.image.read_bytes())
    env = dict(os.environ, SEED_HTTP2_TEST_IMAGE=str(out))
    gates = ('tls_receiver', 'phase_bridge', 'h2_outbound', 'h2_requests', 'h2_cold_send',
             'h2_far_requests', 'h2_exchange', 'h2_receive_credit', 'h2_scheduler', 'h2_tools', 'h2_tool_prompt', 'h2_env', 'h2_publication',
             'h2_tcp_window', 'h2_request_failures', 'h2_nst',
             'h2_normal_nst', 'h2_handshake', 'h2_liveness')
    if args.only:
        if not set(args.only) <= set(gates):
            ap.error('unknown gate name')
        gates = tuple(args.only)
    rows = []
    for gate in gates:
        print(f'HTTP/2 gate: {gate}', flush=True)
        log = out/(gate+'.log')
        with log.open('w') as stream:
            result = subprocess.run([sys.executable, str(HERE/'http2'/f'check_{gate}.py')],
                                    cwd=B.ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode:
            print(log.read_text()[-8000:])
            raise SystemExit(f'{gate} failed; see {log}')
        rows.append(dict(gate=gate, passed=True))
    report = dict(passed=True, core_sha256=metadata['core_sha256'], gates=rows,
                  selected=bool(args.only), limits=__doc__)
    if hashlib.sha256(args.core.read_bytes()).hexdigest() != metadata['core_sha256']:
        raise AssertionError('product image changed during gates')
    (out/'gate.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'HTTP/2 composition: PASS ({len(rows)} gates)', flush=True)


if __name__ == '__main__':
    main()
