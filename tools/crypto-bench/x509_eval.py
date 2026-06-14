#!/usr/bin/env python3
"""Gate the 286 asm X.509 parser (core/x509_verify.inc) against the offline oracle's tamper matrix.

For EVERY tamper-matrix vector: the asm parser's accept/reject must match the oracle's parser-stage
decision (x509_verify.parse_and_policy = strict parse + sigalg + key-sanity + exactly-one-SAN +
exact host; the signature verify and validity-clock compare are the orchestrator's, not the
parser's). For every ACCEPTED vector, the bytes the asm extracted (TBS span, signature, modulus)
must equal what the oracle extracted — so the downstream crypto operates on identical inputs.

This is the offline asm correctness gate; 86Box is the authoritative hardware run afterward.
Run: python3 tools/crypto-bench/x509_eval.py   (exit 0 == asm matches the oracle on every vector)
"""
from __future__ import annotations
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "x509"))
sys.path.insert(0, os.path.dirname(__file__))

import x509_verify as X
import tamper_matrix as TM
from x509_bench_harness import build_x509, run_parse


def main() -> int:
    print("assembling core/x509_verify.inc ...", file=sys.stderr)
    img, exp = build_x509()
    vectors = TM.build_vectors()                      # (name, der, n, e, host, now, expect, reason)

    width = max(len(v[0]) for v in vectors)
    fails = 0
    field_checks = 0
    for name, der, _n, _e, host, _now, _exp, _reason in vectors:
        want = X.parse_and_policy(der, host=host)     # the parser-stage decision (oracle)
        res = run_parse(img, exp, der)
        ok = (res.accepted == want.accepted)
        # on accept, the asm-extracted fields must equal the oracle's
        detail = ""
        if res.accepted and want.accepted:
            cert = want.cert
            asm_tbs = res.field(res.tbs_off, res.tbs_len)
            asm_sig = res.field(res.sig_off, 256)
            asm_mod = int.from_bytes(res.field(res.mod_off, 256), "big")
            field_ok = (asm_tbs == cert.tbs_span and asm_sig == cert.signature
                        and asm_mod == cert.spki_modulus and res.san_count == 1 and res.host_found == 1)
            field_checks += 1
            if not field_ok:
                ok = False
                detail = "  !! extracted fields != oracle"
                if asm_tbs != cert.tbs_span:
                    detail += f" tbs(sha {hashlib.sha256(asm_tbs).hexdigest()[:8]} vs {hashlib.sha256(cert.tbs_span).hexdigest()[:8]})"
                if asm_sig != cert.signature:
                    detail += " sig"
                if asm_mod != cert.spki_modulus:
                    detail += " modulus"
        fails += 0 if ok else 1
        tag = "PASS" if ok else "FAIL"
        wv = "ACCEPT" if want.accepted else "REJECT"
        gv = "ACCEPT" if res.accepted else "REJECT"
        line = f"  [{tag}] {name:<{width}}  oracle={wv} asm={gv}"
        print(line + detail)
        if res.accepted != want.accepted:
            print(f"         !! parser-decision mismatch (oracle reason: {want.reason})")

    total = len(vectors)
    print(f"\nasm vs oracle parser decision: {total - fails}/{total} vectors match "
          f"({field_checks} accept-vectors had their extracted fields cross-checked)")
    print(f"OVERALL: {'ALL GREEN — asm parser mirrors the oracle' if fails == 0 else 'MISMATCHES PRESENT'}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
