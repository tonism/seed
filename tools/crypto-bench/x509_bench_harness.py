#!/usr/bin/env python3
"""Unicorn harness for the 286 asm X.509 parser (core/x509_verify.inc).

Mirrors rsa_bench_harness: assemble the REAL shipped .inc + a tiny caller, run x509_parse_leaf in
16-bit unicorn against a cert deployed into RAM, and read back the accept/reject + extracted field
pointers. This lets x509_eval.py gate the asm parser against the SAME tamper vectors the offline
oracle (tools/x509/x509_verify.py) uses, before any 86Box run. Buffers are defined here, not in any
shipped layout (the module supplies its own when wired).
"""
from __future__ import annotations
import struct
from pathlib import Path

import bench_harness as bh
from bench_harness import build, Run

CERT_CAP = 4096

# results exported from x509_verify.inc + the harness data block, located via a magic marker.
X509_EXPORTS = [
    "x509_certbuf", "x509_certlen", "x509_accept",
    "x509_tbs_ptr", "x509_tbs_len", "x509_sig_ptr", "x509_mod_ptr",
    "x509_nb_ptr", "x509_na_ptr", "x509_san_count", "x509_host_found",
]

X509_DATA = (
    "\n; ---- X.509 parser bench data (defined by the harness) ----\n"
    "align 2\n"
    f"x509_certbuf: times {CERT_CAP} db 0\n"
    "x509_certlen: dw 0\n"
    "x509_accept:  db 0\n"
)

# caller: parse the cert in x509_certbuf, capture CF as the accept flag (CF=0 accept -> 1).
X509_CALLER = """
    mov si, x509_certbuf
    mov cx, [x509_certlen]
    call x509_parse_leaf
    sbb al, al              ; CF=0 -> 0x00, CF=1 -> 0xFF
    inc al                  ; CF=0 -> 0x01 (accept), CF=1 -> 0x00 (reject)
    mov [x509_accept], al
"""


def build_x509(inc: str = "core/x509_verify.inc") -> tuple[bytes, dict]:
    X509_MAGIC = 0x5A5A1509
    export_tbl = (
        f"\n__x509_exports:\n    dd 0x{X509_MAGIC:08X}\n"
        + "".join(f"    dd {name}\n" for name in X509_EXPORTS)
    )
    body = f'%include "{inc}"\n' + export_tbl + X509_DATA
    img, exports = build(body, X509_CALLER)
    marker = struct.pack("<I", X509_MAGIC)
    pos = img.find(marker)
    if pos < 0:
        raise RuntimeError("x509 export marker not found")
    vals = struct.unpack_from("<%dI" % len(X509_EXPORTS), img, pos + 4)
    exports.update(dict(zip(X509_EXPORTS, vals)))
    return img, exports


class ParseResult:
    """Decoded result of one asm parse run."""
    def __init__(self, uc, exp):
        self._uc = uc
        self._base = exp["x509_certbuf"]
        self.accept = uc.mem_read(exp["x509_accept"], 1)[0] == 1
        rd = lambda name: struct.unpack("<H", bytes(uc.mem_read(exp[name], 2)))[0]
        self.accepted = self.accept
        if self.accept:
            self.tbs_off = rd("x509_tbs_ptr") - self._base
            self.tbs_len = rd("x509_tbs_len")
            self.sig_off = rd("x509_sig_ptr") - self._base
            self.mod_off = rd("x509_mod_ptr") - self._base
            self.nb_off = rd("x509_nb_ptr") - self._base
            self.na_off = rd("x509_na_ptr") - self._base
        self.san_count = uc.mem_read(exp["x509_san_count"], 1)[0]
        self.host_found = uc.mem_read(exp["x509_host_found"], 1)[0]

    def field(self, off: int, n: int) -> bytes:
        """Read n bytes the asm extracted at certbuf-relative offset off (e.g. the signature/TBS)."""
        return bytes(self._uc.mem_read(self._base + off, n))


def run_parse(img: bytes, exp: dict, cert_der: bytes) -> ParseResult:
    if len(cert_der) > CERT_CAP:
        raise ValueError(f"cert {len(cert_der)}B exceeds bench buffer {CERT_CAP}")
    r = Run(img, exp)

    def setup(uc, e):
        uc.mem_write(e["x509_certbuf"], cert_der)
        uc.mem_write(e["x509_certlen"], struct.pack("<H", len(cert_der)))

    uc = r.run(setup=setup)
    res = ParseResult(uc, exp)
    res.instrs = r.instr_count
    return res


if __name__ == "__main__":
    # smoke: assemble + parse the real leaf
    leaf = (Path(__file__).resolve().parents[2] / "tools" / "x509" / "certs" / "leaf.der").read_bytes()
    img, exp = build_x509()
    res = run_parse(img, exp, leaf)
    print(f"real leaf: accept={res.accepted} san_count={res.san_count} host_found={res.host_found} "
          f"({res.instrs} instrs)")
    if res.accepted:
        print(f"  tbs_off={res.tbs_off} tbs_len={res.tbs_len} sig_off={res.sig_off} mod_off={res.mod_off}")
