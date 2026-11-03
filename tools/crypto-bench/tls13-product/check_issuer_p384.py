#!/usr/bin/env python3
"""Independent arithmetic, canonical-DER, hash and memory gates for YE2 auth.

Host cryptography supplies public test vectors only. The target verifier and
SHA-384 are assembled directly from the shipping includes and execute entirely
in Unicorn. No host result replaces a target operation.
"""
from __future__ import annotations

import decimal
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import (
    UC_X86_REG_BP, UC_X86_REG_BX, UC_X86_REG_CS, UC_X86_REG_CX,
    UC_X86_REG_DI, UC_X86_REG_DS, UC_X86_REG_EFLAGS, UC_X86_REG_ES,
    UC_X86_REG_IP, UC_X86_REG_SI, UC_X86_REG_SP, UC_X86_REG_SS,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / 'build/ibm_pc_5150/crypto-bench/issuer-p384'
SOURCE = ROOT / 'targets/ibm_pc_5150/boot'
P = 2**384 - 2**128 - 2**96 + 2**32 - 1
N = int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf'
        '581a0db248b0a77aecec196accc52973', 16)
B = int('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac'
        '656398d8a2ed19d2a85c8edd3ec2aef', 16)
ANCHOR = 'b3fb5d00e994cddf2cc9a4eea9f806bc5727e83cc0e4299bf956f2d524fe5376'
REGS = dict(SI=UC_X86_REG_SI, DI=UC_X86_REG_DI, CX=UC_X86_REG_CX,
            BX=UC_X86_REG_BX, BP=UC_X86_REG_BP)


def assemble(name: str, includes: list[str], labels: list[str]) -> tuple[bytes, dict[str, int]]:
    path = BUILD / (name + '.asm')
    path.write_text('bits 16\ncpu 8086\norg 0x1800\n' +
                    ''.join(f'%include "tls13/{x}"\n' for x in includes) +
                    'dw ' + ','.join(labels) + '\n')
    subprocess.run(['nasm', '-f', 'bin', '-I' + str(SOURCE) + '/', str(path),
                    '-o', str(path.with_suffix('.bin'))], check=True)
    raw = path.with_suffix('.bin').read_bytes()
    addresses = struct.unpack('<' + 'H' * len(labels), raw[-2 * len(labels):])
    return raw, dict(zip(labels, addresses))


class Target:
    def __init__(self, raw: bytes, labels: dict[str, int], scratch: tuple[int, int]):
        self.u = Uc(UC_ARCH_X86, UC_MODE_16)
        self.u.mem_map(0, 0x100000)
        self.u.mem_write(0x1800, raw)
        self.u.mem_protect(0, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
        self.u.mem_protect(0x4000, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_protect(0x7000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        self.labels = labels
        lo, hi = scratch
        self.guards = [(0x4000, lo), (hi, 0x6000), (0x7000, 0x7e00)]
        for a, b in self.guards:
            self.u.mem_write(a, bytes([0x97]) * (b - a))

    def run(self, name: str, **regs: int) -> bool:
        for reg in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            self.u.reg_write(reg, 0)
        self.u.reg_write(UC_X86_REG_SP, 0x7ffe)
        self.u.reg_write(UC_X86_REG_EFLAGS, 2)
        for key, value in regs.items():
            self.u.reg_write(REGS[key], value)
        self.u.mem_write(0x7ffe, b'\x00\x60')
        self.u.emu_start(self.labels[name], 0x6000, count=500_000_000)
        assert self.u.reg_read(UC_X86_REG_IP) == 0x6000, name
        assert self.u.reg_read(UC_X86_REG_SP) == 0x8000, name
        for a, b in self.guards:
            assert bytes(self.u.mem_read(a, b-a)) == bytes([0x97]) * (b-a), (name, hex(a))
        return not bool(self.u.reg_read(UC_X86_REG_EFLAGS) & 1)

    def put(self, at: int, value: int) -> None:
        self.u.mem_write(at, value.to_bytes(48, 'little'))

    def get(self, at: int) -> int:
        return int.from_bytes(self.u.mem_read(at, 48), 'little')


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    chain = x509.load_pem_x509_certificates((HERE / 'fixtures/provider_auth_live_chain.pem').read_bytes())
    leaf, issuer = chain[:2]
    spki = issuer.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert hashlib.sha256(spki).hexdigest() == ANCHOR
    q = issuer.public_key().public_numbers()
    generator = ec.derive_private_key(1, ec.SECP384R1()).public_key().public_numbers()
    constants = dict(pc_p=P, pc_n=N, pc_r2_p=pow(2, 768, P), pc_r2_n=pow(2, 768, N),
                     pc_one=1, pc_one_p=pow(2, 384, P), pc_b_mont=B * pow(2, 384, P) % P,
                     pc_g=generator.x, pc_gy=generator.y, pc_issuer=q.x, pc_issuer_y=q.y)
    exports = ['p384_verify', 'pm_mul', 'pm_inverse', 'pm_add', 'pm_sub',
               'pm_mod', 'pm_n0', 'pv_end', *constants]
    raw, labels = assemble('p384', ['p384_ye2_constants.inc', 'p384_verify_286.inc'], exports)
    target = Target(raw, labels, (0x4230, labels['pv_end']))
    for key, value in constants.items():
        assert target.get(labels[key]) == value, key
    rng = random.Random(28)
    arithmetic = []
    # Arithmetic-only calls deliberately alias outputs with the near operands.
    target.u.mem_protect(0, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    for name, modulus in [('pc_p', P), ('pc_n', N)]:
        target.u.mem_write(labels['pm_mod'], struct.pack('<H', labels[name]))
        target.u.mem_write(labels['pm_n0'], struct.pack('<H', -pow(modulus, -1, 65536) % 65536))
        inverse_r = pow(2**384, -1, modulus)
        for i in range(150):
            a = rng.choice([0, 1, modulus - 1, rng.randrange(modulus)])
            b = rng.choice([0, 1, modulus - 1, rng.randrange(modulus)])
            for function, expected in [('pm_mul', a*b*inverse_r % modulus),
                                       ('pm_add', (a+b) % modulus),
                                       ('pm_sub', (a-b) % modulus)]:
                target.put(0x800, a)
                target.put(0x840, b)
                output = (0x800, 0x840, 0x880)[i % 3]
                target.run(function, SI=0x800, DI=0x840, BX=output)
                assert target.get(output) == expected, (function, name, i)
        for i in range(35):
            value = rng.choice([1, modulus - 1, rng.randrange(1, modulus)])
            target.put(0x800, value)
            assert target.run('pm_inverse', SI=0x800, DI=0x840)
            assert target.get(0x840) == pow(value, -1, modulus)
        for value in (0, modulus, modulus + 1):
            target.put(0x800, value)
            assert not target.run('pm_inverse', SI=0x800, DI=0x840)
        arithmetic.append(dict(modulus=name, field_cases=450, inverses=35, inverse_refusals=3))

    target.u.mem_protect(0, 0x1000, UC_PROT_READ)
    signatures = []

    def verify(name: str, digest: bytes, signature: bytes, point: tuple[int, int], expected: bool) -> None:
        target.u.mem_write(0x800, digest)
        target.u.mem_write(0x840, signature)
        target.put(0x900, point[0])
        target.put(0x930, point[1])
        before = bytes(target.u.mem_read(0x800, 0x160))
        result = target.run('p384_verify', SI=0x800, DI=0x840, CX=len(signature), BP=0x900)
        assert result == expected, (name, result, expected)
        assert bytes(target.u.mem_read(0x800, 0x160)) == before
        signatures.append(dict(name=name, accepted=result))

    digest = hashlib.sha384(leaf.tbs_certificate_bytes).digest()
    issuer.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
    verify('current-YE2-leaf', digest, leaf.signature, (q.x, q.y), True)
    # Q=-G covers the joint infinity table entry with both zero and nonzero
    # digest scalars; the latter exercises digit 3 during the joint multiply.
    for i, scalar in enumerate([1, N-1, N-1] + [rng.randrange(1, N) for _ in range(6)]):
        key = ec.derive_private_key(scalar, ec.SECP384R1())
        point = key.public_key().public_numbers()
        digest = [bytes(48), N.to_bytes(48, 'big'), b'\xff'*48, rng.randbytes(48)][i % 4]
        signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA384())))
        key.public_key().verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA384())))
        xy = (point.x, point.y)
        verify(f'synthetic-{i}', digest, signature, xy, True)
        if i != 0:
            continue
        verify('changed-digest', b'\x01' + digest[1:], signature, xy, False)
        verify('changed-signature', digest, signature[:-1] + bytes([signature[-1] ^ 1]), xy, False)
        verify('off-curve', digest, signature, (point.x, (point.y + 1) % P), False)
        verify('x-out-of-field', digest, signature, (P, point.y), False)
        verify('y-out-of-field', digest, signature, (point.x, P), False)
        verify('infinity-encoding', digest, signature, (0, 0), False)
        for label, r, s in [('zero-r', 0, 1), ('zero-s', 1, 0), ('order-r', N, 1),
                            ('order-s', 1, N), ('wide-r', 2**384, 1)]:
            verify(label, digest, utils.encode_dss_signature(r, s), xy, False)
        for label, malformed in [
            ('truncated', signature[:-1]), ('trailing', signature + b'\0'),
            ('empty', b''), ('oversized', b'\0'*105),
            ('nonminimal-integer', bytes.fromhex('300702020001020101')),
            ('negative-integer', bytes.fromhex('3006020180020101')),
            ('empty-integer', bytes.fromhex('30050200020101')),
            ('nonminimal-length', bytes.fromhex('308106020101020101')),
            ('indefinite-length', bytes.fromhex('30800201010201010000')),
            ('wrong-tag', bytes.fromhex('3006030101020101')),
        ]:
            verify(label, digest, malformed, xy, False)
    print(f'P-384: {len(signatures)} signatures/DER cases; 900 field cases, 70 inverses', flush=True)

    sha_raw, sha_labels = assemble('sha384', ['sha384_286.inc', 'sha384_constants.inc'],
                                  ['sha384_hash', 's_digest', 'sc_iv', 'sc_k'])
    sha = Target(sha_raw, sha_labels, (0x5000, 0x5900))
    # Reconstruct the fixed FIPS 180-4 constants independently at high precision.
    decimal.getcontext().prec = 110
    primes = [p for p in range(2, 410) if all(p % d for d in range(2, int(p**.5)+1))][:80]
    D = decimal.Decimal
    frac = lambda value: int((value-int(value)) * 2**64)
    iv = [frac(D(p).sqrt()) for p in primes[8:16]]
    rounds = [frac(D(p)**(D(1)/3)) for p in primes]
    for label, values in [('sc_iv', iv), ('sc_k', rounds)]:
        assert bytes(sha.u.mem_read(sha_labels[label], 8*len(values))) == struct.pack('<'+'Q'*len(values), *values)
    lengths = [0, 1, 2, 3, 47, 48, 63, 64, 111, 112, 113, 127, 128, 129, 255, 256,
               1023, 1024] + [rng.randrange(1025) for _ in range(30)]
    for length in lengths:
        message = rng.randbytes(length)
        sha.u.mem_write(0x800, message)
        assert sha.run('sha384_hash', SI=0x800, CX=length)
        assert bytes(sha.u.mem_read(sha_labels['s_digest'], 48)) == hashlib.sha384(message).digest()
        assert bytes(sha.u.mem_read(0x800, length)) == message
    for pointer, length in [(0x800, 1025), (0x800, 65535), (0xffff, 1), (0xff00, 256)]:
        assert not sha.run('sha384_hash', SI=pointer, CX=length)
    report = dict(passed=True, arithmetic=arithmetic, signatures=signatures,
                  sha384_lengths=lengths, sha384_bound_refusals=4,
                  p384_sha256=hashlib.sha256(raw).hexdigest(),
                  sha384_sha256=hashlib.sha256(sha_raw).hexdigest(),
                  read_only_code_inputs_and_peripherals=True, scratch_and_stack_guards=True,
                  host_seconds=time.monotonic()-started)
    (BUILD/'gate.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
