#!/usr/bin/env python3
"""Offline oracle/build gate for both observed TLS 1.3 flight profiles.

No emulator is launched.  The gate independently freezes the AEAD tag,
decrypted transcript hash, isolated SHA hash, final ChaCha block, operation
counts, and serial ``ck`` values, then assembles the full and component images.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BOOT = ROOT / "targets" / "ibm_pc_5150" / "boot"
BUILD = ROOT / "build" / "ibm_pc_5150" / "crypto-bench"
KEY = bytes(range(32))
NONCE = bytes(range(0xA0, 0xAC))
CHUNK = 384


@dataclass(frozen=True)
class Profile:
    name: str
    outer: int
    cipher: int
    transcript: int
    inner_cipher_byte: int
    expected_tag: str
    expected_digest: str
    expected_component_sha: str
    expected_chaxor_ck: int
    expected_poly_ck: int
    expected_sha_ck: int
    expected_full_ck: int
    full_asm: str
    components_asm: str


PROFILES = (
    Profile(
        name="rsa",
        outer=4327,
        cipher=4311,
        transcript=4310,
        inner_cipher_byte=0xA1,
        expected_tag="5b0b7286410ac9727d00594275d1abf4",
        expected_digest="30d3e8a20fcad7b54079e9b95b832be5133956d96981bb20eec7232ea02df2f1",
        expected_component_sha="1f06f6b95b79ad322897914feb4f940051f139ce820f37a3ed5bc9ccc81068c1",
        expected_chaxor_ck=0x4E87,
        expected_poly_ck=0x17CD,
        expected_sha_ck=0x107E,
        expected_full_ck=0x73AA,
        full_asm="flight_bench.asm",
        components_asm="flight_components_bench.asm",
    ),
    Profile(
        name="ecdsa",
        outer=2638,
        cipher=2622,
        transcript=2621,
        inner_cipher_byte=0xD9,
        expected_tag="5792221a60d9e0d1e01f5156aa9d64b0",
        expected_digest="c107bf3077b50916a6ce96fe13270e324f5b7e5236cfbaabbb0c71618275362c",
        expected_component_sha="82680e1b19bab2f1024daab85ad17e7e5c8f7bd955f37d9538f80b91ac7cd8ad",
        expected_chaxor_ck=0xBB1B,
        expected_poly_ck=0x1BF8,
        expected_sha_ck=0x2A4F,
        expected_full_ck=0x7EF6,
        full_asm="flight_ecdsa_bench.asm",
        components_asm="flight_ecdsa_components_bench.asm",
    ),
    Profile(
        name="certcomp",
        outer=1942,
        cipher=1926,
        transcript=1925,
        inner_cipher_byte=0xE4,
        expected_tag="26bb2db23d60f286af030f462c8d3c95",
        expected_digest="d2a7f98711a72bd7f214c196f0e5e720f38501a7b2242ec58b56ca37571a9f85",
        expected_component_sha="253643a6917fa19fcadf69eaf3d038a57b44844e1a8f32c11bc74076715c9d56",
        expected_chaxor_ck=0x2527,
        expected_poly_ck=0xC0A8,
        expected_sha_ck=0x0FAC,
        expected_full_ck=0x6658,
        full_asm="flight_certcomp_bench.asm",
        components_asm="flight_certcomp_components_bench.asm",
    ),
)


def load_oracle():
    spec = importlib.util.spec_from_file_location("seed_tls13_profiles", HERE / "tls13_spike.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load TLS 1.3 spike oracle")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def word_checksum(value: bytes) -> int:
    assert len(value) % 2 == 0
    return sum(
        int.from_bytes(value[offset : offset + 2], "little")
        for offset in range(0, len(value), 2)
    ) & 0xFFFF


def vector(oracle, profile: Profile) -> dict[str, object]:
    data_blocks = (profile.cipher + 63) // 64
    keystream_blocks = [
        oracle.chacha20_block(KEY, counter, NONCE)
        for counter in range(data_blocks + 1)
    ]
    keystream = b"".join(keystream_blocks[1:])
    inner_offset = (profile.cipher - 1) % CHUNK
    computed_inner_cipher = keystream[profile.cipher - 1] ^ 0x16
    assert computed_inner_cipher == profile.inner_cipher_byte
    template = bytes(
        profile.inner_cipher_byte
        if index == inner_offset
        else ((index * 73 + 41) ^ (index >> 1)) & 0xFF
        for index in range(CHUNK)
    )
    ciphertext = template * (profile.cipher // CHUNK)
    ciphertext += template[: profile.cipher % CHUNK]
    plaintext = bytes(left ^ right for left, right in zip(ciphertext, keystream))
    aad = bytes(
        [0x17, 0x03, 0x03, (profile.outer >> 8) & 0xFF, profile.outer & 0xFF]
    )
    otk = keystream_blocks[0][:32]
    mac_input = aad + oracle._pad16(aad)
    mac_input += ciphertext + oracle._pad16(ciphertext)
    mac_input += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    tag = oracle.poly1305_mac(mac_input, otk)
    digest = hashlib.sha256(plaintext[: profile.transcript]).digest()
    sha_input = template * (profile.transcript // CHUNK)
    sha_input += template[: profile.transcript % CHUNK]
    component_sha = hashlib.sha256(sha_input).digest()
    final_chunk = plaintext[-(profile.cipher % CHUNK) :]
    last_block = keystream_blocks[-1]
    chaxor_ck = (sum(last_block) + sum(final_chunk)) & 0xFFFF
    return {
        "tag": tag,
        "digest": digest,
        "component_sha": component_sha,
        "last_block": last_block,
        "chaxor_ck": chaxor_ck,
        "poly_ck": word_checksum(tag),
        "sha_ck": word_checksum(component_sha),
        "full_ck": word_checksum(tag + digest),
        "chacha_blocks": data_blocks + 1,
        "poly_blocks": 1 + (profile.cipher + 15) // 16 + 1,
        "sha_blocks": (profile.transcript + 9 + 63) // 64,
        "chunks": (profile.cipher + CHUNK - 1) // CHUNK,
        "inner": plaintext[-1],
    }


def assemble(source_name: str, output_stem: str) -> tuple[int, int, bytes]:
    BUILD.mkdir(parents=True, exist_ok=True)
    source = HERE / source_name
    output = BUILD / f"{output_stem}.bin"
    listing = output.with_suffix(".lst")
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{BOOT}/",
        f"-I{ROOT / 'tools' / 'crypto-bench'}/",
        "-l",
        str(listing),
        "-o",
        str(output),
        str(source),
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode:
        raise SystemExit(f"nasm failed for {source_name}:\n{completed.stderr}")
    binary = output.read_bytes()
    match = re.search(
        r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+\S+.*\btag_flight\s+db\s",
        listing.read_text(),
        re.MULTILINE,
    )
    if match is None:
        raise RuntimeError(f"cannot find data boundary for {source_name}")
    return len(binary), int(match.group(1), 16), binary


def main() -> None:
    oracle = load_oracle()
    for profile in PROFILES:
        values = vector(oracle, profile)
        tag = bytes.fromhex(profile.expected_tag)
        digest = bytes.fromhex(profile.expected_digest)
        component_sha = bytes.fromhex(profile.expected_component_sha)
        assert profile.outer == profile.cipher + 16
        assert profile.transcript == profile.cipher - 1
        assert values["tag"] == tag
        assert values["digest"] == digest
        assert values["component_sha"] == component_sha
        assert values["chaxor_ck"] == profile.expected_chaxor_ck
        assert values["poly_ck"] == profile.expected_poly_ck
        assert values["sha_ck"] == profile.expected_sha_ck
        assert values["full_ck"] == profile.expected_full_ck
        assert values["inner"] == 0x16

        full_size, full_code, full_binary = assemble(
            profile.full_asm, f"tls13-flight-{profile.name}"
        )
        component_size, component_code, component_binary = assemble(
            profile.components_asm, f"tls13-flight-{profile.name}-components"
        )
        # Profile geometry can change a short/near jump encoding by a byte or
        # two; the original RSA/ECDSA image sizes are the upper bounds.
        assert full_size <= 5572
        assert component_size <= 6411
        assert 0x1000 + full_size <= 0x3600
        assert 0x1000 + component_size <= 0x3600
        assert tag in full_binary and digest in full_binary
        assert tag in component_binary and digest in component_binary
        assert values["last_block"] in component_binary
        assert component_sha in component_binary

        print(
            f"{profile.name.upper()} PASS: "
            f"record={profile.outer}/{profile.cipher}/{profile.transcript} "
            f"chunks={values['chunks']} "
            f"ops={values['chacha_blocks']}/{values['poly_blocks']}/{values['sha_blocks']}"
        )
        print(
            f"  ck CHAXOR={profile.expected_chaxor_ck:04X} "
            f"POLY={profile.expected_poly_ck:04X} "
            f"SHAFLT={profile.expected_sha_ck:04X} "
            f"FLIGHT={profile.expected_full_ck:04X}"
        )
        print(
            f"  full={full_size} B (code+header={full_code}, data={full_size-full_code}); "
            f"components={component_size} B "
            f"(code+header={component_code}, data={component_size-component_code})"
        )


if __name__ == "__main__":
    main()
