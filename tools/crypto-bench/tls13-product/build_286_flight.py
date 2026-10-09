#!/usr/bin/env python3
"""Build the fixed-origin TLS 1.3 286 protected-flight coordinator."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"
SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_flight.asm"
RUNTIME_ABI = BUILD / "tls13-286-runtime-abi.inc"
SYM_ABI = BUILD / "tls13-286-flight-sym-abi.inc"
RAW = BUILD / "tls13-286-flight.bin"
COMPONENT = BUILD / "tls13-286-flight-component.bin"
ABI_OUT = BUILD / "tls13-286-flight-component-abi.inc"
REPORT = BUILD / "tls13-286-flight.json"
HELPER = BUILD / "tls13-286-h2-helper.bin"
HTTP_BUILD = BUILD / "http2"
BOOT = ROOT / "targets/ibm_pc_5150/boot"

LOAD = 0x6300
LIMIT = 0x7380
MAGIC = b"S286FL02"
ABI = 2
LZ4_HEADER = struct.Struct("<4sHHHH")


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = (
                ((value << 1) ^ 0x1021) & 0xFFFF
                if value & 0x8000
                else (value << 1) & 0xFFFF
            )
    return value


def compress_raw_lz4(raw: bytes) -> bytes:
    if shutil.which("lz4") is None:
        raise SystemExit("lz4 command is required to build the 286 flight")
    with tempfile.TemporaryDirectory(prefix="seed-286-flight-", dir=BUILD) as temp:
        directory = Path(temp)
        source = directory / "flight.raw"
        framed = directory / "flight.legacy.lz4"
        decoded = directory / "flight.roundtrip"
        source.write_bytes(raw)
        subprocess.run(
            ["lz4", "-q", "-l", "-9", "-f", str(source), str(framed)],
            cwd=ROOT,
            check=True,
        )
        wrapped = framed.read_bytes()
        if len(wrapped) < 8 or wrapped[:4] != b"\x02\x21\x4c\x18":
            raise AssertionError("lz4 did not emit one legacy raw block")
        size = int.from_bytes(wrapped[4:8], "little")
        block = wrapped[8:]
        if size != len(block):
            raise AssertionError("286 flight did not fit one raw LZ4 block")
        subprocess.run(
            ["lz4", "-q", "-d", "-f", str(framed), str(decoded)],
            cwd=ROOT,
            check=True,
        )
        if decoded.read_bytes() != raw:
            raise AssertionError("286 flight LZ4 round trip changed bytes")
        return block


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    if not RUNTIME_ABI.is_file() or not SYM_ABI.is_file():
        raise SystemExit("build the generated 286 runtime/symmetric ABIs first")
    with tempfile.TemporaryDirectory(prefix="seed-286-flight-", dir=BUILD) as temp:
        work = Path(temp)

        def assemble(name: str, source: Path) -> bytes:
            output = work / f"{name}.bin"
            subprocess.run([
                "nasm", "-f", "bin",
                *(f"-I{path}/" for path in (work, HTTP_BUILD, BOOT / "phases/http2", BOOT,
                                            ROOT / "tools/crypto-bench/tls13-poc", BUILD, ROOT)),
                "-l", str(work / f"{name}.lst"), "-o", str(output), str(source),
            ], cwd=ROOT, check=True)
            return output.read_bytes()

        # Probe actual labels rather than duplicating offsets in a hand ABI.
        names = ("h2_init", "h2_new_frame", "h2_payload_byte", "h2_frame_done")
        source = work / "post-probe.asm"
        source.write_text('%include "h2_post.asm"\n' + "".join(f"dw {name}\n" for name in names))
        post = assemble("post-probe", source)
        shared = (HTTP_BUILD / "h2_post.bin").read_bytes()
        if post[:-8] != shared:
            raise AssertionError("286 parser probe differs from the shared application parser")
        values = {f"FLIGHT_{name.upper()}": value for name, value in
                  zip(names, struct.unpack("<4H", post[-8:]), strict=True)}
        values.update(FLIGHT_H2_BYTES=len(shared), FLIGHT_H2_CRC=crc16(shared),
                      FLIGHT_H2_SEG=0x02a3, FLIGHT_H2_DELTA=0x2a30)
        names = ("sym_seal_record", "sym_record_key_ptr", "sym_record_iv_ptr", "sym_record_seq_ptr")
        source = work / "sym-probe.asm"
        source.write_text('%define TLS13_POC_K14\n%define TLS13_POC_286\n%include "tls13_sym_overlay.asm"\n' +
                          "".join(f"dw {name}\n" for name in names))
        sym = assemble("sym-probe", source)
        if sym[:-8] != (BUILD / "tls13-286-flight-sym.bin").read_bytes():
            raise AssertionError("286 H2 sealing ABI differs from the exact flight SYM")
        values.update({f"FLIGHT_{name.upper()}": value for name, value in
                       zip(names, struct.unpack("<4H", sym[-8:]), strict=True)})
        (work / "h2-286-post-abi.inc").write_text("".join(
            f"{name} equ 0x{value:04x}\n" for name, value in values.items()))

        # Helper references affect its CRC but never the fixed-width flight
        # instructions. Require an actual fixed point before publication.
        refs = dict(flight_crc16=0, flight_wire_left=0, flight_h2_send=0)
        source = work / "flight-probe.asm"
        source.write_text('%include "tls13/tls13_286_flight.asm"\n' +
                          "".join(f"dw {name}\n" for name in refs))
        for _attempt in range(3):
            (work / "h2-helper-refs.inc").write_text('%include "tls13-286-runtime-abi.inc"\n' +
                "".join(f"{name} equ 0x{value:04x}\n" for name, value in refs.items()))
            helper = assemble("helper", BOOT / "tls13/h2_286_helper.asm")
            if not 0 < len(helper) <= 512:
                raise AssertionError("286 H2 adapter exceeds its one-sector slot")
            (work / "h2-helper-crc.inc").write_text(
                f"%define H2_HELPER_BYTES {len(helper)}\n%define H2_HELPER_CRC {crc16(helper)}\n")
            probe = assemble("flight-probe", source)
            updated = dict(zip(refs, struct.unpack("<3H", probe[-6:]), strict=True))
            if refs == updated:
                break
            refs = updated
        else:
            raise AssertionError("286 H2 helper binding did not stabilize")
        raw = probe[:-6]
    if not 0 < len(raw) <= LIMIT - LOAD:
        raise AssertionError("286 flight escaped its fixed coordinator window")
    if raw[:8] != MAGIC:
        raise AssertionError("286 flight magic drifted")
    abi, image_bytes, entries, entry = struct.unpack_from("<HHHH", raw, 8)
    if (
        abi != ABI
        or image_bytes != len(raw)
        or entries != 1
        or not LOAD <= entry < LOAD + len(raw)
    ):
        raise AssertionError("286 flight header/entry drifted")

    block = compress_raw_lz4(raw)
    checksum = crc16(raw)
    stored_bytes = LZ4_HEADER.size + len(block)
    sectors = (stored_bytes + 511) // 512
    if sectors > 6:
        raise AssertionError("286 flight exceeds its pre-TCP high-RAM staging band")
    component = (
        LZ4_HEADER.pack(b"LZ4B", len(raw), len(block), checksum, 0) + block
    )
    component += bytes(sectors * 512 - len(component))
    report = {
        "schema": "seed-tls13-286-flight-v1",
        "source": str(SOURCE.relative_to(ROOT)),
        "raw": str(RAW.relative_to(ROOT)),
        "component": str(COMPONENT.relative_to(ROOT)),
        "load": f"0x{LOAD:04x}",
        "limit": f"0x{LIMIT:04x}",
        "entry": f"0x{entry:04x}",
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_crc16_ccitt": f"{checksum:04X}",
        "compressed_block_bytes": len(block),
        "stored_bytes": stored_bytes,
        "component_sectors": sectors,
        "component_sha256": hashlib.sha256(component).hexdigest(),
        "h2_helper_bytes": len(helper),
        "h2_helper_sha256": hashlib.sha256(helper).hexdigest(),
    }
    include = f"""; Generated by build_286_flight.py; do not edit.
%define TLS13_286_FLIGHT_COMPONENT_LOAD 0x{LOAD:04x}
%define TLS13_286_FLIGHT_COMPONENT_ENTRY 0x{entry:04x}
%define TLS13_286_FLIGHT_COMPONENT_RAW_BYTES 0x{len(raw):04x}
%define TLS13_286_FLIGHT_COMPONENT_RAW_CRC16 0x{checksum:04x}
%define TLS13_286_FLIGHT_COMPONENT_BLOCK_BYTES 0x{len(block):04x}
%define TLS13_286_FLIGHT_COMPONENT_STORED_BYTES 0x{stored_bytes:04x}
%define TLS13_286_FLIGHT_COMPONENT_SECTORS 0x{sectors:04x}
""".encode("ascii")
    atomic_write(RAW, raw)
    atomic_write(COMPONENT, component)
    atomic_write(ABI_OUT, include)
    atomic_write(HELPER, helper.ljust(512, b"\0"))
    atomic_write(
        REPORT,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
