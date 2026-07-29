#!/usr/bin/env python3
"""Prove the fixed live-P256 -> LP1 -> ROG3 publication path in 16 KiB."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from unicorn import UC_HOOK_MEM_WRITE

import auth_p256_check as A
import read_only_commit_gate_check as G


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "auth_p256_publication_adapter.asm"
README = HERE / "auth_p256_publication_adapter_README.md"
CHECKER = Path(__file__).resolve()
LIVE_VECTOR = HERE / "issuer_auth_live_vector.json"

ORIGIN = 0x3200
MAX_BYTES = 512
HEADER_BYTES = 26
PIN_BYTES = 96

AUTH_VERIFY_SLOT = 0x1800
AUTH_GENERATION = 0x3C2E
AUTH_DIGEST = 0x3C30
AUTH_SIGNATURE_LEN = 0x3C50
AUTH_SIGNATURE = 0x3C52
AUTH_STATUS = 0x3C9A

ISSUER_START = 0x3600
ISSUER_STATUS = ISSUER_START
ISSUER_RESERVED = ISSUER_STATUS + 1
ISSUER_MAGIC = ISSUER_RESERVED + 1
ISSUER_MAGIC_INVERSE = ISSUER_MAGIC + 4
ISSUER_GENERATION = ISSUER_MAGIC_INVERSE + 4
ISSUER_PROFILE = ISSUER_GENERATION + 2
ISSUER_LEAF_X = ISSUER_PROFILE + 2
ISSUER_LEAF_Y = ISSUER_LEAF_X + 32
ISSUER_DIGEST = ISSUER_LEAF_Y + 32
ISSUER_CHECKSUM_A = ISSUER_DIGEST + 32
ISSUER_CHECKSUM_B = ISSUER_CHECKSUM_A + 2
ISSUER_END = ISSUER_CHECKSUM_B + 2
ISSUER_PROFILE_VALUE = 0x003F

GENERATION = 0x4A31


@dataclass(frozen=True)
class Header:
    version: int
    image_bytes: int
    entry: int
    auth_verify_slot: int
    generation: int
    digest: int
    signature_len: int
    signature: int
    auth_status: int
    issuer_start: int
    issuer_end: int


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(directory: Path) -> tuple[bytes, Header]:
    binary = directory / "auth_p256_publication_adapter.bin"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{HERE}/",
            "-o",
            str(binary),
            str(SOURCE),
        ],
        cwd=ROOT,
        check=True,
    )
    image = binary.read_bytes()
    if image[:4] != b"LPA1":
        raise AssertionError("live publication adapter magic mismatch")
    header = Header(*struct.unpack_from("<11H", image, 4))
    expected = Header(
        version=1,
        image_bytes=len(image),
        entry=ORIGIN + HEADER_BYTES,
        auth_verify_slot=AUTH_VERIFY_SLOT,
        generation=AUTH_GENERATION,
        digest=AUTH_DIGEST,
        signature_len=AUTH_SIGNATURE_LEN,
        signature=AUTH_SIGNATURE,
        auth_status=AUTH_STATUS,
        issuer_start=ISSUER_START,
        issuer_end=ISSUER_END,
    )
    if header != expected:
        raise AssertionError(f"publication adapter ABI drifted: {header!r}")
    if not (HEADER_BYTES < len(image) <= MAX_BYTES):
        raise AssertionError("publication adapter is not a one-sector phase")
    return image, header


def static_gate(image: bytes, header: Header) -> dict[str, object]:
    code_end = ORIGIN + len(image) - PIN_BYTES
    instructions = tuple(
        Cs(CS_ARCH_X86, CS_MODE_16).disasm(
            image[header.entry - ORIGIN : code_end - ORIGIN],
            header.entry,
        )
    )
    if sum(instruction.size for instruction in instructions) != (
        code_end - header.entry
    ):
        raise AssertionError("adapter executable did not decode exactly")
    forbidden = {
        "in",
        "insb",
        "insw",
        "int",
        "int1",
        "int3",
        "into",
        "out",
        "outsb",
        "outsw",
    }
    hits = [
        f"{instruction.address:#06x} {instruction.mnemonic} "
        f"{instruction.op_str}".rstrip()
        for instruction in instructions
        if instruction.mnemonic in forbidden
    ]
    if hits:
        raise AssertionError(f"adapter contains external I/O: {hits}")
    indirect_calls = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "call" and "[" in instruction.op_str
    ]
    if len(indirect_calls) != 1 or "0x1800" not in indirect_calls[0].op_str:
        raise AssertionError(
            "adapter must contain one fixed auth-table call through [0x1800]"
        )
    source = SOURCE.read_text(encoding="utf-8").lower()
    forbidden_literals = (
        "authorization:",
        "bearer ",
        "api-key",
        "int 0x13",
        "int 13h",
    )
    literal_hits = [token for token in forbidden_literals if token in source]
    if literal_hits:
        raise AssertionError(
            f"adapter source contains credential/media surface: {literal_hits}"
        )
    return {
        "decoded_instructions": len(instructions),
        "decoded_code_bytes": code_end - header.entry,
        "interrupt_or_port_io_count": len(hits),
        "fixed_auth_table_calls": len(indirect_calls),
        "fixed_auth_table_call": f"{indirect_calls[0].address:#06x}",
        "caller_selectable_calls": 0,
        "credential_or_media_literals": literal_hits,
    }


def live_inputs() -> tuple[bytes, bytes]:
    vector = json.loads(LIVE_VECTOR.read_text(encoding="utf-8"))
    certificate_verify = vector["certificate_verify"]
    return (
        bytes.fromhex(certificate_verify["signed_input_sha256"]),
        bytes.fromhex(certificate_verify["signature_der"]),
    )


def new_auth_machine(
    auth_image: bytes,
    adapter_image: bytes,
    abi: dict[str, int],
    *,
    digest: bytes,
    signature: bytes,
    generation: int = GENERATION,
    forged_status: int | None = None,
    stale_publication: bytes | None = None,
) -> object:
    machine = A.new_machine(auth_image)
    machine.mem_write(ORIGIN, adapter_image)
    A.write_compact_inputs(
        machine,
        abi,
        digest=digest,
        signature=signature,
    )
    machine.mem_write(AUTH_GENERATION, struct.pack("<H", generation))
    if forged_status is not None:
        machine.mem_write(AUTH_STATUS, bytes([forged_status]))
    if stale_publication is not None:
        machine.mem_write(ISSUER_START, stale_publication)
    return machine


def invoke_adapter(
    machine: object,
    header: Header,
    *,
    expect_success: bool,
) -> tuple[list[tuple[int, int, int]], int, bool]:
    writes: list[tuple[int, int, int]] = []

    def record_write(
        _machine: object,
        _access: int,
        address: int,
        size: int,
        value: int,
        _data: object,
    ) -> None:
        writes.append((address, size, value))

    hook = machine.hook_add(UC_HOOK_MEM_WRITE, record_write)
    try:
        ax, carry = A.invoke(machine, header.entry)
    finally:
        machine.hook_del(hook)
    ax &= 0xFFFF
    if expect_success and (carry or ax != 1):
        raise AssertionError(
            f"adapter rejected valid auth: AX={ax:#06x} CF={int(carry)}"
        )
    if not expect_success and (not carry or ax != 0):
        raise AssertionError("adapter accepted hostile authentication state")
    return writes, ax, carry


def read(machine: object, address: int, length: int) -> bytes:
    return bytes(machine.mem_read(address, length))


def publication(machine: object) -> bytes:
    return read(machine, ISSUER_START, ISSUER_END - ISSUER_START)


def assert_clear(machine: object, label: str) -> None:
    if any(publication(machine)):
        raise AssertionError(f"{label} left a partial issuer publication")


def expected_publication(
    *,
    generation: int,
    digest: bytes,
    leaf_x: bytes,
    leaf_y: bytes,
) -> bytes:
    value = bytearray(ISSUER_END - ISSUER_START)
    value[ISSUER_STATUS - ISSUER_START] = 1
    value[ISSUER_MAGIC - ISSUER_START : ISSUER_MAGIC - ISSUER_START + 4] = (
        b"LP1!"
    )
    value[
        ISSUER_MAGIC_INVERSE
        - ISSUER_START : ISSUER_MAGIC_INVERSE
        - ISSUER_START
        + 4
    ] = bytes(byte ^ 0xFF for byte in b"LP1!")
    struct.pack_into(
        "<HH",
        value,
        ISSUER_GENERATION - ISSUER_START,
        generation,
        ISSUER_PROFILE_VALUE,
    )
    value[
        ISSUER_LEAF_X - ISSUER_START : ISSUER_LEAF_X - ISSUER_START + 32
    ] = leaf_x
    value[
        ISSUER_LEAF_Y - ISSUER_START : ISSUER_LEAF_Y - ISSUER_START + 32
    ] = leaf_y
    value[
        ISSUER_DIGEST - ISSUER_START : ISSUER_DIGEST - ISSUER_START + 32
    ] = digest
    check = bytes(
        value[
            ISSUER_GENERATION
            - ISSUER_START : ISSUER_CHECKSUM_A
            - ISSUER_START
        ]
    )
    checksum_a, checksum_b = G.issuer_checksum(check)
    struct.pack_into(
        "<HH",
        value,
        ISSUER_CHECKSUM_A - ISSUER_START,
        checksum_a,
        checksum_b,
    )
    return bytes(value)


def gate_machine(
    gate_image: bytes,
    gate_header: G.Header,
    issuer: bytes,
) -> G.Machine:
    machine = G.Machine(gate_image, gate_header)
    machine.clear_ticket()
    machine.write(
        G.ISSUER_INPUT_START,
        bytes(G.ISSUER_INPUT_END - G.ISSUER_INPUT_START),
    )
    machine.write(G.ISSUER_COMMIT_START, issuer)
    return machine


def gate_reject(
    gate_image: bytes,
    gate_header: G.Header,
    issuer: bytes,
    mutate: Callable[[bytearray], None],
) -> None:
    hostile = bytearray(issuer)
    mutate(hostile)
    machine = gate_machine(gate_image, gate_header, bytes(hostile))
    machine.call(
        G.ENTRY_COMMIT,
        ax=GENERATION,
        bx=G.ROUTE_LIVE_NO_TICKET,
        expect_success=False,
    )
    if machine.loader_calls:
        raise AssertionError("hostile LP1 publication reached credential loader")


def run() -> dict[str, object]:
    digest, signature = live_inputs()
    with tempfile.TemporaryDirectory(
        prefix="seed-auth-p256-publication-"
    ) as temp_name:
        directory = Path(temp_name)
        adapter, header = assemble(directory)
        auth, auth_listing = A.assemble(directory, live_compact=True)
        abi = A.compact_abi_probe(directory, auth)
    static = static_gate(adapter, header)
    if (
        abi["auth_input_digest"] != AUTH_DIGEST
        or abi["auth_input_signature_len"] != AUTH_SIGNATURE_LEN
        or abi["auth_input_signature"] != AUTH_SIGNATURE
        or abi["auth_output_status"] != AUTH_STATUS
    ):
        raise AssertionError("adapter no longer matches live compact auth ABI")

    pin_x = adapter[-PIN_BYTES : -PIN_BYTES + 32]
    pin_y = adapter[-PIN_BYTES + 32 : -PIN_BYTES + 64]
    _cert_der, _spki, live_point, _public = A.extract_p256_spki(A.LIVE_LEAF)
    if (
        pin_x != live_point[0].to_bytes(32, "big")
        or pin_y != live_point[1].to_bytes(32, "big")
    ):
        raise AssertionError("adapter exact leaf differs from live auth leaf")

    valid = new_auth_machine(
        auth,
        adapter,
        abi,
        digest=digest,
        signature=signature,
    )
    valid_writes, _ax, _carry = invoke_adapter(
        valid, header, expect_success=True
    )
    expected = expected_publication(
        generation=GENERATION,
        digest=digest,
        leaf_x=pin_x,
        leaf_y=pin_y,
    )
    if publication(valid) != expected:
        raise AssertionError("adapter published the wrong exact LP1 object")
    issuer_writes = [
        event
        for event in valid_writes
        if ISSUER_START <= event[0] < ISSUER_END
    ]
    if not issuer_writes or issuer_writes[-1] != (ISSUER_STATUS, 1, 1):
        raise AssertionError("LP1 status was not the final publication write")

    hostile: dict[str, object] = {}

    bad_digest = bytearray(digest)
    bad_digest[-1] ^= 1
    forged_digest = new_auth_machine(
        auth,
        adapter,
        abi,
        digest=bytes(bad_digest),
        signature=signature,
        forged_status=1,
    )
    invoke_adapter(forged_digest, header, expect_success=False)
    assert_clear(forged_digest, "forged compact status + altered digest")
    hostile["forged_lone_auth_status_altered_digest"] = "rejected_and_clear"

    bad_signature = bytearray(signature)
    bad_signature[-1] ^= 1
    forged_signature = new_auth_machine(
        auth,
        adapter,
        abi,
        digest=digest,
        signature=bytes(bad_signature),
        forged_status=1,
    )
    invoke_adapter(forged_signature, header, expect_success=False)
    assert_clear(forged_signature, "forged compact status + altered signature")
    hostile["forged_lone_auth_status_altered_signature"] = (
        "rejected_and_clear"
    )

    zero_generation = new_auth_machine(
        auth,
        adapter,
        abi,
        digest=digest,
        signature=signature,
        generation=0,
        forged_status=1,
    )
    invoke_adapter(zero_generation, header, expect_success=False)
    assert_clear(zero_generation, "zero generation")
    hostile["zero_generation"] = "rejected_before_auth_and_clear"

    malformed = new_auth_machine(
        auth,
        adapter,
        abi,
        digest=digest,
        signature=signature,
        forged_status=1,
    )
    malformed.mem_write(AUTH_SIGNATURE_LEN, struct.pack("<H", 73))
    invoke_adapter(malformed, header, expect_success=False)
    assert_clear(malformed, "malformed signature length")
    hostile["malformed_signature_length"] = "rejected_and_clear"

    stale = new_auth_machine(
        auth,
        adapter,
        abi,
        digest=bytes(bad_digest),
        signature=signature,
        forged_status=1,
        stale_publication=expected,
    )
    invoke_adapter(stale, header, expect_success=False)
    assert_clear(stale, "stale complete LP1 + invalid auth")
    hostile["stale_complete_lp1_invalid_auth"] = "rejected_and_clear"

    gate_image, gate_header = G.assemble()
    composed = gate_machine(gate_image, gate_header, expected)
    composed.call(
        G.ENTRY_COMMIT,
        ax=GENERATION,
        bx=G.ROUTE_LIVE_NO_TICKET,
        expect_success=True,
    )
    composed.call(G.ENTRY_AUTHORIZE, expect_success=True)
    composed.call(G.ENTRY_UNLOCK, expect_success=True)
    if len(composed.loader_calls) != 1:
        raise AssertionError("LP1 route did not invoke one fixed loader")
    if composed.loader_calls[0]["callback"] != G.READ_LOADER:
        raise AssertionError("LP1 route used the wrong credential loader")

    lone = bytearray(ISSUER_END - ISSUER_START)
    lone[ISSUER_STATUS - ISSUER_START] = 1
    lone_machine = gate_machine(gate_image, gate_header, bytes(lone))
    lone_machine.call(
        G.ENTRY_COMMIT,
        ax=GENERATION,
        bx=G.ROUTE_LIVE_NO_TICKET,
        expect_success=False,
    )
    hostile["rog3_lone_lp1_status"] = "rejected"

    mutations: dict[str, Callable[[bytearray], None]] = {
        "rog3_torn_magic": lambda value: value.__setitem__(
            ISSUER_MAGIC - ISSUER_START, value[ISSUER_MAGIC - ISSUER_START] ^ 1
        ),
        "rog3_torn_magic_inverse": lambda value: value.__setitem__(
            ISSUER_MAGIC_INVERSE - ISSUER_START,
            value[ISSUER_MAGIC_INVERSE - ISSUER_START] ^ 1,
        ),
        "rog3_torn_leaf": lambda value: value.__setitem__(
            ISSUER_LEAF_X - ISSUER_START + 7,
            value[ISSUER_LEAF_X - ISSUER_START + 7] ^ 1,
        ),
        "rog3_torn_digest": lambda value: value.__setitem__(
            ISSUER_DIGEST - ISSUER_START + 9,
            value[ISSUER_DIGEST - ISSUER_START + 9] ^ 1,
        ),
        "rog3_torn_checksum": lambda value: value.__setitem__(
            ISSUER_CHECKSUM_A - ISSUER_START,
            value[ISSUER_CHECKSUM_A - ISSUER_START] ^ 1,
        ),
    }
    for label, mutation in mutations.items():
        gate_reject(gate_image, gate_header, expected, mutation)
        hostile[label] = "rejected"

    stale_generation = bytearray(expected)
    struct.pack_into(
        "<H",
        stale_generation,
        ISSUER_GENERATION - ISSUER_START,
        GENERATION ^ 1,
    )
    checksum_a, checksum_b = G.issuer_checksum(
        bytes(
            stale_generation[
                ISSUER_GENERATION
                - ISSUER_START : ISSUER_CHECKSUM_A
                - ISSUER_START
            ]
        )
    )
    struct.pack_into(
        "<HH",
        stale_generation,
        ISSUER_CHECKSUM_A - ISSUER_START,
        checksum_a,
        checksum_b,
    )
    stale_generation_machine = gate_machine(
        gate_image, gate_header, bytes(stale_generation)
    )
    stale_generation_machine.call(
        G.ENTRY_COMMIT,
        ax=GENERATION,
        bx=G.ROUTE_LIVE_NO_TICKET,
        expect_success=False,
    )
    hostile["rog3_stale_checksummed_generation"] = "rejected"

    return {
        "schema": "seed-tls13-auth-p256-publication-adapter-v1",
        "status": "pass",
        "adapter": {
            "origin": f"0x{ORIGIN:04x}",
            "entry": f"0x{header.entry:04x}",
            "content_bytes": len(adapter),
            "sector_count": 1,
            "sector_slack_bytes": MAX_BYTES - len(adapter),
            "sha256": hashlib.sha256(adapter).hexdigest(),
            "header": {
                key: (
                    f"0x{value:04x}"
                    if key
                    not in {
                        "version",
                        "image_bytes",
                    }
                    else value
                )
                for key, value in asdict(header).items()
            },
            "static": static,
        },
        "auth": {
            "actual_live_compact_image_sha256": hashlib.sha256(auth).hexdigest(),
            "actual_entry_table_slot": f"0x{AUTH_VERIFY_SLOT:04x}",
            "generation_source": f"0x{AUTH_GENERATION:04x}",
            "generation": f"0x{GENERATION:04x}",
            "digest": f"0x{AUTH_DIGEST:04x}",
            "signature_length": f"0x{AUTH_SIGNATURE_LEN:04x}",
            "signature": f"0x{AUTH_SIGNATURE:04x}",
            "legacy_status_preserved": f"0x{AUTH_STATUS:04x}",
            "forged_status_cannot_bypass_full_p256": True,
        },
        "publication": {
            "range": f"0x{ISSUER_START:04x}..0x{ISSUER_END:04x}",
            "bytes": ISSUER_END - ISSUER_START,
            "status": f"0x{ISSUER_STATUS:04x}",
            "magic": "LP1!",
            "generation": f"0x{ISSUER_GENERATION:04x}",
            "profile": f"0x{ISSUER_PROFILE:04x}",
            "profile_value": f"0x{ISSUER_PROFILE_VALUE:04x}",
            "leaf_x": f"0x{ISSUER_LEAF_X:04x}..0x{ISSUER_LEAF_Y:04x}",
            "leaf_y": f"0x{ISSUER_LEAF_Y:04x}..0x{ISSUER_DIGEST:04x}",
            "authenticated_digest": (
                f"0x{ISSUER_DIGEST:04x}..0x{ISSUER_CHECKSUM_A:04x}"
            ),
            "checksum_a": f"0x{ISSUER_CHECKSUM_A:04x}",
            "checksum_b": f"0x{ISSUER_CHECKSUM_B:04x}",
            "status_written_last": True,
            "exact_object_sha256": hashlib.sha256(expected).hexdigest(),
        },
        "composition": {
            "gate_image_sha256": hashlib.sha256(gate_image).hexdigest(),
            "gate_entry": f"0x{G.ORIGIN + G.HEADER_BYTES:04x}",
            "credential_loader_callback": f"0x{G.READ_LOADER:04x}",
            "live_no_ticket_commit": True,
            "gate_authorization": True,
            "credential_unlock": True,
            "old_compact_status_not_required_by_gate": True,
            "exact_16k_map": True,
        },
        "hostile_cases": hostile,
        "hostile_case_count": len(hostile),
        "limits": [
            (
                "LP1 provenance is enforced by the fixed phase graph and the "
                "adapter rerunning P-256; the public torn-write checksum is "
                "not an arbitrary-RAM-attacker MAC."
            )
        ],
        "sources": {
            "adapter": sha256_file(SOURCE),
            "checker": sha256_file(CHECKER),
            "readme": sha256_file(README) if README.exists() else None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
