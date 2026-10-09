#!/usr/bin/env python3
"""Execute the fresh product HELLO with only conventional-RAM inputs."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


# hello_check selects the exact K14 address contract while it is imported.
os.environ["TLS13_POC_K14"] = "1"

import hello_check as hello  # noqa: E402


HERE = Path(__file__).resolve().parent

ROOT_START = 0x0500
ROOT_END = 0x0520
D_START = ROOT_END
D_END = 0x0540
Z_START = D_END
Z_END = 0x0560
RANDOM_START = Z_END
SESSION_START = 0x0580
INPUT_END = 0x05A0
CONFIG_START = 0x3B9C
CONFIG_END = 0x3C9C


def allowed_write(
    address: int,
    size: int,
    header: hello.Header,
    image_len: int,
) -> bool:
    ranges = (
        (hello.K_START, hello.K_START + image_len),
        (hello.RX_START, hello.RX_END),
        (hello.EK_START, hello.EK_START + hello.EK_LEN),
        (hello.HELLO_HANDOFF_START, hello.HELLO_HANDOFF_END),
        (header.state_start, header.state_end),
        (header.ticket_start, header.ticket_start + header.ticket_max),
        (header.sha_start, header.sha_end),
        (RANDOM_START, INPUT_END),
        (hello.STACK_GUARD, hello.RAM_END),
    )
    return any(start <= address and address + size <= end for start, end in ranges)


def main() -> int:
    image = hello.assemble(
        "TLS13_PRODUCT_TLS13",
        "HELLO_FRESH_ONLY",
        "HELLO_CACHED_CONNECT",
        "HELLO_FRESH_TICKET_REQUEST",
        "HELLO_SYSTEM_RAM_INPUTS",
    )
    header = hello.parse_header(image)
    hello.verify_static_header(image, header, expected_entries=14)
    if header.attempt_end != INPUT_END:
        raise AssertionError(
            f"system-RAM HELLO input end drifted: {header.attempt_end:04x}"
        )

    fixture = hello.make_fixture()
    message, record = hello.build_fresh_client(
        fixture.ek,
        fixture.random,
        fixture.session,
        request_ticket=True,
        alpn=b"h2",
    )
    server = hello.build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=False,
    )

    vm = hello.Overlay(image, header)
    root = hashlib.sha256(b"Seed system-RAM entropy root").digest()
    d_seed = hashlib.sha256(b"Seed system-RAM ML-KEM d").digest()
    z_seed = hashlib.sha256(b"Seed system-RAM ML-KEM z").digest()
    vm.write(ROOT_START, root)
    vm.write(D_START, d_seed)
    vm.write(Z_START, z_seed)
    vm.write(RANDOM_START, fixture.random)
    vm.write(SESSION_START, fixture.session)
    vm.write(hello.EK_START, fixture.ek)

    config_before = vm.read(CONFIG_START, CONFIG_END - CONFIG_START)
    video_before = vm.read(0xB000, 0x1000)
    nic_before = vm.read(0xD000, 0x1000)

    vm.call(0)
    emitted, fragments = hello.drain_client(vm, fixture.ek)
    hello.assert_equal("system-RAM fresh ClientHello", emitted, record)
    hello.feed_server(vm, server, cuts=(1, 2, 380, 384, 384, 59))
    hello.assert_equal(
        "system-RAM transcript digest",
        vm.read(hello.HELLO_DIGEST, 32),
        hashlib.sha256(message + server).digest(),
    )
    hello.verify_transcript_handoff(vm, message + server)

    for name, start, expected in (
        ("entropy root", ROOT_START, root),
        ("ML-KEM d", D_START, d_seed),
        ("ML-KEM z", Z_START, z_seed),
        ("product config", CONFIG_START, config_before),
        ("MDA video", 0xB000, video_before),
        ("CGA video", 0xB800, video_before[0x800:]),
        ("NIC/card RAM", 0xD000, nic_before),
    ):
        hello.assert_equal(name + " preservation", vm.read(start, len(expected)), expected)

    escaped = [
        (address, size)
        for address, size in vm.emulated_writes
        if not allowed_write(address, size, header, len(image))
    ]
    if escaped:
        raise AssertionError(f"system-RAM HELLO write escaped: {escaped[:8]}")

    vm.call(8)
    hello.assert_equal(
        "conditioned random/session zeroization",
        vm.read(RANDOM_START, INPUT_END - RANDOM_START),
        b"\x00" * (INPUT_END - RANDOM_START),
    )
    hello.assert_equal("entropy root after clear", vm.read(ROOT_START, 32), root)
    hello.assert_equal("ML-KEM d after clear", vm.read(D_START, 32), d_seed)
    hello.assert_equal("ML-KEM z after clear", vm.read(Z_START, 32), z_seed)
    hello.assert_equal(
        "product config after clear",
        vm.read(CONFIG_START, CONFIG_END - CONFIG_START),
        config_before,
    )
    hello.assert_equal("MDA video after clear", vm.read(0xB000, 0x800), video_before[:0x800])
    hello.assert_equal("CGA video after clear", vm.read(0xB800, 0x800), video_before[0x800:])
    hello.assert_equal("NIC/card RAM after clear", vm.read(0xD000, 0x1000), nic_before)

    print("TLS 1.3 system-RAM fresh HELLO: PASS")
    print(f"  exact product record: {len(record)} bytes / {len(fragments)} fragments")
    print("  inputs: random=0560..0580 session=0580..05a0")
    print("  entropy root + ML-KEM seeds retained; config/video/NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
