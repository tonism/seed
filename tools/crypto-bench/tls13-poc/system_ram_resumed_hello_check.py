#!/usr/bin/env python3
"""Execute the resumed product HELLO from its conventional-RAM capsule."""

from __future__ import annotations

import hashlib
import os


os.environ["TLS13_POC_K14"] = "1"

import hello_check as hello  # noqa: E402


ROOT = 0x3400
INPUT_START = 0x3420
RANDOM = INPUT_START
SESSION = RANDOM + 32
PSK = SESSION + 32
AGE = PSK + 32
TICKET_LEN = AGE + 4
INPUT_END = TICKET_LEN + 2
CONFIG = 0x3B9C
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
        (INPUT_START, INPUT_END),
        (hello.STACK_GUARD, hello.RAM_END),
    )
    return any(start <= address and address + size <= end for start, end in ranges)


def main() -> int:
    image = hello.assemble(
        "TLS13_PRODUCT_TLS13",
        "HELLO_RESUMED_ONLY",
        "HELLO_RESUMED_CACHED_CONNECT",
        "HELLO_SYSTEM_RAM_RESUME_INPUTS",
    )
    header = hello.parse_header(image)
    hello.verify_static_header(image, header, expected_entries=14)
    if header.attempt_end != INPUT_END:
        raise AssertionError(
            f"system resumed HELLO input end drifted: {header.attempt_end:04x}"
        )

    fixture = hello.make_fixture()
    message, record, truncated, binder = hello.build_resumed_client(
        fixture.ek,
        fixture.random,
        fixture.session,
        fixture.identity,
        fixture.age,
        fixture.psk,
        record_size_limit=hello.PRODUCT_RECORD_SIZE_LIMIT,
    )
    server = hello.build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=True,
    )

    vm = hello.Overlay(image, header)
    root = hashlib.sha256(b"Seed system resumption entropy root").digest()
    vm.write(ROOT, root)
    vm.write(RANDOM, fixture.random)
    vm.write(SESSION, fixture.session)
    vm.write(PSK, fixture.psk)
    vm.write(AGE, fixture.age)
    vm.write(TICKET_LEN, len(fixture.identity).to_bytes(2, "little"))
    vm.write(hello.TICKET_START, fixture.identity)
    vm.write(hello.EK_START, fixture.ek)

    config_before = vm.read(CONFIG, CONFIG_END - CONFIG)
    video_before = vm.read(0xB000, 0x1000)
    nic_before = vm.read(0xD000, 0x1000)

    vm.call(1)
    first = vm.call(2)
    expected_first = hello.RX_START + 14 + 20 + 20
    if first[:3] != (1, expected_first, 147):
        raise AssertionError(
            "system resumed HELLO first-fragment ABI drifted: "
            f"AX/SI/CX={first[:3]!r}, expected={(1, expected_first, 147)!r}"
        )
    emitted, fragments = hello.drain_client(vm, fixture.ek)
    hello.assert_equal("system-RAM resumed ClientHello", emitted, record)
    hello.assert_equal(
        "system-RAM resumed binder",
        emitted[-32:],
        binder,
    )
    if hashlib.sha256(truncated).digest() == bytes(32):
        raise AssertionError("resumed truncated transcript unexpectedly zero")
    hello.feed_server(vm, server, cuts=(1, 2, 380, 384, 384, 65))
    hello.assert_equal(
        "system-RAM resumed transcript digest",
        vm.read(hello.HELLO_DIGEST, 32),
        hashlib.sha256(message + server).digest(),
    )
    hello.verify_transcript_handoff(vm, message + server)

    for name, address, expected in (
        ("entropy root", ROOT, root),
        ("ticket PSK", PSK, fixture.psk),
        ("ticket identity", hello.TICKET_START, fixture.identity),
        ("product config", CONFIG, config_before),
        ("MDA/CGA video RAM", 0xB000, video_before),
        ("NIC/card RAM", 0xD000, nic_before),
    ):
        hello.assert_equal(name, vm.read(address, len(expected)), expected)

    escaped = [
        (address, size)
        for address, size in vm.emulated_writes
        if not allowed_write(address, size, header, len(image))
    ]
    if escaped:
        raise AssertionError(f"system resumed HELLO write escaped: {escaped[:8]}")

    vm.call(8)
    hello.assert_equal("entropy root after clear", vm.read(ROOT, 32), root)
    hello.assert_equal(
        "resumed input clear",
        vm.read(INPUT_START, INPUT_END - INPUT_START),
        bytes(INPUT_END - INPUT_START),
    )
    hello.assert_equal(
        "ticket identity clear",
        vm.read(hello.TICKET_START, len(fixture.identity)),
        bytes(len(fixture.identity)),
    )
    hello.assert_equal("product config after clear", vm.read(CONFIG, len(config_before)), config_before)
    hello.assert_equal("video RAM after clear", vm.read(0xB000, len(video_before)), video_before)
    hello.assert_equal("NIC/card RAM after clear", vm.read(0xD000, len(nic_before)), nic_before)

    print("TLS 1.3 system-RAM resumed HELLO: PASS")
    print(f"  exact product record: {len(record)} bytes / {len(fragments)} fragments")
    print("  root retained; random/session/PSK/age + ticket identity bounded")
    print("  config/video/NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
