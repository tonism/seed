#!/usr/bin/env python3
"""Execute preconnect-prehashed resumed HELLO and ninth-sector connector phases."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


os.environ["TLS13_POC_K14"] = "1"

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import check_tls13_sym_overlay as S
import hello_check as H


CHECKER = Path(__file__).resolve()
HELLO_SOURCE = HERE / "hello_overlay.asm"
CONNECT_SOURCE = HERE / "post_auth_cached_connect.asm"
DEFAULT_OUTPUT = HERE / "post_auth_resumed_hello_results.json"
HELLO_DEFINES = ("HELLO_RESUMED_ONLY", "HELLO_RESUMED_EARLY_DATA")
SECTOR = 512
HELLO_SECTORS = 8
CONNECT_ORIGIN = 0x2800
RX_SECTORS = 2
LIVE_RESUMED_EE = S.RESUMED_ENCRYPTED_EXTENSIONS
LIVE_RESUMED_SERVER_EXT_PREFIX = bytes.fromhex(
    "0029000200000033046411ec0460"
)
LIVE_RESUMED_SERVER_EXT_SUFFIX = bytes.fromhex("002b00020304")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def repository_path(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def listing_mov_immediate(listing: str, label: str) -> int:
    pattern = re.compile(
        rf"^\s*\d+\s+[0-9A-Fa-f]{{8}}\s+"
        rf"([0-9A-Fa-f]{{6}})\s+.*\b{re.escape(label)}\b"
    )
    for line in listing.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        encoded = bytes.fromhex(match.group(1))
        if 0xB8 <= encoded[0] <= 0xBF:
            return int.from_bytes(encoded[1:3], "little")
    raise AssertionError(f"cannot resolve immediate {label} in HELLO listing")


def assemble_hello() -> tuple[bytes, int, int]:
    with tempfile.TemporaryDirectory(
        prefix="seed-post-auth-resumed-hello-"
    ) as temp_name:
        output = Path(temp_name) / "hello.bin"
        listing = Path(temp_name) / "hello.lst"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-DTLS13_POC_K14=1",
                *(f"-D{define}=1" for define in HELLO_DEFINES),
                "-I",
                str(HERE) + "/",
                "-I",
                str(ROOT / "targets/ibm_pc_5150/boot") + "/",
                "-l",
                str(listing),
                "-o",
                str(output),
                str(HELLO_SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        listing_text = listing.read_text(encoding="utf-8")
        return (
            output.read_bytes(),
            listing_mov_immediate(listing_text, "hello_truncated_digest"),
            listing_mov_immediate(listing_text, "hello_secret_b"),
        )


def assemble_connector() -> bytes:
    with tempfile.TemporaryDirectory(
        prefix="seed-post-auth-connect-"
    ) as temp_name:
        output = Path(temp_name) / "cached-connect.bin"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                f"-DPOST_AUTH_CACHED_CONNECT_ORIGIN=0x{CONNECT_ORIGIN:04x}",
                "-I",
                str(HERE) + "/",
                "-o",
                str(output),
                str(CONNECT_SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        return output.read_bytes()


def parse_connector(image: bytes) -> tuple[int, int, int]:
    if image[:4] != b"RHC1":
        raise AssertionError("cached connector magic mismatch")
    version, image_bytes, entry_count = struct.unpack_from("<3H", image, 4)
    entries = struct.unpack_from("<3H", image, 10)
    if (
        version != 1
        or image_bytes != len(image)
        or entry_count != 3
        or len(image) > SECTOR
        or not all(
            CONNECT_ORIGIN <= entry < CONNECT_ORIGIN + len(image)
            for entry in entries
        )
    ):
        raise AssertionError("cached connector header/ABI drifted")
    return entries


def input_spans(fixture: H.Fixture) -> tuple[tuple[str, int, bytes], ...]:
    return (
        ("ek", H.EK_START, fixture.ek),
        ("random", H.CLIENT_RANDOM, fixture.random),
        ("session", H.SESSION_ID, fixture.session),
        ("ticket", H.TICKET_START, fixture.identity),
        ("psk", H.TICKET_PSK, fixture.psk),
        ("age", H.TICKET_AGE, fixture.age),
        (
            "ticket_len",
            H.TICKET_LEN,
            len(fixture.identity).to_bytes(2, "little"),
        ),
    )


def build_early_resumed_client(
    fixture: H.Fixture,
) -> tuple[bytes, bytes, bytes, bytes]:
    identity = fixture.identity
    if not 1 <= len(identity) <= H.TICKET_MAX:
        raise ValueError("ticket identity outside overlay bound")
    identities = (
        H.u16(2 + len(identity) + 4)
        + H.u16(len(identity))
        + identity
        + fixture.age
    )
    binder_placeholder = H.u16(33) + b"\x20" + b"\x00" * 32
    psk_extension = H.extension(41, identities + binder_placeholder)
    extensions = (
        H.base_extensions(fixture.ek)
        + H.extension(45, b"\x01\x01")
        + H.extension(42, b"")
        + psk_extension
    )
    placeholder = H.handshake(
        1,
        H.client_body_prefix(
            fixture.random,
            fixture.session,
            extensions,
        ),
    )
    truncated = placeholder[:-35]
    binder = H.resumption_binder(fixture.psk, truncated)
    message = placeholder[:-32] + binder
    if len(message) != 1433 + len(identity):
        raise AssertionError(
            f"early resumed ClientHello length drifted: {len(message)}"
        )
    record = b"\x16\x03\x01" + H.u16(len(message)) + message
    return message, record, truncated, binder


def prehash_client(
    vm: H.Overlay,
    ek: bytes,
) -> tuple[bytes, list[int]]:
    """Drive the product's complete offline iterator pass."""

    chunks: list[bytes] = []
    lengths: list[int] = []
    while True:
        ax, si, cx, _ = vm.call(2)
        if ax == 0:
            if cx != 0:
                raise AssertionError(
                    "prehash end-of-stream returned a nonzero length"
                )
            break
        if ax != 1 or not 1 <= cx <= H.MSS:
            raise AssertionError("bad prehash fragment iterator result")
        repeated = vm.call(2)
        if repeated[:3] != (ax, si, cx):
            raise AssertionError(
                "pending prehash fragment was not stable"
            )
        chunks.append(vm.read(si, cx))
        lengths.append(cx)
        if vm.read(H.EK_START, H.EK_LEN) != ek:
            raise AssertionError(
                "ek changed before pending prehash fragment consumption"
            )
        # EXCHANGE uses the shared checked advance entry for its offline pass;
        # rewind is what prevents the later byte-identical replay from hashing.
        vm.call(3)
        if vm.read(H.EK_START, H.EK_LEN) != ek:
            raise AssertionError(
                "ek changed before complete ClientHello prehash"
            )
    return b"".join(chunks), lengths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    hello, truncated_digest_address, binder_address = assemble_hello()
    hello_header = H.parse_header(hello)
    H.verify_static_header(hello, hello_header, expected_entries=15)
    if (
        len(set(hello_header.entries[9:12])) != 1
        or len(set(hello_header.entries[12:15])) != 3
        or any(
            entry in hello_header.entries[9:12]
            for entry in hello_header.entries[12:15]
        )
    ):
        raise AssertionError(
            "early resumed-only HELLO extended entry table drifted"
        )
    if not (
        H.HELLO_HANDOFF_END
        <= truncated_digest_address
        < truncated_digest_address + 32
        <= binder_address
        < binder_address + 32
        <= 0x1000
    ):
        raise AssertionError("resumed HELLO digest/binder low-state ABI drifted")
    if not 7 * SECTOR < len(hello) <= HELLO_SECTORS * SECTOR:
        raise AssertionError("resumed HELLO is not an exact eight-sector phase")
    if H.K_START + len(hello) > 0x2800:
        raise AssertionError("resumed HELLO reaches the ninth symmetric sector")
    if CONNECT_ORIGIN != H.K_START + HELLO_SECTORS * SECTOR:
        raise AssertionError("cached connector is not the ninth HELLO sector")

    connector = assemble_connector()
    connector_entries = parse_connector(connector)
    if CONNECT_ORIGIN + SECTOR > hello_header.sha_start:
        raise AssertionError("cached connector reaches the live SHA context")
    connector_header = dataclasses.replace(
        hello_header,
        entries=connector_entries,
    )

    fixture = H.make_fixture()
    expected_message, expected_record, truncated, expected_binder = (
        build_early_resumed_client(fixture)
    )
    expected_client_digest = hashlib.sha256(expected_message).digest()
    hello_padded = hello.ljust(HELLO_SECTORS * SECTOR, b"\0")
    connector_padded = connector.ljust(SECTOR, b"\0")
    machine = H.CachedConnectOverlay(
        hello,
        hello_header,
        receive_actions=("empty", "valid"),
    )

    events: list[str] = []
    machine.write(H.K_START, hello_padded)
    machine.uc.ctl_remove_cache(
        H.K_START,
        H.K_START + HELLO_SECTORS * SECTOR,
    )
    events.append("phase_load:resumed_hello_8_sectors")
    restored = input_spans(fixture)
    fixed_restored = tuple(
        span for span in restored if span[0] != "ticket"
    )
    identity_span = next(span for span in restored if span[0] == "ticket")
    for _label, address, value in fixed_restored:
        machine.write(address, value)
    events.append("fixed_restore:random/session/psk/age/ticket_len/ek")
    low_state_before_connector_load = machine.read(
        hello_header.state_start,
        hello_header.state_end - hello_header.state_start,
    )
    sha_before_connector_load = machine.read(
        hello_header.sha_start,
        hello_header.sha_end - hello_header.sha_start,
    )
    machine.write(CONNECT_ORIGIN, connector_padded)
    machine.uc.ctl_remove_cache(CONNECT_ORIGIN, CONNECT_ORIGIN + SECTOR)
    events.append("phase_preload:cached_connector_ninth_sector")
    if machine.read(
        hello_header.state_start,
        hello_header.state_end - hello_header.state_start,
    ) != low_state_before_connector_load:
        raise AssertionError("ninth-sector connector load changed low HELLO state")
    if machine.read(
        hello_header.sha_start,
        hello_header.sha_end - hello_header.sha_start,
    ) != sha_before_connector_load:
        raise AssertionError("ninth-sector connector load changed SHA context")

    _identity_label, identity_address, identity = identity_span
    machine.write(identity_address, identity)
    events.append("tx_restore:ticket_identity")
    machine.call(1)
    events.append("hello.entry1:resumed_begin")
    for label, address, value in restored:
        if machine.read(address, len(value)) != value:
            raise AssertionError(f"resumed begin destroyed restored {label}")

    extensions = H.client_extensions(expected_message)
    if [kind for kind, _body in extensions][-3:] != [45, 42, 41]:
        raise AssertionError(
            "psk_dhe_ke/early_data/final pre_shared_key ordering changed"
        )
    if extensions[-3][1] != b"\x01\x01" or extensions[-2][1] != b"":
        raise AssertionError("early resumed ClientHello extension body drifted")
    independently_derived_binder = H.resumption_binder(
        fixture.psk,
        truncated,
    )
    if expected_binder != independently_derived_binder:
        raise AssertionError("resumed HELLO binder differs from independent oracle")
    if machine.read(truncated_digest_address, 32) != hashlib.sha256(
        truncated
    ).digest():
        raise AssertionError("8086 truncated ClientHello digest differs from oracle")
    if machine.read(binder_address, 32) != expected_binder:
        raise AssertionError("8086 in-memory binder differs from oracle")
    prehashed, fragments = prehash_client(machine, fixture.ek)
    events.append("hello.entry3:full_transcript_prehash")
    if prehashed != expected_record:
        raise AssertionError(
            "8086 prehashed resumed ClientHello differs from oracle"
        )
    expected_fragments = [
        147,
        384,
        384,
        384,
        32,
        68,
        len(fixture.identity),
        39,
    ]
    if fragments != expected_fragments:
        raise AssertionError(
            f"early resumed fragment geometry drifted: {fragments!r}"
        )
    machine.call(4)
    events.append("hello.entry4:rewind")
    if machine.read(CONNECT_ORIGIN, len(connector_padded)) != connector_padded:
        raise AssertionError("HELLO prehash/rewind changed cached connector")

    low_state_before_connector = machine.read(
        hello_header.state_start,
        hello_header.state_end - hello_header.state_start,
    )
    sha_context_before_connector = machine.read(
        hello_header.sha_start,
        hello_header.sha_end - hello_header.sha_start,
    )
    machine.header = connector_header
    machine.call(0)
    events.append("cached_phase.entry0:connect")
    if len(machine.transmit_calls) != 1 or machine.ack_calls != 1:
        raise AssertionError("cached connector did not establish one fresh socket")
    if machine.read(
        hello_header.state_start,
        hello_header.state_end - hello_header.state_start,
    ) != low_state_before_connector:
        raise AssertionError("cached connect changed low HELLO state")
    if machine.read(
        hello_header.sha_start,
        hello_header.sha_end - hello_header.sha_start,
    ) != sha_context_before_connector:
        raise AssertionError("cached connect changed SHA context")

    machine.header = hello_header
    replayed, replay_fragments = H.drain_client(machine, fixture.ek)
    events.append("hello.replay:byte_exact")
    if replayed != expected_record or replay_fragments != fragments:
        raise AssertionError("post-connect ClientHello replay differs from prehash")
    if machine.read(
        hello_header.sha_start,
        hello_header.sha_end - hello_header.sha_start,
    ) != sha_context_before_connector:
        raise AssertionError("post-connect replay rehashed the ClientHello")

    low_state_before_rx = machine.read(
        hello_header.state_start,
        hello_header.state_end - hello_header.state_start,
    )
    sha_context_before_rx = machine.read(
        hello_header.sha_start,
        hello_header.sha_end - hello_header.sha_start,
    )
    rx_replacement = bytes([0xC7]) * (RX_SECTORS * SECTOR)
    machine.write(CONNECT_ORIGIN, rx_replacement)
    machine.uc.ctl_remove_cache(
        CONNECT_ORIGIN,
        CONNECT_ORIGIN + len(rx_replacement),
    )
    events.append("phase_load:rx_overwrites_cached_connector")
    if machine.read(CONNECT_ORIGIN, len(connector)) == connector:
        raise AssertionError("later RX phase did not overwrite cached connector")
    if machine.read(
        hello_header.state_start,
        hello_header.state_end - hello_header.state_start,
    ) != low_state_before_rx:
        raise AssertionError("later RX phase changed low HELLO state")
    if machine.read(
        hello_header.sha_start,
        hello_header.sha_end - hello_header.sha_start,
    ) != sha_context_before_rx:
        raise AssertionError("later RX phase changed SHA context")

    digest_machine = H.Overlay(hello, hello_header)
    H.seed_inputs(digest_machine, fixture)
    digest_machine.call(1)
    digest_emitted, digest_fragments = prehash_client(
        digest_machine,
        fixture.ek,
    )
    if digest_emitted != expected_record or digest_fragments != fragments:
        raise AssertionError("full-digest prehash differs from primary prehash")
    digest_machine.call(14)
    if (
        digest_machine.read(truncated_digest_address, 32)
        != expected_client_digest
    ):
        raise AssertionError("8086 full ClientHello digest differs from oracle")

    premature_digest = H.Overlay(hello, hello_header)
    H.seed_inputs(premature_digest, fixture)
    premature_digest.call(1)
    premature_digest.call(14, expect_success=False)
    if premature_digest.read(H.STATUS, 1) != b"\x00":
        raise AssertionError("premature full ClientHello digest committed status")

    server = H.build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=True,
    )
    H.feed_server(machine, server, cuts=(384, 1, 383, 2, 17))
    events.append("hello.server:transcript_commit")
    expected_digest = hashlib.sha256(expected_message + server).digest()
    if machine.read(H.HELLO_DIGEST, 32) != expected_digest:
        raise AssertionError("resumed HELLO transcript digest differs from oracle")
    if machine.read(H.STATUS, 1) != b"\x01":
        raise AssertionError("resumed HELLO did not publish status last")
    H.verify_transcript_handoff(machine, expected_message + server)

    psk_first_server = H.build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=True,
        psk_first=True,
    )
    if (
        psk_first_server[76:90] != LIVE_RESUMED_SERVER_EXT_PREFIX
        or psk_first_server[1210:1216] != LIVE_RESUMED_SERVER_EXT_SUFFIX
    ):
        raise AssertionError(
            "PSK-first resumed ServerHello differs from live public shape"
        )
    psk_first_machine = H.new_ready_vm(
        hello,
        hello_header,
        fixture,
        resumed=True,
    )
    H.feed_server(
        psk_first_machine,
        psk_first_server,
        cuts=(384, 384, 384, 64),
    )
    psk_first_digest = hashlib.sha256(
        expected_message + psk_first_server
    ).digest()
    if psk_first_machine.read(H.HELLO_DIGEST, 32) != psk_first_digest:
        raise AssertionError(
            "PSK-first resumed HELLO transcript digest differs from oracle"
        )
    H.verify_transcript_handoff(
        psk_first_machine,
        expected_message + psk_first_server,
    )

    hostile_servers = {
        "duplicate_versions": bytearray(server),
        "duplicate_psk": bytearray(psk_first_server),
        "unknown_resumed_extension": bytearray(psk_first_server),
        "malformed_resumed_extension_length": bytearray(psk_first_server),
    }
    hostile_servers["duplicate_versions"][1211] = 0x2B
    hostile_servers["duplicate_versions"][1214:1216] = b"\x03\x04"
    hostile_servers["duplicate_psk"][1211] = 0x29
    hostile_servers["duplicate_psk"][1214:1216] = b"\x00\x00"
    hostile_servers["unknown_resumed_extension"][77] = 0x2A
    hostile_servers["malformed_resumed_extension_length"][79] = 0x03
    for label, hostile in hostile_servers.items():
        rejected = H.new_ready_vm(
            hello,
            hello_header,
            fixture,
            resumed=True,
        )
        H.feed_server(rejected, bytes(hostile), expect_success=False)
        if rejected.read(H.STATUS, 1) != b"\x00":
            raise AssertionError(f"{label} committed resumed HELLO status")

    fresh = H.Overlay(hello, hello_header)
    H.seed_inputs(fresh, fixture)
    fresh.call(0, expect_success=False)
    if fresh.read(H.STATUS, 1) != b"\x00":
        raise AssertionError("resumed-only phase committed through fresh entry")

    if S.BASE.build_encrypted_extensions() != LIVE_RESUMED_EE:
        raise AssertionError(
            "resumed EncryptedExtensions literal differs from live target profile"
        )

    result = {
        "schema": "seed-post-auth-resumed-hello-v4",
        "status": "pass",
        "scope": (
            "offline preconnect-prehashed K14 resumed-only HELLO and "
            "ninth-sector cached connector phases; "
            "no VM, network, credential, target entropy, or security credit"
        ),
        "sources": {
            "hello": repository_path(HELLO_SOURCE),
            "hello_sha256": sha256(HELLO_SOURCE.read_bytes()),
            "cached_connector": repository_path(CONNECT_SOURCE),
            "cached_connector_sha256": sha256(CONNECT_SOURCE.read_bytes()),
            "checker_sha256": sha256(CHECKER.read_bytes()),
        },
        "cached_connector": {
            "bytes": len(connector),
            "sha256": sha256(connector),
            "sectors": 1,
            "padded_bytes": len(connector_padded),
            "padded_sha256": sha256(connector_padded),
            "destination": f"0x{CONNECT_ORIGIN:04x}",
            "hello_sector_ordinal": 9,
            "preloaded_after_hello_before_tx_prehash": True,
            "overwritten_by_later_rx": True,
            "header_entry_table_file_offset": 10,
            "entries": [f"0x{entry:04x}" for entry in connector_entries],
        },
        "resumed_hello": {
            "defines": ["TLS13_POC_K14", *HELLO_DEFINES],
            "bytes": len(hello),
            "sha256": sha256(hello),
            "sectors": HELLO_SECTORS,
            "padded_bytes": len(hello_padded),
            "padded_sha256": sha256(hello_padded),
            "destination": "0x1800",
            "runtime_end": f"0x{H.K_START + len(hello):04x}",
            "ninth_symmetric_sector_touched": False,
            "preconnect_restore_sectors": 8,
            "header_entry_table_file_offset": 48,
            "entry_count": len(hello_header.entries),
            "entries": [
                f"0x{entry:04x}" for entry in hello_header.entries
            ],
            "fresh_entry": f"0x{hello_header.entries[0]:04x}",
            "resumed_begin": f"0x{hello_header.entries[1]:04x}",
            "full_client_digest": f"0x{hello_header.entries[14]:04x}",
            "truncated_digest_address": f"0x{truncated_digest_address:04x}",
            "binder_address": f"0x{binder_address:04x}",
        },
        "dispatcher_order": {
            "events": events,
            "hello_load_and_fixed_restore_before_connector_preload": True,
            "connector_preload_before_tx_identity_restore": True,
            "full_transcript_prehash_before_cached_connect": True,
            "rewind_before_cached_connect": True,
            "cached_connector_loaded_at_ninth_sector": True,
            "cached_connector_overwritten_by_later_rx": True,
            "restored_inputs_survive_resumed_begin": True,
        },
        "wire": {
            "client_hello_bytes": len(expected_message),
            "record_bytes": len(expected_record),
            "fragments": fragments,
            "replay_fragments": replay_fragments,
            "extension_tail": ["psk_dhe_ke", "early_data", "pre_shared_key"],
            "early_data_body_bytes": 0,
            "truncated_client_hello_sha256": hashlib.sha256(
                truncated
            ).hexdigest(),
            "full_client_hello_sha256": expected_client_digest.hex(),
            "binder_sha256": sha256(expected_binder),
            "independent_binder_oracle": True,
            "server_hello_bytes": len(server),
            "psk_first_server_hello_bytes": len(psk_first_server),
            "transcript_sha256": sha256(expected_message + server),
            "psk_first_transcript_sha256": sha256(
                expected_message + psk_first_server
            ),
            "live_resumed_encrypted_extensions_hex": LIVE_RESUMED_EE.hex(),
            "live_resumed_server_extension_prefix_hex": (
                LIVE_RESUMED_SERVER_EXT_PREFIX.hex()
            ),
            "live_resumed_server_extension_suffix_hex": (
                LIVE_RESUMED_SERVER_EXT_SUFFIX.hex()
            ),
        },
        "gates": {
            "fresh_entry_fails_closed": True,
            "hello_loaded_before_cached_connect": True,
            "fixed_inputs_restored_before_resumed_begin": True,
            "connector_preloaded_before_full_prehash": True,
            "prehash_and_rewind_preserve_connector": True,
            "full_clienthello_prehashed_before_connect": True,
            "hello_rewound_before_connect": True,
            "cached_connector_is_ninth_sector": True,
            "connector_preserves_low_hello_state": True,
            "connector_preserves_sha_context": True,
            "connector_overwritten_by_later_rx": True,
            "post_connect_replay_is_byte_exact": True,
            "first_post_connect_work_is_replay": True,
            "post_connect_replay_does_not_rehash": True,
            "post_connector_server_transcript_matches_oracle": True,
            "fifteen_entry_early_data_abi": True,
            "early_data_before_final_psk": True,
            "exact_truncated_digest_matches_oracle": True,
            "exact_full_client_digest_matches_oracle": True,
            "premature_full_client_digest_fails_closed": True,
            "exact_8086_record_matches_oracle": True,
            "exact_resumed_server_hello_accepted": True,
            "canonical_and_psk_first_server_orders_accepted": True,
            "live_psk_first_public_shape_accepted": True,
            "duplicate_resumed_extensions_rejected": True,
            "unknown_resumed_extension_rejected": True,
            "malformed_resumed_extension_length_rejected": True,
            "status_last_handoff": True,
        },
    }
    args.output.write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )
    print("post-auth prehashed HELLO/ninth-sector connector phases: PASS")
    print(
        f"  connector={len(connector)} bytes/1 sector "
        f"sha256={sha256(connector)}"
    )
    print(
        f"  hello={len(hello)} bytes/{HELLO_SECTORS} sectors "
        f"sha256={sha256(hello)} end=0x{H.K_START + len(hello):04x}"
    )
    print(
        "  order=8-sector HELLO/fixed restore -> ninth-sector connector "
        "preload -> identity/prehash/rewind -> connect/replay -> RX overwrite"
    )
    print(
        f"  binder={sha256(expected_binder)} "
        f"full_client_digest={expected_client_digest.hex()} "
        f"ServerHello={len(server)} bytes EE={LIVE_RESUMED_EE.hex()}"
    )
    print(f"  results={args.output}")


if __name__ == "__main__":
    main()
