#!/usr/bin/env python3
"""Crash oracle for the self-contained 8088 attempt-seed ratchet.

This is an architecture spike, not product persistence code.  It models two
dedicated 512-byte floppy slots.  Before an attempt seed becomes usable, the
machine derives and durably verifies the next ratchet state in the alternate
slot.  A power loss before that point emits no attempt; a power loss afterward
leaves the next boot on the advanced state.

The oracle exhausts every prefix-torn sector write and the commit/emit
boundaries.  It proves deterministic non-reuse under the stated media model.
It does not make a copied/rolled-back floppy safe, authenticate mutable media,
or establish how much entropy human timing contributes on write-protected
media.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass


SECTOR_BYTES = 512
BODY_BYTES = 480
DIGEST_BYTES = 32
MAGIC = b"SEEDRT13"
VERSION = 1
STATE_BYTES = 32
ERASED = bytes([0xF6]) * SECTOR_BYTES


def sha3(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_256()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


@dataclass(frozen=True)
class Record:
    generation: int
    state: bytes

    def encode(self) -> bytes:
        if not 0 <= self.generation < 1 << 64:
            raise ValueError("generation is outside uint64")
        if len(self.state) != STATE_BYTES:
            raise ValueError("ratchet state must be 32 bytes")
        prefix = (
            MAGIC
            + bytes([VERSION, 0, 0, 0])
            + struct.pack("<Q", self.generation)
            + self.state
        )
        body = prefix + bytes(BODY_BYTES - len(prefix))
        return body + sha3(b"Seed ratchet record v1\0", body)

    @classmethod
    def decode(cls, sector: bytes) -> "Record | None":
        if len(sector) != SECTOR_BYTES:
            return None
        body = sector[:BODY_BYTES]
        if sector[BODY_BYTES:] != sha3(b"Seed ratchet record v1\0", body):
            return None
        if body[: len(MAGIC)] != MAGIC or body[len(MAGIC)] != VERSION:
            return None
        generation = struct.unpack_from("<Q", body, 12)[0]
        state = body[20 : 20 + STATE_BYTES]
        return cls(generation, state)


@dataclass
class Media:
    slots: list[bytes]

    @classmethod
    def initialized(cls, state: bytes) -> "Media":
        return cls([Record(0, state).encode(), ERASED])

    def clone(self) -> "Media":
        return Media(list(self.slots))

    def current(self) -> tuple[int, Record]:
        decoded = [(index, Record.decode(slot)) for index, slot in enumerate(self.slots)]
        valid = [(index, record) for index, record in decoded if record is not None]
        if not valid:
            raise ValueError("no valid ratchet slot")
        valid.sort(key=lambda item: item[1].generation)
        if (
            len(valid) == 2
            and valid[0][1].generation == valid[1][1].generation
            and valid[0][1].state != valid[1][1].state
        ):
            raise ValueError("ambiguous equal-generation ratchet slots")
        return valid[-1]


@dataclass(frozen=True)
class PreparedAttempt:
    target_slot: int
    next_record: Record
    encoded_record: bytes
    attempt_seed: bytes


def prepare_attempt(media: Media, local_entropy: bytes) -> PreparedAttempt:
    current_slot, current = media.current()
    generation = current.generation + 1
    generation_bytes = struct.pack("<Q", generation)
    next_state = sha3(
        b"Seed ratchet next-state v1\0",
        current.state,
        generation_bytes,
        local_entropy,
    )
    attempt_seed = sha3(
        b"Seed ML-KEM attempt seed v1\0",
        current.state,
        generation_bytes,
        local_entropy,
    )
    record = Record(generation, next_state)
    return PreparedAttempt(
        target_slot=1 - current_slot,
        next_record=record,
        encoded_record=record.encode(),
        attempt_seed=attempt_seed,
    )


def torn_prefix(old: bytes, new: bytes, written: int) -> bytes:
    if not 0 <= written <= SECTOR_BYTES:
        raise ValueError("written prefix is outside sector")
    return new[:written] + old[written:]


def verified_commit(media: Media, prepared: PreparedAttempt) -> None:
    media.slots[prepared.target_slot] = prepared.encoded_record
    if media.slots[prepared.target_slot] != prepared.encoded_record:
        raise IOError("ratchet readback mismatch")
    decoded = Record.decode(media.slots[prepared.target_slot])
    if decoded != prepared.next_record:
        raise IOError("ratchet record did not verify")


def next_normal_attempt(media: Media, entropy: bytes) -> bytes:
    prepared = prepare_attempt(media, entropy)
    verified_commit(media, prepared)
    return prepared.attempt_seed


def crash_matrix() -> dict[str, object]:
    initial = sha3(b"Seed ratchet oracle initial state v1\0")
    entropy_a = b"physical timing sample A"
    entropy_b = b"physical timing sample B"
    base = Media.initialized(initial)
    first = prepare_attempt(base, entropy_a)
    examined = 0

    # A prefix tear emits no attempt.  On reboot the valid record is either the
    # old generation or (only when the complete sector landed) the new one.
    for written in range(SECTOR_BYTES + 1):
        crashed = base.clone()
        old = crashed.slots[first.target_slot]
        crashed.slots[first.target_slot] = torn_prefix(
            old,
            first.encoded_record,
            written,
        )
        current_generation = crashed.current()[1].generation
        if written < SECTOR_BYTES and current_generation != 0:
            raise AssertionError(
                f"prefix tear {written} unexpectedly committed generation "
                f"{current_generation}"
            )
        if written == SECTOR_BYTES and current_generation != 1:
            raise AssertionError("complete sector did not advance generation")
        next_seed = next_normal_attempt(crashed, entropy_b)
        if next_seed == first.attempt_seed:
            raise AssertionError(f"attempt seed reused after prefix tear {written}")
        examined += 1

    # The fully written record may be followed by a crash before readback,
    # after readback but before emission, or after emission.  All reboot from
    # the advanced state; only the final case counts the first seed as used.
    boundary_names = (
        "after-sector-before-readback",
        "after-readback-before-emission",
        "after-emission",
    )
    for boundary in boundary_names:
        crashed = base.clone()
        verified_commit(crashed, first)
        next_seed = next_normal_attempt(crashed, entropy_b)
        if next_seed == first.attempt_seed:
            raise AssertionError(f"attempt seed reused at {boundary}")
        examined += 1

    # Long successful sequence with deliberately identical local entropy:
    # ratchet state and generation must still prevent deterministic reuse.
    sequence_media = Media.initialized(initial)
    seen: set[bytes] = set()
    sequence_count = 4096
    for _ in range(sequence_count):
        seed = next_normal_attempt(sequence_media, b"identical supplemental input")
        if seed in seen:
            raise AssertionError("successful ratchet sequence repeated an attempt seed")
        seen.add(seed)

    # Single-byte corruptions in either a valid record or its digest must not
    # make a distinct altered record validate.
    encoded = first.encoded_record
    corruptions = 0
    for index in range(SECTOR_BYTES):
        corrupted = bytearray(encoded)
        corrupted[index] ^= 0x01
        if Record.decode(bytes(corrupted)) is not None:
            raise AssertionError(f"single-byte corruption accepted at {index}")
        corruptions += 1

    return {
        "status": "PASS",
        "sector_bytes": SECTOR_BYTES,
        "slots": 2,
        "record_digest": "SHA3-256",
        "prefix_torn_write_cases": SECTOR_BYTES + 1,
        "post_write_boundary_cases": len(boundary_names),
        "crash_cases_examined": examined,
        "successful_sequence_attempts": sequence_count,
        "single_byte_corruptions_rejected": corruptions,
        "guarantee": (
            "No deterministic attempt-seed reuse after a prefix-torn write or "
            "crash at the modeled commit/emission boundaries, provided the "
            "latest valid floppy state is not copied or rolled back."
        ),
        "not_established": [
            "active mutable-media authenticity",
            "copied or rolled-back floppy safety",
            "arbitrary analog sector-failure distributions",
            "human timing entropy credit",
            "write-protected cold-boot freshness",
            "product FAT allocation or BIOS write implementation",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = crash_matrix()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("self-contained attempt-seed ratchet crash oracle: PASS")
        print(
            f"  crash cases: {result['crash_cases_examined']}; "
            f"single-byte corruptions: {result['single_byte_corruptions_rejected']}; "
            f"successful sequence: {result['successful_sequence_attempts']}"
        )
        print("  copied/rolled-back media and write-protected entropy remain unresolved")


if __name__ == "__main__":
    main()
