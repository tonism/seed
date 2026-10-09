#!/usr/bin/env python3
"""Build deterministic target vectors for exact 286 flight timing.

The hostile offline flight gate remains the semantic oracle.  This builder
exports its current ordinary-Certificate acquisition and no-0RTT PSK-DHE
resumption fixtures so the real product flight and relocated symmetric images
can execute on the exact 6 MHz target gate.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import ModuleType


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"
OUT = BUILD / "crypto-bench/tls13-286-flight-timing"
CHECKER = HERE / "check_286_flight.py"
HELLO_CHECKER = HERE / "check_286_hello_controller.py"
HELLO_PROBE = HERE / "tls13_286_hello_timing_abi_probe.asm"
K14_SYM = BUILD / "tls13-286-flight-sym-k14.bin"
HELLO_RAW = BUILD / "tls13-286-hello.bin"
HELLO_PROBE_MAGIC = b"H286TIM2"
HELLO_PROBE_FIELDS = (
    "hello_phase",
    "hello_mode",
    "hello_hash_enabled",
    "hello_segment",
    "hello_pending",
    "hello_crypto_seg",
    "hello_wire_message_len",
    "hello_wire_extensions_len",
    "hello_wire_tail_len",
    "hello_ticket_len_snapshot",
    "hello_ticket_age",
    "hello_random",
    "hello_session",
    "hello_client_x",
    "hello_clear_work",
    "hello_live_send_client",
    "hello_live_receive_server",
    "hello_server_begin",
    "hello_server_feed",
    "hello_server_finish",
    "hello_live_acquire",
    "hello_live_fresh",
    "hello_sha256_init",
    "hello_phase_tx",
    "hello_mode_acquire",
    "hello_mode_resume",
    "hello_message_len",
    "hello_extensions_len",
    "hello_tail_len",
    "hello_resumption_delta",
)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write(name: str, payload: bytes) -> dict[str, object]:
    path = OUT / name
    path.write_bytes(payload)
    return {
        "path": str(path.relative_to(ROOT)),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def main() -> None:
    if not K14_SYM.is_file() or not HELLO_RAW.is_file():
        raise SystemExit("build the current 286 HELLO/symmetric images first")
    checker = load_module(CHECKER, "seed_tls13_286_flight_timing_checker")
    hello = load_module(HELLO_CHECKER, "seed_tls13_286_hello_timing_checker")
    fixture = checker.build_fixture()
    OUT.mkdir(parents=True, exist_ok=True)

    expected_dk = hello.MLKEM_DK.read_bytes()
    ciphertext = hello.MLKEM_CIPHERTEXT.read_bytes()
    acquisition_client_record = hello.client_oracle(
        expected_dk[1152 : 1152 + hello.EK_BYTES],
        hello.x25519_base(hello.X_SCALAR),
    )
    acquisition_server = hello.server_oracle(
        "versions-first",
        ciphertext=ciphertext,
    )
    fresh = hello.FRESH_BUNDLE
    resumed_dk = hello.KEYGEN_ORACLE.fips_keygen_internal(fresh[:64])
    resumed_ek = resumed_dk[1152 : 1152 + hello.EK_BYTES]
    resumed_client_record, truncated, binder, age = (
        hello.resume_client_oracle(
            resumed_ek,
            hello.x25519_base(fresh[64:96]),
            fixture["ticket_identity"],
            fixture["ticket_psk"],
            int(fixture["ticket_age_add"]).to_bytes(4, "big"),
            10,
            fresh[96:128],
            fresh[128:160],
        )
    )
    resumed_server = hello.server_oracle(
        "versions-first",
        resumed=True,
        ciphertext=ciphertext,
        session_id=fresh[128:160],
    )
    acquisition_client = acquisition_client_record[5:]
    resumed_client = resumed_client_record[5:]
    acquisition_ek = expected_dk[1152 : 1152 + hello.EK_BYTES]
    acquisition_x = hello.x25519_base(hello.X_SCALAR)
    resumed_x = hello.x25519_base(fresh[64:96])
    acquisition_digest = hashlib.sha256(
        acquisition_client + acquisition_server
    ).digest()
    resumed_digest = hashlib.sha256(resumed_client + resumed_server).digest()
    acquisition_server_segments = hello.segmented_server_wire(
        acquisition_server
    )
    resumed_server_segments = hello.segmented_server_wire(resumed_server)
    acquisition_server_wire = b"".join(acquisition_server_segments)
    resumed_server_wire = b"".join(resumed_server_segments)
    acquisition_pending = acquisition_server_wire[
        5 + len(acquisition_server) :
    ]
    resumed_pending = resumed_server_wire[5 + len(resumed_server) :]
    if (
        len(acquisition_server_segments) != 6
        or len(resumed_server_segments) != 6
        or [len(item) for item in acquisition_server_segments[:5]]
        != [1, 2, 380, 384, 384]
        or [len(item) for item in resumed_server_segments[:5]]
        != [1, 2, 380, 384, 384]
        or acquisition_pending != resumed_pending
    ):
        raise AssertionError("HELLO live timing fixture drifted")

    with tempfile.TemporaryDirectory(
        prefix="seed-286-hello-timing-", dir=BUILD
    ) as raw:
        probe_path = Path(raw) / "hello-timing-probe.bin"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-Itargets/ibm_pc_5150/boot/",
                "-Ibuild/ibm_pc_5150/",
                "-o",
                str(probe_path),
                str(HELLO_PROBE),
            ],
            cwd=ROOT,
            check=True,
        )
        probe = probe_path.read_bytes()
    image_bytes = struct.unpack_from("<H", probe, 10)[0]
    if probe[:image_bytes] != HELLO_RAW.read_bytes():
        raise AssertionError("HELLO timing probe changed the product image")
    trailer = probe[image_bytes:]
    if len(trailer) < 10 or trailer[:8] != HELLO_PROBE_MAGIC:
        raise AssertionError("HELLO timing ABI trailer is absent")
    probe_count = struct.unpack_from("<H", trailer, 8)[0]
    if probe_count != len(HELLO_PROBE_FIELDS) or len(trailer) != 10 + 2 * probe_count:
        raise AssertionError("HELLO timing ABI trailer geometry drifted")
    hello_abi = dict(
        zip(
            HELLO_PROBE_FIELDS,
            struct.unpack_from(f"<{probe_count}H", trailer, 10),
            strict=True,
        )
    )
    identity_bytes = len(fixture["ticket_identity"])
    if (
        len(acquisition_client) != hello_abi["hello_message_len"]
        or len(acquisition_client_record) != len(acquisition_client) + 5
        or len(resumed_client)
        != hello_abi["hello_message_len"]
        + identity_bytes
        + hello_abi["hello_resumption_delta"]
        or len(resumed_client_record) != len(resumed_client) + 5
        or len(acquisition_client_record)
        - 140
        - len(acquisition_ek)
        != hello_abi["hello_tail_len"]
        or len(resumed_client_record) - 140 - len(resumed_ek)
        != hello_abi["hello_tail_len"]
        + identity_bytes
        + hello_abi["hello_resumption_delta"]
        or acquisition_server_wire[:5]
        != b"\x16\x03\x03" + len(acquisition_server).to_bytes(2, "big")
        or resumed_server_wire[:5]
        != b"\x16\x03\x03" + len(resumed_server).to_bytes(2, "big")
    ):
        raise AssertionError("HELLO current wire geometry drifted")

    acquisition_wire = checker.EXACT_COMPAT_CCS + b"".join(
        fixture["wire_records"]
    )
    resumed_wire = checker.EXACT_COMPAT_CCS + b"".join(
        fixture["resume_wire_records"]
    )
    application = fixture["resume_application"]
    # The shared parser acknowledges SETTINGS, then sends the 17-byte PING
    # reply through its 16-byte prefix and one-byte tail. Bind all ciphertext,
    # not just Finished/preface, into the exact timing harness.
    controls = (checker.h2_frame(4, 1),
                checker.h2_frame(6, 1, payload=b'12345678')[:16],
                checker.h2_frame(6, 1, payload=b'12345678')[16:])
    def control_records(app):
        return b''.join(checker.BASE.encrypted_record(
            app['client_key'], app['client_iv'], seq,
            checker.ORACLE.CONTENT_APPLICATION_DATA, payload)
            for seq, payload in enumerate(controls, 1))
    outputs = {
        "sym_source": write("sym-source.bin", K14_SYM.read_bytes()),
        "hybrid": write("hybrid.bin", fixture["hybrid"]),
        "acquisition_handoff": write(
            "acquisition-handoff.bin", fixture["handoff"]
        ),
        "acquisition_wire": write("acquisition-wire.bin", acquisition_wire),
        "acquisition_finished": write(
            "acquisition-client-finished.bin",
            fixture["client_finished_record"],
        ),
        "acquisition_head": write("acquisition-head.bin", fixture["head_record"]),
        "resumed_handoff": write("resumed-handoff.bin", fixture["resume_handoff"]),
        "resumed_wire": write("resumed-wire.bin", resumed_wire),
        "resumed_finished": write(
            "resumed-client-finished.bin",
            fixture["resume_client_finished_record"],
        ),
        "resumed_head": write(
            "resumed-head.bin", fixture["resume_head_record"]
        ),
        "acquisition_controls": write('acquisition-controls.bin',
                                      control_records(fixture['application'])),
        "resumed_controls": write('resumed-controls.bin',
                                  control_records(application)),
        "ticket_psk": write("ticket-psk.bin", fixture["ticket_psk"]),
        "ticket_identity": write(
            "ticket-identity.bin", fixture["ticket_identity"]
        ),
        "ticket_nonce": write("ticket-nonce.bin", fixture["ticket_nonce"]),
        "ticket_age_add": write(
            "ticket-age-add.bin",
            int(fixture["ticket_age_add"]).to_bytes(4, "big"),
        ),
        "ticket_binder_hash": write(
            "ticket-binder-hash.bin", fixture["binder_hash"]
        ),
        "ticket_binder": write("ticket-binder.bin", fixture["binder"]),
        "early_derived": write("early-derived.bin", fixture["early_derived"]),
        "app_client_key": write("app-client-key.bin", application["client_key"]),
        "app_server_key": write("app-server-key.bin", application["server_key"]),
        "app_client_iv": write("app-client-iv.bin", application["client_iv"]),
        "app_server_iv": write("app-server-iv.bin", application["server_iv"]),
        "app_client_seq": write(
            "app-client-seq.bin", (1 + len(controls)).to_bytes(8, "big")
        ),
        "app_server_seq": write(
            "app-server-seq.bin",
            int(fixture["resume_publish_after_records"]).to_bytes(8, "big"),
        ),
        "hello_acquisition_client": write(
            "hello-acquisition-client.bin", acquisition_client
        ),
        "hello_acquisition_client_record": write(
            "hello-acquisition-client-record.bin", acquisition_client_record
        ),
        "hello_acquisition_ek": write(
            "hello-acquisition-ek.bin", acquisition_ek
        ),
        "hello_acquisition_random": write(
            "hello-acquisition-random.bin", hello.CLIENT_RANDOM
        ),
        "hello_acquisition_x": write(
            "hello-acquisition-x.bin", acquisition_x
        ),
        "hello_acquisition_server": write(
            "hello-acquisition-server.bin", acquisition_server
        ),
        "hello_acquisition_server_wire": write(
            "hello-acquisition-server-wire.bin", acquisition_server_wire
        ),
        "hello_acquisition_digest": write(
            "hello-acquisition-digest.bin", acquisition_digest
        ),
        "hello_resumed_client": write(
            "hello-resumed-client.bin", resumed_client
        ),
        "hello_resumed_client_record": write(
            "hello-resumed-client-record.bin", resumed_client_record
        ),
        "hello_resumed_ek": write("hello-resumed-ek.bin", resumed_ek),
        "hello_resumed_random": write(
            "hello-resumed-random.bin", fresh[96:128]
        ),
        "hello_resumed_x": write("hello-resumed-x.bin", resumed_x),
        "hello_resumed_server": write(
            "hello-resumed-server.bin", resumed_server
        ),
        "hello_resumed_server_wire": write(
            "hello-resumed-server-wire.bin", resumed_server_wire
        ),
        "hello_resumed_digest": write(
            "hello-resumed-digest.bin", resumed_digest
        ),
        "hello_server_x": write("hello-server-x.bin", hello.SERVER_X),
        "hello_pending_suffix": write(
            "hello-pending-suffix.bin", acquisition_pending
        ),
        "hello_acquisition_session": write(
            "hello-acquisition-session.bin", hello.SESSION_ID
        ),
        "hello_resumed_session": write(
            "hello-resumed-session.bin", fresh[128:160]
        ),
        "hello_resumed_binder": write("hello-resumed-binder.bin", binder),
        "hello_resumed_truncated_hash": write(
            "hello-resumed-truncated-hash.bin", truncated
        ),
        "hello_resumed_age": write("hello-resumed-age.bin", age),
    }

    metadata = {
        "sym_source_bytes": len(K14_SYM.read_bytes()),
        "handoff_bytes": len(fixture["handoff"]),
        "hybrid_bytes": len(fixture["hybrid"]),
        "acquisition_wire_bytes": len(acquisition_wire),
        "acquisition_finished_bytes": len(fixture["client_finished_record"]),
        "acquisition_head_bytes": len(fixture["head_record"]),
        "resumed_wire_bytes": len(resumed_wire),
        "resumed_finished_bytes": len(fixture["resume_client_finished_record"]),
        "resumed_head_bytes": len(fixture["resume_head_record"]),
        "resumed_post_records": len(fixture["resume_post_records"]),
        "resumed_publish_after_records": int(
            fixture["resume_publish_after_records"]
        ),
        "resumed_unconsumed_wire_bytes": int(
            fixture["resume_unconsumed_wire_bytes"]
        ),
        "ticket_identity_bytes": len(fixture["ticket_identity"]),
        "ticket_nonce_bytes": len(fixture["ticket_nonce"]),
        "ticket_age_add": int(fixture["ticket_age_add"]),
        "hello_acquisition_client_bytes": len(acquisition_client),
        "hello_acquisition_client_record_bytes": len(
            acquisition_client_record
        ),
        "hello_acquisition_server_bytes": len(acquisition_server),
        "hello_acquisition_server_wire_bytes": len(acquisition_server_wire),
        "hello_acquisition_server_tail_bytes": len(
            acquisition_server_segments[-1]
        ),
        "hello_resumed_client_bytes": len(resumed_client),
        "hello_resumed_client_record_bytes": len(resumed_client_record),
        "hello_resumed_server_bytes": len(resumed_server),
        "hello_resumed_server_wire_bytes": len(resumed_server_wire),
        "hello_resumed_server_tail_bytes": len(resumed_server_segments[-1]),
        "hello_pending_suffix_bytes": len(acquisition_pending),
        "hello_ek_bytes": len(acquisition_ek),
        "hello_client_x_bytes": len(acquisition_x),
        "hello_random_bytes": len(hello.CLIENT_RANDOM),
        "hello_session_bytes": len(hello.SESSION_ID),
        "hello_server_segment_count": len(acquisition_server_segments),
        **hello_abi,
    }
    (OUT / "fixture_meta.inc").write_text(
        "".join(
            f"flight_timing_{name} equ {value}\n"
            for name, value in metadata.items()
        ),
        encoding="ascii",
    )
    report = {
        "schema": "seed-tls13-286-flight-timing-v2",
        "source_gates": [
            str(CHECKER.relative_to(ROOT)),
            str(HELLO_CHECKER.relative_to(ROOT)),
        ],
        "scope": (
            "deterministic exact-target timing vectors for the current HELLO "
            "TX/RX wrappers and acquisition/resumed protected-flight "
            "controllers"
        ),
        "geometry": metadata,
        "outputs": outputs,
    }
    (OUT / "fixtures.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
