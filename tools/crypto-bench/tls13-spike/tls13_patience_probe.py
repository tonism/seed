#!/usr/bin/env python3
"""Measure how long api.openai.com waits for a TLS 1.3 client Finished.

This is a bounded, diagnostic-only relay.  It starts OpenSSL ``s_client``
against an ephemeral IPv4 localhost listener, connects that listener to
api.openai.com:443, and:

* forwards the first TLS record (validated as a ClientHello) immediately;
* forwards every server byte to OpenSSL immediately; and
* queues every later client TLS record for ``--delay-seconds`` after the first
  such record arrives, then releases the queue in order.

OpenSSL can declare its *local* handshake complete as soon as it writes
Finished into the localhost socket, before the relay releases that record.
Consequently the probe only reports ``handshake_completed_after_release`` when
OpenSSL subsequently decodes a server NewSessionTicket.  Raw server data after
release is reported independently and is not treated as proof: it could be an
encrypted alert.

The program has connect, accept, and overall deadlines, caps retained OpenSSL
output, terminates its child, shuts down every socket, and emits one JSON
document on stdout.  It deliberately sends no HTTP request.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TARGET_HOST = "api.openai.com"
TARGET_PORT = 443
LISTEN_HOST = "127.0.0.1"
MAX_TLS_RECORD_PAYLOAD = (1 << 14) + 2048
MAX_OPENSSL_OUTPUT = 64 * 1024
SOCKET_POLL_SECONDS = 0.05

TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_ALERT = 21
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_APPLICATION_DATA = 23
TLS_HANDSHAKE_CLIENT_HELLO = 1

LOCAL_HANDSHAKE_MARKERS = (
    b"connection established",
    b"ssl negotiation finished successfully",
)
SERVER_ACCEPTANCE_MARKERS = (
    b"newsessionticket",
    b"read server session ticket",
)
OPENSSL_FAILURE_MARKERS = (
    b"alert handshake failure",
    b"alert internal error",
    b"certificate verify failed",
    b"unexpected eof",
    b"ssl_connect:error",
)


class ProbeError(RuntimeError):
    """A bounded probe failure that should be represented in its JSON result."""


class TLSStreamReader:
    """Incrementally frame TLS records without assuming TCP write boundaries."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.eof = False

    def receive_one(self, sock: socket.socket) -> bytes | None:
        """Return one complete record, or None when more bytes are required."""
        record = self._extract_one()
        if record is not None:
            return record
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return None
        if not chunk:
            self.eof = True
            if self.buffer:
                raise ProbeError(
                    f"client EOF in a partial TLS record ({len(self.buffer)} bytes)"
                )
            return None
        self.buffer.extend(chunk)
        return self._extract_one()

    def _extract_one(self) -> bytes | None:
        if len(self.buffer) < 5:
            return None
        payload_len = int.from_bytes(self.buffer[3:5], "big")
        if payload_len > MAX_TLS_RECORD_PAYLOAD:
            raise ProbeError(
                f"client TLS record payload {payload_len} exceeds "
                f"{MAX_TLS_RECORD_PAYLOAD}-byte bound"
            )
        record_len = 5 + payload_len
        if len(self.buffer) < record_len:
            return None
        record = bytes(self.buffer[:record_len])
        del self.buffer[:record_len]
        return record


@dataclass
class SharedState:
    origin: float
    events: list[dict[str, Any]] = field(default_factory=list)
    client_records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    client_hello_forwarded_at: float | None = None
    hold_started_at: float | None = None
    release_started_at: float | None = None
    release_completed_at: float | None = None
    upstream_eof_at: float | None = None
    first_server_data_at: float | None = None
    first_post_release_server_data_at: float | None = None
    local_handshake_at: float | None = None
    server_acceptance_at: float | None = None
    openssl_failure_at: float | None = None
    bytes_client_to_server: int = 0
    bytes_server_to_client: int = 0
    held_bytes: int = 0
    held_records: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def now(self) -> float:
        return time.monotonic()

    def event(self, name: str, **details: Any) -> float:
        stamp = self.now()
        item: dict[str, Any] = {
            "event": name,
            "t_monotonic_s": round(stamp, 6),
            "t_since_start_s": round(stamp - self.origin, 6),
        }
        item.update(details)
        with self.lock:
            self.events.append(item)
        return stamp

    def error(self, message: str) -> None:
        with self.lock:
            self.errors.append(message)
        self.event("relay_error", message=message)


class OpenSSLOutput:
    """Bound retained output while scanning the complete stream for markers."""

    def __init__(self, state: SharedState) -> None:
        self.state = state
        self.tail = bytearray()
        self.scan_tail = bytearray()
        self.lock = threading.Lock()

    def consume(self, pipe: Any, stop: threading.Event) -> None:
        try:
            while not stop.is_set():
                # BufferedReader.read(n) may wait for all n bytes.  os.read()
                # returns the currently available diagnostic stream so a
                # post-release NewSessionTicket is observed without waiting
                # for process termination.
                chunk = os.read(pipe.fileno(), 4096)
                if not chunk:
                    break
                self._append(chunk)
        except (OSError, ValueError) as exc:
            if not stop.is_set():
                self.state.error(f"reading OpenSSL output: {exc}")

    def _append(self, chunk: bytes) -> None:
        lowered = bytes(self.scan_tail) + chunk.lower()
        now = time.monotonic()
        with self.state.lock:
            if (
                self.state.local_handshake_at is None
                and any(marker in lowered for marker in LOCAL_HANDSHAKE_MARKERS)
            ):
                self.state.local_handshake_at = now
                local_event = True
            else:
                local_event = False
            if (
                self.state.server_acceptance_at is None
                and any(marker in lowered for marker in SERVER_ACCEPTANCE_MARKERS)
            ):
                self.state.server_acceptance_at = now
                acceptance_event = True
            else:
                acceptance_event = False
            if (
                self.state.openssl_failure_at is None
                and any(marker in lowered for marker in OPENSSL_FAILURE_MARKERS)
            ):
                self.state.openssl_failure_at = now
                failure_event = True
            else:
                failure_event = False

        # Keep enough overlap for a marker split across pipe reads.
        self.scan_tail[:] = lowered[-128:]
        with self.lock:
            self.tail.extend(chunk)
            if len(self.tail) > MAX_OPENSSL_OUTPUT:
                del self.tail[: len(self.tail) - MAX_OPENSSL_OUTPUT]

        if local_event:
            self.state.event("openssl_local_handshake_complete")
        if acceptance_event:
            self.state.event("openssl_server_new_session_ticket")
        if failure_event:
            self.state.event("openssl_failure_marker")

    def decoded_tail(self) -> str:
        with self.lock:
            return bytes(self.tail).decode("utf-8", errors="replace")


def tls_record_metadata(record: bytes) -> dict[str, Any]:
    if len(record) < 5:
        raise ProbeError("internal error: short framed TLS record")
    return {
        "content_type": record[0],
        "legacy_version": record[1:3].hex(),
        "payload_bytes": len(record) - 5,
        "wire_bytes": len(record),
    }


def validate_first_client_hello(record: bytes) -> None:
    meta = tls_record_metadata(record)
    if meta["content_type"] != TLS_CONTENT_HANDSHAKE:
        raise ProbeError(
            "first client TLS record is not Handshake "
            f"(content type {meta['content_type']})"
        )
    if len(record) < 6 or record[5] != TLS_HANDSHAKE_CLIENT_HELLO:
        raise ProbeError("first client TLS record does not begin with ClientHello")
    if record[1] != 3:
        raise ProbeError(f"unexpected TLS record major version {record[1]}")


def send_bounded(
    sock: socket.socket,
    data: bytes,
    stop: threading.Event,
    overall_deadline: float,
) -> None:
    view = memoryview(data)
    sent = 0
    while sent < len(view):
        if stop.is_set():
            raise ProbeError("relay stopped during socket write")
        if time.monotonic() >= overall_deadline:
            raise ProbeError("overall deadline reached during socket write")
        try:
            count = sock.send(view[sent:])
        except socket.timeout:
            continue
        if count <= 0:
            raise ProbeError("socket closed during relay write")
        sent += count


def connect_upstream_bounded(timeout_seconds: float) -> socket.socket:
    """Bound DNS plus TCP connect even though stdlib getaddrinfo is synchronous."""
    completed = threading.Event()
    lock = threading.Lock()
    shared: dict[str, Any] = {"cancelled": False}

    def worker() -> None:
        connected: socket.socket | None = None
        failure: OSError | None = None
        try:
            connected = socket.create_connection(
                (TARGET_HOST, TARGET_PORT),
                timeout=timeout_seconds,
            )
        except OSError as exc:
            failure = exc
        with lock:
            if shared["cancelled"]:
                shutdown_socket(connected)
            else:
                shared["socket"] = connected
                shared["error"] = failure
        completed.set()

    threading.Thread(
        target=worker,
        name="bounded-upstream-connect",
        daemon=True,
    ).start()
    if not completed.wait(timeout_seconds):
        with lock:
            shared["cancelled"] = True
            shutdown_socket(shared.pop("socket", None))
        raise ProbeError(
            f"DNS/TCP connect did not complete within {timeout_seconds}s"
        )
    with lock:
        failure = shared.get("error")
        connected = shared.get("socket")
    if failure is not None:
        raise ProbeError(f"upstream DNS/TCP connect failed: {failure}")
    if not isinstance(connected, socket.socket):
        raise ProbeError("upstream connect completed without a socket")
    return connected


def relay_client_to_server(
    client: socket.socket,
    upstream: socket.socket,
    delay_seconds: float,
    overall_deadline: float,
    state: SharedState,
    stop: threading.Event,
) -> None:
    reader = TLSStreamReader()
    held: list[bytes] = []
    record_index = 0
    released = False
    release_deadline: float | None = None

    try:
        while not stop.is_set() and time.monotonic() < overall_deadline:
            record = reader.receive_one(client)
            if record is not None:
                record_index += 1
                meta = tls_record_metadata(record)
                now = time.monotonic()

                if record_index == 1:
                    validate_first_client_hello(record)
                    send_bounded(upstream, record, stop, overall_deadline)
                    with state.lock:
                        state.client_hello_forwarded_at = now
                        state.bytes_client_to_server += len(record)
                        state.client_records.append(
                            {
                                "index": record_index,
                                "held": False,
                                "received_t_since_start_s": round(
                                    now - state.origin, 6
                                ),
                                **meta,
                            }
                        )
                    state.event(
                        "client_hello_forwarded",
                        wire_bytes=len(record),
                        payload_bytes=len(record) - 5,
                    )
                    continue

                with state.lock:
                    state.client_records.append(
                        {
                            "index": record_index,
                            "held": not released,
                            "received_t_since_start_s": round(
                                now - state.origin, 6
                            ),
                            **meta,
                        }
                    )

                if released:
                    send_bounded(upstream, record, stop, overall_deadline)
                    with state.lock:
                        state.bytes_client_to_server += len(record)
                    continue

                held.append(record)
                with state.lock:
                    state.held_records += 1
                    state.held_bytes += len(record)
                if release_deadline is None:
                    hold_started = state.event(
                        "client_finished_hold_started",
                        delay_seconds=delay_seconds,
                        first_held_content_type=record[0],
                    )
                    with state.lock:
                        state.hold_started_at = hold_started
                    release_deadline = hold_started + delay_seconds

            if (
                not released
                and release_deadline is not None
                and time.monotonic() >= release_deadline
            ):
                release_started = state.event(
                    "delayed_client_records_release_started",
                    records=len(held),
                    wire_bytes=sum(map(len, held)),
                )
                with state.lock:
                    state.release_started_at = release_started
                for queued in held:
                    send_bounded(upstream, queued, stop, overall_deadline)
                    with state.lock:
                        state.bytes_client_to_server += len(queued)
                held.clear()
                release_completed = state.event(
                    "delayed_client_records_release_completed"
                )
                with state.lock:
                    state.release_completed_at = release_completed
                released = True

            if reader.eof:
                state.event("openssl_client_eof")
                return
    except (OSError, ProbeError) as exc:
        if not stop.is_set():
            state.error(f"client-to-server relay: {exc}")
            stop.set()


def relay_server_to_client(
    upstream: socket.socket,
    client: socket.socket,
    overall_deadline: float,
    state: SharedState,
    stop: threading.Event,
) -> None:
    try:
        while not stop.is_set() and time.monotonic() < overall_deadline:
            try:
                chunk = upstream.recv(16384)
            except socket.timeout:
                continue
            except ConnectionResetError:
                chunk = b""
            if not chunk:
                eof = state.event("upstream_eof")
                with state.lock:
                    state.upstream_eof_at = eof
                return

            now = time.monotonic()
            with state.lock:
                state.bytes_server_to_client += len(chunk)
                first = state.first_server_data_at is None
                if first:
                    state.first_server_data_at = now
                after_release = (
                    state.release_started_at is not None
                    and now >= state.release_started_at
                )
                first_after_release = (
                    after_release
                    and state.first_post_release_server_data_at is None
                )
                if first_after_release:
                    state.first_post_release_server_data_at = now

            if first:
                state.event("first_server_data", wire_bytes=len(chunk))
            if first_after_release:
                state.event(
                    "first_post_release_server_data",
                    wire_bytes=len(chunk),
                )
            send_bounded(client, chunk, stop, overall_deadline)
    except (OSError, ProbeError) as exc:
        if not stop.is_set():
            state.error(f"server-to-client relay: {exc}")
            stop.set()


def monotonic_field(value: float | None, origin: float) -> dict[str, float] | None:
    if value is None:
        return None
    return {
        "t_monotonic_s": round(value, 6),
        "t_since_start_s": round(value - origin, 6),
    }


def build_openssl_command(openssl: str, port: int) -> list[str]:
    return [
        openssl,
        "s_client",
        "-connect",
        f"{LISTEN_HOST}:{port}",
        "-servername",
        TARGET_HOST,
        "-verify_hostname",
        TARGET_HOST,
        "-verify_return_error",
        "-tls1_3",
        "-ciphersuites",
        "TLS_CHACHA20_POLY1305_SHA256",
        "-groups",
        "P-256",
        "-sigalgs",
        "rsa_pss_rsae_sha256",
        "-brief",
        "-state",
        "-msg",
        "-ign_eof",
    ]


def terminate_child(process: subprocess.Popen[bytes] | None) -> tuple[int | None, bool]:
    if process is None:
        return None, False
    terminated = False
    if process.poll() is None:
        terminated = True
        process.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
    return process.poll(), terminated


def shutdown_socket(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def run_probe(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    origin = time.monotonic()
    state = SharedState(origin)
    started_utc = datetime.now(timezone.utc).isoformat()
    overall_deadline = origin + args.overall_timeout_seconds
    stop = threading.Event()

    listener: socket.socket | None = None
    client: socket.socket | None = None
    upstream: socket.socket | None = None
    process: subprocess.Popen[bytes] | None = None
    output_thread: threading.Thread | None = None
    relay_threads: list[threading.Thread] = []
    openssl_output = OpenSSLOutput(state)
    command: list[str] = []
    termination_reason = "setup_error"
    top_level_error: str | None = None

    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, 0))
        listener.listen(1)
        listen_port = listener.getsockname()[1]
        state.event("localhost_listener_ready", port=listen_port)

        # Establish the upstream socket before launching OpenSSL.  Once the
        # client writes ClientHello, the only relay delay is TLS framing and a
        # socket write—not DNS or TCP setup.
        connect_budget = min(
            args.connect_timeout_seconds,
            max(0.0, overall_deadline - time.monotonic()),
        )
        if connect_budget <= 0:
            raise ProbeError("overall deadline reached before upstream connect")
        upstream = connect_upstream_bounded(connect_budget)
        upstream.settimeout(SOCKET_POLL_SECONDS)
        state.event("upstream_tcp_connected", host=TARGET_HOST, port=TARGET_PORT)

        command = build_openssl_command(args.openssl, listen_port)
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
        state.event("openssl_started", pid=process.pid)
        assert process.stdout is not None
        output_thread = threading.Thread(
            target=openssl_output.consume,
            args=(process.stdout, stop),
            name="openssl-output",
            daemon=True,
        )
        output_thread.start()

        accept_budget = min(
            args.accept_timeout_seconds,
            max(0.0, overall_deadline - time.monotonic()),
        )
        if accept_budget <= 0:
            raise ProbeError("overall deadline reached before local accept")
        listener.settimeout(accept_budget)
        try:
            client, peer = listener.accept()
        except socket.timeout as exc:
            raise ProbeError(
                f"OpenSSL did not connect within {accept_budget}s"
            ) from exc
        client.settimeout(SOCKET_POLL_SECONDS)
        state.event("openssl_connected_to_relay", peer_host=peer[0], peer_port=peer[1])

        relay_threads = [
            threading.Thread(
                target=relay_client_to_server,
                args=(
                    client,
                    upstream,
                    args.delay_seconds,
                    overall_deadline,
                    state,
                    stop,
                ),
                name="client-to-server",
                daemon=True,
            ),
            threading.Thread(
                target=relay_server_to_client,
                args=(upstream, client, overall_deadline, state, stop),
                name="server-to-client",
                daemon=True,
            ),
        ]
        for thread in relay_threads:
            thread.start()

        while time.monotonic() < overall_deadline:
            with state.lock:
                accepted = state.server_acceptance_at is not None
                upstream_eof = state.upstream_eof_at is not None
                errors = bool(state.errors)
            if accepted:
                termination_reason = "server_new_session_ticket"
                break
            if upstream_eof:
                termination_reason = "upstream_eof"
                break
            if errors:
                termination_reason = "relay_error"
                break
            if process.poll() is not None:
                termination_reason = "openssl_exited"
                break
            time.sleep(0.02)
        else:
            termination_reason = "overall_timeout"
            state.event("overall_timeout")

    except (OSError, ProbeError, subprocess.SubprocessError) as exc:
        top_level_error = str(exc)
        state.error(f"probe setup/run: {exc}")
    finally:
        stop.set()
        shutdown_socket(client)
        shutdown_socket(upstream)
        shutdown_socket(listener)
        openssl_exit_code, openssl_terminated = terminate_child(process)
        for thread in relay_threads:
            thread.join(timeout=1.0)
        if output_thread is not None:
            output_thread.join(timeout=1.0)
        state.event("cleanup_complete")

    with state.lock:
        release_started = state.release_started_at
        upstream_eof = state.upstream_eof_at
        remote_closed_before_release = (
            upstream_eof is not None
            and (release_started is None or upstream_eof < release_started)
        )
        handshake_completed_after_release = (
            state.server_acceptance_at is not None
            and release_started is not None
            and state.server_acceptance_at >= release_started
            and state.openssl_failure_at is None
        )
        post_release_server_data = (
            state.first_post_release_server_data_at is not None
        )
        snapshot = {
            "events": list(state.events),
            "client_records": list(state.client_records),
            "errors": list(state.errors),
            "bytes_client_to_server": state.bytes_client_to_server,
            "bytes_server_to_client": state.bytes_server_to_client,
            "held_records": state.held_records,
            "held_bytes": state.held_bytes,
            "client_hello_forwarded_at": state.client_hello_forwarded_at,
            "hold_started_at": state.hold_started_at,
            "release_started_at": state.release_started_at,
            "release_completed_at": state.release_completed_at,
            "upstream_eof_at": state.upstream_eof_at,
            "first_post_release_server_data_at": (
                state.first_post_release_server_data_at
            ),
            "local_handshake_at": state.local_handshake_at,
            "server_acceptance_at": state.server_acceptance_at,
            "openssl_failure_at": state.openssl_failure_at,
        }

    if handshake_completed_after_release:
        outcome = "handshake_completed_after_release"
        exit_code = 0
    elif remote_closed_before_release:
        outcome = "remote_closed_before_release"
        exit_code = 2
    elif termination_reason == "overall_timeout":
        outcome = "inconclusive_timeout"
        exit_code = 3
    else:
        outcome = "inconclusive_or_failed"
        exit_code = 4

    result = {
        "schema": "seed.tls13-client-finished-patience.v1",
        "started_at_utc": started_utc,
        "monotonic_origin_s": round(origin, 6),
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
            "sni": TARGET_HOST,
        },
        "forced_profile": {
            "protocol": "TLSv1.3",
            "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256",
            "group": "P-256",
            "signature_algorithm": "rsa_pss_rsae_sha256",
        },
        "delay_seconds": args.delay_seconds,
        "timeouts_seconds": {
            "accept": args.accept_timeout_seconds,
            "connect": args.connect_timeout_seconds,
            "overall": args.overall_timeout_seconds,
        },
        "openssl_command": command,
        "termination_reason": termination_reason,
        "outcome": outcome,
        "remote_closed_before_release": remote_closed_before_release,
        "post_release_server_data_observed": post_release_server_data,
        "openssl_local_handshake_completed": snapshot["local_handshake_at"]
        is not None,
        "server_new_session_ticket_observed": snapshot["server_acceptance_at"]
        is not None,
        "openssl_failure_observed": snapshot["openssl_failure_at"] is not None,
        "handshake_completed_after_release": handshake_completed_after_release,
        "timestamps": {
            "client_hello_forwarded": monotonic_field(
                snapshot["client_hello_forwarded_at"], origin
            ),
            "hold_started": monotonic_field(snapshot["hold_started_at"], origin),
            "release_started": monotonic_field(
                snapshot["release_started_at"], origin
            ),
            "release_completed": monotonic_field(
                snapshot["release_completed_at"], origin
            ),
            "upstream_eof": monotonic_field(snapshot["upstream_eof_at"], origin),
            "first_post_release_server_data": monotonic_field(
                snapshot["first_post_release_server_data_at"], origin
            ),
            "openssl_local_handshake_complete": monotonic_field(
                snapshot["local_handshake_at"], origin
            ),
            "openssl_server_new_session_ticket": monotonic_field(
                snapshot["server_acceptance_at"], origin
            ),
            "openssl_failure": monotonic_field(
                snapshot["openssl_failure_at"], origin
            ),
        },
        "traffic": {
            "client_to_server_bytes": snapshot["bytes_client_to_server"],
            "server_to_client_bytes": snapshot["bytes_server_to_client"],
            "held_records": snapshot["held_records"],
            "held_bytes": snapshot["held_bytes"],
            "client_records": snapshot["client_records"],
        },
        "events": snapshot["events"],
        "errors": snapshot["errors"],
        "top_level_error": top_level_error,
        "openssl_exit_code": openssl_exit_code,
        "openssl_terminated_by_probe": openssl_terminated,
        "openssl_output_tail": openssl_output.decoded_tail(),
    }
    return result, exit_code


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Hold api.openai.com's TLS 1.3 client second flight behind a "
            "localhost OpenSSL relay and emit JSON timing evidence."
        )
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        required=True,
        help="seconds to hold all client TLS records after ClientHello",
    )
    parser.add_argument(
        "--accept-timeout-seconds",
        type=float,
        default=5.0,
        help="hard deadline for local OpenSSL to connect (default: 5)",
    )
    parser.add_argument(
        "--connect-timeout-seconds",
        type=float,
        default=8.0,
        help="hard deadline for the api.openai.com TCP connect (default: 8)",
    )
    parser.add_argument(
        "--overall-timeout-seconds",
        type=float,
        default=40.0,
        help="hard whole-probe deadline (default: 40)",
    )
    parser.add_argument(
        "--openssl",
        default=shutil.which("openssl") or "openssl",
        help="OpenSSL executable (default: resolved openssl on PATH)",
    )
    args = parser.parse_args(argv)
    for name in (
        "delay_seconds",
        "accept_timeout_seconds",
        "connect_timeout_seconds",
        "overall_timeout_seconds",
    ):
        value = getattr(args, name)
        if not math.isfinite(value) or value < 0:
            parser.error(f"--{name.replace('_', '-')} must be nonnegative")
    if args.overall_timeout_seconds <= args.delay_seconds:
        parser.error("--overall-timeout-seconds must exceed --delay-seconds")
    if not Path(args.openssl).exists() and shutil.which(args.openssl) is None:
        parser.error(f"OpenSSL executable not found: {args.openssl}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result, exit_code = run_probe(args)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
