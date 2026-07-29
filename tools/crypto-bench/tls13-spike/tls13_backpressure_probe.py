#!/usr/bin/env python3
"""Test whether TCP receive-window backpressure extends OpenAI's TLS deadline.

This diagnostic relay gives the upstream socket a deliberately tiny receive
buffer before connect.  It forwards exactly the first complete server TLS
record (normally ServerHello), stops reading upstream for a bounded interval,
then resumes.  The local OpenSSL client therefore has the server key share but
cannot finish the handshake until the relay reopens the receive window.

A post-release NewSessionTicket is the success oracle.  Merely receiving the
queued encrypted server flight after release is not success: the server may
already have closed and TCP must deliver earlier bytes before its FIN.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tls13_patience_probe as base


@dataclass
class State:
    origin: float
    events: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    local_handshake_at: float | None = None
    server_acceptance_at: float | None = None
    openssl_failure_at: float | None = None
    first_server_record_at: float | None = None
    release_at: float | None = None
    upstream_eof_at: float | None = None
    bytes_client_to_server: int = 0
    bytes_server_to_client: int = 0
    first_record_bytes: int = 0
    buffered_tail_bytes: int = 0
    kernel_peek_bytes_before_release: int = 0

    def event(self, name: str, **details: Any) -> float:
        now = time.monotonic()
        item = {
            "event": name,
            "t_since_start_s": round(now - self.origin, 6),
            **details,
        }
        with self.lock:
            self.events.append(item)
        return now

    def error(self, message: str) -> None:
        with self.lock:
            self.errors.append(message)
        self.event("relay_error", message=message)


def connect_with_tiny_window(
    host: str, port: int, receive_buffer: int, timeout: float
) -> socket.socket:
    """Resolve/connect in a worker, setting SO_RCVBUF before the TCP SYN."""

    done = threading.Event()
    result: dict[str, Any] = {}

    def worker() -> None:
        last_error: OSError | None = None
        try:
            addresses = socket.getaddrinfo(
                host, port, socket.AF_INET, socket.SOCK_STREAM
            )
            for family, kind, proto, _, address in addresses:
                sock = socket.socket(family, kind, proto)
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer
                    )
                    sock.settimeout(timeout)
                    sock.connect(address)
                    result["socket"] = sock
                    return
                except OSError as exc:
                    last_error = exc
                    base.shutdown_socket(sock)
            result["error"] = last_error or OSError("no IPv4 address")
        except OSError as exc:
            result["error"] = exc
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True).start()
    if not done.wait(timeout):
        raise base.ProbeError(f"upstream connect exceeded {timeout}s")
    if "error" in result:
        raise base.ProbeError(f"upstream connect failed: {result['error']}")
    sock = result.get("socket")
    if not isinstance(sock, socket.socket):
        raise base.ProbeError("upstream connect returned no socket")
    return sock


def relay_client(
    client: socket.socket,
    upstream: socket.socket,
    deadline: float,
    state: State,
    stop: threading.Event,
) -> None:
    try:
        while not stop.is_set() and time.monotonic() < deadline:
            try:
                data = client.recv(4096)
            except socket.timeout:
                continue
            if not data:
                state.event("openssl_client_eof")
                return
            base.send_bounded(upstream, data, stop, deadline)
            with state.lock:
                state.bytes_client_to_server += len(data)
    except (OSError, base.ProbeError) as exc:
        if not stop.is_set():
            state.error(f"client-to-server relay: {exc}")
            stop.set()


def relay_server(
    upstream: socket.socket,
    client: socket.socket,
    hold_seconds: float,
    deadline: float,
    state: State,
    stop: threading.Event,
) -> None:
    reader = base.TLSStreamReader()
    try:
        first: bytes | None = None
        while (
            first is None
            and not stop.is_set()
            and time.monotonic() < deadline
        ):
            first = reader.receive_one(upstream)
        if first is None:
            raise base.ProbeError("no complete first server TLS record")
        meta = base.tls_record_metadata(first)
        if meta["content_type"] != base.TLS_CONTENT_HANDSHAKE:
            raise base.ProbeError(
                "first server record was not a plaintext Handshake record"
            )
        base.send_bounded(client, first, stop, deadline)
        first_at = state.event("first_server_record_forwarded", **meta)
        with state.lock:
            state.first_server_record_at = first_at
            state.first_record_bytes = len(first)
            state.bytes_server_to_client += len(first)
            state.buffered_tail_bytes = len(reader.buffer)

        release_deadline = first_at + hold_seconds
        while not stop.is_set() and time.monotonic() < release_deadline:
            time.sleep(min(0.05, max(0.0, release_deadline - time.monotonic())))

        upstream.setblocking(False)
        try:
            try:
                peek = upstream.recv(65535, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                peek = b""
        finally:
            upstream.setblocking(True)
            upstream.settimeout(base.SOCKET_POLL_SECONDS)
        with state.lock:
            state.kernel_peek_bytes_before_release = len(peek)
        release_at = state.event(
            "upstream_receive_window_reopened",
            hold_seconds=hold_seconds,
            user_space_buffered_bytes=len(reader.buffer),
            kernel_peek_bytes=len(peek),
        )
        with state.lock:
            state.release_at = release_at

        if reader.buffer:
            buffered = bytes(reader.buffer)
            reader.buffer.clear()
            base.send_bounded(client, buffered, stop, deadline)
            with state.lock:
                state.bytes_server_to_client += len(buffered)

        while not stop.is_set() and time.monotonic() < deadline:
            try:
                data = upstream.recv(16384)
            except socket.timeout:
                continue
            except ConnectionResetError:
                data = b""
            if not data:
                eof = state.event("upstream_eof")
                with state.lock:
                    state.upstream_eof_at = eof
                return
            base.send_bounded(client, data, stop, deadline)
            with state.lock:
                state.bytes_server_to_client += len(data)
    except (OSError, base.ProbeError) as exc:
        if not stop.is_set():
            state.error(f"server-to-client relay: {exc}")
            stop.set()


def openssl_command(openssl: str, port: int) -> list[str]:
    return [
        openssl,
        "s_client",
        "-connect",
        f"{base.LISTEN_HOST}:{port}",
        "-servername",
        base.TARGET_HOST,
        "-verify_hostname",
        base.TARGET_HOST,
        "-verify_return_error",
        "-tls1_3",
        "-ciphersuites",
        "TLS_CHACHA20_POLY1305_SHA256",
        "-groups",
        "X25519",
        "-sigalgs",
        "ecdsa_secp256r1_sha256",
        "-brief",
        "-state",
        "-msg",
        "-ign_eof",
    ]


def run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    origin = time.monotonic()
    deadline = origin + args.overall_timeout_seconds
    state = State(origin)
    output = base.OpenSSLOutput(state)
    stop = threading.Event()
    listener: socket.socket | None = None
    client: socket.socket | None = None
    upstream: socket.socket | None = None
    process: subprocess.Popen[bytes] | None = None
    threads: list[threading.Thread] = []
    output_thread: threading.Thread | None = None
    command: list[str] = []
    termination_reason = "setup_error"

    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((base.LISTEN_HOST, 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        state.event("listener_ready", port=port)

        upstream = connect_with_tiny_window(
            base.TARGET_HOST,
            base.TARGET_PORT,
            args.receive_buffer_bytes,
            args.connect_timeout_seconds,
        )
        actual_receive_buffer = upstream.getsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF
        )
        upstream.settimeout(base.SOCKET_POLL_SECONDS)
        state.event(
            "upstream_connected",
            requested_receive_buffer_bytes=args.receive_buffer_bytes,
            actual_receive_buffer_bytes=actual_receive_buffer,
        )

        command = openssl_command(args.openssl, port)
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
        assert process.stdout is not None
        output_thread = threading.Thread(
            target=output.consume,
            args=(process.stdout, stop),
            daemon=True,
        )
        output_thread.start()

        listener.settimeout(args.accept_timeout_seconds)
        client, _ = listener.accept()
        client.settimeout(base.SOCKET_POLL_SECONDS)
        threads = [
            threading.Thread(
                target=relay_client,
                args=(client, upstream, deadline, state, stop),
                daemon=True,
            ),
            threading.Thread(
                target=relay_server,
                args=(
                    upstream,
                    client,
                    args.hold_seconds,
                    deadline,
                    state,
                    stop,
                ),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()

        while time.monotonic() < deadline:
            with state.lock:
                accepted = state.server_acceptance_at is not None
                eof = state.upstream_eof_at is not None
                errors = bool(state.errors)
            if accepted:
                termination_reason = "server_new_session_ticket"
                break
            if eof:
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
    except (OSError, base.ProbeError, subprocess.SubprocessError) as exc:
        state.error(f"probe setup/run: {exc}")
    finally:
        stop.set()
        base.shutdown_socket(client)
        base.shutdown_socket(upstream)
        base.shutdown_socket(listener)
        openssl_exit_code, openssl_terminated = base.terminate_child(process)
        for thread in threads:
            thread.join(timeout=1)
        if output_thread is not None:
            output_thread.join(timeout=1)

    with state.lock:
        accepted_after_release = (
            state.server_acceptance_at is not None
            and state.release_at is not None
            and state.server_acceptance_at >= state.release_at
            and state.openssl_failure_at is None
        )
        snapshot = {
            "events": list(state.events),
            "errors": list(state.errors),
            "first_server_record_at": state.first_server_record_at,
            "release_at": state.release_at,
            "upstream_eof_at": state.upstream_eof_at,
            "local_handshake_at": state.local_handshake_at,
            "server_acceptance_at": state.server_acceptance_at,
            "openssl_failure_at": state.openssl_failure_at,
            "bytes_client_to_server": state.bytes_client_to_server,
            "bytes_server_to_client": state.bytes_server_to_client,
            "first_record_bytes": state.first_record_bytes,
            "buffered_tail_bytes": state.buffered_tail_bytes,
            "kernel_peek_bytes_before_release": (
                state.kernel_peek_bytes_before_release
            ),
        }

    if accepted_after_release:
        outcome = "handshake_completed_after_backpressure"
        exit_code = 0
    elif snapshot["upstream_eof_at"] is not None:
        outcome = "server_closed_before_completion"
        exit_code = 2
    elif termination_reason == "overall_timeout":
        outcome = "inconclusive_timeout"
        exit_code = 3
    else:
        outcome = "inconclusive_or_failed"
        exit_code = 4

    result = {
        "schema": "seed.tls13-backpressure-deadline.v1",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": base.TARGET_HOST,
        "profile": {
            "protocol": "TLSv1.3",
            "cipher": "TLS_CHACHA20_POLY1305_SHA256",
            "group": "X25519",
            "signature_algorithm": "ecdsa_secp256r1_sha256",
        },
        "hold_seconds": args.hold_seconds,
        "requested_receive_buffer_bytes": args.receive_buffer_bytes,
        "termination_reason": termination_reason,
        "outcome": outcome,
        "handshake_completed_after_backpressure": accepted_after_release,
        "traffic": {
            "client_to_server_bytes": snapshot["bytes_client_to_server"],
            "server_to_client_bytes": snapshot["bytes_server_to_client"],
            "first_server_record_bytes": snapshot["first_record_bytes"],
            "user_space_tail_bytes_at_hold": snapshot["buffered_tail_bytes"],
            "kernel_peek_bytes_before_release": (
                snapshot["kernel_peek_bytes_before_release"]
            ),
        },
        "timing": {
            "first_server_record_to_release_seconds": (
                None
                if snapshot["first_server_record_at"] is None
                or snapshot["release_at"] is None
                else round(
                    snapshot["release_at"] - snapshot["first_server_record_at"],
                    6,
                )
            ),
            "release_to_ticket_seconds": (
                None
                if snapshot["release_at"] is None
                or snapshot["server_acceptance_at"] is None
                else round(
                    snapshot["server_acceptance_at"] - snapshot["release_at"],
                    6,
                )
            ),
        },
        "events": snapshot["events"],
        "errors": snapshot["errors"],
        "openssl_command": command,
        "openssl_exit_code": openssl_exit_code,
        "openssl_terminated_by_probe": openssl_terminated,
        "openssl_output_tail": output.decoded_tail(),
    }
    return result, exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hold-seconds", type=float, required=True)
    parser.add_argument("--receive-buffer-bytes", type=int, default=256)
    parser.add_argument("--accept-timeout-seconds", type=float, default=5)
    parser.add_argument("--connect-timeout-seconds", type=float, default=8)
    parser.add_argument("--overall-timeout-seconds", type=float, default=40)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    if not 0 <= args.hold_seconds <= 60:
        parser.error("--hold-seconds must be in [0, 60]")
    if not 128 <= args.receive_buffer_bytes <= 4096:
        parser.error("--receive-buffer-bytes must be in [128, 4096]")
    return args


def main() -> None:
    args = parse_args()
    result, exit_code = run(args)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
