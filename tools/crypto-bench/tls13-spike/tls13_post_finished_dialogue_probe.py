#!/usr/bin/env python3
"""Probe which credential-free post-Finished dialogue keeps OpenAI connected.

This live host-side probe sends no Authorization header, API key, prompt, user
context, or tool data.  It uses a normal OpenSSL TLS 1.3 handshake and then:

* ``head`` mode sends a fixed unauthorized ``HEAD /v1/models`` request at a
  bounded interval; or
* ``keyupdate`` mode sends TLS 1.3 requested KeyUpdate commands.

The result distinguishes application-layer progress from TLS-level activity.
It is provider behavior observed by a research spike, not an SLA.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time


HOST = "api.openai.com"
REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"Connection: keep-alive\r\n\r\n"
)


def command(mode: str) -> list[str]:
    result = [
        "openssl",
        "s_client",
        "-connect",
        f"{HOST}:443",
        "-servername",
        HOST,
        "-tls1_3",
        "-ciphersuites",
        "TLS_CHACHA20_POLY1305_SHA256",
        "-groups",
        "X25519MLKEM768",
        "-sigalgs",
        "ecdsa_secp256r1_sha256",
        "-state",
    ]
    if mode == "head":
        result.extend(("-ign_eof", "-quiet"))
    else:
        result.append("-msg")
    return result


def run(mode: str, duration: float, interval: float) -> dict[str, object]:
    process = subprocess.Popen(
        command(mode),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("failed to pipe OpenSSL")

    chunks: list[tuple[float, bytes]] = []

    def reader() -> None:
        while True:
            value = process.stdout.read(4096)
            if not value:
                return
            chunks.append((time.monotonic(), value))

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    started = time.monotonic()
    ready = False
    while time.monotonic() - started < 8:
        output = b"".join(value for _, value in chunks)
        if b"SSL_connect:SSLv3/TLS write finished" in output:
            ready = True
            break
        if process.poll() is not None:
            break
        time.sleep(0.05)

    sent: list[float] = []
    if ready:
        target = 0.1
        while target <= duration and process.poll() is None:
            while (
                time.monotonic() - started < target
                and process.poll() is None
            ):
                time.sleep(0.03)
            if process.poll() is not None:
                break
            try:
                process.stdin.write(REQUEST if mode == "head" else b"K\n")
                process.stdin.flush()
            except BrokenPipeError:
                break
            sent.append(round(time.monotonic() - started, 3))
            target += interval

    while time.monotonic() - started < duration and process.poll() is None:
        time.sleep(0.05)
    alive_at_end = process.poll() is None
    if alive_at_end:
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    thread.join(timeout=1)

    output = b"".join(value for _, value in chunks)
    return {
        "target": f"{HOST}:443",
        "mode": mode,
        "ready": ready,
        "duration_seconds": duration,
        "interval_seconds": interval,
        "sent_at_seconds": sent,
        "alive_at_end": alive_at_end,
        "http_responses": output.count(b"HTTP/1.1"),
        "unauthorized_responses": output.count(b"401 Unauthorized"),
        "keep_alive_responses": output.count(b"Connection: keep-alive"),
        "keyupdate_messages": output.count(b"KeyUpdate"),
        "new_session_tickets": output.count(b"NewSessionTicket"),
        "close_notify_mentions": output.count(b"close notify"),
        "authorization_header_sent": False,
        "output_bytes": len(output),
        "provider_sla": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("head", "keyupdate"), default="head"
    )
    parser.add_argument("--duration", type=float, default=35)
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args()
    if not 5 <= args.duration <= 600:
        parser.error("--duration must be between 5 and 600 seconds")
    if not 1 <= args.interval <= args.duration:
        parser.error("--interval must be between 1 second and --duration")
    print(json.dumps(run(args.mode, args.duration, args.interval), indent=2))


if __name__ == "__main__":
    main()
