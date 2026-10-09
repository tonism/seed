#!/usr/bin/env python3
"""Build the flat runtime's shared HTTP/2 code and exact application ABI.

The private probe omits the cold pack and 286 tail. Their presence cannot
change the resident/K addresses used here. NASM resolves symbols directly;
the final pack/dispatch gates separately bind the completed image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
HTTP = BOOT / "phases/http2"
BUILD = ROOT / "build/ibm_pc_5150"

AUX_NAMES = (
    "h2_rx_clear_record", "tls_prepare_3c501_receive",
    "tls_send_application_data_current_seq", "tls_h2_clear_crypto_prefix",
    "tls_h2_invoke", "h2_tx_control", "h2_tx_reserve", "tls_app_len", "tls_app_plain_ptr",
)
EXCHANGE_NAMES = (
    "load_core_sectors_at", "tls_receive_application_data", "tls_app_content_type",
    "tls_h2_invoke", "h2_tx_control", "tls_app_len", "tls_app_data_ptr", "esc_stop",
    "api_stream_completed", "api_stream_text_seen", "tool_fc_state", "reconnect_retries",
    "ne_transmit_tcp_flags", "h2_rx_clear_record", "h2_rx_consume_credit", "tls_buffered_payload_len",
)
COLD_NAMES = (
    "tls_receive_application_data", "tls_h2_invoke", "tls_send_application_data_current_seq",
    "tls_h2_clear_crypto_prefix", "h2_rx_clear_record", "tls_app_plain_ptr", "tls_app_len",
    "tls_app_content_type", "tls_buffered_payload_ptr", "tls_buffered_payload_len",
    "tcp_rx_payload_ptr", "tcp_rx_payload_len", "nic_vt_rx_fallback",
    "tcp_remote_ack", "tcp_source_port_word", "ne_tx_frame",
)
RESIDENT_NAMES = {
    "resident_load_phase": "load_core_sectors_at",
    "res_tcp_ack": "ne_transmit_tcp_ack",
    "res_tcp_receive": "tcp_receive_payload",
    "res_build_tcp_frame": "build_tcp_segment_frame",
    "res_nic_vt_transmit": "nic_vt_transmit",
}


def definitions(path: Path, values: dict[str, int]) -> None:
    path.write_text("; Generated from assembled source; do not edit.\n" +
                    "".join(f"{name} equ 0x{value:04x}\n" for name, value in values.items()))


def assemble(out: Path, name: str, source: Path, defines: tuple[str, ...] = ()) -> bytes:
    binary = out / f"{name}.bin"
    subprocess.run([
        "nasm", "-f", "bin", *("-D" + value for value in defines),
        *(f"-I{path}/" for path in (out, HTTP, BOOT, BUILD, ROOT)),
        "-l", str(out / f"{name}.lst"), "-o", str(binary), str(source),
    ], cwd=ROOT, check=True)
    return binary.read_bytes()


def probe_core(out: Path, names: tuple[str, ...]) -> dict[str, int]:
    source = out / "core-probe.asm"
    source.write_text('%include "core.asm"\n' + "".join(f"dw {name}\n" for name in names))
    image = assemble(out, "core-probe", source, (
        "LOADER_SECTORS=4", "TLS13_PRODUCT_TLS13=1", "TLS13_PRODUCT_PACK_BASE=1",
    ))
    return dict(zip(names, struct.unpack(f"<{len(names)}H", image[-2*len(names):]), strict=True))


def build(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    post = assemble(out, "h2_post", HTTP / "h2_post.asm")
    if not 3584 < len(post) <= 4096:
        raise AssertionError("shared parser escaped its fixed eight-sector code window")
    tail = post[3584:]
    tail_staged = 0x700 + 35
    bridge_entry = tail_staged + len(tail)
    if bridge_entry != 0x08a8:
        raise AssertionError("K's fixed H2 transition entry must be rebound")
    definitions(out / "bridge-abi.inc", dict(
        H2_BRIDGE_ENTRY=bridge_entry, H2_TAIL_STAGED=tail_staged, H2_TAIL_BYTES=len(tail)))
    bridge = assemble(out, "bridge", HTTP / "h2_phase_bridge.asm")
    (out / "post-head.bin").write_bytes(post[:3584])
    (out / "post-tail.bin").write_bytes(tail + bridge)

    names = tuple(dict.fromkeys(AUX_NAMES + EXCHANGE_NAMES + COLD_NAMES +
                                tuple(RESIDENT_NAMES.values()) +
                                ("core_save_phase_start", "core_save_phase_end", "core_link_window_end",
                                 "tls_h2_tag_verified", "h2_rx_feed_byte", "h2_rx_feed_end", "agent_api_exchange")))
    definitions(out / "request-aux-abi.inc", dict.fromkeys(AUX_NAMES, 0))
    auxiliary = assemble(out, "request-aux", HTTP / "h2_request_aux.asm")
    (out / "request-aux-sector.bin").write_bytes(auxiliary.ljust(512, b"\0"))
    symbols = probe_core(out, names)
    if symbols["core_save_phase_end"] - symbols["core_save_phase_start"] != 547:
        raise AssertionError("shared parser's S-padding location moved")
    definitions(out / "request-aux-abi.inc", {name: symbols[name] for name in AUX_NAMES})
    auxiliary = assemble(out, "request-aux", HTTP / "h2_request_aux.asm")
    entries = struct.unpack("<7H", auxiliary[:14])
    if entries != (10254, 10279, 10296, 10307, 10316, 10375, 10388):
        raise AssertionError("R/X's fixed request-helper calls must be rebound")
    if len(auxiliary) > 512:
        raise AssertionError("request helper escaped R's third sector")
    (out / "request-aux-sector.bin").write_bytes(auxiliary.ljust(512, b"\0"))
    if probe_core(out, names) != symbols:
        raise AssertionError("application ABI changed during helper binding")
    definitions(out / "exchange-abi.inc", {
        **{name: symbols[name] for name in EXCHANGE_NAMES}, "request_aux_fail": entries[-1],
    })
    owner = assemble(out, "exchange", HTTP / "h2_exchange.asm")
    if len(owner) > 512:
        raise AssertionError("response owner escaped the final controller's third sector")
    cold = {name: symbols[name] for name in COLD_NAMES}
    cold.update({name: symbols[target] for name, target in RESIDENT_NAMES.items()})
    cold.update(tcp_window_word=symbols["ne_tx_frame"]+48,
                tcp_checksum_word=symbols["ne_tx_frame"]+50,
                low_abort=0x0f60, lifecycle_entry_table=0x090a)
    definitions(out / "cold-abi.inc", cold)
    report = dict(schema="seed-http2-runtime-v1", post_bytes=len(post),
                  post_sha256=hashlib.sha256(post).hexdigest(),
                  auxiliary_bytes=len(auxiliary), owner_bytes=len(owner),
                  symbols=symbols, bridge_entry=bridge_entry)
    (out / "build.json").write_text(json.dumps(report, indent=2)+"\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=BUILD / "http2")
    args = parser.parse_args()
    print(json.dumps(build(args.output_dir.resolve()), indent=2))
