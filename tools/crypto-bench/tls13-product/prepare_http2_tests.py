#!/usr/bin/env python3
"""Bind guarded HTTP/2 tests to emitted product code and packaged assets."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import build_system_ram_product_pack as B
import build_http2_runtime as H

ROOT = B.ROOT
BUILD = ROOT / "build/ibm_pc_5150"


def prepare(out: Path, work: Path, images: dict, slots: list, pack: bytes,
            *, core: Path | None = None, listing: Path | None = None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    components = out / "pack"
    components.mkdir(exist_ok=True)
    for source in work.iterdir():
        if source.suffix in (".bin", ".lst", ".inc"):
            shutil.copyfile(source, components / source.name)
    for name in ("h2_post.bin", "h2_post.lst", "bridge.lst", "request-aux.bin", "request-aux-sector.bin", "request-aux-abi.inc"):
        shutil.copyfile(BUILD / "http2" / name, out / name)
    (out / "tls13-k14-product-pack.bin").write_bytes(pack)
    (out / "pack.bin").write_bytes(pack)
    if core is None:
        core, listing = out / "SEED.SYS", out / "SEED.SYS.lst"
        subprocess.run([
            "nasm", "-f", "bin", "-DLOADER_SECTORS=4", "-DTLS13_PRODUCT_TLS13=1",
            "-DTLS13_PRODUCT_286_TAIL_BASE=1", "-DTLS13_PRODUCT_286_ABI_BASE=1",
            *(f"-I{p}/" for p in (out, B.BOOT, BUILD, BUILD / "http2", B.HTTP)),
            "-l", str(listing), "-o", str(core), str(B.BOOT / "core.asm"),
        ], cwd=ROOT, check=True)
    else:
        if listing is None:
            raise ValueError("an existing core must have its exact listing")
        shutil.copyfile(core, out / "SEED.SYS")
        shutil.copyfile(listing, out / "SEED.SYS.lst")
        core, listing = out / "SEED.SYS", out / "SEED.SYS.lst"
    raw = core.read_bytes()
    # Only the separately tested 286 adapter may differ from the cold pack.
    actual = bytearray(raw[45*512:175*512])
    actual[(164-45)*512:(165-45)*512] = bytes(512)
    if actual != pack:
        raise AssertionError("HTTP/2 test image is not bound to the checked cold pack")
    support = json.loads((BUILD / "http2/build.json").read_text())
    post = (out / "h2_post.bin").read_bytes()
    bridge = (BUILD / "http2/bridge.bin").read_bytes()
    tail = post[3584:] + bridge
    if (raw[12*512:19*512] != post[:3584] or
            raw[210*512+35:210*512+35+len(tail)] != tail or
            raw[185*512:186*512] != (out / "request-aux-sector.bin").read_bytes()):
        raise AssertionError("HTTP/2 parser/bridge/request helper differs from the emitted runtime")
    labels = support["symbols"]
    entries = struct.unpack("<7H", (out / "request-aux.bin").read_bytes()[:14])
    phases = [dict(name=s.name, start=s.start, sectors=s.sectors, destination=s.destination,
                   bytes=len(s.image.data) if s.image else 0,
                   sha256=hashlib.sha256(s.image.data).hexdigest() if s.image else None) for s in slots]
    metadata = dict(core_sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                    pack_sha256=hashlib.sha256(pack).hexdigest(),
                    labels=labels, k_bytes=labels["core_link_window_end"]-0x1800,
                    post_bytes=len(post), aux_bytes=support["auxiliary_bytes"],
                    exchange_bytes=support["owner_bytes"],
                    r_bytes=B.label_offset(listing,"core_agent_request_phase_end")-B.label_offset(listing,"core_agent_request_phase_start"),
                    x_bytes=B.label_offset(listing,"core_agent_api_stream_phase_end")-B.label_offset(listing,"core_agent_api_stream_phase_start"),
                    bridge_entry=support["bridge_entry"], bootstrap_sector=210,
                    bridge_bytes=len((BUILD / "http2/bridge.bin").read_bytes()),
                    aux_entries=dict(zip(("start","putc","putw","copy","flush","finish","fail"),entries,strict=True)),
                    controllers=[p for p in phases if p["name"] in ("fresh_post","final_post")],
                    phases=phases)
    for name in ("fresh_post", "final_post"):
        shutil.copyfile(work / f"{name}.lst", out / f"{name}.lst")
    H.definitions(out / "upload-abi.inc", {name:labels[name] for name in (
        "h2_rx_clear_record", "tls_prepare_3c501_receive", "tls_send_application_data_current_seq",
        "tls_h2_clear_crypto_prefix", "tls_app_len", "tls_app_plain_ptr")})
    H.assemble(out, "upload", Path(__file__).parent / "http2/upload_fixture.asm")
    # These tests need real FAT chains for streamed prompts, but never need a
    # user key. Their VM writes a synthetic credential into runtime RAM.
    subprocess.run([
        "python3", str(ROOT / "tools/build-fat12-image.py"), "build",
        "--boot", str(BUILD / "boot.bin"), "--loader", str(BUILD / "loader.bin"),
        "--loader-sectors", "4", "--output", str(out / "floppy-160k.img"),
        "--file", f"{core}:SEED.SYS",
        "--file", f"{ROOT / 'prompts/identity.txt'}:SEED/IDENTITY",
        "--file", f"{ROOT / 'prompts/compact.txt'}:SEED/COMPACT",
        "--file", f"{ROOT / 'prompts/tools.json'}:SEED/TOOLS",
    ], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    (out / "build.json").write_text(json.dumps(metadata, indent=2)+"\n")
    return metadata
