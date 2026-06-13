#!/usr/bin/env python3
"""Boot a Seed floppy image on 86Box's IBM AT (286) and screenshot the result.

The 286 secure tier's test harness (Build 12). The AT's 1.2 MB drive rejects the
single-sided 160K image, so this boots the 360K double-sided image (the 2-image
decision). A crafted CMOS gets the AT past SETUP (it halts on a blank CMOS; the XT
has none). 6 MHz is the security clock (the lowest secure CPU); --speed picks others.

An ne2k8 NIC on SLiRP is attached so the 286 can run the REAL secure handshake end to
end (the 286 secure tier needs the network -- without a NIC the boot dies at DHCP). The
286 is a direct floppy boot, so ram_top is the loader's 0x8000 (the 32K tier): the
floppy-free loop cache + the 286-only P-256 module both live in that high region.

Reuses run86box.py's emulator launch + macOS window screenshot + COM1 capture.

  python3 tools/run-286-86box.py                      # boot floppy-360k.img @6 MHz, networked
  python3 tools/run-286-86box.py --speed 8 --timeout 90
"""
from __future__ import annotations
import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "tools/crypto-bench")
import run86box as rb  # noqa: E402  (emulator_path, ComCapture, screenshot_window)

ROOT = rb.ROOT
DEFAULT_IMG = ROOT / "build" / "ibm_pc_5150" / "floppy-360k.img"
VM_PATH = ROOT / "build" / "ibm_pc_5150" / "vm-286-360k"
NVR = VM_PATH / "nvr" / "ibm5170_111585.nvr"


def cmos() -> bytes:
    """IBM AT (5170) CMOS: RTC + 360K floppy A + 512K base, no FPU (from at286_ladder.py)."""
    c = bytearray(64)
    c[0x0A] = 0x26; c[0x0B] = 0x02; c[0x0D] = 0x80
    c[0x04] = 0x12; c[0x07] = 0x01; c[0x08] = 0x06; c[0x09] = 0x26
    c[0x10] = 0x10                  # floppy A = 360K 5.25"
    c[0x14] = 0x21                  # equipment: 1 floppy, CGA 80-col, no FPU
    c[0x15] = 0x00; c[0x16] = 0x02  # 512K base RAM
    chk = sum(c[0x10:0x2E]) & 0xFFFF
    c[0x2E] = (chk >> 8) & 0xFF
    c[0x2F] = chk & 0xFF
    return bytes(c)


CFG = """[General]
emu_build_num = 8200
sound_muted = 1
vid_renderer = qt_software
[Machine]
machine = ibmat
cpu_family = 286
cpu_multi = 1
cpu_speed = {speed}
cpu_use_dynarec = 0
fpu_type = none
mem_size = 512
[Video]
gfxcard = cga
[Input devices]
keyboard_type = keyboard_at
mouse_type = none
[Ports (COM & LPT)]
serial1_passthrough_enabled = 1
[Network]
net_01_card = ne2k8
net_01_link = 1
net_01_net_type = slirp
net_01_promisc = 0
net_01_switch_group = 0
net_02_link = 0
net_03_link = 0
net_04_link = 0
[Storage controllers]

[Floppy and CD-ROM drives]
fdd_01_fn = {img}
fdd_01_type = 525_2dd
fdd_02_type = none
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=str(DEFAULT_IMG))
    ap.add_argument("--speed", type=int, default=6, help="286 clock in MHz (default 6 = security clock)")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="seconds to wait before the screenshot (default 120: the @6 secure handshake "
                         "is the slow case -- ECDHE keypair gen ~6.6s + handshake ~14s + the model reply)")
    ap.add_argument("--out", default=str(ROOT / "build" / "ibm_pc_5150" / "boot-286-360k.png"))
    args = ap.parse_args()

    img = Path(args.image).resolve()
    if not img.exists():
        raise SystemExit(f"image not found: {img}  (run `make all` first)")

    NVR.parent.mkdir(parents=True, exist_ok=True)
    NVR.write_bytes(cmos())
    (VM_PATH / "86box.cfg").write_text(CFG.format(speed=args.speed * 1000000, img=img))

    subprocess.run(["pkill", "-f", "86Box"], capture_output=True)
    time.sleep(1.0)
    cap = rb.ComCapture()
    proc = subprocess.Popen(
        [rb.emulator_path(), "--vmpath", str(VM_PATH), "--image", f"A:{img}"],
        cwd=ROOT, env={**os.environ, "SEED_NO_IMAGE": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        start_new_session=True,
    )
    cap.start(proc)
    out = Path(args.out)
    ok = False
    try:
        time.sleep(args.timeout)
        ok = rb.screenshot_window(out)
    finally:
        cap.finish()
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    print(f"286 @{args.speed} MHz boot of {img.name} ({img.stat().st_size} B)")
    print(f"screenshot: {out}  ({'ok' if ok else 'FAILED to capture'})")
    serial = cap.text()
    if serial.strip():
        print("--- COM1 ---")
        print(serial)


if __name__ == "__main__":
    main()
