#!/usr/bin/env python3
"""Boot a Seed floppy image on an AT-compatible 286 86Box VM and screenshot the result.

The 286 secure tier's test harness (Build 12). The AT's 1.2 MB drive rejects the
single-sided 160K image, so this boots the 360K double-sided image (the 2-image
decision). A crafted CMOS gets the 286 BIOS past SETUP (it halts on a blank CMOS; the XT
has none). 6 MHz is the security clock (the lowest secure CPU); --speed picks others.

An ne2k8 NIC on SLiRP is attached so the 286 can run the REAL secure handshake end to
end (the 286 secure tier needs the network -- without a NIC the boot dies at DHCP). The
286 is a direct floppy boot, so ram_top is the loader's 0x8000 (the 32K tier): the
floppy-free loop cache + the 286-only P-256 module both live in that high region.

Reuses run86box.py's macOS window screenshot helper.

  python3 tools/run-286-86box.py                      # boot floppy-360k.img @6 MHz, networked
  python3 tools/run-286-86box.py --mem-kib 2048       # expose 1 MiB native extended memory
  python3 tools/run-286-86box.py --speed 8 --timeout 90
"""
from __future__ import annotations
import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "tools/crypto-bench")
import run86box as rb  # noqa: E402  (emulator_path, ComCapture, screenshot_window)

ROOT = rb.ROOT
DEFAULT_IMG = ROOT / "build" / "ibm_pc_5150" / "floppy-360k.img"
VM_PATH = ROOT / "build" / "ibm_pc_5150" / "vm-286-360k"
NVR = VM_PATH / "nvr" / "ami286.nvr"
GLOBAL_CFG = VM_PATH / "86box_global.cfg"


def cmos(mem_kib: int) -> bytes:
    """AT CMOS: RTC + 1.2M floppy A + base/extended RAM, no FPU."""
    c = bytearray(128)
    c[0x0A] = 0x26; c[0x0B] = 0x02; c[0x0D] = 0x80
    c[0x04] = 0x12; c[0x07] = 0x01; c[0x08] = 0x06; c[0x09] = 0x26
    c[0x10] = 0x20                  # floppy A = 1.2M 5.25" AT drive; boots the 360K image
    c[0x14] = 0x21                  # equipment: 1 floppy, CGA 80-col, no FPU
    base_kib = 512 if mem_kib < 1024 else 640
    ext_kib = max(0, mem_kib - 1024)
    c[0x15] = base_kib & 0xFF; c[0x16] = (base_kib >> 8) & 0xFF
    c[0x17] = ext_kib & 0xFF; c[0x18] = (ext_kib >> 8) & 0xFF
    c[0x30] = ext_kib & 0xFF; c[0x31] = (ext_kib >> 8) & 0xFF
    chk = sum(c[0x10:0x2E]) & 0xFFFF
    c[0x2E] = (chk >> 8) & 0xFF
    c[0x2F] = chk & 0xFF
    return bytes(c)


CFG = """[General]
emu_build_num = 8200
sound_muted = 1
vid_renderer = qt_software
video_filter_method = 0
[Machine]
machine = ami286
cpu_family = 286
cpu_multi = 1
cpu_speed = {speed}
cpu_use_dynarec = 0
fpu_type = none
mem_size = {mem_kib}
[Video]
gfxcard = cga
[Input devices]
keyboard_type = keyboard_at
mouse_type = none
[Network]
net_01_card = ne2k8
net_01_link = 1
net_01_net_type = slirp
net_01_promisc = 0
net_01_switch_group = 0
net_02_link = 0
net_03_link = 0
net_04_link = 0

[NE2000 Compatible 8-bit #1]
base = 0300
irq = 3
bios_addr = 00000
mac = 2b:86:12
mac_oui = 00:86:b0

[Storage controllers]
fdc = fdc_at

[Floppy and CD-ROM drives]
fdd_01_fn = {img}
fdd_01_type = 525_2hd
fdd_02_type = none
"""


GLOBAL = """confirm_exit = 0
do_auto_pause = 0

[Emulator]
confirm_exit = 0
do_auto_pause = 0
"""


def resume_if_paused() -> None:
    script = """
tell application "System Events"
  repeat 30 times
    if exists process "86Box" then exit repeat
    delay 0.2
  end repeat
  tell process "86Box"
    set frontmost to true
    repeat 30 times
      if exists window 1 then exit repeat
      delay 0.2
    end repeat
    repeat 20 times
      set acceptedMovedDialog to false
      repeat with oneWindow in windows
        try
          if exists button "I Copied It" of oneWindow then
            click button "I Copied It" of oneWindow
            set acceptedMovedDialog to true
            exit repeat
          end if
        end try
        try
          set dialogPosition to position of oneWindow
          set dialogSize to size of oneWindow
          set dialogWidth to item 1 of dialogSize
          set dialogHeight to item 2 of dialogSize
          if dialogWidth > 350 and dialogWidth < 750 and dialogHeight > 150 and dialogHeight < 350 then
            set clickX to (item 1 of dialogPosition) + (dialogWidth * 0.34)
            set clickY to (item 2 of dialogPosition) + dialogHeight - 44
            click at {clickX, clickY}
            set acceptedMovedDialog to true
            exit repeat
          end if
        end try
      end repeat
      if acceptedMovedDialog then exit repeat
      delay 0.1
    end repeat
    repeat 40 times
      try
        click menu item "Resume" of menu "Action" of menu bar item "Action" of menu bar 1
        exit repeat
      on error
        delay 0.25
      end try
    end repeat
  end tell
end tell
"""
    subprocess.run(["osascript", "-e", script], capture_output=True, text=True)


def launch_86box(img: Path) -> None:
    subprocess.run([
        "open", "-g", "-n", "-a", "86Box",
        "--env", "SEED_NO_IMAGE=1",
        "--args",
        "--global", str(GLOBAL_CFG),
        "--vmpath", str(VM_PATH),
        "--image", f"A:{img}",
    ], cwd=ROOT, check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=str(DEFAULT_IMG))
    ap.add_argument("--speed", type=int, default=6, help="286 clock in MHz (default 6 = security clock)")
    ap.add_argument("--mem-kib", type=int, default=512,
                    help="total RAM in KiB (default 512; use 2048+ for HMA/native extended-memory gates)")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="seconds to wait before the screenshot (default 120: the @6 secure handshake "
                         "is the slow case -- ECDHE keypair gen ~6.6s + handshake ~14s + the model reply)")
    ap.add_argument("--out", default=str(ROOT / "build" / "ibm_pc_5150" / "boot-286-360k.png"))
    args = ap.parse_args()

    img = Path(args.image).resolve()
    if not img.exists():
        raise SystemExit(f"image not found: {img}  (run `make all` first)")

    NVR.parent.mkdir(parents=True, exist_ok=True)
    NVR.write_bytes(cmos(args.mem_kib))
    GLOBAL_CFG.write_text(GLOBAL)
    (VM_PATH / "86box.cfg").write_text(CFG.format(
        speed=args.speed * 1000000,
        img=img,
        mem_kib=args.mem_kib,
    ))

    subprocess.run(["pkill", "-f", "86Box"], capture_output=True)
    time.sleep(1.0)
    launch_86box(img)
    resume_if_paused()
    out = Path(args.out)
    ok = False
    try:
        time.sleep(args.timeout)
        ok = rb.screenshot_window(out)
    finally:
        subprocess.run(["pkill", "-9", "-f", "86Box"], capture_output=True)
    print(f"286 @{args.speed} MHz, {args.mem_kib} KiB boot of {img.name} ({img.stat().st_size} B)")
    print(f"screenshot: {out}  ({'ok' if ok else 'FAILED to capture'})")


if __name__ == "__main__":
    main()
