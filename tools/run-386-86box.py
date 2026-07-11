#!/usr/bin/env python3
"""Boot a Seed floppy image on an AT-compatible 386 86Box VM.

Build 12 unreal-mode validation harness. It uses the same 360K boot image and
NE2000 SLiRP network path as the 286 harness, but selects the local 86Box
`adi386sx` machine with an `i386sx` CPU. Default RAM is 4096 KiB so BIOS
int 15h reports native extended memory and Seed can enable HMA/unreal mode.

  python3 tools/run-386-86box.py
  python3 tools/run-386-86box.py --mem-kib 8192 --speed 25 --timeout 90
"""
from __future__ import annotations
import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "tools/crypto-bench")
import run86box as rb  # noqa: E402

ROOT = rb.ROOT
DEFAULT_IMG = ROOT / "build" / "ibm_pc_5150" / "floppy-360k.img"
VM_PATH = ROOT / "build" / "ibm_pc_5150" / "vm-386-360k"
NVR = VM_PATH / "nvr" / "adi386sx.nvr"
GLOBAL_CFG = VM_PATH / "86box_global.cfg"


def cmos(mem_kib: int) -> bytes:
    c = bytearray(128)
    c[0x0A] = 0x26; c[0x0B] = 0x02; c[0x0D] = 0x80
    c[0x04] = 0x12; c[0x07] = 0x01; c[0x08] = 0x06; c[0x09] = 0x26
    c[0x10] = 0x20
    c[0x14] = 0x21
    base_kib = 640 if mem_kib >= 1024 else mem_kib
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
machine = adi386sx
cpu_family = i386sx
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
net_01_card = ne2k
net_01_link = 1
net_01_net_type = slirp
net_01_promisc = 0
net_01_switch_group = 0
net_02_link = 0
net_03_link = 0
net_04_link = 0

[NE2000 Compatible #1]
base = 0300
irq = 3
bios_addr = 00000
mac = 2b:86:13
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
    ap.add_argument("--speed", type=int, default=16, help="386 clock in MHz (default 16)")
    ap.add_argument("--mem-kib", type=int, default=4096, help="total RAM in KiB (default 4096)")
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--out", default=str(ROOT / "build" / "ibm_pc_5150" / "boot-386-360k.png"))
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
    print(f"386 @{args.speed} MHz, {args.mem_kib} KiB boot of {img.name} ({img.stat().st_size} B)")
    print(f"screenshot: {out}  ({'ok' if ok else 'FAILED to capture'})")


if __name__ == "__main__":
    main()
