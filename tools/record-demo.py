#!/usr/bin/env python3
"""Record a Seed demo as a timestamped PNG frame sequence (source for a GIF).

Two modes:
  --grab-only         just capture the running 86Box window to frames (run
                      alongside another harness, e.g. run-basic-bootstrap).
  --profile 286       launch a networked 286 @<speed>, capture frames, and type
                      a prompt at --type-at seconds (or after --greet-gate OCR).

Frames are written as f_<index>_<ms>.png (ms = real milliseconds since capture
start) so a later ffmpeg pass can place both machines on one real-time timeline.

Reuses run86box.py (screenshot_window) and the 286 cfg from run-286-86box.py.
"""
from __future__ import annotations
import argparse, shutil, subprocess, sys, threading, time
from pathlib import Path

OCR_SWIFT = Path("tools/ocr-vision.swift")


def ocr_text(path: Path) -> str:
    """OCR a frame via the macOS Vision helper; '' on any failure."""
    swift = shutil.which("swift")
    if not swift or not path or not path.exists():
        return ""
    try:
        r = subprocess.run([swift, str(OCR_SWIFT), str(path)],
                           capture_output=True, text=True, timeout=40)
        return (r.stdout or "").lower()
    except Exception:
        return ""

sys.path.insert(0, "tools/crypto-bench")
import run86box as rb  # screenshot_window, ROOT

ROOT = rb.ROOT
VM_PATH = ROOT / "build" / "ibm_pc_5150" / "vm-286-360k"
NVR = VM_PATH / "nvr" / "ami286.nvr"
GLOBAL_CFG = VM_PATH / "86box_global.cfg"
DEFAULT_IMG = ROOT / "build" / "ibm_pc_5150" / "floppy-360k.img"

# ---- 286 CMOS + cfg (verbatim shape from run-286-86box.py) ----
def cmos(mem_kib: int) -> bytes:
    c = bytearray(128)
    c[0x0A] = 0x26; c[0x0B] = 0x02; c[0x0D] = 0x80
    c[0x04] = 0x12; c[0x07] = 0x01; c[0x08] = 0x06; c[0x09] = 0x26
    c[0x10] = 0x20; c[0x14] = 0x21
    base_kib = 512 if mem_kib < 1024 else 640
    ext_kib = max(0, mem_kib - 1024)
    c[0x15] = base_kib & 0xFF; c[0x16] = (base_kib >> 8) & 0xFF
    c[0x17] = ext_kib & 0xFF; c[0x18] = (ext_kib >> 8) & 0xFF
    c[0x30] = ext_kib & 0xFF; c[0x31] = (ext_kib >> 8) & 0xFF
    chk = sum(c[0x10:0x2E]) & 0xFFFF
    c[0x2E] = (chk >> 8) & 0xFF; c[0x2F] = chk & 0xFF
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
GLOBAL = "confirm_exit = 0\ndo_auto_pause = 0\n\n[Emulator]\nconfirm_exit = 0\ndo_auto_pause = 0\n"

RESUME = ROOT / "tools" / "_resume286.applescript"  # extracted from run-286 at runtime


def resume_if_paused():
    # Bring 86Box up, dismiss the "image moved" dialog, hit Action->Resume.
    script = r'''
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
      repeat with w in windows
        try
          if exists button "I Copied It" of w then
            click button "I Copied It" of w
            exit repeat
          end if
        end try
      end repeat
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
'''
    subprocess.run(["osascript", "-e", script], capture_output=True, text=True)


def launch_286(img: Path, speed: int, mem_kib: int):
    NVR.parent.mkdir(parents=True, exist_ok=True)
    NVR.write_bytes(cmos(mem_kib))
    GLOBAL_CFG.write_text(GLOBAL)
    (VM_PATH / "86box.cfg").write_text(CFG.format(speed=speed * 1000000, img=img, mem_kib=mem_kib))
    subprocess.run(["pkill", "-f", "86Box"], capture_output=True)
    time.sleep(1.0)
    # foreground launch (no -g): 86Box must be the active window for the window
    # server to deliver posted key events at type time.
    subprocess.run(["open", "-n", "-a", "86Box", "--env", "SEED_NO_IMAGE=1", "--args",
                    "--global", str(GLOBAL_CFG), "--vmpath", str(VM_PATH), "--image", f"A:{img}"],
                   cwd=ROOT, check=True)
    resume_if_paused()


_RBB = None
def _rbb():
    """Import run-basic-bootstrap-86box.py (hyphenated filename) once, to reuse
    its proven VM-typing + pid-matching helpers verbatim."""
    global _RBB
    if _RBB is None:
        import importlib.util as ilu
        spec = ilu.spec_from_file_location("rbb", str(ROOT / "tools" / "run-basic-bootstrap-86box.py"))
        _RBB = ilu.module_from_spec(spec)
        spec.loader.exec_module(_RBB)
    return _RBB


def type_prompt(text: str):
    """Reuse the harness's proven path: find the 86Box pid by its --vmpath (not a
    name guess), then post key events straight to that pid (pidkeycode mode)."""
    rbb = _rbb()
    pids = rbb.matching_86box_pids(VM_PATH)
    if not pids:
        print(f"  type_prompt: no 86Box pid matching {VM_PATH}"); return
    pid = sorted(pids)[0]
    # ensure 86Box is frontmost so posted key events are delivered
    subprocess.run(["osascript", "-e",
                    'tell application "System Events" to tell process "86Box" to set frontmost to true'],
                   capture_output=True, text=True)
    time.sleep(1.5)
    t = text if text.endswith("\n") else text + "\n"
    rbb.type_basic_pid_keycodes(pid, t, 0.03, 0.2)
    print(f"  typed {len(t.rstrip())} chars to 86Box pid {pid}")


class Grabber(threading.Thread):
    def __init__(self, outdir: Path, interval: float):
        super().__init__(daemon=True)
        self.outdir = outdir; self.interval = interval
        self.stop = False; self.n = 0
    def run(self):
        t0 = time.time()
        while not self.stop:
            ts = time.time() - t0
            out = self.outdir / f"f_{self.n:05d}_{int(ts * 1000):08d}.png"
            try:
                rb.screenshot_window(out)
            except Exception:
                pass
            self.n += 1
            dt = self.interval - ((time.time() - t0) - ts)
            if dt > 0:
                time.sleep(dt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["grab-only", "286"], required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--interval", type=float, default=0.4, help="seconds between frames")
    ap.add_argument("--duration", type=float, default=240.0, help="total capture seconds")
    ap.add_argument("--image", default=str(DEFAULT_IMG))
    ap.add_argument("--speed", type=int, default=6)
    ap.add_argument("--mem-kib", type=int, default=512)
    ap.add_argument("--prompt", default="")
    ap.add_argument("--type-at", type=float, default=0.0, help="seconds after launch to type --prompt (0 = OCR-gated)")
    ap.add_argument("--gate-text", default="help you", help="OCR substring that means the greeting/prompt is ready")
    ap.add_argument("--gate-timeout", type=float, default=220.0, help="max seconds to wait for the gate text")
    ap.add_argument("--answer-secs", type=float, default=90.0, help="seconds to keep capturing after typing the prompt")
    args = ap.parse_args()

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    for old in outdir.glob("f_*.png"):
        old.unlink()

    if args.mode == "286":
        launch_286(Path(args.image).resolve(), args.speed, args.mem_kib)

    grab = Grabber(outdir, args.interval)
    grab.start()
    t0 = time.time()

    def latest_frame():
        fs = sorted(outdir.glob("f_*.png"))
        return fs[-1] if fs else None

    try:
        if args.prompt:
            if args.type_at > 0:
                while time.time() - t0 < args.type_at:
                    time.sleep(0.5)
                print(f"[{time.time()-t0:.0f}s] typing (fixed --type-at)")
            else:
                # gate on the real DPI '>' prompt being ready for input (reuse the
                # harness's proven detector), not just the greeting text — typing
                # before the prompt accepts input loses the keystrokes.
                ready = False
                rbb = _rbb()
                while time.time() - t0 < args.gate_timeout:
                    time.sleep(4.0)
                    f = latest_frame()
                    if f is None:
                        continue
                    try:
                        _, lines = rbb.screen_ocr_lines(f, 8.0)
                    except Exception:
                        lines = []
                    if rbb.ocr_lines_suggest_dpi_ready(lines):
                        print(f"[{time.time()-t0:.0f}s] DPI prompt ready -> typing")
                        ready = True
                        break
                if not ready:
                    print(f"[{time.time()-t0:.0f}s] gate timeout -> typing anyway")
            type_prompt(args.prompt)
            ans_end = time.time() + args.answer_secs
            while time.time() < ans_end:
                time.sleep(0.5)
        else:
            while time.time() - t0 < args.duration:
                time.sleep(0.5)
    finally:
        grab.stop = True
        grab.join(timeout=5)
    print(f"captured {grab.n} attempts, {len(list(outdir.glob('f_*.png')))} frames -> {outdir}")
    if args.mode == "286":
        subprocess.run(["pkill", "-9", "-f", "86Box"], capture_output=True)


if __name__ == "__main__":
    main()
