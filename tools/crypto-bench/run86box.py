#!/usr/bin/env python3
"""Ground-truth 4.77 MHz timing for the crypto micro-benchmark via 86Box.

Assembles bench.asm into a SEED.SYS, wraps it in the real boot.bin/loader.bin
FAT12 chain, boots it on an isolated 86Box profile (8088 @ 4.772728 MHz, no
dynarec, CGA, COM1 passthrough), and reads the per-op result lines off COM1:

    SHABLK N=256 dt=427 ck=1A2B
    PRFMAS N=8 dt=...
    PRFALL N=4 dt=...
    DONE

dt = elapsed BIOS ticks; 1 tick = 65536/1193182 s = 54.9254 ms. ms/iter =
dt * 54.9254 / N. A window screenshot is always saved as a fallback / for eyeball
verification. One 86Box at a time (we pkill first).

Reuses the ComCapture + CGWindow-screenshot logic from run-basic-bootstrap-86box.py.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import signal
import subprocess
import sys
import termios
import threading
import time
import tty
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = Path(__file__).resolve().parent
BOOT_INC = ROOT / "targets" / "ibm_pc_5150" / "boot"
BUILD = ROOT / "build" / "ibm_pc_5150"
BENCH_BUILD = BUILD / "crypto-bench"
PROFILE = "vm-crypto-bench"
VM_PATH = ROOT / "targets" / "ibm_pc_5150" / "86box" / PROFILE
IMAGE = BENCH_BUILD / "crypto-bench.img"
BOOT_BIN = BUILD / "boot.bin"
LOADER_BIN = BUILD / "loader.bin"
TICK_MS = 65536.0 / 1193182.0 * 1000.0   # 54.9254 ms

PTY_PATH_RE = re.compile(r"serial_passthrough:\s*Slave side is\s*(/dev/ttys\d+)")
RESULT_RE = re.compile(r"^([A-Z0-9]+)\s+N=(\d+)\s+dt=(\d+)\s+ck=([0-9A-Fa-f]+)")


def emulator_path() -> str:
    for cand in ("86Box", "/Applications/86Box.app/Contents/MacOS/86Box"):
        if cand == "86Box":
            import shutil
            if shutil.which("86Box"):
                return "86Box"
        elif Path(cand).exists():
            return cand
    raise SystemExit("86Box not found")


def assemble(bench_asm: Path, out_bin: Path, defines: list[str] | None = None) -> int:
    cmd = ["nasm", "-f", "bin", f"-I{BOOT_INC}/", f"-I{BENCH_DIR}/"]
    for d in defines or []:
        cmd.append(f"-D{d}")
    cmd += ["-o", str(out_bin), str(bench_asm)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"nasm failed:\n{r.stderr}")
    return out_bin.stat().st_size


def build_image(core_bin: Path) -> None:
    BENCH_BUILD.mkdir(parents=True, exist_ok=True)
    if not BOOT_BIN.exists() or not LOADER_BIN.exists():
        subprocess.run(["make", "-C", str(ROOT),
                        f"{BUILD}/boot.bin", f"{BUILD}/loader.bin"], check=True)
    subprocess.run([
        "python3", str(ROOT / "tools" / "build-fat12-image.py"), "build",
        "--boot", str(BOOT_BIN), "--loader", str(LOADER_BIN),
        "--loader-sectors", "4", "--output", str(IMAGE),
        "--file", f"{core_bin}:SEED.SYS",
    ], check=True, capture_output=True, text=True)


# --- ComCapture (serial PTY reader), trimmed from run-basic-bootstrap-86box.py ---
class ComCapture:
    def __init__(self):
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.pty_path = None

    def start(self, process):
        threading.Thread(target=self._read_stdout, args=(process,), daemon=True).start()

    def _read_stdout(self, process):
        try:
            for line in iter(process.stdout.readline, ""):
                if self.stop_event.is_set():
                    break
                m = PTY_PATH_RE.search(line)
                if m and self.pty_path is None:
                    self.pty_path = m.group(1)
                    threading.Thread(target=self._read_pty, daemon=True).start()
        except (ValueError, OSError):
            pass

    def _read_pty(self):
        try:
            fd = os.open(self.pty_path, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
        except OSError:
            return
        try:
            try:
                tty.setraw(fd, termios.TCSANOW)
            except termios.error:
                pass
            while not self.stop_event.is_set():
                try:
                    chunk = os.read(fd, 4096)
                    if chunk:
                        with self.lock:
                            self.buf.extend(chunk)
                    else:
                        time.sleep(0.03)
                except BlockingIOError:
                    time.sleep(0.03)
                except OSError:
                    break
        finally:
            os.close(fd)

    def text(self):
        with self.lock:
            return bytes(self.buf).decode("ascii", errors="replace")

    def finish(self):
        self.stop_event.set()
        time.sleep(0.2)


def find_86box_window_id():
    try:
        cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        cg.CGWindowListCopyWindowInfo.restype = ctypes.c_void_p
        cf.CFArrayGetCount.argtypes = [ctypes.c_void_p]
        cf.CFArrayGetCount.restype = ctypes.c_long
        cf.CFArrayGetValueAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long]
        cf.CFArrayGetValueAtIndex.restype = ctypes.c_void_p
        cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cf.CFDictionaryGetValue.restype = ctypes.c_void_p
        cf.CFStringGetCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
        cf.CFStringGetCString.restype = ctypes.c_bool
        cf.CFNumberGetValue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        cf.CFNumberGetValue.restype = ctypes.c_bool
        cf.CFRelease.argtypes = [ctypes.c_void_p]

        def sym(n):
            return ctypes.c_void_p(ctypes.c_void_p.in_dll(cg, n).value)
        key_owner, key_num, key_layer = sym("kCGWindowOwnerName"), sym("kCGWindowNumber"), sym("kCGWindowLayer")

        def cf_str(p):
            if not p:
                return ""
            b = ctypes.create_string_buffer(1024)
            return b.value.decode() if cf.CFStringGetCString(p, b, len(b), 0x08000100) else ""

        def cf_num(p):
            if not p:
                return 0
            v = ctypes.c_longlong()
            cf.CFNumberGetValue(p, 4, ctypes.byref(v))
            return int(v.value)

        wl = cg.CGWindowListCopyWindowInfo(1, 0)
        if not wl:
            return None
        try:
            for i in range(cf.CFArrayGetCount(wl)):
                it = cf.CFArrayGetValueAtIndex(wl, i)
                if cf_str(cf.CFDictionaryGetValue(it, key_owner)) != "86Box":
                    continue
                if cf_num(cf.CFDictionaryGetValue(it, key_layer)) != 0:
                    continue
                wid = cf_num(cf.CFDictionaryGetValue(it, key_num))
                if wid:
                    return wid
            return None
        finally:
            cf.CFRelease(wl)
    except (OSError, ValueError, AttributeError):
        return None


def screenshot_window(path: Path) -> bool:
    wid = find_86box_window_id()
    if wid is None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["screencapture", "-x", "-o", f"-l{wid}", str(path)],
                       capture_output=True, text=True)
    return r.returncode == 0 and path.exists() and path.stat().st_size > 0


def parse_results(text: str) -> dict:
    ops = {}
    for line in text.splitlines():
        m = RESULT_RE.match(line.strip())
        if m:
            tag, n, dt, ck = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4).upper()
            ms_iter = dt * TICK_MS / n if n else 0.0
            ops[tag] = {"N": n, "dt": dt, "ck": ck,
                        "ms_per_iter": round(ms_iter, 2),
                        "s_per_iter": round(ms_iter / 1000.0, 4)}
    return ops


def run(timeout: float = 90.0, settle: float = 4.0) -> dict:
    subprocess.run(["pkill", "-f", "86Box"], capture_output=True)
    time.sleep(1.0)
    cap = ComCapture()
    proc = subprocess.Popen(
        [emulator_path(), "--vmpath", str(VM_PATH), "--image", f"A:{IMAGE}"],
        cwd=ROOT, env={**os.environ, "SEED_NO_IMAGE": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        start_new_session=True,
    )
    cap.start(proc)
    shot = BENCH_BUILD / "crypto-bench.png"
    deadline = time.monotonic() + timeout
    got_done = False
    try:
        while time.monotonic() < deadline:
            if "DONE" in cap.text():
                got_done = True
                break
            time.sleep(0.5)
        time.sleep(settle)
        screenshot_window(shot)
    finally:
        cap.finish()
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    text = cap.text()
    (BENCH_BUILD / "crypto-bench.serial.txt").write_text(text)
    return {"done": got_done, "serial_pty": cap.pty_path, "serial_text": text,
            "ops": parse_results(text), "screenshot": str(shot)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", default=str(BENCH_DIR / "bench.asm"))
    ap.add_argument("--sha", help="SHA-256 source to benchmark (default core/sha256.inc)")
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    core = BENCH_BUILD / "bench.bin"
    if not args.no_build:
        defines = [f'SHA256_SRC="{args.sha}"'] if args.sha else None
        size = assemble(Path(args.asm), core, defines=defines)
        build_image(core)
        print(f"built {core.name}: {size} B ({(size+511)//512} sectors)")
    res = run(timeout=args.timeout)
    print(f"serial PTY: {res['serial_pty']}  done={res['done']}")
    print(f"screenshot: {res['screenshot']}")
    print("--- serial text ---")
    print(res["serial_text"] or "(none)")
    print("--- parsed (1 tick = %.4f ms) ---" % TICK_MS)
    print(json.dumps(res["ops"], indent=2))


if __name__ == "__main__":
    main()
