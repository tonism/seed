#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import struct
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = "vm-net-ne2k8"
DEFAULT_BASIC = ROOT / "build/ibm_pc_5150/SEED24B.BAS"
DEFAULT_LOADER = ROOT / "build/ibm_pc_5150/seed24a-loader.bin"
DEFAULT_BASIC_LOADER = ROOT / "build/ibm_pc_5150/seed24b-loader.bin"
DEFAULT_FLOPPY = ROOT / "build/ibm_pc_5150/floppy-160k.img"
DEFAULT_LOADER_FLOPPY = ROOT / "build/ibm_pc_5150/floppy-160k-lowmem-loader.img"
DEFAULT_SCREENSHOT = ROOT / "build/ibm_pc_5150/86box-seed24-basic.png"
DEFAULT_ORACLE_SCREENSHOT = ROOT / "build/ibm_pc_5150/86box-oracle.png"
DEFAULT_OCR_SCRIPT = ROOT / "tools/ocr-vision.swift"
DEFAULT_BASIC_STARTUP_DELAY = 10.0
DEFAULT_BASIC_CAPTURE_DELAY = 35.0
DEFAULT_DIRECT_STARTUP_DELAY = 10.0
DEFAULT_DIRECT_CAPTURE_DELAY = 50.0
BASIC_BOOTSTRAP_ADDR = 0x3A00
BASIC_BOOTSTRAP_CLEAR_TOP = 14847
BASIC_HEX_CHUNK_SIZE = 32
CG_EVENT_FLAG_MASK_SHIFT = 1 << 17
RTC_UTC_ATTEST_RAM_KIB = 512
RTC_UTC_ATTEST_MACHINE_SETTINGS = {
    "machine": "ami286",
    "cpu_family": "286",
    "cpu_speed": "6000000",
    "cpu_multi": "1",
    "cpu_use_dynarec": "0",
}
# Do not abort the AMI286 count at its first visible 96-KiB step.  The direct
# loader places the 150,016-byte product at 0000:1000, and the known-good
# manual bypass first let the count advance into the 160--192 KiB range.
# Ninety seconds retains that loader-safe margin while avoiding the complete,
# very slow 512-KiB POST count at the exact 6-MHz floor.
AMI286_MEMORY_BYPASS_DELAY_SECONDS = 90.0

KEY_CODES = {
    "\n": (36, False),
    " ": (49, False),
    ",": (43, False),
    ".": (47, False),
    ":": (41, True),
    ";": (41, False),
    "'": (39, False),
    "?": (44, True),
    "/": (44, False),
    "!": (18, True),
    "-": (27, False),
    "_": (27, True),
    "=": (24, False),
    "(": (25, True),
    ")": (29, True),
    '"': (39, True),
    "&": (26, True),
    "$": (21, True),
    "+": (24, True),
    "*": (28, True),
    "0": (29, False),
    "1": (18, False),
    "2": (19, False),
    "3": (20, False),
    "4": (21, False),
    "5": (23, False),
    "6": (22, False),
    "7": (26, False),
    "8": (28, False),
    "9": (25, False),
    "a": (0, False),
    "b": (11, False),
    "c": (8, False),
    "d": (2, False),
    "e": (14, False),
    "f": (3, False),
    "g": (5, False),
    "h": (4, False),
    "i": (34, False),
    "j": (38, False),
    "k": (40, False),
    "l": (37, False),
    "m": (46, False),
    "n": (45, False),
    "o": (31, False),
    "p": (35, False),
    "q": (12, False),
    "r": (15, False),
    "s": (1, False),
    "t": (17, False),
    "u": (32, False),
    "v": (9, False),
    "w": (13, False),
    "x": (7, False),
    "y": (16, False),
    "z": (6, False),
}


FOCUS_86BOX_SCRIPT = """
set found86Box to false
tell application "System Events"
  repeat with i from 1 to 30
    if exists process "86Box" then
      tell process "86Box" to set frontmost to true
      set found86Box to true
      delay 0.5
      exit repeat
    end if
    delay 0.5
  end repeat
end tell
if found86Box is false then
  error "86Box process not found"
end if
"""


def run(args: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, **kwargs)


def current_branch() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip() or "unknown"


class TestLock:
    def __init__(self, path: Path, name: str, profile: str, timeout: float):
        self.path = path
        self.name = name
        self.profile = profile
        self.timeout = timeout
        self.content = ""
        self.acquired = False

    def acquire(self) -> None:
        deadline = time.monotonic() + self.timeout
        warned = False
        timestamp = datetime.now(timezone.utc).isoformat()
        self.content = f"{self.name} | {current_branch()} | {timestamp} | {self.profile}\n"
        while True:
            try:
                fd = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o644,
                )
            except FileExistsError:
                try:
                    existing = self.path.read_text(encoding="utf-8").strip()
                except OSError:
                    existing = "(unreadable)"
                if time.monotonic() >= deadline:
                    raise SystemExit(f"test lock busy after {self.timeout:.0f}s: {self.path}: {existing}")
                if not warned:
                    print(f"test lock: waiting for {self.path}: {existing}")
                    warned = True
                time.sleep(2.0)
                continue
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(self.content)
            except BaseException:
                self.path.unlink(missing_ok=True)
                raise
            self.acquired = True
            print(f"test lock: acquired {self.path}")
            return

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            existing = self.path.read_text(encoding="utf-8")
            if existing == self.content:
                self.path.unlink()
                print(f"test lock: released {self.path}")
        except FileNotFoundError:
            pass
        finally:
            self.acquired = False


def emulator_path() -> str:
    found = shutil.which("86Box")
    if found:
        return found
    app_path = "/Applications/86Box.app/Contents/MacOS/86Box"
    if Path(app_path).exists():
        return app_path
    raise SystemExit("86Box was not found")


def activate_86box() -> None:
    run(["osascript", "-e", FOCUS_86BOX_SCRIPT])


def frontmost_process_name() -> str | None:
    script = (
        'tell application "System Events" to '
        'get name of first application process whose frontmost is true'
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None
    name = result.stdout.strip()
    return name or None


def restore_frontmost_process(name: str | None) -> None:
    if not name or name == "86Box":
        return
    script = """
on run argv
  set processName to item 1 of argv
  tell application "System Events"
    if exists process processName then
      tell process processName to set frontmost to true
    end if
  end tell
end run
"""
    subprocess.run(
        ["osascript", "-e", script, name],
        check=False,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def paste_basic(basic: str) -> None:
    script = """
on run argv
  set the clipboard to item 1 of argv
""" + FOCUS_86BOX_SCRIPT + """
  tell application "System Events"
    keystroke "v" using {command down}
  end tell
end run
"""
    run(["osascript", "-e", script, basic])


def type_basic_text(basic: str, line_delay: float) -> None:
    script = """
on run argv
  set lineDelay to (item 1 of argv) as real
  set basicText to item 2 of argv
""" + FOCUS_86BOX_SCRIPT + """
  tell application "System Events"
    repeat with oneLine in paragraphs of basicText
      if length of oneLine is greater than 0 then
        keystroke oneLine
        key code 36
        delay lineDelay
      end if
    end repeat
  end tell
end run
"""
    run(["osascript", "-e", script, str(line_delay), basic])


def type_basic_chars(basic: str, key_delay: float, line_delay: float) -> None:
    script = """
on run argv
  set keyDelay to (item 1 of argv) as real
  set lineDelay to (item 2 of argv) as real
  set basicText to item 3 of argv
""" + FOCUS_86BOX_SCRIPT + """
  tell application "System Events"
    repeat with oneLine in paragraphs of basicText
      if length of oneLine is greater than 0 then
        repeat with i from 1 to length of oneLine
          keystroke character i of oneLine
          delay keyDelay
        end repeat
        key code 36
        delay lineDelay
      end if
    end repeat
  end tell
end run
"""
    run(["osascript", "-e", script, str(key_delay), str(line_delay), basic])


def type_basic_keycodes(basic: str, key_delay: float, line_delay: float) -> None:
    unsupported = sorted({char for char in basic.lower().replace("\r", "") if char not in KEY_CODES})
    if unsupported:
        raise SystemExit(
            "unsupported BASIC injection characters: "
            + " ".join(repr(char) for char in unsupported)
        )

    lines = [
        FOCUS_86BOX_SCRIPT,
        'tell application "System Events"',
    ]
    for char in basic.lower():
        if char == "\r":
            continue
        key_code, shifted = KEY_CODES[char]
        if shifted:
            lines.append(f"  key code {key_code} using {{shift down}}")
        else:
            lines.append(f"  key code {key_code}")
        if char == "\n":
            lines.append(f"  delay {line_delay}")
        else:
            lines.append(f"  delay {key_delay}")
    lines.append(f"  delay {line_delay}")
    lines.append("  key code 36")
    lines.append("end tell")

    with tempfile.NamedTemporaryFile("w", suffix=".applescript", delete=False) as handle:
        handle.write("\n".join(lines) + "\n")
        path = Path(handle.name)
    try:
        run(["osascript", str(path)])
    finally:
        path.unlink(missing_ok=True)


def type_basic_pid_keycodes(
    pid: int,
    basic: str,
    key_delay: float,
    line_delay: float,
) -> None:
    unsupported = sorted({char for char in basic.lower().replace("\r", "") if char not in KEY_CODES})
    if unsupported:
        raise SystemExit(
            "unsupported BASIC injection characters: "
            + " ".join(repr(char) for char in unsupported)
        )

    cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    cg.CGEventCreateKeyboardEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_bool]
    cg.CGEventCreateKeyboardEvent.restype = ctypes.c_void_p
    cg.CGEventKeyboardSetUnicodeString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_uint16),
    ]
    cg.CGEventSetFlags.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    cg.CGEventPostToPid.argtypes = [ctypes.c_int, ctypes.c_void_p]
    cf.CFRelease.argtypes = [ctypes.c_void_p]

    key_hold = min(0.01, max(0.002, key_delay / 3.0))

    def post_raw_key(
        key_code: int,
        text: str | None = None,
        flags: int = 0,
    ) -> None:
        for pressed in (True, False):
            event = cg.CGEventCreateKeyboardEvent(None, key_code, pressed)
            if not event:
                raise SystemExit("CGEventCreateKeyboardEvent failed")
            try:
                if flags:
                    cg.CGEventSetFlags(event, flags)
                if pressed and text:
                    chars = (ctypes.c_uint16 * len(text))(*[ord(char) for char in text])
                    cg.CGEventKeyboardSetUnicodeString(event, len(text), chars)
                cg.CGEventPostToPid(pid, event)
                if pressed:
                    time.sleep(key_hold)
            finally:
                cf.CFRelease(event)

    def post_key(key_code: int, shifted: bool, text: str) -> None:
        if not shifted:
            post_raw_key(key_code, text)
            return
        shift_code = 56
        shift_down = cg.CGEventCreateKeyboardEvent(None, shift_code, True)
        shift_up = cg.CGEventCreateKeyboardEvent(None, shift_code, False)
        if not shift_down or not shift_up:
            raise SystemExit("CGEventCreateKeyboardEvent failed")
        try:
            cg.CGEventSetFlags(shift_down, CG_EVENT_FLAG_MASK_SHIFT)
            cg.CGEventPostToPid(pid, shift_down)
            try:
                time.sleep(key_hold)
                # 86Box consumes the raw key chord.  Carry the modifier on the
                # punctuation events too so macOS cannot transiently present
                # ":" as an unshifted ";" when posting directly to the VM.
                post_raw_key(key_code, text, CG_EVENT_FLAG_MASK_SHIFT)
                time.sleep(key_hold)
            finally:
                cg.CGEventPostToPid(pid, shift_up)
        finally:
            cf.CFRelease(shift_down)
            cf.CFRelease(shift_up)

    for char in basic.lower():
        if char == "\r":
            continue
        key_code, shifted = KEY_CODES[char]
        post_key(key_code, shifted, char)
        time.sleep(line_delay if char == "\n" else key_delay)
    time.sleep(line_delay)


def post_pid_focused_keycode(
    pid: int,
    key_code: int,
    *,
    restore_focus: bool = True,
) -> None:
    """Focus the exact 86Box PID briefly and submit one physical key."""
    previous_frontmost = frontmost_process_name() if restore_focus else None
    script = """
on run argv
  set targetPid to (item 1 of argv) as integer
  set targetKeyCode to (item 2 of argv) as integer
  tell application "System Events"
    -- Stored process references resolve by app name when multiple VMs are open.
    set frontmost of (first application process whose unix id is targetPid) to true
    delay 0.05
    key code targetKeyCode
  end tell
end run
"""
    try:
        run(["osascript", "-e", script, str(pid), str(key_code)])
    finally:
        restore_frontmost_process(previous_frontmost)


def image_suggests_86box_paused(path: Path) -> bool:
    """Recognize 86Box's bottom-right `0 Hz` status without OCR."""
    width, height, channels, rows = read_png_rgb(path)
    x0 = width * 3 // 4
    x1 = width * 93 // 100
    y0 = height * 88 // 100
    y1 = height
    bright: set[tuple[int, int]] = set()
    for y in range(y0, y1):
        row = rows[y]
        for x in range(x0, x1):
            off = x * channels
            r, g, b = row[off], row[off + 1], row[off + 2]
            if min(r, g, b) > 150 and max(r, g, b) - min(r, g, b) < 45:
                bright.add((x, y))

    components: list[tuple[int, int, int, int, int]] = []
    while bright:
        seed = bright.pop()
        pending = [seed]
        xs: list[int] = []
        ys: list[int] = []
        while pending:
            x, y = pending.pop()
            xs.append(x)
            ys.append(y)
            for dx, dy in (
                (-1, -1), (0, -1), (1, -1),
                (-1, 0),             (1, 0),
                (-1, 1),  (0, 1),   (1, 1),
            ):
                adjacent = (x + dx, y + dy)
                if adjacent in bright:
                    bright.remove(adjacent)
                    pending.append(adjacent)
        if len(xs) >= 8:
            components.append(
                (min(xs), min(ys), max(xs) + 1, max(ys) + 1, len(xs))
            )

    min_height = max(7, height // 100)
    max_height = max(min_height, height // 25)
    glyphs = sorted(
        component
        for component in components
        if min_height <= component[3] - component[1] <= max_height
        and component[2] - component[0] <= width // 25
    )
    if len(glyphs) < 3:
        return False

    # `60 Hz`/`59 Hz` has four adjacent glyphs; paused `0 Hz` has three.
    # The following status icons are separated by a visibly wider gap.
    status: list[tuple[int, int, int, int, int]] = [glyphs[0]]
    gap_limit = max(8, width // 64)
    for component in glyphs[1:]:
        if component[0] - status[-1][2] > gap_limit:
            break
        status.append(component)
    return len(status) == 3


def click_86box_pause_menu(pid: int) -> None:
    """Toggle the exact 86Box process through its native Pause menu item."""
    script = """
on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    set frontmost of (first application process whose unix id is targetPid) to true
    delay 0.05
    click menu item "Pause" of menu 1 of menu bar item "Action" of menu bar 1 of (first application process whose unix id is targetPid)
  end tell
end run
"""
    run(["osascript", "-e", script, str(pid)])


def focus_86box_pid(pid: int) -> None:
    """Bring the exact 86Box process forward without submitting guest input."""
    script = """
on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    set frontmost of (first application process whose unix id is targetPid) to true
  end tell
end run
"""
    run(["osascript", "-e", script, str(pid)])


def ensure_86box_running(
    screenshot_path: Path,
    profile: str,
    pid: int,
) -> bool:
    """Leave a newly launched exact VM focused and normalize a 0-Hz pause."""
    focus_86box_pid(pid)
    # The later AMI state machine owns the one counted bypass Escape.  Give
    # the native status bar time to repaint after bringing the VM forward.
    time.sleep(0.2)
    if not screenshot_86box_window_or_screen(screenshot_path, profile, pid):
        return False
    try:
        paused = image_suggests_86box_paused(screenshot_path)
    except (OSError, ValueError):
        return False
    if not paused:
        return True
    print("harness: 86Box launched at 0 Hz; resuming exact VM", flush=True)
    click_86box_pause_menu(pid)
    time.sleep(0.5)
    if not screenshot_86box_window_or_screen(screenshot_path, profile, pid):
        return False
    try:
        return not image_suggests_86box_paused(screenshot_path)
    except (OSError, ValueError):
        return False


class ComCapture:
    """Capture COM1 through 86Box v9001's fixed Unix FIFO device."""

    def __init__(self, output_path: Path, base_path: Path):
        self.output_path = output_path
        self.base_path = base_path
        self.input_path = Path(f"{base_path}.in")
        self.output_fifo = Path(f"{base_path}.out")
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.fd: int | None = None
        self.finished = False

    def start(self) -> None:
        self.base_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_bytes(b"")
        for path in (self.input_path, self.output_fifo):
            path.unlink(missing_ok=True)
            os.mkfifo(path, 0o600)
        # Open the read end before 86Box starts so its nonblocking writer can
        # connect during serial-device initialization.
        self.fd = os.open(
            self.output_fifo,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY,
        )
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        fd = self.fd
        assert fd is not None
        with self.output_path.open("ab") as output:
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    chunk = None
                except OSError:
                    break
                if chunk is None:
                    time.sleep(0.02)
                    continue
                if chunk:
                    with self.lock:
                        self.buf.extend(chunk)
                        output.write(chunk)
                        output.flush()
                else:
                    # A zero-length FIFO read means no writer is connected.
                    # Before launch/reconnect, keep the read end available.
                    # During teardown, it is the EOF that proves all queued
                    # guest bytes have been drained after 86Box stopped.
                    if self.stop_event.is_set():
                        break
                    time.sleep(0.02)

    def finish(self) -> None:
        if self.finished:
            return
        self.finished = True
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
            if self.thread.is_alive() and self.fd is not None:
                # A deliberately left-running VM can retain the writer. Close
                # the nonblocking read end after the bounded drain attempt.
                os.close(self.fd)
                self.fd = None
                self.thread.join(timeout=0.5)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        with self.lock:
            data = bytes(self.buf)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_bytes(data)
        for path in (self.input_path, self.output_fifo):
            path.unlink(missing_ok=True)
        print(f"com capture: {len(data)} byte(s) -> {self.output_path}")
        if not data:
            print("com capture: FIFO opened but no bytes received")
            return
        preview = data[:64]
        print(f"com capture: first {len(preview)} bytes hex: {preview.hex()}")
        ascii_preview = preview.decode("ascii", errors="replace")
        printable = "".join(
            c if 32 <= ord(c) < 127 else "." for c in ascii_preview
        )
        print(f"com capture: first {len(preview)} bytes ascii: {printable}")


class PcapCapture:
    """Drive `sudo tcpdump` as a subprocess so the harness can capture host
    network traffic for the run, then dump a quick text summary at the end.

    Requires a `/etc/sudoers.d/*` entry granting NOPASSWD for /usr/sbin/tcpdump.
    """

    def __init__(
        self,
        path: Path,
        filter_expr: str,
        iface: str,
        report_filter: str | None,
        max_lines: int,
    ):
        self.path = path
        self.filter_expr = filter_expr
        self.iface = iface
        self.report_filter = report_filter
        self.max_lines = max_lines
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        # tcpdump needs root to open the capture device, then drops back to the
        # invoking user. Keeping the running tcpdump child user-owned lets the
        # harness send SIGINT for a clean pcap flush without orphaning a root
        # process. This is intentionally the default en0 path; pktap0 may reject
        # privilege drop on some macOS versions.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or "nobody"
        cmd = [
            "sudo", "-n", "/usr/sbin/tcpdump",
            "-i", self.iface,
            "-U",
            "-Z", user,
            "-w", str(self.path),
            self.filter_expr,
        ]
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise SystemExit(f"pcap: tcpdump not found: {exc}")
        time.sleep(0.6)
        if self.proc.poll() is not None:
            err = self.proc.stderr.read().decode("utf-8", errors="replace") if self.proc.stderr else ""
            raise SystemExit(
                f"pcap: tcpdump exited immediately (rc={self.proc.returncode}). "
                f"Verify `/etc/sudoers.d/seed-tcpdump` is present and `sudo -n tcpdump --version` works.\n{err}"
            )
        print(f"pcap: capturing on {self.iface} with filter '{self.filter_expr}' -> {self.path}")

    def stop(self) -> None:
        if self.proc is None:
            return
        pgid = self.proc.pid
        try:
            os.killpg(pgid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.SubprocessError:
                pass
        self.proc = None

    def analyze(self) -> None:
        lines = self.decoded_lines(report=True)
        if lines is None:
            print("pcap: capture file empty or missing")
            return
        if not lines:
            print(f"pcap: decoding {self.path} ({self.path.stat().st_size} bytes)")
            if self.report_filter:
                print(f"pcap: no packets matched report filter '{self.report_filter}'")
            else:
                print("pcap: no packets captured")
            return
        print(f"pcap: decoding {self.path} ({self.path.stat().st_size} bytes)")
        self.print_flow_summary(lines)
        # Find the first timestamp to use as t=0
        first_t = None
        for line in lines:
            try:
                first_t = float(line.split()[0])
                break
            except (ValueError, IndexError):
                continue
        print("=== pcap: packets (t relative to first) ===")
        if len(lines) > self.max_lines:
            print(f"pcap: showing first {self.max_lines} of {len(lines)} decoded packets")
        prev_t = first_t
        for line in lines[: self.max_lines]:
            tokens = line.split(None, 1)
            try:
                t_abs = float(tokens[0])
            except (ValueError, IndexError):
                print(line)
                continue
            t_rel = t_abs - first_t if first_t is not None else 0.0
            gap = (t_abs - prev_t) if prev_t is not None else 0.0
            gap_marker = ""
            if gap >= 1.0:
                gap_marker = f"  <-- {gap:.2f}s gap"
            print(f"  t={t_rel:8.3f}  {tokens[1] if len(tokens) > 1 else ''}{gap_marker}")
            prev_t = t_abs

    def print_flow_summary(self, lines: list[str]) -> None:
        flows = self.tcp443_flows(lines)
        if not flows:
            return
        ranked = self.rank_flows(flows)
        print("=== pcap: tcp/443 flow summary (top 12 by payload bytes) ===")
        for (local_port, remote_host), flow in ranked[:12]:
            duration = float(flow["last"]) - float(flow["first"])
            print(
                f"  lport={local_port:>5} remote={remote_host:<39} "
                f"out={int(flow['out_pkts']):>4}p/{int(flow['out_bytes']):>6}B "
                f"in={int(flow['in_pkts']):>4}p/{int(flow['in_bytes']):>6}B "
                f"span={duration:>6.2f}s"
            )

    def tcp443_flows(self, lines: list[str]) -> dict[tuple[str, str], dict[str, float | int]]:
        flows: dict[tuple[str, str], dict[str, float | int]] = {}
        for line in lines:
            parts = line.split()
            if len(parts) < 7 or parts[1] not in ("IP", "IP6"):
                continue
            if parts[5] != "tcp":
                continue
            try:
                t_abs = float(parts[0])
            except ValueError:
                continue
            src_host, src_port = self.split_endpoint(parts[2])
            dst_host, dst_port = self.split_endpoint(parts[4].rstrip(":"))
            if src_host is None or dst_host is None:
                continue
            if src_port == "443":
                key = (dst_port or "?", src_host)
                direction = "in"
            elif dst_port == "443":
                key = (src_port or "?", dst_host)
                direction = "out"
            else:
                continue
            try:
                size = int(parts[6])
            except ValueError:
                size = 0
            flow = flows.setdefault(
                key,
                {
                    "first": t_abs,
                    "last": t_abs,
                    "in_pkts": 0,
                    "out_pkts": 0,
                    "in_bytes": 0,
                    "out_bytes": 0,
                },
            )
            flow["first"] = min(float(flow["first"]), t_abs)
            flow["last"] = max(float(flow["last"]), t_abs)
            flow[f"{direction}_pkts"] = int(flow[f"{direction}_pkts"]) + 1
            flow[f"{direction}_bytes"] = int(flow[f"{direction}_bytes"]) + size
        return flows

    @staticmethod
    def rank_flows(
        flows: dict[tuple[str, str], dict[str, float | int]]
    ) -> list[tuple[tuple[str, str], dict[str, float | int]]]:
        return sorted(
            flows.items(),
            key=lambda item: (
                int(item[1]["in_bytes"]) + int(item[1]["out_bytes"]),
                int(item[1]["in_pkts"]) + int(item[1]["out_pkts"]),
            ),
            reverse=True,
        )

    @staticmethod
    def split_endpoint(endpoint: str) -> tuple[str | None, str | None]:
        if "." not in endpoint:
            return None, None
        host, port = endpoint.rsplit(".", 1)
        if not port.isdigit():
            return None, None
        return host, port

    def decoded_lines(self, report: bool = False) -> list[str] | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        cmd = ["/usr/sbin/tcpdump", "-r", str(self.path), "-nn", "-tt", "-q"]
        if report and self.report_filter:
            cmd.append(self.report_filter)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"pcap: tcpdump -r failed (rc={result.returncode}): {result.stderr}")
            return []
        lines = [line for line in result.stdout.splitlines() if line and not line.startswith("reading from")]
        return lines


def ensure_com_pipe(lines: list[str], base_path: Path) -> list[str]:
    """Select 86Box v9001's fixed Unix FIFO COM device."""

    result: list[str] = []
    in_ports = False
    in_pipe = False
    saw_ports = False
    saw_serial = False
    saw_pipe = False
    saw_path = False
    saw_mode = False
    saw_reconnect = False

    def finish_ports() -> None:
        nonlocal saw_serial
        if in_ports and not saw_serial:
            result.append("serial1_device = pipe")
            saw_serial = True

    def finish_pipe() -> None:
        nonlocal saw_path, saw_mode, saw_reconnect
        if not in_pipe:
            return
        if not saw_path:
            result.append(f"path = {base_path}")
            saw_path = True
        if not saw_mode:
            result.append("mode = 1")
            saw_mode = True
        if not saw_reconnect:
            result.append("reconnect = 1")
            saw_reconnect = True

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            finish_ports()
            finish_pipe()
            in_ports = stripped == "[Ports (COM & LPT)]"
            in_pipe = stripped == "[Named Pipe (COM) #1]"
            if in_ports:
                saw_ports = True
                saw_serial = False
            if in_pipe:
                saw_pipe = True
                saw_path = saw_mode = saw_reconnect = False
            result.append(line)
            continue
        if in_ports and (
            stripped.startswith("serial1_device")
            or stripped.startswith("serial1_passthrough_enabled")
        ):
            if not saw_serial:
                result.append("serial1_device = pipe")
                saw_serial = True
            continue
        if in_pipe and stripped.startswith("path ="):
            result.append(f"path = {base_path}")
            saw_path = True
            continue
        if in_pipe and stripped.startswith("mode ="):
            result.append("mode = 1")
            saw_mode = True
            continue
        if in_pipe and stripped.startswith("reconnect ="):
            result.append("reconnect = 1")
            saw_reconnect = True
            continue
        result.append(line)

    finish_ports()
    finish_pipe()
    if not saw_ports:
        if result and result[-1].strip() != "":
            result.append("")
        result.append("[Ports (COM & LPT)]")
        result.append("serial1_device = pipe")
    if not saw_pipe:
        if result and result[-1].strip() != "":
            result.append("")
        result.extend(
            [
                "[Named Pipe (COM) #1]",
                f"path = {base_path}",
                "mode = 1",
                "reconnect = 1",
            ]
        )

    return result


def rewrite_vm_config(
    config: Path,
    ram_kib: int | None,
    floppy: Path,
    rom_basic: bool,
    rom_basic_drive: str = "b",
    com_passthrough: bool = False,
    com_pipe_base: Path | None = None,
    muted: bool = True,
    attest_rtc_utc: bool = False,
    floppy_read_only: bool = False,
) -> None:
    if rom_basic_drive not in {"a", "b"}:
        raise ValueError("ROM BASIC drive must be 'a' or 'b'")
    rom_basic_a = rom_basic and rom_basic_drive == "a"
    rom_basic_b = rom_basic and rom_basic_drive == "b"
    lines = config.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_general_section = False
    in_machine_section = False
    in_floppy_section = False
    saw_machine_section = False
    wrote_sound_muted = False
    wrote_sound_gain = False
    wrote_time_sync = False
    wrote_fdd1_fn = False
    wrote_fdd1_writeprot = False
    wrote_fdd2_check = False
    wrote_fdd2_fn = False
    wrote_fdd2_type = False
    wrote_fdd2_writeprot = False
    wrote_video_filter = False
    floppy_size = floppy.stat().st_size
    if floppy_size == 1474560:
        direct_fdd_type = "35_2hd"
    elif floppy_size > 184320:
        direct_fdd_type = "525_2hd"
    else:
        direct_fdd_type = "525_1dd"

    def flush_general_tail():
        # All VM profiles render with nearest-neighbour scaling (crisp CGA pixels). Forced here so it
        # survives the rewrite + a fresh checkout regardless of what the committed cfg holds.
        if not wrote_video_filter:
            out.append("video_filter_method = 0")
        if not muted:
            return
        if not wrote_sound_muted:
            out.append("sound_muted = 1")
        if not wrote_sound_gain:
            out.append("sound_gain = 0")

    def flush_machine_tail():
        if attest_rtc_utc and not wrote_time_sync:
            out.append("time_sync = utc")

    def flush_floppy_tail():
        # Called when leaving the floppy section. Append any keys we still
        # need that weren't already written from the source iteration.
        if (not rom_basic or rom_basic_a) and not wrote_fdd1_fn:
            out.append(f"fdd_01_fn = {floppy}")
        if (
            floppy_read_only
            and (not rom_basic or rom_basic_a)
            and not wrote_fdd1_writeprot
        ):
            out.append("fdd_01_writeprot = 1")
        if rom_basic_b and not wrote_fdd2_check:
            out.append("fdd_02_check_bpb = 0")
        if rom_basic_b and not wrote_fdd2_fn:
            out.append(f"fdd_02_fn = {floppy}")
        if floppy_read_only and rom_basic_b and not wrote_fdd2_writeprot:
            out.append("fdd_02_writeprot = 1")
        if not wrote_fdd2_type:
            out.append("fdd_02_type = 525_1dd" if rom_basic_b else "fdd_02_type = none")

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_general_section:
                flush_general_tail()
            if in_machine_section:
                flush_machine_tail()
            if in_floppy_section:
                flush_floppy_tail()
            in_general_section = stripped == "[General]"
            in_machine_section = stripped == "[Machine]"
            in_floppy_section = stripped == "[Floppy and CD-ROM drives]"
            saw_machine_section = saw_machine_section or in_machine_section
            wrote_sound_muted = False
            wrote_sound_gain = False
            wrote_time_sync = False
            wrote_fdd1_fn = False
            wrote_fdd1_writeprot = False
            wrote_fdd2_check = False
            wrote_fdd2_fn = False
            wrote_fdd2_type = False
            wrote_fdd2_writeprot = False
            wrote_video_filter = False
            out.append(line)
            continue

        if in_machine_section and attest_rtc_utc and stripped.startswith("time_sync ="):
            if not wrote_time_sync:
                out.append("time_sync = utc")
            wrote_time_sync = True
            continue

        if in_general_section and muted:
            if stripped.startswith("sound_muted ="):
                out.append("sound_muted = 1")
                wrote_sound_muted = True
                continue
            if stripped.startswith("sound_gain ="):
                out.append("sound_gain = 0")
                wrote_sound_gain = True
                continue

        if in_general_section and stripped.startswith("video_filter_method ="):
            out.append("video_filter_method = 0")
            wrote_video_filter = True
            continue

        if ram_kib is not None and stripped.startswith("mem_size ="):
            out.append(f"mem_size = {ram_kib}")
            continue

        if in_floppy_section:
            if stripped.startswith("fdd_01_check_bpb ="):
                out.append("fdd_01_check_bpb = 0" if rom_basic_a else line)
                continue
            if stripped.startswith("fdd_01_fn ="):
                if not rom_basic or rom_basic_a:
                    out.append(f"fdd_01_fn = {floppy}")
                    wrote_fdd1_fn = True
                continue
            if (
                floppy_read_only
                and (not rom_basic or rom_basic_a)
                and stripped.startswith("fdd_01_writeprot =")
            ):
                if not wrote_fdd1_writeprot:
                    out.append("fdd_01_writeprot = 1")
                wrote_fdd1_writeprot = True
                continue
            if stripped.startswith("fdd_01_type ="):
                # A physical/BIOS B: drive exists only behind an A: drive.
                # Keep A: configured but empty so the BIOS falls through to
                # ROM BASIC while still reporting the Seed floppy as B:.
                out.append(
                    "fdd_01_type = 525_1dd"
                    if rom_basic_b
                    else f"fdd_01_type = {direct_fdd_type}"
                )
                continue
            if stripped.startswith("fdd_02_check_bpb ="):
                if not rom_basic_b:
                    continue
                out.append("fdd_02_check_bpb = 0")
                wrote_fdd2_check = True
                continue
            if stripped.startswith("fdd_02_fn ="):
                if not rom_basic_b:
                    continue
                out.append(f"fdd_02_fn = {floppy}")
                wrote_fdd2_fn = True
                continue
            if (
                floppy_read_only
                and rom_basic_b
                and stripped.startswith("fdd_02_writeprot =")
            ):
                if not wrote_fdd2_writeprot:
                    out.append("fdd_02_writeprot = 1")
                wrote_fdd2_writeprot = True
                continue
            if stripped.startswith("fdd_02_type ="):
                if not rom_basic_b:
                    out.append("fdd_02_type = none")
                    wrote_fdd2_type = True
                    continue
                out.append("fdd_02_type = 525_1dd")
                wrote_fdd2_type = True
                continue

        out.append(line)

    if in_floppy_section:
        flush_floppy_tail()
    if in_machine_section:
        flush_machine_tail()
    if in_general_section:
        flush_general_tail()

    if attest_rtc_utc and not saw_machine_section:
        raise ValueError("platform UTC RTC mode requires a [Machine] config section")

    if com_pipe_base is not None:
        out = ensure_com_pipe(out, com_pipe_base)
    elif com_passthrough:
        raise ValueError("COM capture requires a fixed FIFO base path")

    config.write_text("\n".join(out) + "\n", encoding="utf-8")


def vm_config_section(config: Path, section: str) -> dict[str, str]:
    in_section = False
    settings: dict[str, str] = {}
    for line in config.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped == section
            continue
        if in_section and "=" in stripped:
            key, value = stripped.split("=", 1)
            settings[key.strip()] = value.strip()
    return settings


def vm_machine_name(config: Path) -> str | None:
    return vm_config_section(config, "[Machine]").get("machine")


def require_exact_rtc_utc_machine(
    config: Path,
    *,
    expected_ram_kib: int | None,
    phase: str,
) -> dict[str, str]:
    settings = vm_config_section(config, "[Machine]")
    expected = dict(RTC_UTC_ATTEST_MACHINE_SETTINGS)
    if expected_ram_kib is not None:
        expected["mem_size"] = str(expected_ram_kib)
        expected["time_sync"] = "utc"
    mismatches = [
        f"{key}={settings.get(key)!r}, expected {value!r}"
        for key, value in expected.items()
        if settings.get(key) != value
    ]
    if mismatches:
        raise SystemExit(
            "platform UTC RTC mode requires the exact 6 MHz 286 floor "
            f"({phase}: " + "; ".join(mismatches) + ")"
        )
    return settings


def require_attested_floppy_config(config: Path, *, rom_basic: bool) -> None:
    settings = vm_config_section(config, "[Floppy and CD-ROM drives]")
    drive = "fdd_02" if rom_basic else "fdd_01"
    if settings.get(f"{drive}_writeprot") != "1":
        raise SystemExit(
            "the exact 286 gate requires 86Box guest floppy write protection "
            f"({drive}_writeprot = 1)"
        )


def validate_rtc_utc_attestation(
    *,
    enabled: bool,
    entry: str,
    ram_kib: int | None,
    machine_settings: dict[str, str],
    screen_ocr_disabled: bool,
    prompt_timeout: float,
    answer_timeout: float,
    interval: float,
    leave_running: bool,
    long_running: bool,
) -> None:
    if not enabled:
        return
    if entry != "direct":
        raise SystemExit("--platform-rtc-utc requires --entry direct")
    if ram_kib != RTC_UTC_ATTEST_RAM_KIB:
        raise SystemExit(
            "--platform-rtc-utc requires --ram-kib "
            f"{RTC_UTC_ATTEST_RAM_KIB}"
        )
    mismatches = [
        f"{key}={machine_settings.get(key)!r}, expected {value!r}"
        for key, value in RTC_UTC_ATTEST_MACHINE_SETTINGS.items()
        if machine_settings.get(key) != value
    ]
    if mismatches:
        raise SystemExit(
            "--platform-rtc-utc requires ami286 with a 286 at exactly 6 MHz, "
            "multiplier 1, and dynarec disabled ("
            + "; ".join(mismatches)
            + ")"
        )
    # These arguments remain in the compatibility signature for callers that
    # used the former interactive attestation harness.  Platform-clock mode is
    # now silent and therefore imposes no OCR, timeout, or run-duration rule.
    del (
        screen_ocr_disabled,
        prompt_timeout,
        answer_timeout,
        interval,
        leave_running,
        long_running,
    )


def at_cmos(mem_kib: int, machine: str) -> bytes | None:
    if machine not in {"ami286", "adi386sx", "win486pci"}:
        return None
    c = bytearray(256 if machine == "win486pci" else 128)
    c[0x0A] = 0x26
    c[0x0B] = 0x02
    c[0x0D] = 0x80
    c[0x04] = 0x12
    c[0x07] = 0x01
    c[0x08] = 0x06
    c[0x09] = 0x26
    c[0x10] = 0x20
    c[0x14] = 0x21
    if machine == "ami286":
        base_kib = 512 if mem_kib < 1024 else 640
    else:
        base_kib = 640 if mem_kib >= 1024 else mem_kib
    ext_kib = max(0, mem_kib - 1024)
    c[0x15] = base_kib & 0xFF
    c[0x16] = (base_kib >> 8) & 0xFF
    c[0x17] = ext_kib & 0xFF
    c[0x18] = (ext_kib >> 8) & 0xFF
    c[0x30] = ext_kib & 0xFF
    c[0x31] = (ext_kib >> 8) & 0xFF
    chk = sum(c[0x10:0x2E]) & 0xFFFF
    c[0x2E] = (chk >> 8) & 0xFF
    c[0x2F] = chk & 0xFF
    return bytes(c)


def at_min_ram_kib(machine: str) -> int | None:
    if machine == "ami286":
        return 512
    if machine in {"adi386sx", "cs4031", "ibmps2_m55sx", "win486pci"}:
        return 640
    return None


def validate_vm_ram_override(vm_path: Path, ram_kib: int | None) -> None:
    if ram_kib is None:
        return
    machine = vm_machine_name(vm_path / "86box.cfg")
    if machine is None:
        return
    min_ram_kib = at_min_ram_kib(machine)
    if min_ram_kib is not None and ram_kib < min_ram_kib:
        raise SystemExit(
            f"{machine} profile requires at least {min_ram_kib} KiB RAM; "
            f"use an XT profile for {ram_kib} KiB tests"
        )


def snapshot_vm_nvr(
    vm_path: Path,
    ram_kib: int | None,
) -> tuple[Path, bytes] | None:
    machine = vm_machine_name(vm_path / "86box.cfg")
    if machine is None:
        return None
    min_ram_kib = at_min_ram_kib(machine)
    if min_ram_kib is None:
        return None
    if ram_kib is not None and min_ram_kib is not None and ram_kib < min_ram_kib:
        raise SystemExit(
            f"{machine} profile requires at least {min_ram_kib} KiB RAM; "
            f"use an XT profile for {ram_kib} KiB tests"
        )
    nvr = vm_path / "nvr" / f"{machine}.nvr"
    if not nvr.exists():
        return None
    return nvr, nvr.read_bytes()


def apply_vm_nvr_override(
    restore: tuple[Path, bytes] | None,
    ram_kib: int | None,
) -> None:
    if restore is None or ram_kib is None:
        return
    nvr, _original = restore
    cmos = at_cmos(ram_kib, nvr.stem)
    if cmos is not None:
        nvr.write_bytes(cmos)


def prepare_vm_nvr(vm_path: Path, ram_kib: int | None) -> tuple[Path, bytes] | None:
    restore = snapshot_vm_nvr(vm_path, ram_kib)
    try:
        apply_vm_nvr_override(restore, ram_kib)
    except BaseException:
        if restore is not None:
            restore[0].write_bytes(restore[1])
        raise
    return restore


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_floppy_media(floppy: Path) -> tuple[Path, int, str]:
    return (
        floppy,
        stat.S_IMODE(floppy.stat().st_mode),
        sha256_file(floppy),
    )


def make_floppy_read_only(
    media: tuple[Path, int, str],
) -> None:
    floppy, _original_mode, _sha256_before = media
    floppy.chmod(0o444)
    try:
        descriptor = os.open(floppy, os.O_WRONLY)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS}:
            return
        raise
    os.close(descriptor)
    raise RuntimeError(
        "read-only floppy still permits a host write open"
    )


def restore_harness_state(
    *,
    com_capture: ComCapture | None,
    pcap_capture: PcapCapture | None,
    restore_config: tuple[Path, bytes] | None,
    restore_nvr: tuple[Path, bytes] | None,
    floppy_media: tuple[Path, int, str] | None,
    test_lock: TestLock | None,
) -> None:
    errors: list[str] = []
    missing = object()

    def attempt(label: str, operation):
        try:
            return operation()
        except BaseException as exc:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            return missing

    if com_capture is not None:
        attempt("finish COM capture", com_capture.finish)
    if pcap_capture is not None:
        attempt("stop pcap capture", pcap_capture.stop)
    if restore_config is not None:
        attempt(
            "restore 86Box config",
            lambda: restore_config[0].write_bytes(restore_config[1]),
        )
    if restore_nvr is not None:
        attempt(
            "restore 86Box NVR",
            lambda: restore_nvr[0].write_bytes(restore_nvr[1]),
        )

    floppy_hash_after = missing
    if floppy_media is not None:
        floppy, original_mode, sha256_before = floppy_media
        floppy_hash_after = attempt(
            "hash floppy after run",
            lambda: sha256_file(floppy),
        )
        attempt(
            "restore floppy mode",
            lambda: floppy.chmod(original_mode),
        )
        if (
            floppy_hash_after is not missing
            and floppy_hash_after != sha256_before
        ):
            errors.append(
                "verify floppy contents: SHA-256 changed during the run"
            )

    if restore_config is not None:
        config_after = attempt(
            "verify 86Box config",
            restore_config[0].read_bytes,
        )
        if config_after is not missing and config_after != restore_config[1]:
            errors.append("verify 86Box config: byte-for-byte mismatch")
    if restore_nvr is not None:
        nvr_after = attempt(
            "verify 86Box NVR",
            restore_nvr[0].read_bytes,
        )
        if nvr_after is not missing and nvr_after != restore_nvr[1]:
            errors.append("verify 86Box NVR: byte-for-byte mismatch")
    if floppy_media is not None:
        floppy, original_mode, _sha256_before = floppy_media
        floppy_mode_after = attempt(
            "verify floppy mode",
            lambda: stat.S_IMODE(floppy.stat().st_mode),
        )
        if (
            floppy_mode_after is not missing
            and floppy_mode_after != original_mode
        ):
            errors.append(
                "verify floppy mode: "
                f"0o{floppy_mode_after:o} != 0o{original_mode:o}"
            )

    if test_lock is not None:
        attempt("release VM lock", test_lock.release)
    if errors:
        raise RuntimeError(
            "86Box harness cleanup failed:\n  - "
            + "\n  - ".join(errors)
        )


def boot_debug_marker(char: str) -> list[int]:
    return [
        0x50,  # push ax
        0x06,  # push es
        0xB8, 0x00, 0xB8,  # mov ax, 0xb800
        0x8E, 0xC0,  # mov es, ax
        0x26, 0xC7, 0x06, 0x00, 0x00, ord(char), 0x07,  # mov word [es:0], char/attr
        0x07,  # pop es
        0x58,  # pop ax
    ]


def boot_halt_loop() -> list[int]:
    return [0xF4, 0xEB, 0xFD]


def patch_loader_debug_stop(loader_bytes: bytes, debug_stop: str) -> bytes:
    if debug_stop == "none":
        return loader_bytes

    patched = bytearray(loader_bytes)
    marker = bytes(boot_debug_marker("L" if debug_stop == "entry" else "R") + boot_halt_loop())
    if debug_stop == "entry":
        patched[: len(marker)] = marker
        return bytes(patched)

    after_read = b""
    idx = -1
    for boot_drive in (0, 1):
        candidate = bytes(
            [
                0xB8, 0x00, 0x60,  # mov ax, 0x6000
                0xBB, 0x45, 0x53,  # mov bx, 0x5345
                0xB9, 0x44, 0x45,  # mov cx, 0x4544
                0xB2, boot_drive,  # mov dl, boot_drive
                0xEA, 0x00, 0x10, 0x00, 0x00,  # jmp 0000:1000
            ]
        )
        idx = patched.find(candidate)
        if idx >= 0:
            after_read = candidate
            break
    if idx < 0:
        raise SystemExit("could not find BASIC loader handoff sequence")
    patched[idx : idx + len(marker)] = marker
    patched[idx + len(marker) : idx + len(after_read)] = b"\x90" * (len(after_read) - len(marker))
    return bytes(patched)


def hex_pairs(data: bytes) -> str:
    return data.hex().upper()


def basic_text_from_loader(loader_bytes: bytes) -> str:
    chunks = [
        loader_bytes[offset : offset + BASIC_HEX_CHUNK_SIZE]
        for offset in range(0, len(loader_bytes), BASIC_HEX_CHUNK_SIZE)
    ]
    lines = [
        f"10 CLEAR ,{BASIC_BOOTSTRAP_CLEAR_TOP}",
        "20 DEF SEG=0",
        f"30 P={BASIC_BOOTSTRAP_ADDR}",
        f"40 FOR K=0 TO {len(chunks) - 1}",
        "50 READ A$,N",
        "60 FOR I=0 TO N-1",
        "70 J=I*2+1",
        '80 POKE P+I,VAL("&H"+MID$(A$,J,2))',
        "90 NEXT I",
        "100 P=P+N",
        "110 NEXT K",
        f"120 DEF USR0={BASIC_BOOTSTRAP_ADDR}",
        "130 A=USR0(0)",
    ]
    line_no = 200
    for chunk in chunks:
        lines.append(f"{line_no} DATA {hex_pairs(chunk)},{len(chunk)}")
        line_no += 10
    return "\n".join(lines) + "\n"


def make_loader_boot_floppy(
    source_floppy: Path,
    loader: Path,
    output: Path,
    boot_debug_stop: str,
    loader_debug_stop: str,
) -> None:
    image = bytearray(source_floppy.read_bytes())
    loader_bytes = patch_loader_debug_stop(loader.read_bytes(), loader_debug_stop)
    if len(loader_bytes) > 480:
        raise SystemExit(f"loader is too large for temporary boot sector: {loader}")

    code_offset = 0x3E
    payload_offset = 0x80
    payload_addr = 0x7C00 + payload_offset
    if payload_offset + len(loader_bytes) > 510:
        raise SystemExit("temporary boot sector overflow")

    code = [
        0xFA,  # cli
        0x31, 0xC0,  # xor ax, ax
        0x8E, 0xD8,  # mov ds, ax
        0x8E, 0xC0,  # mov es, ax
        0x8E, 0xD0,  # mov ss, ax
        0xBC, 0x00, 0x7C,  # mov sp, 0x7c00
        0xFB,  # sti
        0xFC,  # cld
    ]
    if boot_debug_stop != "none":
        code.extend(boot_debug_marker("B"))
    if boot_debug_stop == "before-copy":
        code.extend(boot_halt_loop())
    code.extend(
        [
            0xBE, payload_addr & 0xFF, payload_addr >> 8,  # mov si, payload
            0xBF, 0x00, 0x3A,  # mov di, 0x3a00
            0xB9, len(loader_bytes) & 0xFF, len(loader_bytes) >> 8,  # mov cx, len
            0xF3, 0xA4,  # rep movsb
        ]
    )
    if boot_debug_stop != "none":
        code.extend(boot_debug_marker("J"))
    if boot_debug_stop == "before-jump":
        code.extend(boot_halt_loop())
    code.extend([0xEA, 0x00, 0x3A, 0x00, 0x00])  # jmp 0000:3a00
    if code_offset + len(code) > payload_offset:
        raise SystemExit("temporary boot sector code overflow")

    boot = bytearray(image[:512])
    boot[0:3] = b"\xeb\x3c\x90"
    boot[code_offset:510] = b"\0" * (510 - code_offset)
    boot[code_offset : code_offset + len(code)] = bytes(code)
    boot[payload_offset : payload_offset + len(loader_bytes)] = loader_bytes
    boot[510:512] = b"\x55\xaa"

    image[:512] = boot
    output.write_bytes(image)


class ExternalProcess:
    """Minimal process handle for apps launched through macOS LaunchServices."""

    def __init__(self, pid: int, vm_path: Path | None = None):
        self.pid = pid
        self.vm_path = vm_path
        self.stdout = None

    def poll(self) -> int | None:
        if self.vm_path is not None:
            current = matching_86box_pids(self.vm_path)
            if current:
                # LaunchServices/86Box may replace its initial process after
                # opening the VM.  Follow the live VM-path owner so a harmless
                # PID handoff cannot be mistaken for guest completion.
                if self.pid not in current:
                    self.pid = max(current)
                return None
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return 0
        except PermissionError:
            return None
        return None

    def kill(self) -> None:
        if self.vm_path is not None:
            stop_matching_86box_pids(self.vm_path)
            return
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(["86Box"], timeout)
            time.sleep(0.1)
        return 0


def matching_86box_pids(vm_path: Path) -> set[int]:
    def parse_process_lines(lines: list[str]) -> set[int]:
        pids: set[int] = set()
        vm_path_text = str(vm_path)
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            pid_text, _, command = stripped.partition(" ")
            if not pid_text.isdigit():
                continue
            if "86Box" not in command or "--vmpath" not in command:
                continue
            if vm_path_text not in command:
                continue
            pids.add(int(pid_text))
        return pids

    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        result = None
    if result is not None and result.returncode == 0:
        return parse_process_lines(result.stdout.splitlines())

    try:
        pgrep = subprocess.run(
            ["pgrep", "-fl", "86Box"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if pgrep.returncode not in (0, 1):
        return set()
    return parse_process_lines(pgrep.stdout.splitlines())


def stop_matching_86box_pids(vm_path: Path, timeout: float = 5.0) -> None:
    pids = sorted(matching_86box_pids(vm_path))
    if not pids:
        return
    print(
        "harness: closing existing 86Box for this VM path: "
        + ", ".join(str(pid) for pid in pids),
        flush=True,
    )
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not matching_86box_pids(vm_path):
            return
        time.sleep(0.1)
    for pid in sorted(matching_86box_pids(vm_path)):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    kill_deadline = time.monotonic() + timeout
    while time.monotonic() < kill_deadline:
        if not matching_86box_pids(vm_path):
            return
        time.sleep(0.1)
    remaining = sorted(matching_86box_pids(vm_path))
    if remaining:
        raise RuntimeError(
            "86Box processes did not stop for VM path "
            f"{vm_path}: {', '.join(str(pid) for pid in remaining)}"
        )


def launch_86box(
    vm_path: Path,
    image_args: list[str] | None = None,
    capture_stdout: bool = False,
    background: bool = True,
    detached: bool = False,
) -> subprocess.Popen[str] | ExternalProcess:
    env = os.environ.copy()
    env["SEED_NO_IMAGE"] = "1"
    if background and not capture_stdout:
        before = matching_86box_pids(vm_path)
        cmd = [
            "open",
            "-g",
            "-n",
            "-a",
            "86Box",
            "--env",
            "SEED_NO_IMAGE=1",
            "--args",
            "--vmpath",
            str(vm_path),
        ]
        if image_args:
            for image in image_args:
                cmd.extend(["--image", image])
        try:
            subprocess.run(cmd, cwd=ROOT, check=True, text=True)
        except subprocess.CalledProcessError as exc:
            print(f"open(1) launch failed ({exc.returncode}); falling back to direct 86Box launch")
        else:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                current = matching_86box_pids(vm_path)
                created = sorted(current - before)
                if created:
                    return ExternalProcess(created[-1], vm_path)
                time.sleep(0.1)
            current = sorted(matching_86box_pids(vm_path))
            if current:
                return ExternalProcess(current[-1], vm_path)
            print("open(1) launch produced no matching 86Box process; falling back to direct 86Box launch")

    cmd = [emulator_path(), "--vmpath", str(vm_path)]
    if image_args:
        for image in image_args:
            cmd.extend(["--image", image])
    kwargs: dict = {"cwd": ROOT, "env": env, "text": True}
    if capture_stdout:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.STDOUT
        kwargs["bufsize"] = 1
    elif detached:
        kwargs["stdin"] = subprocess.DEVNULL
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
        kwargs["start_new_session"] = True
    return subprocess.Popen(cmd, **kwargs)


def accept_moved_or_copied_dialog(pid: int | None = None) -> bool:
    """Accept only the named identity button, on the requested VM if supplied."""
    script = """
on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    if targetPid is 0 then
      if not (exists application process "86Box") then return "none"
      set targetPid to unix id of first application process whose name is "86Box"
    end if
    if not (exists first application process whose unix id is targetPid) then return "none"
    repeat with windowIndex from 1 to (count of windows of (first application process whose unix id is targetPid))
      try
        if exists button "I Copied It" of window windowIndex of (first application process whose unix id is targetPid) then
          click button "I Copied It" of window windowIndex of (first application process whose unix id is targetPid)
          return "accepted"
        end if
      end try
      try
        if exists button "I Copied It" of group 1 of window windowIndex of (first application process whose unix id is targetPid) then
          click button "I Copied It" of group 1 of window windowIndex of (first application process whose unix id is targetPid)
          return "accepted"
        end if
      end try
    end repeat
  end tell
  return "none"
end run
"""
    result = subprocess.run(
        ["osascript", "-e", script, str(pid or 0)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "accepted"


def wait_for_86box_window_or_identity_dialog(
    profile: str | None,
    pid: int | None,
    timeout: float = 15.0,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if accept_moved_or_copied_dialog(pid):
            print("harness: accepted 86Box moved/copied identity dialog", flush=True)
        window_id = find_86box_window_id(profile, pid)
        # A copied-VM identity dialog is itself a visible window. The native
        # main window may also appear just before that dialog, so a window ID
        # alone can let direct-boot runs wait forever without starting the VM.
        # The Action menu belongs to the running VM UI, not the identity UI.
        if window_id is not None and (pid is None or has_86box_main_menu(pid)):
            return True
        time.sleep(0.2)
    return False


def has_86box_main_menu(pid: int) -> bool:
    script = """
on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    return exists menu bar item "Action" of menu bar 1 of (first application process whose unix id is targetPid)
  end tell
end run
"""
    result = subprocess.run(
        ["osascript", "-e", script, str(pid)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def screenshot(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    run(["screencapture", "-x", str(path)])


def find_86box_window_id(
    profile: str | None = None,
    pid: int | None = None,
) -> int | None:
    """Return a visible 86Box CGWindow id without activating it."""
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
        cf.CFStringGetCString.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_long,
            ctypes.c_uint32,
        ]
        cf.CFStringGetCString.restype = ctypes.c_bool
        cf.CFNumberGetValue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        cf.CFNumberGetValue.restype = ctypes.c_bool
        cf.CFRelease.argtypes = [ctypes.c_void_p]

        def cg_symbol(name: str) -> ctypes.c_void_p:
            return ctypes.c_void_p(ctypes.c_void_p.in_dll(cg, name).value)

        key_owner = cg_symbol("kCGWindowOwnerName")
        key_owner_pid = cg_symbol("kCGWindowOwnerPID")
        key_title = cg_symbol("kCGWindowName")
        key_number = cg_symbol("kCGWindowNumber")
        key_layer = cg_symbol("kCGWindowLayer")

        def cf_string(ptr: int | None) -> str:
            if not ptr:
                return ""
            buf = ctypes.create_string_buffer(1024)
            ok = cf.CFStringGetCString(ptr, buf, len(buf), 0x08000100)
            return buf.value.decode("utf-8", errors="replace") if ok else ""

        def cf_number(ptr: int | None) -> int:
            if not ptr:
                return 0
            value = ctypes.c_longlong()
            # kCFNumberLongLongType is stable enough for CGWindow ids/layers.
            cf.CFNumberGetValue(ptr, 4, ctypes.byref(value))
            return int(value.value)

        # kCGWindowListOptionAll == 0.  Window-id capture works without raising
        # the VM, including when macOS has placed 86Box on another Space; the
        # on-screen-only list silently drops that otherwise valid window.
        window_list = cg.CGWindowListCopyWindowInfo(0, 0)
        if not window_list:
            return None
        try:
            fallback: int | None = None
            count = cf.CFArrayGetCount(window_list)
            for idx in range(count):
                item = cf.CFArrayGetValueAtIndex(window_list, idx)
                owner = cf_string(cf.CFDictionaryGetValue(item, key_owner))
                if owner != "86Box":
                    continue
                owner_pid = cf_number(cf.CFDictionaryGetValue(item, key_owner_pid))
                if pid is not None and owner_pid != pid:
                    continue
                layer = cf_number(cf.CFDictionaryGetValue(item, key_layer))
                if layer != 0:
                    continue
                title = cf_string(cf.CFDictionaryGetValue(item, key_title))
                if title == "86Box VM Manager":
                    continue
                window_id = cf_number(cf.CFDictionaryGetValue(item, key_number))
                if window_id == 0:
                    continue
                if fallback is None:
                    fallback = window_id
                if profile and profile in title:
                    return window_id
            return fallback
        finally:
            cf.CFRelease(window_list)
    except (OSError, ValueError, AttributeError):
        return None


def screenshot_86box_window(
    path: Path,
    profile: str | None = None,
    pid: int | None = None,
) -> bool:
    """Capture the requested VM only, without activating or raising it."""
    window_id = find_86box_window_id(profile, pid)
    if window_id is None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["screencapture", "-x", "-o", f"-l{window_id}", str(path)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and path.exists() and path.stat().st_size > 0


def vm_path_for_pid(pid: int | None) -> Path | None:
    """Recover the absolute 86Box VM path from the launched process."""
    if pid is None:
        return None
    try:
        result = subprocess.run(
            ["ps", "-ww", "-o", "args=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        argv = shlex.split(result.stdout.strip())
    except ValueError:
        return None
    for option in ("--vmpath", "-P"):
        try:
            index = argv.index(option)
        except ValueError:
            continue
        if index + 1 < len(argv):
            return Path(argv[index + 1]).resolve()
    return None


def screenshot_86box_native(path: Path, pid: int | None) -> bool:
    """Ask 86Box itself for a rendered guest screenshot.

    This avoids macOS screen-recording permission and captures only the VM's
    display.  86Box writes a unique PNG below the VM profile; move that exact
    new file to the caller's evidence path so source profiles do not collect
    screenshot debris.
    """
    vm_path = vm_path_for_pid(pid)
    if vm_path is None or pid is None:
        return False
    screenshot_dir = vm_path / "screenshots"
    before = set(screenshot_dir.glob("Monitor_1_*.png"))
    started_ns = time.time_ns()
    script = """
on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    click menu item "Take screenshot" of menu 1 of menu bar item "Tools" of menu bar 1 of (first application process whose unix id is targetPid)
  end tell
end run
"""
    result = subprocess.run(
        ["osascript", "-e", script, str(pid)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        candidates = []
        for candidate in screenshot_dir.glob("Monitor_1_*.png"):
            try:
                stat_result = candidate.stat()
            except OSError:
                continue
            if (
                candidate not in before
                and stat_result.st_size > 0
                and stat_result.st_mtime_ns >= started_ns
            ):
                candidates.append((stat_result.st_mtime_ns, candidate))
        if candidates:
            source = max(candidates)[1]
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(source, path)
            except OSError:
                return False
            return path.exists() and path.stat().st_size > 0
        time.sleep(0.1)
    return False


def wait_for_86box_window(
    profile: str | None,
    pid: int | None,
    timeout: float = 15.0,
) -> bool:
    return wait_for_86box_window_or_identity_dialog(profile, pid, timeout)


def screenshot_86box_window_or_screen(
    path: Path,
    profile: str | None = None,
    pid: int | None = None,
) -> bool:
    if screenshot_86box_native(path, pid):
        return True
    return screenshot_86box_window(path, profile, pid)


def read_png_rgb(path: Path) -> tuple[int, int, int, list[list[int]]]:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    offset = 8
    width = height = bit_depth = color_type = None
    idat = bytearray()
    while offset < len(data):
        chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk = data[offset + 8 : offset + 8 + chunk_len]
        offset += 12 + chunk_len
        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(
                ">IIBBBBB", chunk
            )
            if interlace != 0:
                raise ValueError("interlaced PNG is unsupported")
        elif chunk_type == b"IDAT":
            idat.extend(chunk)
        elif chunk_type == b"IEND":
            break
    if width is None or height is None or bit_depth != 8 or color_type not in (2, 6):
        raise ValueError("unsupported PNG format")

    channels = 4 if color_type == 6 else 3
    stride = width * channels
    raw = zlib.decompress(bytes(idat))
    rows: list[list[int]] = []
    previous = [0] * stride
    pos = 0
    for _ in range(height):
        filter_type = raw[pos]
        pos += 1
        current = list(raw[pos : pos + stride])
        pos += stride
        for i in range(stride):
            left = current[i - channels] if i >= channels else 0
            up = previous[i]
            upper_left = previous[i - channels] if i >= channels else 0
            if filter_type == 1:
                current[i] = (current[i] + left) & 0xFF
            elif filter_type == 2:
                current[i] = (current[i] + up) & 0xFF
            elif filter_type == 3:
                current[i] = (current[i] + ((left + up) // 2)) & 0xFF
            elif filter_type == 4:
                estimate = left + up - upper_left
                pa = abs(estimate - left)
                pb = abs(estimate - up)
                pc = abs(estimate - upper_left)
                predictor = left if pa <= pb and pa <= pc else up if pb <= pc else upper_left
                current[i] = (current[i] + predictor) & 0xFF
            elif filter_type != 0:
                raise ValueError(f"unsupported PNG filter {filter_type}")
        rows.append(current)
        previous = current
    return width, height, channels, rows


def classify_86box_screen(path: Path) -> tuple[str, str]:
    """Classify Seed's visible VM state from a local 86Box window capture.

    This intentionally uses coarse color/position signals rather than OCR:
    - a centered splash/prompt state is success;
    - red text in the main display is a possible Seed error state;
    - gray text on an otherwise dark display is the known freeze class;
    - anything else is ambiguous and should keep the screenshot for inspection.

    Callers must corroborate ``clean-failure`` with the retry/restart menu.
    The normal 8088 TLS 1.3 splash uses a neutral gray ``security note``;
    red text is reserved for a possible failure state.
    """
    width, height, channels, rows = read_png_rgb(path)
    if width < 320 or height < 240:
        return "ambiguous", "capture too small"

    display_x0, display_y0, display_x1, display_y1 = image_display_bounds(
        width,
        height,
        channels,
        rows,
    )
    display_w = max(1, display_x1 - display_x0 + 1)
    display_h = max(1, display_y1 - display_y0 + 1)
    x0 = display_x0 + display_w // 20
    x1 = display_x1 + 1 - display_w // 20
    y0 = display_y0 + display_h // 20
    y1 = display_y1 + 1 - display_h // 30
    lower_y0 = y0 + ((y1 - y0) * 68) // 100
    lower_y1 = y0 + ((y1 - y0) * 93) // 100

    center_red_pixels = 0
    lower_bright_pixels = 0
    lower_text_pixels = 0
    center_dim_pixels = 0
    non_dark_pixels = 0
    sampled_pixels = 0
    active_glyph_rows = 0
    dense_glyph_rows = 0
    glyph_column_pixels = [0] * max(1, x1 - x0)
    splash_pixels = 0
    splash_min_x = width
    splash_max_x = 0
    splash_min_y = height
    splash_max_y = 0

    center_x0 = display_x0 + display_w * 35 // 100
    center_x1 = display_x0 + display_w * 65 // 100
    center_y0 = y0 + ((y1 - y0) * 35) // 100
    center_y1 = y0 + ((y1 - y0) * 65) // 100
    splash_x0 = display_x0 + display_w * 30 // 100
    splash_x1 = display_x0 + display_w * 75 // 100
    splash_y0 = y0 + ((y1 - y0) * 34) // 100
    splash_y1 = y0 + ((y1 - y0) * 64) // 100
    error_x0 = display_x0 + display_w * 28 // 100
    error_x1 = display_x0 + display_w * 78 // 100
    error_y0 = y0 + ((y1 - y0) * 38) // 100
    error_y1 = y0 + ((y1 - y0) * 76) // 100

    for y in range(y0, y1):
        row = rows[y]
        row_non_dark = 0
        for x in range(x0, x1):
            off = x * channels
            r, g, b = row[off], row[off + 1], row[off + 2]
            sampled_pixels += 1
            if (
                error_x0 <= x <= error_x1
                and error_y0 <= y <= error_y1
                and r > 145
                and g < 100
                and b < 100
            ):
                center_red_pixels += 1
            if r > 165 and g > 165 and b > 165:
                non_dark_pixels += 1
                row_non_dark += 1
                glyph_column_pixels[x - x0] += 1
                if lower_y0 <= y <= lower_y1:
                    lower_bright_pixels += 1
            elif r > 45 or g > 45 or b > 45:
                non_dark_pixels += 1
                row_non_dark += 1
                glyph_column_pixels[x - x0] += 1
                if lower_y0 <= y <= lower_y1:
                    lower_text_pixels += 1
            if (
                splash_x0 <= x <= splash_x1
                and splash_y0 <= y <= splash_y1
                and 35 <= r <= 245
                and 35 <= g <= 245
                and 35 <= b <= 245
                and abs(r - g) < 36
                and abs(g - b) < 36
            ):
                splash_pixels += 1
                splash_min_x = min(splash_min_x, x)
                splash_max_x = max(splash_max_x, x)
                splash_min_y = min(splash_min_y, y)
                splash_max_y = max(splash_max_y, y)
            if center_x0 <= x <= center_x1 and center_y0 <= y <= center_y1:
                if 35 <= r <= 150 and 35 <= g <= 150 and 35 <= b <= 150:
                    center_dim_pixels += 1

        if row_non_dark >= max(8, (x1 - x0) // 100):
            active_glyph_rows += 1
        if row_non_dark >= max(24, (x1 - x0) // 8):
            dense_glyph_rows += 1

    sampled_height = max(1, y1 - y0)
    sampled_width = max(1, x1 - x0)
    active_glyph_columns = sum(
        count >= max(8, sampled_height // 100)
        for count in glyph_column_pixels
    )

    # A screen whose glyphs span nearly every row and column is not a normal
    # Seed splash/prompt oracle. Corrupted memory rendered as character/
    # attribute pairs can otherwise look like a very large gray splash and be
    # misclassified as success. Keep legitimately dense conversation screens
    # conservative too: they require inspection instead of being accepted
    # from this coarse shape oracle.
    if (
        active_glyph_rows * 4 >= sampled_height * 3
        and active_glyph_columns * 10 >= sampled_width * 9
        and dense_glyph_rows * 5 >= sampled_height * 2
    ):
        return (
            "dense-glyph-screen",
            f"active_rows={active_glyph_rows}/{sampled_height} "
            f"dense_rows={dense_glyph_rows}/{sampled_height} "
            f"active_columns={active_glyph_columns}/{sampled_width}",
        )

    if center_red_pixels >= 70:
        return "clean-failure", f"center_red={center_red_pixels}"
    splash_width = splash_max_x - splash_min_x + 1 if splash_pixels else 0
    splash_height = splash_max_y - splash_min_y + 1 if splash_pixels else 0
    if splash_pixels >= 300 and splash_width >= 80 and splash_height >= 12:
        return "success", f"splash={splash_pixels} bbox={splash_width}x{splash_height}"
    if lower_bright_pixels >= 40:
        return "success", f"lower_bright={lower_bright_pixels}"
    if lower_text_pixels >= 40:
        return "success", f"lower_text={lower_text_pixels}"
    try:
        if image_suggests_dpi_prompt(path):
            return "success", "dpi_prompt"
    except (OSError, ValueError):
        pass
    if center_dim_pixels >= 15 and non_dark_pixels < max(4000, sampled_pixels // 120):
        return "freeze", f"center_dim={center_dim_pixels} non_dark={non_dark_pixels}"
    return (
        "ambiguous",
        f"center_red={center_red_pixels} lower_bright={lower_bright_pixels} "
        f"lower_text={lower_text_pixels} "
        f"splash={splash_pixels}/{splash_width}x{splash_height} "
        f"center_dim={center_dim_pixels} non_dark={non_dark_pixels}",
    )


def image_display_bounds(
    width: int,
    height: int,
    channels: int,
    rows: list[list[int]],
) -> tuple[int, int, int, int]:
    """Return the largest black display-like rectangle in an 86Box capture."""
    sample_x0 = width // 20
    sample_x1 = width - width // 20
    sample_width = sample_x1 - sample_x0
    row_threshold = max(sample_width // 2, (sample_width * 70) // 100)
    row_dark: list[int] = []
    for y in range(height):
        row = rows[y]
        dark = 0
        for x in range(sample_x0, sample_x1):
            off = x * channels
            if row[off] < 10 and row[off + 1] < 10 and row[off + 2] < 10:
                dark += 1
        row_dark.append(dark)

    dark_rows = [y for y, dark in enumerate(row_dark) if dark >= row_threshold]
    if not dark_rows:
        return 0, 0, width - 1, height - 1
    y0, y1 = dark_rows[0], dark_rows[-1]
    col_threshold = max(1, ((y1 - y0 + 1) * 55) // 100)
    dark_cols: list[int] = []
    for x in range(width):
        dark = 0
        for y in range(y0, y1 + 1):
            row = rows[y]
            off = x * channels
            if row[off] < 10 and row[off + 1] < 10 and row[off + 2] < 10:
                dark += 1
        if dark >= col_threshold:
            dark_cols.append(x)
    if not dark_cols:
        return 0, y0, width - 1, y1
    return dark_cols[0], y0, dark_cols[-1], y1


def image_suggests_dpi_prompt(path: Path) -> bool:
    """Detect a real idle DPI prompt when OCR drops the lone `>` marker.

    A true idle DPI prompt has the prompt glyph, the visible BIOS text cursor,
    and an otherwise blank input row. Seed may leave that row high on the screen
    after a short greeting/answer, so scan text rows instead of only the bottom.
    Long streamed answers can put arbitrary text at the left edge; those must not
    open the next harness gate.
    """
    width, height, channels, rows = read_png_rgb(path)
    if width < 320 or height < 240:
        return False

    display_x0, display_y0, display_x1, display_y1 = image_display_bounds(
        width,
        height,
        channels,
        rows,
    )
    display_w = max(1, display_x1 - display_x0 + 1)
    display_h = max(1, display_y1 - display_y0 + 1)
    cell_w = max(6, display_w // 80)
    cell_h = max(10, display_h // 25)
    y0 = display_y0 + (display_h * 92) // 100
    y1 = min(display_y1 + 1, display_y0 + (display_h * 99) // 100)
    prompt_x0 = display_x0
    prompt_x1 = min(display_x1 + 1, display_x0 + cell_w * 2)
    cursor_x0 = min(display_x1 + 1, display_x0 + cell_w * 2)
    cursor_x1 = min(display_x1 + 1, display_x0 + cell_w * 4)
    tail_x0 = min(display_x1 + 1, display_x0 + cell_w * 4)
    tail_x1 = max(tail_x0, display_x1 + 1 - max(8, display_w // 40))

    def band_has_prompt(band_y0: int, band_y1: int) -> bool:
        prompt_pixels = 0
        cursor_pixels = 0
        tail_pixels = 0
        prompt_min_x = width
        prompt_max_x = 0
        prompt_min_y = height
        prompt_max_y = 0
        cursor_min_x = width
        cursor_max_x = 0
        cursor_min_y = height
        cursor_max_y = 0

        for y in range(band_y0, band_y1):
            row = rows[y]
            for x in range(prompt_x0, prompt_x1):
                off = x * channels
                r, g, b = row[off], row[off + 1], row[off + 2]
                if r > 165 and g > 165 and b > 165:
                    prompt_pixels += 1
                    prompt_min_x = min(prompt_min_x, x)
                    prompt_max_x = max(prompt_max_x, x)
                    prompt_min_y = min(prompt_min_y, y)
                    prompt_max_y = max(prompt_max_y, y)
            for x in range(cursor_x0, cursor_x1):
                off = x * channels
                r, g, b = row[off], row[off + 1], row[off + 2]
                if r > 165 and g > 165 and b > 165:
                    cursor_pixels += 1
                    cursor_min_x = min(cursor_min_x, x)
                    cursor_max_x = max(cursor_max_x, x)
                    cursor_min_y = min(cursor_min_y, y)
                    cursor_max_y = max(cursor_max_y, y)
            for x in range(tail_x0, tail_x1):
                off = x * channels
                r, g, b = row[off], row[off + 1], row[off + 2]
                if r > 165 and g > 165 and b > 165:
                    tail_pixels += 1

        prompt_width = prompt_max_x - prompt_min_x + 1 if prompt_pixels else 0
        prompt_height = prompt_max_y - prompt_min_y + 1 if prompt_pixels else 0
        cursor_width = cursor_max_x - cursor_min_x + 1 if cursor_pixels else 0
        cursor_height = cursor_max_y - cursor_min_y + 1 if cursor_pixels else 0
        prompt_shape = (
            8 <= prompt_pixels <= max(220, cell_w * cell_h)
            and 4 <= prompt_width <= cell_w + 2
            and 8 <= prompt_height <= band_y1 - band_y0
            and tail_pixels <= max(20, prompt_pixels // 3)
        )
        cursor_shape = (
            6 <= cursor_pixels <= max(260, cell_w * cell_h)
            and max(4, cell_w // 2) <= cursor_width <= cell_w * 2
            and 1 <= cursor_height <= cell_h
        )
        return prompt_shape and (
            cursor_shape
            or tail_pixels <= max(20, prompt_pixels // 3)
        )

    # Preserve the old bottom-row check, then scan visible text rows from top to
    # bottom. A half-cell step tolerates captures where the text grid is not
    # aligned exactly to the detected display rectangle.
    if band_has_prompt(y0, y1):
        return True
    scan_y0 = display_y0 + cell_h
    scan_y1 = min(display_y1 + 1, display_y0 + (display_h * 99) // 100)
    step = max(1, cell_h // 2)
    for row_y0 in range(scan_y0, max(scan_y0, scan_y1 - cell_h + 1), step):
        if band_has_prompt(row_y0, min(scan_y1, row_y0 + cell_h)):
            return True
    return False


def image_prompt_band_crc(path: Path) -> int:
    width, height, channels, rows = read_png_rgb(path)
    display_x0, display_y0, display_x1, display_y1 = image_display_bounds(
        width,
        height,
        channels,
        rows,
    )
    display_w = max(1, display_x1 - display_x0 + 1)
    display_h = max(1, display_y1 - display_y0 + 1)
    cell_w = max(6, display_w // 80)
    y0 = display_y0 + (display_h * 82) // 100
    y1 = min(display_y1 + 1, display_y0 + (display_h * 99) // 100)
    x0 = min(display_x1 + 1, display_x0 + cell_w * 4)
    x1 = display_x1 + 1 - max(8, display_w // 40)
    checksum = 0
    for y in range(y0, min(y1, height)):
        row = rows[y]
        for x in range(x0, x1, 4):
            off = x * channels
            checksum = zlib.crc32(bytes(row[off : off + 3]), checksum)
    return checksum


def image_response_area_crc(path: Path) -> int:
    width, height, channels, rows = read_png_rgb(path)
    display_x0, display_y0, display_x1, display_y1 = image_display_bounds(
        width,
        height,
        channels,
        rows,
    )
    display_w = max(1, display_x1 - display_x0 + 1)
    display_h = max(1, display_y1 - display_y0 + 1)
    cell_w = max(6, display_w // 80)
    x0 = min(display_x1 + 1, display_x0 + cell_w * 4)
    x1 = display_x1 + 1 - max(8, display_w // 40)
    y0 = display_y0 + (display_h * 10) // 100
    y1 = display_y1 + 1
    checksum = 0
    for y in range(y0, min(y1, height), 2):
        row = rows[y]
        for x in range(x0, x1, 4):
            off = x * channels
            checksum = zlib.crc32(bytes(row[off : off + 3]), checksum)
    return checksum


def sample_process_https_remotes(pid: int) -> set[str]:
    """Return remote TCP/443 IPs owned by the emulator process.

    en0 captures all host traffic, so DNS or broad-flow heuristics can mistake
    unrelated Codex/Claude/browser traffic for the VM. lsof gives us the
    process-owned SLIRP sockets while 86Box is still running.
    """
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(pid), "-iTCP"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()

    remotes: set[str] = set()
    for line in result.stdout.splitlines()[1:]:
        if "->" not in line or ":443" not in line:
            continue
        match = re.search(r"->([^:() ]+):443(?:\s|\()", line)
        if match:
            remotes.add(match.group(1))
    return remotes


def wait_with_process_https_sampling(process: subprocess.Popen[str], seconds: float) -> set[str]:
    remotes: set[str] = set()
    deadline = time.monotonic() + seconds
    while True:
        remotes.update(sample_process_https_remotes(process.pid))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1.0, remaining))
    return remotes


def argv_without_repeat() -> list[str]:
    argv: list[str] = []
    skip_next = False
    for arg in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "--repeat":
            skip_next = True
            continue
        if arg.startswith("--repeat="):
            continue
        if arg == "--repeat-fail-fast":
            continue
        argv.append(arg)
    return argv


def run_repeat(args: argparse.Namespace) -> int:
    if args.leave_running:
        raise SystemExit("--repeat cannot be combined with --leave-running")
    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")
    if not args.no_build:
        run(["make"], cwd=ROOT)
        run(["make", "basic-bootstrap"], cwd=ROOT)

    base_argv = argv_without_repeat()
    if not args.no_build and "--no-build" not in base_argv:
        base_argv.append("--no-build")

    passed = 0
    failures: list[tuple[int, int]] = []
    started = time.monotonic()
    for index in range(1, args.repeat + 1):
        run_started = time.monotonic()
        cmd = [sys.executable, str(Path(__file__).resolve()), *base_argv]
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        elapsed = time.monotonic() - run_started
        ok = result.returncode == 0
        if ok:
            passed += 1
        else:
            failures.append((index, result.returncode))
        print(
            f"repeat {index}/{args.repeat}: "
            f"{'PASS' if ok else 'FAIL'} rc={result.returncode} {elapsed:.1f}s"
        )
        output = result.stdout.strip()
        if output:
            for line in output.splitlines()[-12:]:
                print(f"  {line}")
        if not ok and args.repeat_fail_fast:
            break

    attempted = passed + len(failures)
    total_elapsed = time.monotonic() - started
    rate = (passed / attempted * 100.0) if attempted else 0.0
    print(
        f"repeat summary: {passed}/{attempted} passed "
        f"({rate:.1f}%) in {total_elapsed:.1f}s"
    )
    if failures:
        print(
            "repeat failures: "
            + ", ".join(f"#{index} rc={code}" for index, code in failures)
        )
        return 1
    return 0


def classify_running_vm(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
    label: str,
) -> tuple[str, str]:
    if not screenshot_86box_window_or_screen(
        args.oracle_screenshot,
        args.profile,
        process.pid,
    ):
        print(f"{label}: ambiguous (could not capture 86Box window)")
        return "ambiguous", "could not capture 86Box window"
    try:
        shape_verdict, shape_detail = classify_86box_screen(args.oracle_screenshot)
    except (OSError, ValueError) as exc:
        shape_verdict, shape_detail = "ambiguous", str(exc)

    engine: str | None = None
    lines: list[str] = []
    should_ocr = (
        not args.no_screen_ocr
    )
    if should_ocr:
        engine, lines = screen_ocr_lines_for_expected(
            args.oracle_screenshot,
            args.screen_ocr_timeout,
            args.screen_expect_text,
        )

    verdict = shape_verdict
    detail = shape_detail
    if lines and ocr_lines_suggest_rom_basic(lines):
        verdict = "bootstrap-failure"
        detail = f"ocr_{engine or 'unknown'}_rom_basic"
    elif lines and ocr_lines_suggest_seed_failure_menu(lines):
        # Sparse Seed failure screens can have the same centered-text/prompt
        # geometry as DPI.  The retry/restart pair is the stronger signal and
        # must never be promoted to success by the coarse pixel classifier.
        verdict = "clean-failure"
        detail = f"ocr_{engine or 'unknown'}_failure_menu"
    elif verdict == "clean-failure":
        verdict = "ambiguous"
        detail = f"{shape_detail} without failure menu"
    if verdict == "ambiguous":
        if ocr_lines_suggest_dpi_ready(lines):
            verdict = "success"
            detail = f"ocr_{engine or 'unknown'}_dpi"
        elif ocr_lines_suggest_seed_greeting(lines):
            verdict = "success"
            detail = f"ocr_{engine or 'unknown'}_greeting"
    missing_expected = missing_expected_ocr_text(lines, args.screen_expect_text)
    if args.screen_expect_text and (engine is None or missing_expected):
        verdict = "missing-expected"
        detail = (
            "ocr_unavailable"
            if engine is None
            else "missing " + ", ".join(repr(text) for text in missing_expected)
        )

    print(f"{label}: shape={shape_verdict} ({shape_detail})")
    if should_ocr:
        print_screen_ocr_lines(label, engine, lines)
    if verdict != shape_verdict or detail != shape_detail:
        print(f"{label}: derived={verdict} ({detail})")
    else:
        print(f"{label}: verdict={verdict} ({detail})")
    if verdict == "success" and not args.keep_success_oracle_screenshot:
        args.oracle_screenshot.unlink(missing_ok=True)
    elif verdict != "success":
        print(f"{label}: kept {args.oracle_screenshot}")
    return verdict, detail


def validate_post_dpi_expectations(
    post_dpi_text: list[str],
    post_dpi_expect_text: list[str],
    *,
    screen_oracle: bool,
    no_screen_ocr: bool,
) -> None:
    if not post_dpi_expect_text:
        return
    if len(post_dpi_expect_text) != len(post_dpi_text):
        raise SystemExit(
            "--post-dpi-expect-text count must match --post-dpi-text count "
            f"({len(post_dpi_expect_text)} != {len(post_dpi_text)})"
        )
    if any(not text.strip() for text in post_dpi_expect_text):
        raise SystemExit("--post-dpi-expect-text values must not be empty")
    for index, (prompt, expected) in enumerate(
        zip(post_dpi_text, post_dpi_expect_text),
        start=1,
    ):
        folded_prompt = re.sub(r"\s+", " ", prompt.strip().casefold())
        folded_expected = re.sub(r"\s+", " ", expected.strip().casefold())
        if folded_expected in folded_prompt:
            raise SystemExit(
                "--post-dpi-expect-text must not already appear in the "
                f"corresponding --post-dpi-text prompt (turn {index})"
            )
    if not screen_oracle:
        raise SystemExit(
            "--post-dpi-expect-text requires --screen-oracle"
        )
    if no_screen_ocr:
        raise SystemExit(
            "--post-dpi-expect-text cannot be combined with --no-screen-ocr"
        )


def wait_for_dpi_prompt(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
    label: str,
    timeout: float,
    interval: float,
    changed_from_crc: int | None = None,
    expected_response_text: str | None = None,
) -> bool:
    """Wait until the visible VM has the DPI prompt marker.

    The shape oracle intentionally treats the splash as success, which is good
    for final pass/fail but too early for typing the next prompt. For prompt
    injection we trust the bottom-left visual prompt shape. OCR is logged as
    corroborating evidence only: long answers can contain OCR fragments that
    look like a prompt, while OCR can also drop the real lone `>` marker.
    """
    deadline = time.monotonic() + timeout
    last_shape = ("ambiguous", "not captured")
    last_engine: str | None = None
    last_lines: list[str] = []
    visual_candidate_crc: int | None = None
    visual_candidate_count = 0
    samples = 0

    while True:
        if process.poll() is not None:
            print(f"{label}: process exited before DPI prompt")
            return False
        if screenshot_86box_window_or_screen(
            args.oracle_screenshot,
            args.profile,
            process.pid,
        ):
            samples += 1
            try:
                last_shape = classify_86box_screen(args.oracle_screenshot)
            except (OSError, ValueError) as exc:
                last_shape = ("ambiguous", str(exc))
            if last_shape[0] == "dense-glyph-screen":
                print(
                    f"{label}: rejected dense glyph screen "
                    f"({last_shape[1]})"
                )
                print(f"{label}: kept {args.oracle_screenshot}")
                return False
            last_engine, last_lines = screen_ocr_lines_for_expected(
                args.oracle_screenshot,
                args.screen_ocr_timeout,
                [expected_response_text] if expected_response_text else [],
            )
            if ocr_lines_suggest_seed_failure_menu(last_lines):
                print(f"{label}: failure menu before DPI prompt")
                print_screen_ocr_lines(label, last_engine, last_lines)
                print(f"{label}: kept {args.oracle_screenshot}")
                return False
            # Current product images never ask an RTC question.  If an older
            # image does show one, keep it distinct from the identical-looking
            # DPI input marker and refuse to inject a chat turn into it.
            rtc_question_visible = (
                not ocr_lines_suggest_rtc_utc_answered(last_lines)
                and
                ocr_lines_suggest_rtc_utc_question(last_lines)
            )
            visual_prompt = False
            try:
                visual_prompt = image_suggests_dpi_prompt(args.oracle_screenshot)
            except (OSError, ValueError):
                visual_prompt = False
            ocr_prompt = ocr_lines_suggest_dpi_ready(last_lines)
            try:
                candidate_crc = image_prompt_band_crc(args.oracle_screenshot)
            except (OSError, ValueError):
                candidate_crc = None
            try:
                response_crc = image_response_area_crc(args.oracle_screenshot)
            except (OSError, ValueError):
                response_crc = None
            response_changed = (
                changed_from_crc is None
                or response_crc is None
                or response_crc != changed_from_crc
            )
            expected_response_seen = (
                expected_response_text is None
                or not missing_expected_ocr_text(
                    last_lines,
                    [expected_response_text],
                )
            )
            if (
                candidate_crc is not None
                and visual_candidate_crc is not None
                and candidate_crc != visual_candidate_crc
            ):
                visual_candidate_crc = None
                visual_candidate_count = 0
            prompt_candidate = (
                not rtc_question_visible
                and (visual_prompt or ocr_prompt)
            )
            prompt_ready = False
            if prompt_candidate:
                if candidate_crc is not None and candidate_crc == visual_candidate_crc:
                    visual_candidate_count += 1
                else:
                    visual_candidate_crc = candidate_crc
                    visual_candidate_count = 1
                prompt_ready = (
                    (visual_prompt and visual_candidate_count >= 2)
                    or (ocr_prompt and visual_candidate_count >= 3)
                )
                if changed_from_crc is None and ocr_prompt:
                    prompt_ready = True
                prompt_ready = (
                    prompt_ready
                    and response_changed
                    and expected_response_seen
                )
            else:
                visual_candidate_crc = None
                visual_candidate_count = 0
            if prompt_ready:
                # A VM can exit while capture/OCR is running. Never advance a
                # controller from a stale frame after its target has exited.
                if process.poll() is not None:
                    print(f"{label}: process exited during DPI prompt capture")
                    return False
                print(
                    f"{label}: DPI prompt ready "
                    f"(shape={last_shape[0]} {last_shape[1]}, "
                    f"ocr={last_engine or 'none'}, ocr_prompt={ocr_prompt}, "
                    f"visual_prompt={visual_prompt}, visual_count={visual_candidate_count}, "
                    f"expected_response={expected_response_seen})"
                )
                print_screen_ocr_lines(label, last_engine, last_lines)
                if not args.keep_success_oracle_screenshot:
                    args.oracle_screenshot.unlink(missing_ok=True)
                return True
            if samples % max(1, int(60 / max(interval, 1))) == 0:
                changed_detail = (
                    "n/a" if changed_from_crc is None else str(response_changed)
                )
                print(
                    f"{label}: waiting "
                    f"(shape={last_shape[0]} {last_shape[1]}, "
                    f"ocr_prompt={ocr_prompt}, visual_prompt={visual_prompt}, "
                    f"visual_count={visual_candidate_count}, "
                    f"changed={changed_detail}, "
                    f"expected_response={expected_response_seen})"
                )
                print_screen_ocr_lines(label, last_engine, last_lines)
        else:
            last_shape = ("ambiguous", "could not capture 86Box window")
            last_engine = None
            last_lines = []

        if time.monotonic() >= deadline:
            print(f"{label}: timed out waiting for DPI prompt ({last_shape[0]} {last_shape[1]})")
            print_screen_ocr_lines(label, last_engine, last_lines)
            if args.oracle_screenshot.exists():
                print(f"{label}: kept {args.oracle_screenshot}")
            return False
        time.sleep(interval)


RTC_UTC_QUESTION_OCR = re.compile(
    r"\br[ti]c\s+is\s+set\s+to\s+utc\s+[\(c]?\s*y\s*/\s*n\s*\)?\s*\??"
)
AMI286_MEMORY_TEST_OCR = re.compile(
    r"press\s+[\(\{<\[]?\s*esc\s*[\)\}>\]]?\s+to\s+bypass\s+memory\s+test"
)


def ocr_lines_suggest_ami286_memory_test(lines: list[str]) -> bool:
    joined = " ".join(line.strip().casefold() for line in lines)
    joined = re.sub(r"\s+", " ", joined)
    bios_identity = "american megatrends" in joined or "286-bio" in joined
    return bios_identity and AMI286_MEMORY_TEST_OCR.search(joined) is not None


def bypass_ami286_memory_test(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
) -> bool:
    """Submit one loader-safe Escape during the exact-floor AMI286 POST."""
    deadline = time.monotonic() + args.ami286_memory_bypass_timeout
    bypass_ready_at: float | None = None
    bypass_submitted = False
    saw_memory_test = False
    last_engine: str | None = None
    last_lines: list[str] = []

    while True:
        if process.poll() is not None:
            print("AMI286 POST: process exited during memory count")
            return False
        if screenshot_86box_window_or_screen(
            args.oracle_screenshot,
            args.profile,
            process.pid,
        ):
            last_engine, last_lines = screen_ocr_lines(
                args.oracle_screenshot,
                args.screen_ocr_timeout,
            )
            memory_test_visible = ocr_lines_suggest_ami286_memory_test(last_lines)
            if memory_test_visible:
                saw_memory_test = True
                if bypass_ready_at is None:
                    bypass_ready_at = (
                        time.monotonic() + AMI286_MEMORY_BYPASS_DELAY_SECONDS
                    )
                    print(
                        "AMI286 POST: waiting 90s for a loader-safe memory "
                        "count before bypass"
                    )
                elif not bypass_submitted and time.monotonic() >= bypass_ready_at:
                    post_pid_focused_keycode(
                        process.pid,
                        53,
                        restore_focus=False,
                    )
                    bypass_submitted = True
                    print("AMI286 POST: submitted one Escape key")
            elif bypass_submitted:
                print("AMI286 POST: memory bypass accepted")
                return True
            elif saw_memory_test:
                # The count completed naturally before the delayed bypass.
                print("AMI286 POST: memory count completed without injection")
                return True
            elif (
                ocr_lines_suggest_seed_greeting(last_lines)
                or ocr_lines_suggest_dpi_ready(last_lines)
                or ocr_lines_suggest_seed_failure_menu(last_lines)
            ):
                # The harness attached after POST. Never inject Escape into Seed.
                print("AMI286 POST: Seed already owns the display; no key injected")
                return True

        if time.monotonic() >= deadline:
            print(
                "AMI286 POST: timed out waiting for a safely bypassable memory "
                f"count (ocr={last_engine or 'none'})"
            )
            print_screen_ocr_lines("AMI286 POST", last_engine, last_lines)
            if args.oracle_screenshot.exists():
                print(f"AMI286 POST: kept {args.oracle_screenshot}")
            return False
        time.sleep(args.ami286_memory_bypass_interval)


def ocr_lines_suggest_rtc_utc_question(lines: list[str]) -> bool:
    joined = " ".join(line.strip().casefold() for line in lines)
    joined = re.sub(r"\s+", " ", joined)
    # The 86Box CGA glyphs make T look like I and '(' look like C to
    # Tesseract.  Accept only those observed single-glyph confusions while
    # retaining the complete question/choice shape and the separate visual
    # input-marker requirement in wait_for_rtc_utc_question().
    return RTC_UTC_QUESTION_OCR.search(joined) is not None


def ocr_lines_suggest_rtc_utc_answered(lines: list[str]) -> bool:
    joined = "\n".join(line.strip().casefold() for line in lines)
    question = RTC_UTC_QUESTION_OCR.search(joined)
    if question is None:
        return False
    for line in joined[question.end() :].splitlines()[:5]:
        folded = line.strip().casefold()
        # Exact 86Box CGA captures can render the `>` input marker as `d`,
        # yielding `dy` for the visible `> y`.
        if re.fullmatch(r"[>›»)d]?\s*y", folded):
            return True
    return False


def wait_for_rtc_utc_question(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
) -> bool:
    """Wait for the exact 286 UTC-attestation question and visible input marker."""
    deadline = time.monotonic() + args.rtc_prompt_timeout
    last_engine: str | None = None
    last_lines: list[str] = []
    last_visual_prompt = False
    samples = 0
    bios_memory_bypass_submitted = False
    bios_memory_bypass_departure_confirmed = False
    bios_memory_bypass_ready_at: float | None = None

    while True:
        if process.poll() is not None:
            print("RTC UTC attestation: process exited before the question")
            return False
        if screenshot_86box_window_or_screen(
            args.oracle_screenshot,
            args.profile,
            process.pid,
        ):
            samples += 1
            last_engine, last_lines = screen_ocr_lines(
                args.oracle_screenshot,
                args.screen_ocr_timeout,
            )
            memory_test_visible = ocr_lines_suggest_ami286_memory_test(last_lines)
            if not bios_memory_bypass_submitted and memory_test_visible:
                if bios_memory_bypass_ready_at is None:
                    bios_memory_bypass_ready_at = (
                        time.monotonic() + AMI286_MEMORY_BYPASS_DELAY_SECONDS
                    )
                    print(
                        "RTC UTC attestation: waiting 90s for a loader-safe "
                        "AMI286 memory count before bypass"
                    )
                elif time.monotonic() >= bios_memory_bypass_ready_at:
                    post_pid_focused_keycode(
                        process.pid,
                        53,
                        restore_focus=False,
                    )
                    bios_memory_bypass_submitted = True
                    print(
                        "RTC UTC attestation: submitted one Escape key to the "
                        "AMI286 BIOS memory count"
                    )
            elif (
                bios_memory_bypass_submitted
                and not bios_memory_bypass_departure_confirmed
                and not memory_test_visible
            ):
                print("RTC UTC attestation: AMI286 BIOS memory bypass accepted")
                bios_memory_bypass_departure_confirmed = True
            if ocr_lines_suggest_seed_failure_menu(last_lines):
                print("RTC UTC attestation: failure menu before the question")
                print_screen_ocr_lines("RTC UTC attestation", last_engine, last_lines)
                print(f"RTC UTC attestation: kept {args.oracle_screenshot}")
                return False
            try:
                last_visual_prompt = image_suggests_dpi_prompt(args.oracle_screenshot)
            except (OSError, ValueError):
                last_visual_prompt = False
            exact_question = ocr_lines_suggest_rtc_utc_question(last_lines)
            if last_engine is not None and exact_question and last_visual_prompt:
                print(
                    "RTC UTC attestation: exact question ready "
                    f"(ocr={last_engine}, visual_prompt={last_visual_prompt})"
                )
                print_screen_ocr_lines("RTC UTC attestation", last_engine, last_lines)
                return True
            if samples % max(1, int(60 / max(args.rtc_prompt_interval, 1))) == 0:
                print(
                    "RTC UTC attestation: waiting "
                    f"(ocr={last_engine or 'none'}, exact_question={exact_question}, "
                    f"visual_prompt={last_visual_prompt})"
                )
                print_screen_ocr_lines("RTC UTC attestation", last_engine, last_lines)
        else:
            last_engine = None
            last_lines = []
            last_visual_prompt = False

        if time.monotonic() >= deadline:
            print(
                "RTC UTC attestation: timed out waiting for the exact question "
                f"(ocr={last_engine or 'none'}, visual_prompt={last_visual_prompt})"
            )
            print_screen_ocr_lines("RTC UTC attestation", last_engine, last_lines)
            if args.oracle_screenshot.exists():
                print(f"RTC UTC attestation: kept {args.oracle_screenshot}")
            return False
        time.sleep(args.rtc_prompt_interval)


def submit_rtc_utc_answer(
    pid: int,
    key_delay: float,
    line_delay: float,
) -> None:
    """Submit affirmative same-boot UTC consent without an Enter key."""
    # The BIOS Escape and Seed's single-key UTC question both sit before the
    # normal DPI input loop.  Direct CGEventPostToPid delivery is reliable for
    # the latter loop but can be dropped at this early boundary; use the same
    # exact-PID, briefly focused physical-key path that bypasses the AMI memory
    # test.  Submit exactly one key so a late duplicate cannot leak into DPI.
    del key_delay, line_delay
    post_pid_focused_keycode(
        pid,
        KEY_CODES["y"][0],
        restore_focus=False,
    )


def wait_for_rtc_utc_question_clear(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
) -> bool:
    """Require two OCR samples showing the affirmative echo or later progress."""
    deadline = time.monotonic() + args.rtc_answer_timeout
    clear_samples = 0
    last_engine: str | None = None
    last_lines: list[str] = []
    last_visual_prompt = True

    while True:
        if process.poll() is not None:
            print("RTC UTC attestation: process exited before accepting the answer")
            return False
        if screenshot_86box_window_or_screen(
            args.oracle_screenshot,
            args.profile,
            process.pid,
        ):
            last_engine, last_lines = screen_ocr_lines(
                args.oracle_screenshot,
                args.screen_ocr_timeout,
            )
            if ocr_lines_suggest_seed_failure_menu(last_lines):
                print("RTC UTC attestation: failure menu after answering")
                print_screen_ocr_lines("RTC UTC attestation", last_engine, last_lines)
                print(f"RTC UTC attestation: kept {args.oracle_screenshot}")
                return False
            try:
                last_visual_prompt = image_suggests_dpi_prompt(args.oracle_screenshot)
            except (OSError, ValueError):
                last_visual_prompt = True
            answered_echo = ocr_lines_suggest_rtc_utc_answered(last_lines)
            question_gone = (
                not ocr_lines_suggest_rtc_utc_question(last_lines)
                and not last_visual_prompt
            )
            if last_engine is not None and (answered_echo or question_gone):
                clear_samples += 1
                if clear_samples >= 2:
                    print("RTC UTC attestation: affirmative answer accepted")
                    if not args.keep_success_oracle_screenshot:
                        args.oracle_screenshot.unlink(missing_ok=True)
                    return True
            else:
                clear_samples = 0

        if time.monotonic() >= deadline:
            print(
                "RTC UTC attestation: affirmative echo/progress was not confirmed "
                f"(ocr={last_engine or 'none'}, visual_prompt={last_visual_prompt})"
            )
            print_screen_ocr_lines("RTC UTC attestation", last_engine, last_lines)
            if args.oracle_screenshot.exists():
                print(f"RTC UTC attestation: kept {args.oracle_screenshot}")
            return False
        time.sleep(args.rtc_prompt_interval)


def attest_rtc_utc(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
) -> bool:
    if not wait_for_rtc_utc_question(args, process):
        return False
    submit_rtc_utc_answer(process.pid, args.type_delay, args.line_delay)
    print("RTC UTC attestation: submitted one 'y' key without Enter")
    return wait_for_rtc_utc_question_clear(args, process)


def capture_response_area_crc(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
) -> int | None:
    if not screenshot_86box_window_or_screen(
        args.oracle_screenshot,
        args.profile,
        process.pid,
    ):
        return None
    try:
        return image_response_area_crc(args.oracle_screenshot)
    except (OSError, ValueError):
        return None
    finally:
        if not args.keep_success_oracle_screenshot:
            args.oracle_screenshot.unlink(missing_ok=True)


def ocr_lines_suggest_dpi_ready(lines: list[str]) -> bool:
    has_completion_trace = any(
        "c" in line.strip().lower()
        and ("cpr" in line.strip().lower() or "prsat" in line.strip().lower())
        for line in lines
    )
    for line in lines[-5:]:
        folded = line.strip().lower()
        if folded in {">", "›", "»", ")", "gee", "gee,"}:
            return True
        if len(folded) <= 3 and folded[-1:] in {">", "›", "»"}:
            return True
        if len(folded) <= 6 and folded[:1] in {">", "›", "»", ")"}:
            return True
        if has_completion_trace and 1 <= len(folded) <= 6:
            return True
    return False


def ocr_lines_suggest_seed_greeting(lines: list[str]) -> bool:
    """Recognize Seed's initial authenticated greeting in noisy CGA OCR."""
    joined = " ".join(line.strip().casefold() for line in lines)
    joined = re.sub(r"\s+", " ", joined)
    seed_identity = "seed build" in joined or any(
        line.strip().casefold() == "seed" for line in lines
    )
    return seed_identity and "how can i help" in joined


def ocr_lines_suggest_seed_failure_menu(lines: list[str]) -> bool:
    folded_lines = [line.strip().casefold() for line in lines]
    joined = " ".join(folded_lines)
    retry_choice = any(
        re.fullmatch(r"[1il][.,:]?\s*retry", line) for line in folded_lines
    )
    restart_choice = any(
        re.fullmatch(r"2[.,:]?\s*restart", line) for line in folded_lines
    )
    return (
        ("failed" in joined or (retry_choice and restart_choice))
        and "retry" in joined
        and "restart" in joined
    )


def ocr_lines_suggest_rom_basic(lines: list[str]) -> bool:
    joined = " ".join(line.lower() for line in lines)
    return (
        "personal computer basic" in joined
        or "copyright ibm corp" in joined
        or "syntax error" in joined
    )


def missing_expected_ocr_text(lines: list[str], expected_text: list[str]) -> list[str]:
    if not expected_text:
        return []
    folded = " ".join(lines).casefold()
    folded = re.sub(r"\s+", " ", folded)
    missing: list[str] = []
    for text in expected_text:
        expected = re.sub(r"\s+", " ", text.strip().casefold())
        if expected and expected not in folded:
            missing.append(text)
    return missing


def screen_vision_ocr_lines(path: Path, timeout: float) -> tuple[str | None, list[str]]:
    swift = shutil.which("swift")
    if swift is None or not DEFAULT_OCR_SCRIPT.exists():
        return None, []
    cache_root = Path(tempfile.gettempdir()) / "seed-swift-module-cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["CLANG_MODULE_CACHE_PATH"] = str(cache_root)
    env["SWIFT_MODULE_CACHE_PATH"] = str(cache_root)
    try:
        result = subprocess.run(
            [swift, str(DEFAULT_OCR_SCRIPT), str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, []
    if result.returncode != 0:
        return None, []
    return "vision", unique_nonempty_lines(result.stdout)


def screen_ocr_lines(path: Path, timeout: float) -> tuple[str | None, list[str]]:
    if not path.exists():
        return None, []

    ocr_path = path
    copied_ocr_path: Path | None = None
    local_ocr_dir = ROOT / "build/ibm_pc_5150"
    local_ocr_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(
            prefix="seed-ocr-",
            suffix=path.suffix or ".png",
            dir=local_ocr_dir,
            delete=False,
        ) as copied:
            copied.write(path.read_bytes())
            copied_ocr_path = Path(copied.name)
            ocr_path = copied_ocr_path
    except OSError:
        ocr_path = path

    tesseract_candidates = [
        shutil.which("tesseract"),
        "/opt/homebrew/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/usr/bin/tesseract",
    ]
    tesseract_seen: set[str] = set()
    for tesseract in tesseract_candidates:
        if tesseract is None or tesseract in tesseract_seen:
            continue
        tesseract_seen.add(tesseract)
        try:
            result = subprocess.run(
                [
                    tesseract,
                    str(ocr_path),
                    "stdout",
                    "--psm",
                    "6",
                    "--dpi",
                    "96",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None and result.returncode == 0:
            if copied_ocr_path is not None:
                copied_ocr_path.unlink(missing_ok=True)
            return "tesseract", unique_nonempty_lines(result.stdout)
    if copied_ocr_path is not None:
        copied_ocr_path.unlink(missing_ok=True)

    return screen_vision_ocr_lines(path, timeout)


def screen_ocr_lines_for_expected(
    path: Path,
    timeout: float,
    expected_text: list[str],
) -> tuple[str | None, list[str]]:
    """Use exact Vision text only when the primary OCR misses an expectation."""
    engine, lines = screen_ocr_lines(path, timeout)
    if (
        not expected_text
        or engine == "vision"
        or not missing_expected_ocr_text(lines, expected_text)
    ):
        return engine, lines

    vision_engine, vision_lines = screen_vision_ocr_lines(path, timeout)
    if vision_engine is None or not vision_lines:
        return engine, lines
    combined_lines = unique_nonempty_lines("\n".join([*lines, *vision_lines]))
    combined_engine = (
        f"{engine}+{vision_engine}" if engine is not None else vision_engine
    )
    return combined_engine, combined_lines


def unique_nonempty_lines(text: str) -> list[str]:
    seen: set[str] = set()
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)
    return lines


def maybe_print_screen_ocr(args: argparse.Namespace, label: str, path: Path) -> None:
    if args.no_screen_ocr:
        return
    engine, lines = screen_ocr_lines(path, args.screen_ocr_timeout)
    print_screen_ocr_lines(label, engine, lines)


def print_screen_ocr_lines(
    label: str,
    engine: str | None,
    lines: list[str],
) -> None:
    if engine is None:
        print(f"{label} OCR: unavailable (install tesseract for local text extraction)")
        return
    if not lines:
        print(f"{label} OCR ({engine}): no text recognized")
        return
    print(f"{label} OCR ({engine}):")
    for line in lines:
        print(f"  {line}")


def main() -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass
    parser = argparse.ArgumentParser(
        description="Launch a ROM BASIC 86Box VM and inject Seed's 24 KiB BASIC bootstrap.",
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument(
        "--vm-path",
        type=Path,
        default=None,
        help="override the 86Box profile directory; useful for per-run temporary profile copies",
    )
    parser.add_argument("--basic", type=Path, default=DEFAULT_BASIC)
    parser.add_argument(
        "--basic-drive",
        choices=("a", "b"),
        default="b",
        help=(
            "drive read by the ROM BASIC sidecar (default: b); the harness "
            "also passes an explicit 86Box --image override so an old or "
            "silently stale profile cannot start with an empty drive"
        ),
    )
    parser.add_argument("--loader", type=Path, default=DEFAULT_LOADER)
    parser.add_argument("--basic-loader", type=Path, default=DEFAULT_BASIC_LOADER)
    parser.add_argument("--floppy", type=Path, default=DEFAULT_FLOPPY)
    parser.add_argument(
        "--floppy-read-only",
        action="store_true",
        help=(
            "mount the selected floppy guest-write-protected, remove host write "
            "permission for the run, require its SHA-256 to remain unchanged, "
            "and restore its original mode afterward; implied by "
            "--platform-rtc-utc"
        ),
    )
    parser.add_argument("--loader-floppy", type=Path, default=DEFAULT_LOADER_FLOPPY)
    parser.add_argument("--screenshot", type=Path, default=DEFAULT_SCREENSHOT)
    parser.add_argument("--oracle-screenshot", type=Path, default=DEFAULT_ORACLE_SCREENSHOT)
    parser.add_argument("--ram-kib", type=int, default=None)
    parser.add_argument("--startup-delay", type=float, default=None)
    parser.add_argument("--capture-delay", type=float, default=None)
    parser.add_argument(
        "--platform-rtc-utc",
        dest="attest_rtc_utc",
        action="store_true",
        help=(
            "for the ami286 direct-boot acceptance gate, force 86Box UTC RTC "
            "synchronization; Seed validates and uses the platform clock "
            "silently"
        ),
    )
    parser.add_argument(
        "--attest-rtc-utc",
        dest="attest_rtc_utc",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--rtc-prompt-timeout",
        type=float,
        default=300.0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--rtc-answer-timeout",
        type=float,
        default=30.0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--rtc-prompt-interval",
        type=float,
        default=1.0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--ami286-memory-bypass-timeout",
        type=float,
        default=240.0,
        help=(
            "seconds to allow the loader-safe exact-floor AMI286 POST memory "
            "bypass (default: 240)"
        ),
    )
    parser.add_argument(
        "--ami286-memory-bypass-interval",
        type=float,
        default=1.0,
        help="seconds between AMI286 POST OCR checks (default: 1)",
    )
    parser.add_argument(
        "--post-dpi-text",
        action="append",
        default=[],
        help="after DPI is ready, type this prompt into the same VM and wait for the next response; repeat to send multiple prompts",
    )
    parser.add_argument(
        "--post-dpi-expect-text",
        action="append",
        default=[],
        help=(
            "require OCR to contain this response text before the corresponding "
            "--post-dpi-text turn completes; the text must not occur in the "
            "prompt, and the option must repeat exactly once per prompt"
        ),
    )
    parser.add_argument(
        "--post-dpi-wait",
        type=float,
        default=70.0,
        help="seconds to wait after --post-dpi-text before the final oracle classification",
    )
    parser.add_argument(
        "--post-dpi-at",
        type=float,
        default=None,
        help="absolute seconds after VM launch to type --post-dpi-text; skips the OCR prompt-ready gate",
    )
    parser.add_argument(
        "--post-dpi-gate-timeout",
        type=float,
        default=1200.0,
        help="seconds to wait for OCR to see the DPI prompt before each --post-dpi-text (default: 1200)",
    )
    parser.add_argument(
        "--post-dpi-gate-interval",
        type=float,
        default=3.0,
        help="seconds between DPI prompt-ready OCR checks (default: 3)",
    )
    parser.add_argument(
        "--post-dpi-idle",
        type=float,
        default=0.0,
        help="seconds to idle after the prompt is ready and BEFORE typing each --post-dpi-text. "
        "Lets the server close the idle keep-alive so the prompt exercises the real "
        "reuse-fail->reconnect->resend path. This is the reconnect regression test (default: 0)",
    )
    parser.add_argument("--type-delay", type=float, default=0.03)
    parser.add_argument("--line-delay", type=float, default=0.3)
    parser.add_argument(
        "--mode",
        choices=("paste", "text", "chars", "keycode", "pidkeycode"),
        default="pidkeycode",
        help="BASIC injection mode (default: pidkeycode, posts directly to the 86Box process)",
    )
    parser.add_argument(
        "--pidkeycode-background",
        action="store_true",
        help="deprecated no-op; pidkeycode posts directly to 86Box without changing focus",
    )
    parser.add_argument("--no-type", action="store_true")
    parser.add_argument("--no-run", action="store_true")
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="run this harness invocation N times and print a pass-rate summary",
    )
    parser.add_argument(
        "--repeat-fail-fast",
        action="store_true",
        help="stop --repeat after the first failing run",
    )
    parser.add_argument("--entry", choices=("basic", "loader", "direct"), default="basic")
    parser.add_argument(
        "--debug-boot-stop",
        choices=("none", "before-copy", "before-jump"),
        default="none",
    )
    parser.add_argument(
        "--debug-loader-stop",
        choices=("none", "entry", "after-read"),
        default="none",
    )
    parser.add_argument("--loader-mount", choices=("cli", "config"), default="cli")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--leave-running", action="store_true")
    parser.add_argument(
        "--long-running",
        action="store_true",
        help="manual session mode: type the BASIC loader, run it, skip capture/screenshot, and leave 86Box running",
    )
    parser.add_argument(
        "--com-capture",
        type=Path,
        default=None,
        help="capture COM1 bytes live through a fixed 86Box FIFO",
    )
    parser.add_argument(
        "--no-screenshot",
        action="store_true",
        help="skip the screencapture step (useful when --com-capture is the only output you need)",
    )
    parser.add_argument(
        "--screenshot-if-pcap-quiet",
        action="store_true",
        help="when --pcap is set, screenshot only if no packets matched after the wait",
    )
    parser.add_argument(
        "--screen-oracle",
        action="store_true",
        help="capture the 86Box window without focusing it and classify DPI/fatal/freeze locally",
    )
    parser.add_argument(
        "--oracle-only",
        action="store_true",
        help="classify the currently visible 86Box window and exit without launching a VM",
    )
    parser.add_argument(
        "--keep-success-oracle-screenshot",
        action="store_true",
        help="keep the local oracle screenshot even when the screen classifier reports success",
    )
    parser.add_argument(
        "--fail-on-screen-oracle",
        action="store_true",
        help="exit non-zero unless --screen-oracle classifies the final VM screen as success",
    )
    parser.add_argument(
        "--screen-expect-text",
        action="append",
        default=[],
        help="require OCR from the final --screen-oracle capture to contain this text; repeatable",
    )
    parser.add_argument(
        "--no-screen-ocr",
        action="store_true",
        help="disable local OCR on final screen captures",
    )
    parser.add_argument(
        "--screen-ocr-success",
        action="store_true",
        help="deprecated no-op; successful screen-oracle captures are OCRed by default",
    )
    parser.add_argument(
        "--screen-ocr-timeout",
        type=float,
        default=8.0,
        help="seconds to allow local OCR for screen-oracle captures",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help="run `sudo -n tcpdump` in parallel and capture packets here; requires `/etc/sudoers.d/*` NOPASSWD for tcpdump",
    )
    parser.add_argument(
        "--pcap-filter",
        default="tcp or arp",
        help="BPF filter expression for the pcap capture (default: tcp or arp)",
    )
    parser.add_argument(
        "--pcap-report-filter",
        default=None,
        help="optional tcpdump display filter applied only when decoding the saved pcap",
    )
    parser.add_argument(
        "--pcap-max-lines",
        type=int,
        default=80,
        help="maximum decoded pcap lines to print (default: 80; full capture remains in the pcap file)",
    )
    parser.add_argument(
        "--pcap-iface",
        default="en0",
        help="interface to capture on (default: en0)",
    )
    parser.add_argument(
        "--test-lock",
        type=Path,
        default=None,
        help="optional VM coordination lock path; disabled by default",
    )
    parser.add_argument(
        "--test-lock-name",
        default="codex",
        help="name written into the VM coordination lock (default: codex)",
    )
    parser.add_argument(
        "--test-lock-timeout",
        type=float,
        default=900.0,
        help="seconds to wait for the VM coordination lock (default: 900)",
    )
    parser.add_argument(
        "--no-test-lock",
        action="store_true",
        help="deprecated no-op; locks are disabled unless --test-lock is passed",
    )
    parser.add_argument(
        "--no-restore-focus",
        action="store_true",
        help="deprecated no-op; focus restore is disabled by default",
    )
    parser.add_argument(
        "--restore-focus",
        action="store_true",
        help="restore the previously frontmost app after launching 86Box",
    )
    parser.add_argument(
        "--foreground-launch",
        action="store_true",
        help="launch 86Box directly instead of using macOS background open(1)",
    )
    parser.add_argument(
        "--allow-existing-86box",
        action="store_true",
        help="do not close existing 86Box processes for the same VM path before launch",
    )
    parser.add_argument(
        "--sound",
        action="store_true",
        help="leave 86Box sound enabled; harness runs are muted by default",
    )
    args = parser.parse_args()
    validate_post_dpi_expectations(
        args.post_dpi_text,
        args.post_dpi_expect_text,
        screen_oracle=args.screen_oracle,
        no_screen_ocr=args.no_screen_ocr,
    )
    if args.attest_rtc_utc:
        args.floppy_read_only = True
    if args.long_running:
        args.leave_running = True
        args.no_screenshot = True
        if args.capture_delay is None:
            args.capture_delay = 0
    if args.floppy_read_only and args.leave_running:
        raise SystemExit(
            "--floppy-read-only cannot be combined with "
            "--leave-running or --long-running"
        )

    if args.repeat > 1:
        return run_repeat(args)

    if args.oracle_only:
        oracle_vm_path = args.vm_path or (ROOT / "targets/ibm_pc_5150/86box" / args.profile)
        oracle_pids = sorted(matching_86box_pids(oracle_vm_path))
        oracle_pid = oracle_pids[-1] if len(oracle_pids) == 1 else None
        if len(oracle_pids) > 1:
            print(
                "screen oracle: ambiguous "
                f"(multiple matching 86Box processes: {', '.join(str(pid) for pid in oracle_pids)})"
            )
            return 2 if args.fail_on_screen_oracle else 0
        if not screenshot_86box_window_or_screen(args.oracle_screenshot, args.profile, oracle_pid):
            print("screen oracle: ambiguous (could not capture 86Box window)")
            return 2 if args.fail_on_screen_oracle else 0
        try:
            oracle_verdict, oracle_detail = classify_86box_screen(args.oracle_screenshot)
        except (OSError, ValueError) as exc:
            oracle_verdict, oracle_detail = "ambiguous", str(exc)
        print(f"screen oracle: {oracle_verdict} ({oracle_detail})")
        maybe_print_screen_ocr(args, "screen oracle", args.oracle_screenshot)
        if oracle_verdict == "success" and not args.keep_success_oracle_screenshot:
            args.oracle_screenshot.unlink(missing_ok=True)
        elif oracle_verdict != "success":
            print(f"screen oracle: kept {args.oracle_screenshot}")
        return 2 if args.fail_on_screen_oracle and oracle_verdict != "success" else 0

    # Entry mode drives timing/typing defaults independently of memory size.
    # ROM BASIC sidecar typing needs a longer prompt wait and the AppleScript
    # focus dance; direct loader/BIOS-boot entries don't type anything and
    # don't need to steal window focus from the user.
    if args.entry == "basic":
        if args.startup_delay is None:
            args.startup_delay = DEFAULT_BASIC_STARTUP_DELAY
        if args.capture_delay is None:
            args.capture_delay = DEFAULT_BASIC_CAPTURE_DELAY
        if args.ram_kib is None:
            args.ram_kib = 16
    else:
        if args.startup_delay is None:
            args.startup_delay = DEFAULT_DIRECT_STARTUP_DELAY
        if args.capture_delay is None:
            args.capture_delay = DEFAULT_DIRECT_CAPTURE_DELAY
        args.no_type = True

    if not args.no_build:
        run(["make"], cwd=ROOT)
        run(["make", "basic-bootstrap"], cwd=ROOT)

    if not args.floppy.exists():
        raise SystemExit(f"missing floppy image: {args.floppy}")
    args.floppy = args.floppy.resolve()
    if args.entry == "basic" and not args.basic.exists():
        raise SystemExit(f"missing BASIC bootstrap: {args.basic}")
    if (
        args.entry == "basic"
        and args.debug_loader_stop != "none"
        and not args.basic_loader.exists()
    ):
        raise SystemExit(f"missing BASIC loader binary: {args.basic_loader}")
    if args.entry == "loader" and not args.loader.exists():
        raise SystemExit(f"missing BASIC loader binary: {args.loader}")
    args.loader_floppy = args.loader_floppy.resolve()

    basic_text = ""
    run_text = ""
    if args.entry == "basic":
        if args.debug_loader_stop == "none":
            basic_text = args.basic.read_text(encoding="ascii").replace("\r\n", "\n")
        else:
            loader_bytes = patch_loader_debug_stop(
                args.basic_loader.read_bytes(),
                args.debug_loader_stop,
            )
            basic_text = basic_text_from_loader(loader_bytes)
        basic_text = basic_text.rstrip() + "\n"
        if not args.no_run:
            run_text = "RUN\n"

    floppy = args.floppy
    image_args: list[str] | None = None
    restore_config: tuple[Path, bytes] | None = None
    restore_nvr: tuple[Path, bytes] | None = None
    vm_path = (
        args.vm_path
        or (ROOT / "targets/ibm_pc_5150/86box" / args.profile)
    ).resolve()
    if not vm_path.is_dir():
        raise SystemExit(f"missing 86Box profile: {vm_path}")
    validate_rtc_utc_attestation(
        enabled=args.attest_rtc_utc,
        entry=args.entry,
        ram_kib=args.ram_kib,
        machine_settings=vm_config_section(
            vm_path / "86box.cfg",
            "[Machine]",
        ),
        screen_ocr_disabled=args.no_screen_ocr,
        prompt_timeout=args.rtc_prompt_timeout,
        answer_timeout=args.rtc_answer_timeout,
        interval=args.rtc_prompt_interval,
        leave_running=args.leave_running,
        long_running=args.long_running,
    )
    validate_vm_ram_override(vm_path, args.ram_kib)
    test_lock_path = args.test_lock
    if args.attest_rtc_utc and test_lock_path is None:
        test_lock_path = vm_path / ".seed-rtc-utc.lock"
    test_lock: TestLock | None = None
    if test_lock_path is not None and (
        args.attest_rtc_utc or not args.no_test_lock
    ):
        test_lock = TestLock(
            test_lock_path,
            args.test_lock_name,
            args.profile,
            args.test_lock_timeout,
        )

    if test_lock is not None:
        test_lock.acquire()

    com_capture: ComCapture | None = None
    pcap_capture: PcapCapture | None = None
    floppy_media: tuple[Path, int, str] | None = None
    try:
        # The lock must cover every externally visible VM mutation, including
        # stopping a prior instance and rewriting config/NVR state.
        if not args.allow_existing_86box:
            stop_matching_86box_pids(vm_path)

        com_passthrough = args.com_capture is not None
        com_pipe_base = (
            args.com_capture.resolve().with_suffix(
                args.com_capture.suffix + ".pipe"
            )
            if args.com_capture is not None
            else None
        )

        if args.entry == "loader":
            floppy = args.loader_floppy
            floppy.parent.mkdir(parents=True, exist_ok=True)
            make_loader_boot_floppy(
                args.floppy,
                args.loader,
                floppy,
                args.debug_boot_stop,
                args.debug_loader_stop,
            )
            # Read-only and COM runs need a config mount so 86Box can enforce
            # the drive's write-protect bit.
            if (
                args.loader_mount == "config"
                or com_passthrough
                or args.floppy_read_only
            ):
                config = vm_path / "86box.cfg"
                restore_config = (config, config.read_bytes())
                rewrite_vm_config(
                    config,
                    args.ram_kib,
                    floppy,
                    False,
                    com_pipe_base=com_pipe_base,
                    muted=not args.sound,
                    attest_rtc_utc=args.attest_rtc_utc,
                    floppy_read_only=args.floppy_read_only,
                )
                restore_nvr = snapshot_vm_nvr(vm_path, args.ram_kib)
                apply_vm_nvr_override(restore_nvr, args.ram_kib)
            else:
                image_args = [f"A:{floppy}"]
        elif args.entry == "basic":
            config = vm_path / "86box.cfg"
            restore_config = (config, config.read_bytes())
            rewrite_vm_config(
                config,
                args.ram_kib,
                floppy,
                True,
                rom_basic_drive=args.basic_drive,
                com_pipe_base=com_pipe_base,
                muted=not args.sound,
                attest_rtc_utc=args.attest_rtc_utc,
                floppy_read_only=args.floppy_read_only,
            )
            # The config rewrite supplies drive geometry and the guest
            # write-protect bit, but 86Box 6 can silently retain an empty
            # drive when opening an older profile.  Its command-line image
            # override is applied after config_load(), so bind the exact
            # sidecar drive there as well.  This also makes a mount failure
            # occur before BASIC injection instead of surfacing later as the
            # bootstrap's intentionally terse red X.
            image_args = [f"{args.basic_drive.upper()}:{floppy}"]
            restore_nvr = snapshot_vm_nvr(vm_path, args.ram_kib)
            apply_vm_nvr_override(restore_nvr, args.ram_kib)
        elif args.entry == "direct":
            # Direct BIOS floppy boot: main floppy in A: (rom_basic=False), no sidecar.
            # A >=32K machine boots Seed straight from A:, giving ram_top 0x8000 and the
            # full-size context window - the only way to exercise the big-window send path.
            image_args = [f"A:{floppy}"]
            config = vm_path / "86box.cfg"
            restore_config = (config, config.read_bytes())
            rewrite_vm_config(
                config,
                args.ram_kib,
                floppy,
                False,
                com_pipe_base=com_pipe_base,
                muted=not args.sound,
                attest_rtc_utc=args.attest_rtc_utc,
                floppy_read_only=args.floppy_read_only,
            )
            restore_nvr = snapshot_vm_nvr(vm_path, args.ram_kib)
            apply_vm_nvr_override(restore_nvr, args.ram_kib)

        if args.attest_rtc_utc:
            assert restore_config is not None
            require_exact_rtc_utc_machine(
                restore_config[0],
                expected_ram_kib=RTC_UTC_ATTEST_RAM_KIB,
                phase="post-rewrite",
            )
            require_attested_floppy_config(
                restore_config[0],
                rom_basic=args.entry == "basic",
            )

        if args.floppy_read_only:
            floppy_media = snapshot_floppy_media(floppy)
            make_floppy_read_only(floppy_media)

        if args.com_capture is not None:
            assert com_pipe_base is not None
            com_capture = ComCapture(args.com_capture.resolve(), com_pipe_base)

        if args.pcap is not None:
            pcap_capture = PcapCapture(
                args.pcap,
                args.pcap_filter,
                args.pcap_iface,
                args.pcap_report_filter,
                args.pcap_max_lines,
            )
    except BaseException:
        restore_harness_state(
            com_capture=com_capture,
            pcap_capture=pcap_capture,
            restore_config=restore_config,
            restore_nvr=restore_nvr,
            floppy_media=floppy_media,
            test_lock=test_lock,
        )
        raise

    exit_code = 0
    try:
        previous_frontmost = (
            frontmost_process_name() if args.restore_focus else None
        )
        launch_started_at = time.monotonic()
        if com_capture is not None:
            com_capture.start()
        process = launch_86box(
            vm_path,
            image_args,
            capture_stdout=False,
            background=not args.foreground_launch,
            detached=args.long_running and com_capture is None,
        )
        needs_window_oracle = args.screen_oracle or bool(args.post_dpi_text)
        needs_window = needs_window_oracle or (
            args.entry == "basic" and not args.no_type
        )
        if (
            needs_window
            and not wait_for_86box_window_or_identity_dialog(
                args.profile,
                process.pid,
            )
        ):
            print(
                "harness: launched 86Box has no capturable window; "
                "retrying direct launch",
                flush=True,
            )
            process.kill()
            process.wait(timeout=5)
            process = launch_86box(
                vm_path,
                image_args,
                capture_stdout=False,
                background=False,
                detached=args.long_running and com_capture is None,
            )
            if not wait_for_86box_window_or_identity_dialog(
                args.profile,
                process.pid,
            ):
                print(
                    "harness: direct 86Box launch still has no capturable window",
                    flush=True,
                )
        if (
            args.attest_rtc_utc
            and args.screen_oracle
            and not args.no_screen_ocr
            and not bypass_ami286_memory_test(args, process)
        ):
            raise RuntimeError("exact-floor AMI286 POST bypass failed")
        restore_frontmost_process(previous_frontmost)
        try:
            time.sleep(args.startup_delay)
            if args.entry == "basic" and not args.no_type and args.mode != "pidkeycode":
                activate_86box()
            if args.entry == "basic" and not args.no_type and args.mode == "pidkeycode":
                if args.pidkeycode_background:
                    pass
            if args.entry != "basic" or args.no_type:
                pass
            elif args.mode == "paste":
                paste_basic(basic_text)
            elif args.mode == "text":
                type_basic_text(basic_text, args.line_delay)
            elif args.mode == "chars":
                type_basic_chars(basic_text, args.type_delay, args.line_delay)
            elif args.mode == "pidkeycode":
                type_basic_pid_keycodes(process.pid, basic_text, args.type_delay, args.line_delay)
            else:
                type_basic_keycodes(basic_text, args.type_delay, args.line_delay)
            if run_text:
                time.sleep(max(1.0, args.line_delay * 2))
                if args.mode == "paste":
                    paste_basic(run_text)
                elif args.mode == "text":
                    type_basic_text(run_text, args.line_delay)
                elif args.mode == "chars":
                    type_basic_chars(run_text, args.type_delay, args.line_delay)
                elif args.mode == "pidkeycode":
                    type_basic_pid_keycodes(process.pid, run_text, args.type_delay, args.line_delay)
                else:
                    type_basic_keycodes(run_text, args.type_delay, args.line_delay)
            if pcap_capture is not None:
                pcap_capture.start()
            platform_clock_ready = True
            https_remotes = wait_with_process_https_sampling(
                process, args.capture_delay
            )
            if https_remotes:
                print("process: 86Box HTTPS remotes: " + ", ".join(sorted(https_remotes)))
            oracle_verdict = None
            if args.post_dpi_text and platform_clock_ready:
                if args.post_dpi_at is not None:
                    remaining = launch_started_at + args.post_dpi_at - time.monotonic()
                    if remaining > 0:
                        time.sleep(remaining)
                    for index, post_dpi_text in enumerate(args.post_dpi_text, start=1):
                        prior_prompt_crc = (
                            capture_response_area_crc(args, process)
                            if args.post_dpi_expect_text
                            else None
                        )
                        if not post_dpi_text.endswith(("\n", "\r")):
                            post_dpi_text += "\n"
                        type_basic_pid_keycodes(
                            process.pid,
                            post_dpi_text,
                            args.type_delay,
                            args.line_delay,
                        )
                        print(
                            f"post-DPI {index}: submitted {len(post_dpi_text.rstrip())} chars",
                            flush=True,
                        )
                        more_remotes = wait_with_process_https_sampling(
                            process,
                            args.post_dpi_wait,
                        )
                        https_remotes.update(more_remotes)
                        if more_remotes:
                            print(
                                f"process: post-DPI {index} 86Box HTTPS remotes: "
                                + ", ".join(sorted(more_remotes))
                            )
                        if args.post_dpi_expect_text and not wait_for_dpi_prompt(
                            args,
                            process,
                            f"post-DPI expected-response gate {index}",
                            args.post_dpi_gate_timeout,
                            args.post_dpi_gate_interval,
                            prior_prompt_crc,
                            args.post_dpi_expect_text[index - 1],
                        ):
                            exit_code = 2
                            break
                    oracle_verdict = None
                elif not args.screen_oracle:
                    print("--post-dpi-text requires --screen-oracle", file=sys.stderr)
                    exit_code = 2
                else:
                    post_dpi_gate_failed = False
                    prior_prompt_crc: int | None = None
                    for index, post_dpi_text in enumerate(args.post_dpi_text, start=1):
                        expected_previous_response = (
                            args.post_dpi_expect_text[index - 2]
                            if args.post_dpi_expect_text and index > 1
                            else None
                        )
                        if not wait_for_dpi_prompt(
                            args,
                            process,
                            f"post-DPI gate {index}",
                            args.post_dpi_gate_timeout,
                            args.post_dpi_gate_interval,
                            prior_prompt_crc,
                            expected_previous_response,
                        ):
                            post_dpi_gate_failed = True
                            if (
                                args.fail_on_screen_oracle
                                or expected_previous_response is not None
                            ):
                                exit_code = 2
                            break
                        prior_prompt_crc = capture_response_area_crc(args, process)
                        if args.post_dpi_idle > 0:
                            print(
                                f"post-DPI {index}: idling {args.post_dpi_idle:.0f}s to force keep-alive close (real reconnect)",
                                flush=True,
                            )
                            time.sleep(args.post_dpi_idle)
                        if not post_dpi_text.endswith(("\n", "\r")):
                            post_dpi_text += "\n"
                        type_basic_pid_keycodes(
                            process.pid,
                            post_dpi_text,
                            args.type_delay,
                            args.line_delay,
                        )
                        print(
                            f"post-DPI {index}: submitted {len(post_dpi_text.rstrip())} chars",
                            flush=True,
                        )
                        more_remotes = wait_with_process_https_sampling(
                            process,
                            args.post_dpi_wait,
                        )
                        https_remotes.update(more_remotes)
                        if more_remotes:
                            print(
                                f"process: post-DPI {index} 86Box HTTPS remotes: "
                                + ", ".join(sorted(more_remotes))
                            )
                        oracle_verdict = None
                    if not post_dpi_gate_failed:
                        if not wait_for_dpi_prompt(
                            args,
                            process,
                            "post-DPI final gate",
                            args.post_dpi_gate_timeout,
                            args.post_dpi_gate_interval,
                            prior_prompt_crc,
                            (
                                args.post_dpi_expect_text[-1]
                                if args.post_dpi_expect_text
                                else None
                            ),
                        ):
                            if (
                                args.fail_on_screen_oracle
                                or args.post_dpi_expect_text
                            ):
                                exit_code = 2
            if args.screen_oracle:
                oracle_verdict, _ = classify_running_vm(args, process, "screen oracle")
                if args.fail_on_screen_oracle and oracle_verdict != "success":
                    exit_code = 2
            conditional_pcap_screenshot = (
                args.screenshot_if_pcap_quiet
                and pcap_capture is not None
                and not args.no_screenshot
                and oracle_verdict is None
            )
            if conditional_pcap_screenshot:
                pcap_capture.stop()
                report_lines = None
                if https_remotes:
                    dynamic_report_filter = " or ".join(f"host {host}" for host in sorted(https_remotes))
                    saved_report_filter = pcap_capture.report_filter
                    pcap_capture.report_filter = dynamic_report_filter
                    report_lines = pcap_capture.decoded_lines(report=True)
                    pcap_capture.report_filter = saved_report_filter
                elif pcap_capture.report_filter:
                    report_lines = pcap_capture.decoded_lines(report=True)
                quiet = report_lines is None or len(report_lines) == 0
                if quiet:
                    print("pcap: no matching VM-specific TLS flow; taking screenshot before closing VM")
                    try:
                        screenshot_86box_window_or_screen(args.screenshot, args.profile, process.pid)
                        print(f"screenshot: {args.screenshot}")
                        maybe_print_screen_ocr(args, "screenshot", args.screenshot)
                    except subprocess.CalledProcessError as exc:
                        print(f"screenshot: failed ({exc})", file=sys.stderr)
                else:
                    matched = 0 if report_lines is None else len(report_lines)
                    if matched:
                        print(f"pcap: {matched} report-filtered packets; skipping screenshot")
            elif not args.no_screenshot:
                try:
                    screenshot_86box_window_or_screen(args.screenshot, args.profile, process.pid)
                    print(f"screenshot: {args.screenshot}")
                    maybe_print_screen_ocr(args, "screenshot", args.screenshot)
                except subprocess.CalledProcessError as exc:
                    print(f"screenshot: failed ({exc})", file=sys.stderr)
        finally:
            if not args.leave_running:
                process.kill()
                process.wait(timeout=5)
    finally:
        # COM capture starts before launch so 86Box's nonblocking FIFO writer
        # always finds a reader. Finish it here, after the VM writer has
        # stopped, so launch/window failures cannot leak FIFOs and queued
        # terminal bytes are drained to EOF. The same cleanup also restores
        # config/NVR/media byte-for-byte and releases the VM lock.
        restore_harness_state(
            com_capture=com_capture,
            pcap_capture=pcap_capture,
            restore_config=restore_config,
            restore_nvr=restore_nvr,
            floppy_media=floppy_media,
            test_lock=test_lock,
        )

    if pcap_capture is not None:
        pcap_capture.analyze()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
