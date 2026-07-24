#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import os
import re
import shutil
import signal
import subprocess
import struct
import sys
import tempfile
import termios
import threading
import time
import tty
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

PTY_PATH_RE = re.compile(r"serial_passthrough:\s*Slave side is\s*(/dev/ttys\d+)")


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
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(self.content)
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

    def post_raw_key(key_code: int, text: str | None = None) -> None:
        for pressed in (True, False):
            event = cg.CGEventCreateKeyboardEvent(None, key_code, pressed)
            if not event:
                raise SystemExit("CGEventCreateKeyboardEvent failed")
            try:
                if pressed and text:
                    chars = (ctypes.c_uint16 * len(text))(*[ord(char) for char in text])
                    cg.CGEventKeyboardSetUnicodeString(event, len(text), chars)
                cg.CGEventPostToPid(pid, event)
            finally:
                cf.CFRelease(event)

    def post_key(key_code: int, shifted: bool, text: str) -> None:
        if not shifted:
            post_raw_key(key_code, text)
            return
        shift_code = 56
        chord_delay = min(0.01, max(0.002, key_delay / 3.0))
        shift_down = cg.CGEventCreateKeyboardEvent(None, shift_code, True)
        shift_up = cg.CGEventCreateKeyboardEvent(None, shift_code, False)
        if not shift_down or not shift_up:
            raise SystemExit("CGEventCreateKeyboardEvent failed")
        try:
            cg.CGEventPostToPid(pid, shift_down)
            time.sleep(chord_delay)
            post_raw_key(key_code, text)
            time.sleep(chord_delay)
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


class ComCapture:
    """Reads 86Box stdout for the passthrough PTY path then streams bytes off the PTY.

    86Box prints a line like `serial_passthrough: Slave side is /dev/ttysNNN`
    when `serial1_passthrough_enabled = 1` is set in the VM cfg. We open that
    PTY and accumulate whatever the guest writes to COM1 (port 0x3F8).
    """

    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.pty_path: str | None = None
        self.pty_open_time: float | None = None
        self.start_time: float = 0.0
        self.stdout_thread: threading.Thread | None = None
        self.pty_thread: threading.Thread | None = None

    def start(self, process: subprocess.Popen) -> None:
        self.stdout_thread = threading.Thread(
            target=self._read_stdout, args=(process,), daemon=True
        )
        self.stdout_thread.start()

    def _read_stdout(self, process: subprocess.Popen) -> None:
        log_path = self.output_path.with_suffix(self.output_path.suffix + ".86box.log")
        try:
            log_file = open(log_path, "w")
        except OSError:
            log_file = None
        try:
            assert process.stdout is not None
            for line in iter(process.stdout.readline, ""):
                if self.stop_event.is_set():
                    break
                if log_file is not None:
                    log_file.write(f"[{time.monotonic():.3f}] {line}")
                    log_file.flush()
                match = PTY_PATH_RE.search(line)
                if match and self.pty_path is None:
                    self.pty_path = match.group(1)
                    self.pty_open_time = time.monotonic()
                    print(f"com capture: PTY {self.pty_path} announced at t={self.pty_open_time:.2f}s")
                    self.pty_thread = threading.Thread(
                        target=self._read_pty, daemon=True
                    )
                    self.pty_thread.start()
        except (ValueError, OSError):
            pass
        finally:
            if log_file is not None:
                log_file.close()

    def _read_pty(self) -> None:
        assert self.pty_path is not None
        try:
            fd = os.open(self.pty_path, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
        except OSError as exc:
            print(
                f"com capture: could not open PTY {self.pty_path}: {exc}",
                file=sys.stderr,
            )
            return
        try:
            # PTY slaves default to cooked / line-discipline mode on macOS,
            # which filters binary bytes. Put into raw mode so all bytes pass.
            try:
                tty.setraw(fd, termios.TCSANOW)
            except termios.error as exc:
                print(f"com capture: tty.setraw failed: {exc}", file=sys.stderr)
            while not self.stop_event.is_set():
                try:
                    chunk = os.read(fd, 4096)
                    if chunk:
                        with self.lock:
                            self.buf.extend(chunk)
                    else:
                        time.sleep(0.05)
                except BlockingIOError:
                    time.sleep(0.05)
                except OSError:
                    break
        finally:
            os.close(fd)

    def finish(self) -> None:
        self.stop_event.set()
        time.sleep(0.2)
        if self.stdout_thread is not None:
            self.stdout_thread.join(timeout=2)
        if self.pty_thread is not None:
            self.pty_thread.join(timeout=2)
        with self.lock:
            data = bytes(self.buf)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_bytes(data)
        print(f"com capture: {len(data)} byte(s) -> {self.output_path}")
        if self.pty_path is None:
            print(
                "com capture: WARNING - never observed a 'serial_passthrough: "
                "Slave side is /dev/ttysNNN' line in 86Box stdout"
            )
            return
        if not data:
            print(
                f"com capture: PTY {self.pty_path} opened but no bytes received"
            )
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


def ensure_com_passthrough(lines: list[str]) -> list[str]:
    """Ensure cfg has `serial1_passthrough_enabled = 1` under [Ports (COM & LPT)]."""
    result: list[str] = []
    in_ports = False
    saw_key = False
    section_present = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_ports and not saw_key:
                result.append("serial1_passthrough_enabled = 1")
                saw_key = True
            in_ports = stripped == "[Ports (COM & LPT)]"
            if in_ports:
                section_present = True
            result.append(line)
            continue
        if in_ports and stripped.startswith("serial1_passthrough_enabled"):
            result.append("serial1_passthrough_enabled = 1")
            saw_key = True
            continue
        result.append(line)

    if in_ports and not saw_key:
        result.append("serial1_passthrough_enabled = 1")
        saw_key = True

    if not section_present:
        if result and result[-1].strip() != "":
            result.append("")
        result.append("[Ports (COM & LPT)]")
        result.append("serial1_passthrough_enabled = 1")

    return result


def rewrite_vm_config(
    config: Path,
    ram_kib: int | None,
    floppy: Path,
    rom_basic: bool,
    com_passthrough: bool = False,
    muted: bool = True,
) -> None:
    lines = config.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_general_section = False
    in_floppy_section = False
    wrote_sound_muted = False
    wrote_sound_gain = False
    wrote_fdd1_fn = False
    wrote_fdd2_check = False
    wrote_fdd2_fn = False
    wrote_fdd2_type = False
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

    def flush_floppy_tail():
        # Called when leaving the floppy section. Append any keys we still
        # need that weren't already written from the source iteration.
        if not rom_basic and not wrote_fdd1_fn:
            out.append(f"fdd_01_fn = {floppy}")
        if rom_basic and not wrote_fdd2_check:
            out.append("fdd_02_check_bpb = 0")
        if rom_basic and not wrote_fdd2_fn:
            out.append(f"fdd_02_fn = {floppy}")
        if not wrote_fdd2_type:
            out.append("fdd_02_type = 525_1dd" if rom_basic else "fdd_02_type = none")

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_general_section:
                flush_general_tail()
            if in_floppy_section:
                flush_floppy_tail()
            in_general_section = stripped == "[General]"
            in_floppy_section = stripped == "[Floppy and CD-ROM drives]"
            wrote_sound_muted = False
            wrote_sound_gain = False
            wrote_fdd1_fn = False
            wrote_fdd2_check = False
            wrote_fdd2_fn = False
            wrote_fdd2_type = False
            wrote_video_filter = False
            out.append(line)
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
                if rom_basic:
                    continue
                out.append(line)
                continue
            if stripped.startswith("fdd_01_fn ="):
                if not rom_basic:
                    out.append(f"fdd_01_fn = {floppy}")
                    wrote_fdd1_fn = True
                continue
            if stripped.startswith("fdd_01_type ="):
                out.append("fdd_01_type = none" if rom_basic else f"fdd_01_type = {direct_fdd_type}")
                continue
            if stripped.startswith("fdd_02_check_bpb ="):
                if not rom_basic:
                    continue
                out.append("fdd_02_check_bpb = 0")
                wrote_fdd2_check = True
                continue
            if stripped.startswith("fdd_02_fn ="):
                if not rom_basic:
                    continue
                out.append(f"fdd_02_fn = {floppy}")
                wrote_fdd2_fn = True
                continue
            if stripped.startswith("fdd_02_type ="):
                if not rom_basic:
                    out.append("fdd_02_type = none")
                    wrote_fdd2_type = True
                    continue
                out.append("fdd_02_type = 525_1dd")
                wrote_fdd2_type = True
                continue

        out.append(line)

    if in_floppy_section:
        flush_floppy_tail()
    if in_general_section:
        flush_general_tail()

    if com_passthrough:
        out = ensure_com_passthrough(out)

    config.write_text("\n".join(out) + "\n", encoding="utf-8")


def vm_machine_name(config: Path) -> str | None:
    in_machine_section = False
    for line in config.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_machine_section = stripped == "[Machine]"
            continue
        if in_machine_section and stripped.startswith("machine ="):
            return stripped.split("=", 1)[1].strip()
    return None


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


def prepare_vm_nvr(vm_path: Path, ram_kib: int | None) -> tuple[Path, bytes] | None:
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
    restore = (nvr, nvr.read_bytes())
    if ram_kib is not None:
        cmos = at_cmos(ram_kib, machine)
        if cmos is not None:
            nvr.write_bytes(cmos)
    return restore


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
        f"10 CLEAR ,{BASIC_BOOTSTRAP_CLEAR_TOP}:DEF SEG=0:P={BASIC_BOOTSTRAP_ADDR}",
        f"20 FOR K=0 TO {len(chunks) - 1}:READ A$,N",
        "30 FOR I=0 TO N-1:J=I*2+1",
        '40 POKE P+I,VAL("&H"+MID$(A$,J,2))',
        "50 NEXT I:P=P+N:NEXT K",
        f"60 DEF USR0={BASIC_BOOTSTRAP_ADDR}:A=USR0(0)",
    ]
    line_no = 70
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

    def __init__(self, pid: int):
        self.pid = pid
        self.stdout = None

    def poll(self) -> int | None:
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return 0
        except PermissionError:
            return None
        return None

    def kill(self) -> None:
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
                    return ExternalProcess(created[-1])
                time.sleep(0.1)
            current = sorted(matching_86box_pids(vm_path))
            if current:
                return ExternalProcess(current[-1])
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


def accept_moved_or_copied_dialog() -> bool:
    """Dismiss 86Box's first-run/moved VM identity dialog non-interactively."""
    script = """
try
  tell application "86Box" to activate
end try
delay 0.05
tell application "System Events"
  if not (exists process "86Box") then return "none"
  tell process "86Box"
    repeat with oneWindow in windows
      try
        if exists button "I Copied It" of oneWindow then
          click button "I Copied It" of oneWindow
          return "accepted"
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
          return "accepted"
        end if
      end try
    end repeat
  end tell
end tell
return "none"
"""
    result = subprocess.run(
        ["osascript", "-e", script],
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
        window_id = find_86box_window_id(profile, pid)
        if window_id is None and pid is not None:
            window_id = find_86box_window_id(profile, None)
        if window_id is not None:
            return True
        if accept_moved_or_copied_dialog():
            print("harness: accepted 86Box moved/copied identity dialog", flush=True)
        time.sleep(0.2)
    return False


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

        # kCGWindowListOptionOnScreenOnly == 1. The list includes occluded
        # windows, so this still works when the user puts another window on top.
        window_list = cg.CGWindowListCopyWindowInfo(1, 0)
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
    """Capture the 86Box window by id. This does not activate or raise it."""
    window_id = find_86box_window_id(profile, pid)
    if window_id is None and pid is not None:
        window_id = find_86box_window_id(profile, None)
    if window_id is None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["screencapture", "-x", "-o", f"-l{window_id}", str(path)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and path.exists() and path.stat().st_size > 0


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
    - red text in the main display means a clean Seed fatal error screen;
    - gray text on an otherwise dark display is the known freeze class;
    - anything else is ambiguous and should keep the screenshot for inspection.
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
                if lower_y0 <= y <= lower_y1:
                    lower_bright_pixels += 1
            elif r > 45 or g > 45 or b > 45:
                non_dark_pixels += 1
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
        engine, lines = screen_ocr_lines(args.oracle_screenshot, args.screen_ocr_timeout)

    verdict = shape_verdict
    detail = shape_detail
    if lines and ocr_lines_suggest_rom_basic(lines):
        verdict = "bootstrap-failure"
        detail = f"ocr_{engine or 'unknown'}_rom_basic"
    if verdict == "ambiguous":
        if ocr_lines_suggest_dpi_ready(lines):
            verdict = "success"
            detail = f"ocr_{engine or 'unknown'}_dpi"
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


def wait_for_dpi_prompt(
    args: argparse.Namespace,
    process: subprocess.Popen[str],
    label: str,
    timeout: float,
    interval: float,
    changed_from_crc: int | None = None,
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
            last_engine, last_lines = screen_ocr_lines(
                args.oracle_screenshot,
                args.screen_ocr_timeout,
            )
            if ocr_lines_suggest_seed_failure_menu(last_lines):
                print(f"{label}: failure menu before DPI prompt")
                print_screen_ocr_lines(label, last_engine, last_lines)
                print(f"{label}: kept {args.oracle_screenshot}")
                return False
            if last_shape[0] == "clean-failure":
                print(f"{label}: clean failure before DPI prompt ({last_shape[1]})")
                print_screen_ocr_lines(label, last_engine, last_lines)
                print(f"{label}: kept {args.oracle_screenshot}")
                return False
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
            if (
                candidate_crc is not None
                and visual_candidate_crc is not None
                and candidate_crc != visual_candidate_crc
            ):
                visual_candidate_crc = None
                visual_candidate_count = 0
            prompt_candidate = visual_prompt or ocr_prompt
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
                prompt_ready = prompt_ready and response_changed
            else:
                visual_candidate_crc = None
                visual_candidate_count = 0
            if prompt_ready:
                print(
                    f"{label}: DPI prompt ready "
                    f"(shape={last_shape[0]} {last_shape[1]}, "
                    f"ocr={last_engine or 'none'}, ocr_prompt={ocr_prompt}, "
                    f"visual_prompt={visual_prompt}, visual_count={visual_candidate_count})"
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
                    f"changed={changed_detail})"
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


def ocr_lines_suggest_seed_failure_menu(lines: list[str]) -> bool:
    joined = " ".join(line.strip().lower() for line in lines)
    return (
        "failed" in joined
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
    parser.add_argument("--loader", type=Path, default=DEFAULT_LOADER)
    parser.add_argument("--basic-loader", type=Path, default=DEFAULT_BASIC_LOADER)
    parser.add_argument("--floppy", type=Path, default=DEFAULT_FLOPPY)
    parser.add_argument("--loader-floppy", type=Path, default=DEFAULT_LOADER_FLOPPY)
    parser.add_argument("--screenshot", type=Path, default=DEFAULT_SCREENSHOT)
    parser.add_argument("--oracle-screenshot", type=Path, default=DEFAULT_ORACLE_SCREENSHOT)
    parser.add_argument("--ram-kib", type=int, default=None)
    parser.add_argument("--startup-delay", type=float, default=None)
    parser.add_argument("--capture-delay", type=float, default=None)
    parser.add_argument(
        "--post-dpi-text",
        action="append",
        default=[],
        help="after DPI is ready, type this prompt into the same VM and wait for the next response; repeat to send multiple prompts",
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
        default=420.0,
        help="seconds to wait for OCR to see the DPI prompt before each --post-dpi-text (default: 420)",
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
        help="enable serial1 passthrough and capture COM1 bytes to this file",
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
    if args.long_running:
        args.leave_running = True
        args.no_screenshot = True
        if args.capture_delay is None:
            args.capture_delay = 0

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
    vm_path = args.vm_path or (ROOT / "targets/ibm_pc_5150/86box" / args.profile)
    if not vm_path.is_dir():
        raise SystemExit(f"missing 86Box profile: {vm_path}")
    validate_vm_ram_override(vm_path, args.ram_kib)
    if not args.allow_existing_86box:
        stop_matching_86box_pids(vm_path)

    com_passthrough = args.com_capture is not None

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
        # --com-capture requires cfg rewrite to inject the passthrough key,
        # which is also where the floppy gets put in fdd_01 for BIOS boot.
        if args.loader_mount == "config" or com_passthrough:
            config = vm_path / "86box.cfg"
            restore_config = (config, config.read_bytes())
            rewrite_vm_config(
                config,
                args.ram_kib,
                floppy,
                False,
                com_passthrough=com_passthrough,
                muted=not args.sound,
            )
            restore_nvr = prepare_vm_nvr(vm_path, args.ram_kib)
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
            com_passthrough=com_passthrough,
            muted=not args.sound,
        )
        restore_nvr = prepare_vm_nvr(vm_path, args.ram_kib)
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
            com_passthrough=com_passthrough,
            muted=not args.sound,
        )
        restore_nvr = prepare_vm_nvr(vm_path, args.ram_kib)

    com_capture: ComCapture | None = None
    if args.com_capture is not None:
        com_capture = ComCapture(args.com_capture)

    pcap_capture: PcapCapture | None = None
    if args.pcap is not None:
        pcap_capture = PcapCapture(
            args.pcap,
            args.pcap_filter,
            args.pcap_iface,
            args.pcap_report_filter,
            args.pcap_max_lines,
        )

    test_lock: TestLock | None = None
    if args.test_lock is not None and not args.no_test_lock:
        test_lock = TestLock(
            args.test_lock,
            args.test_lock_name,
            args.profile,
            args.test_lock_timeout,
        )

    if test_lock is not None:
        test_lock.acquire()
    exit_code = 0
    previous_frontmost = frontmost_process_name() if args.restore_focus else None
    launch_started_at = time.monotonic()
    try:
        process = launch_86box(
            vm_path,
            image_args,
            capture_stdout=com_capture is not None,
            background=not args.foreground_launch,
            detached=args.long_running and com_capture is None,
        )
        needs_window_oracle = args.screen_oracle or bool(args.post_dpi_text)
        if (
            needs_window_oracle
            and not wait_for_86box_window(args.profile, process.pid)
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
                capture_stdout=com_capture is not None,
                background=False,
                detached=args.long_running and com_capture is None,
            )
            if not wait_for_86box_window(args.profile, process.pid):
                print(
                    "harness: direct 86Box launch still has no capturable window",
                    flush=True,
                )
        restore_frontmost_process(previous_frontmost)
        if com_capture is not None:
            com_capture.start(process)
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
            https_remotes = wait_with_process_https_sampling(process, args.capture_delay)
            if https_remotes:
                print("process: 86Box HTTPS remotes: " + ", ".join(sorted(https_remotes)))
            oracle_verdict = None
            if args.post_dpi_text:
                if args.post_dpi_at is not None:
                    remaining = launch_started_at + args.post_dpi_at - time.monotonic()
                    if remaining > 0:
                        time.sleep(remaining)
                    for index, post_dpi_text in enumerate(args.post_dpi_text, start=1):
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
                elif not args.screen_oracle:
                    print("--post-dpi-text requires --screen-oracle", file=sys.stderr)
                    exit_code = 2
                else:
                    post_dpi_gate_failed = False
                    prior_prompt_crc: int | None = None
                    for index, post_dpi_text in enumerate(args.post_dpi_text, start=1):
                        if not wait_for_dpi_prompt(
                            args,
                            process,
                            f"post-DPI gate {index}",
                            args.post_dpi_gate_timeout,
                            args.post_dpi_gate_interval,
                            prior_prompt_crc,
                        ):
                            post_dpi_gate_failed = True
                            if args.fail_on_screen_oracle:
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
                        ):
                            if args.fail_on_screen_oracle:
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
            if com_capture is not None:
                com_capture.finish()
            if not args.leave_running:
                process.kill()
                process.wait(timeout=5)
    finally:
        if pcap_capture is not None:
            pcap_capture.stop()
        if restore_config is not None:
            restore_config[0].write_bytes(restore_config[1])
        if restore_nvr is not None:
            restore_nvr[0].write_bytes(restore_nvr[1])
        if test_lock is not None:
            test_lock.release()

    if pcap_capture is not None:
        pcap_capture.analyze()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
