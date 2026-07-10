#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import re


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tools" / "run-basic-bootstrap-86box.py"
DEFAULT_OUT_ROOT = ROOT / "build" / "ibm_pc_5150" / "watch"
TCP_ARROW_RE = re.compile(r"\bTCP\s+(.+?)->(.+?)\s+\(([^)]+)\)")


def load_harness():
    spec = importlib.util.spec_from_file_location("seed_86box_harness", HARNESS)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load harness helpers from {HARNESS}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HAR = load_harness()


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def run_text(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)
    return result.returncode, (result.stdout + result.stderr).strip()


def sudo_tcpdump_available() -> tuple[bool, str]:
    tcpdump = shutil.which("tcpdump") or "/usr/sbin/tcpdump"
    if not Path(tcpdump).exists():
        return False, "tcpdump not found"
    rc, out = run_text(["sudo", "-n", tcpdump, "--version"], timeout=3)
    if rc != 0:
        return False, out or f"sudo tcpdump exited {rc}"
    return True, tcpdump


class Logger:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, message: str = "") -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            if message:
                handle.write(f"{stamp()} {message}\n")
            else:
                handle.write("\n")

    def block(self, title: str, body: str) -> None:
        self.write(title)
        with self.path.open("a", encoding="utf-8") as handle:
            for line in body.splitlines() or ["(empty)"]:
                handle.write(f"    {line}\n")


class TcpdumpCapture:
    def __init__(
        self,
        path: Path,
        iface: str,
        filter_expr: str,
        log: Logger,
        rotate_mb: int,
        rotate_files: int,
    ):
        self.path = path
        self.iface = iface
        self.filter_expr = filter_expr
        self.log = log
        self.rotate_mb = rotate_mb
        self.rotate_files = rotate_files
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        available, detail = sudo_tcpdump_available()
        if not available:
            self.log.write(f"pcap disabled: {detail}")
            return
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or "nobody"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            "sudo",
            "-n",
            detail,
            "-i",
            self.iface,
            "-U",
            "-Z",
            user,
        ]
        if self.rotate_mb > 0 and self.rotate_files > 1:
            cmd.extend(["-C", str(self.rotate_mb), "-W", str(self.rotate_files)])
        cmd.extend([
            "-w",
            str(self.path),
            self.filter_expr,
        ])
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        time.sleep(0.6)
        if self.proc.poll() is not None:
            err = ""
            if self.proc.stderr:
                err = self.proc.stderr.read().decode("utf-8", errors="replace").strip()
            self.log.write(f"pcap disabled: tcpdump exited {self.proc.returncode}: {err}")
            self.proc = None
            return
        if self.rotate_mb > 0 and self.rotate_files > 1:
            self.log.write(
                f"pcap capturing iface={self.iface} filter={self.filter_expr!r} "
                f"file={self.path} rotate={self.rotate_mb}MBx{self.rotate_files}"
            )
        else:
            self.log.write(f"pcap capturing iface={self.iface} filter={self.filter_expr!r} file={self.path}")

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            os.killpg(self.proc.pid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.SubprocessError:
                pass
        self.log.write(f"pcap stopped file={self.path}")
        self.proc = None


def sample_lsof(pid: int) -> str:
    rc, out = run_text(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP"], timeout=4)
    if rc != 0 and not out:
        return f"lsof exited {rc}"
    lines = [line.rstrip() for line in out.splitlines() if line.strip()]
    if not lines:
        return "(no TCP sockets)"
    return "\n".join(lines)


def sample_process(pid: int) -> str:
    rc, out = run_text(["ps", "-p", str(pid), "-o", "pid=,etime=,stat=,command="], timeout=3)
    return out if rc == 0 and out else f"ps exited {rc}: {out}"


def endpoint_port(endpoint: str) -> tuple[str, str] | None:
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        close = endpoint.rfind("]:")
        if close < 0:
            return None
        return endpoint[1:close], endpoint[close + 2 :]
    if ":" not in endpoint:
        return None
    host, port = endpoint.rsplit(":", 1)
    return host, port


def tcp_socket_summary(lsof_text: str) -> tuple[str, int]:
    entries: list[tuple[str, str, str]] = []
    for line in lsof_text.splitlines():
        match = TCP_ARROW_RE.search(line)
        if not match:
            continue
        src = endpoint_port(match.group(1))
        dst = endpoint_port(match.group(2))
        state = match.group(3)
        if src is None or dst is None:
            continue
        if dst[1] == "443":
            entries.append((src[1], f"{dst[0]}:{dst[1]}", state))
    entries.sort()
    established_443 = sum(1 for _, _, state in entries if state == "ESTABLISHED")
    if not entries:
        return "remote443=0", 0
    detail = ", ".join(f"{local}->{remote}({state})" for local, remote, state in entries)
    return f"remote443={len(entries)} established={established_443}: {detail}", established_443


def maybe_capture_screen(
    out_dir: Path,
    profile: str,
    pid: int,
    index: int,
    ocr: bool,
    ocr_timeout: float,
    log: Logger,
    reason: str | None = None,
) -> None:
    path = out_dir / f"screen-{index:04d}.png"
    ok = HAR.screenshot_86box_window_or_screen(path, profile, pid)
    if not ok:
        log.write("screen capture failed")
        return
    try:
        verdict, detail = HAR.classify_86box_screen(path)
    except (OSError, ValueError) as exc:
        verdict, detail = "ambiguous", str(exc)
    reason_text = f" {reason}" if reason else ""
    log.write(f"screen {path.name}{reason_text}: {verdict} ({detail})")
    if not ocr:
        return
    engine, lines = HAR.screen_ocr_lines(path, ocr_timeout)
    if lines:
        log.block(f"screen {path.name} OCR ({engine or 'none'})", "\n".join(lines))
    else:
        log.write(f"screen {path.name} OCR: no lines ({engine or 'none'})")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Rootless background watcher for intermittent 86Box/Seed no-response runs."
    )
    ap.add_argument("--profile", default="vm-net-ne2k8")
    ap.add_argument("--vm-path", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between socket samples")
    ap.add_argument("--screen-interval", type=float, default=15.0, help="seconds between screenshots")
    ap.add_argument("--ocr-interval", type=float, default=45.0, help="seconds between OCR passes")
    ap.add_argument("--ocr-timeout", type=float, default=6.0)
    ap.add_argument("--max-open-443", type=int, default=1, help="warn above this many ESTABLISHED 86Box TCP/443 sockets")
    ap.add_argument("--no-socket-change-screen", action="store_true", help="do not screenshot immediately when the 86Box TCP socket set changes")
    ap.add_argument("--no-socket-change-ocr", action="store_true", help="do not OCR immediate socket-change screenshots")
    ap.add_argument("--duration", type=float, default=0.0, help="seconds to run; 0 means until stopped")
    ap.add_argument("--pcap", action="store_true", help="also start sudo tcpdump when sudoers permits it")
    ap.add_argument("--pcap-iface", default="en0")
    ap.add_argument("--pcap-filter", default="tcp port 443 or arp or udp port 53")
    ap.add_argument("--pcap-rotate-mb", type=int, default=32, help="tcpdump ring file size in MB; use 0 to disable rotation")
    ap.add_argument("--pcap-rotate-files", type=int, default=8, help="tcpdump ring file count when rotation is enabled")
    args = ap.parse_args()

    vm_path = args.vm_path or (ROOT / "targets" / "ibm_pc_5150" / "86box" / args.profile)
    if not vm_path.is_dir():
        raise SystemExit(f"missing 86Box profile: {vm_path}")

    if args.out_dir is None:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_dir = DEFAULT_OUT_ROOT / f"{run_id}-{args.profile}"
    else:
        out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    log = Logger(out_dir / "watch.log")
    (out_dir / "watch.pid").write_text(f"{os.getpid()}\n", encoding="ascii")
    log.write(f"watch start profile={args.profile} vm_path={vm_path}")
    log.write(f"pid={os.getpid()} out_dir={out_dir}")

    tcpdump = TcpdumpCapture(
        out_dir / "capture.pcap",
        args.pcap_iface,
        args.pcap_filter,
        log,
        args.pcap_rotate_mb,
        args.pcap_rotate_files,
    )
    if args.pcap:
        tcpdump.start()
    else:
        available, detail = sudo_tcpdump_available()
        if available:
            log.write("pcap available but disabled; pass --pcap to capture packets")
        else:
            log.write(f"pcap unavailable without sudoers: {detail}")

    stop = False

    def on_stop(signum, _frame):
        nonlocal stop
        stop = True
        log.write(f"signal {signum}: stopping")

    signal.signal(signal.SIGINT, on_stop)
    signal.signal(signal.SIGTERM, on_stop)

    deadline = None if args.duration <= 0 else time.monotonic() + args.duration
    last_pids: set[int] = set()
    last_lsof: dict[int, str] = {}
    last_socket_summary: dict[int, str] = {}
    next_screen_at = 0.0
    next_ocr_at = 0.0
    screen_index = 0

    try:
        while not stop:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                log.write("duration elapsed")
                break

            pids = HAR.matching_86box_pids(vm_path)
            if pids != last_pids:
                log.write(f"86Box pids: {sorted(pids) if pids else 'none'}")
                for pid in sorted(pids):
                    log.block(f"process {pid}", sample_process(pid))
                last_pids = set(pids)

            for pid in sorted(pids):
                lsof = sample_lsof(pid)
                if lsof != last_lsof.get(pid):
                    log.block(f"tcp sockets pid={pid}", lsof)
                    last_lsof[pid] = lsof
                summary, established_443 = tcp_socket_summary(lsof)
                if summary != last_socket_summary.get(pid):
                    log.write(f"tcp summary pid={pid}: {summary}")
                    if established_443 > args.max_open_443:
                        log.write(
                            f"warning: pid={pid} has {established_443} ESTABLISHED TCP/443 sockets "
                            f"(threshold {args.max_open_443})"
                        )
                    last_socket_summary[pid] = summary
                    if not args.no_socket_change_screen:
                        screen_index += 1
                        do_ocr = not args.no_socket_change_ocr
                        maybe_capture_screen(
                            out_dir,
                            args.profile,
                            pid,
                            screen_index,
                            do_ocr,
                            args.ocr_timeout,
                            log,
                            reason="[socket-change]",
                        )
                        next_screen_at = now + args.screen_interval
                        if do_ocr:
                            next_ocr_at = now + args.ocr_interval

            if pids and now >= next_screen_at:
                pid = sorted(pids)[-1]
                screen_index += 1
                do_ocr = now >= next_ocr_at
                maybe_capture_screen(
                    out_dir,
                    args.profile,
                    pid,
                    screen_index,
                    do_ocr,
                    args.ocr_timeout,
                    log,
                )
                next_screen_at = now + args.screen_interval
                if do_ocr:
                    next_ocr_at = now + args.ocr_interval

            time.sleep(max(0.25, args.interval))
    finally:
        tcpdump.stop()
        log.write("watch stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
