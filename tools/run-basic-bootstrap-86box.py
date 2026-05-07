#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = "vm-net-ne2k8"
DEFAULT_BASIC = ROOT / "build/ibm_pc_5150/SEED24B.BAS"
DEFAULT_LOADER = ROOT / "build/ibm_pc_5150/seed24a-loader.bin"
DEFAULT_BASIC_LOADER = ROOT / "build/ibm_pc_5150/seed24b-loader.bin"
DEFAULT_FLOPPY = ROOT / "build/ibm_pc_5150/floppy-160k.img"
DEFAULT_LOADER_FLOPPY = ROOT / "build/ibm_pc_5150/floppy-160k-lowmem-loader.img"
DEFAULT_SCREENSHOT = ROOT / "build/ibm_pc_5150/86box-seed24-basic.png"
BASIC_BOOTSTRAP_ADDR = 0x5A00
BASIC_BOOTSTRAP_CLEAR_TOP = 23039
BASIC_DATA_BYTES_PER_LINE = 12


KEY_CODES = {
    "\n": (36, False),
    " ": (49, False),
    ",": (43, False),
    ".": (47, False),
    ":": (41, True),
    "-": (27, False),
    "=": (24, False),
    "(": (25, True),
    ")": (29, True),
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


def run(args: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, **kwargs)


def emulator_path() -> str:
    found = shutil.which("86Box")
    if found:
        return found
    app_path = "/Applications/86Box.app/Contents/MacOS/86Box"
    if Path(app_path).exists():
        return app_path
    raise SystemExit("86Box was not found")


def activate_86box() -> None:
    run(["osascript", "-e", 'tell application "86Box" to activate'])
    time.sleep(0.5)


def paste_basic(basic: str) -> None:
    script = """
on run argv
  set the clipboard to item 1 of argv
  tell application "86Box" to activate
  delay 0.5
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
  tell application "System Events" to count processes
  tell application "86Box" to activate
  delay 1.0
  tell application "System Events"
    tell process "86Box" to set frontmost to true
    delay 0.5
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
  tell application "System Events" to count processes
  tell application "86Box" to activate
  delay 1.0
  tell application "System Events"
    tell process "86Box" to set frontmost to true
    delay 0.5
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
        'tell application "System Events" to count processes',
        'tell application "86Box" to activate',
        "delay 1.0",
        'tell application "System Events"',
        '  tell process "86Box" to set frontmost to true',
        "  delay 0.5",
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


def rewrite_vm_config(config: Path, ram_kib: int, floppy: Path, rom_basic: bool) -> None:
    lines = config.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_floppy_section = False
    wrote_fdd2_check = False
    wrote_fdd2_fn = False
    wrote_fdd2_type = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_floppy_section:
                if not wrote_fdd2_check:
                    out.append("fdd_02_check_bpb = 0")
                if not wrote_fdd2_fn:
                    out.append(f"fdd_02_fn = {floppy}")
                if not wrote_fdd2_type:
                    out.append("fdd_02_type = 525_1dd")
            in_floppy_section = stripped == "[Floppy and CD-ROM drives]"
            wrote_fdd2_check = False
            wrote_fdd2_fn = False
            wrote_fdd2_type = False
            out.append(line)
            continue

        if stripped.startswith("mem_size ="):
            out.append(f"mem_size = {ram_kib}")
            continue

        if in_floppy_section:
            if stripped.startswith("fdd_01_fn ="):
                if not rom_basic:
                    out.append(f"fdd_01_fn = {floppy}")
                continue
            if stripped.startswith("fdd_01_type ="):
                out.append("fdd_01_type = 525_1dd")
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
        if not rom_basic:
            out.append(f"fdd_01_fn = {floppy}")
        if rom_basic and not wrote_fdd2_check:
            out.append("fdd_02_check_bpb = 0")
        if rom_basic and not wrote_fdd2_fn:
            out.append(f"fdd_02_fn = {floppy}")
        if not wrote_fdd2_type:
            out.append("fdd_02_type = 525_1dd" if rom_basic else "fdd_02_type = none")

    config.write_text("\n".join(out) + "\n", encoding="utf-8")


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


def basic_text_from_loader(loader_bytes: bytes) -> str:
    lines = [
        f"10 CLEAR ,{BASIC_BOOTSTRAP_CLEAR_TOP}",
        "20 DEF SEG=0",
        f"30 FOR A={BASIC_BOOTSTRAP_ADDR} TO {BASIC_BOOTSTRAP_ADDR + len(loader_bytes) - 1}",
        "40 READ B",
        "50 POKE A,B",
        "60 NEXT A",
        f"70 DEF USR0={BASIC_BOOTSTRAP_ADDR}",
        "80 A=USR0(0)",
    ]
    line_no = 100
    for offset in range(0, len(loader_bytes), BASIC_DATA_BYTES_PER_LINE):
        chunk = loader_bytes[offset : offset + BASIC_DATA_BYTES_PER_LINE]
        lines.append(f"{line_no} DATA {','.join(str(byte) for byte in chunk)}")
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


def launch_86box(vm_path: Path, image_args: list[str] | None = None) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["SEED_NO_IMAGE"] = "1"
    cmd = [emulator_path(), "--vmpath", str(vm_path)]
    if image_args:
        for image in image_args:
            cmd.extend(["--image", image])
    return subprocess.Popen(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
    )


def screenshot(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    run(["screencapture", "-x", str(path)])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Launch a ROM BASIC 86Box VM and inject Seed's 24 KiB BASIC bootstrap.",
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--basic", type=Path, default=DEFAULT_BASIC)
    parser.add_argument("--loader", type=Path, default=DEFAULT_LOADER)
    parser.add_argument("--basic-loader", type=Path, default=DEFAULT_BASIC_LOADER)
    parser.add_argument("--floppy", type=Path, default=DEFAULT_FLOPPY)
    parser.add_argument("--loader-floppy", type=Path, default=DEFAULT_LOADER_FLOPPY)
    parser.add_argument("--screenshot", type=Path, default=DEFAULT_SCREENSHOT)
    parser.add_argument("--ram-kib", type=int, default=32)
    parser.add_argument("--startup-delay", type=float, default=22.0)
    parser.add_argument("--capture-delay", type=float, default=60.0)
    parser.add_argument("--type-delay", type=float, default=0.035)
    parser.add_argument("--line-delay", type=float, default=0.5)
    parser.add_argument("--mode", choices=("paste", "text", "chars", "keycode"), default="keycode")
    parser.add_argument("--no-type", action="store_true")
    parser.add_argument("--no-run", action="store_true")
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
    args = parser.parse_args()

    if not args.no_build:
        run(["make"], cwd=ROOT)
        run(["make", "basic-bootstrap"], cwd=ROOT)

    if not args.floppy.exists():
        raise SystemExit(f"missing floppy image: {args.floppy}")
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
    vm_path = ROOT / "targets/ibm_pc_5150/86box" / args.profile
    if not vm_path.is_dir():
        raise SystemExit(f"missing 86Box profile: {vm_path}")

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
        if args.loader_mount == "config":
            config = vm_path / "86box.cfg"
            restore_config = (config, config.read_bytes())
            rewrite_vm_config(config, args.ram_kib, floppy, False)
        else:
            image_args = [f"A:{floppy}"]
    elif args.entry == "basic":
        config = vm_path / "86box.cfg"
        restore_config = (config, config.read_bytes())
        rewrite_vm_config(config, args.ram_kib, floppy, True)

    try:
        process = launch_86box(vm_path, image_args)
        try:
            time.sleep(args.startup_delay)
            activate_86box()
            if args.entry != "basic" or args.no_type:
                pass
            elif args.mode == "paste":
                paste_basic(basic_text)
            elif args.mode == "text":
                type_basic_text(basic_text, args.line_delay)
            elif args.mode == "chars":
                type_basic_chars(basic_text, args.type_delay, args.line_delay)
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
                else:
                    type_basic_keycodes(run_text, args.type_delay, args.line_delay)
            time.sleep(args.capture_delay)
            screenshot(args.screenshot)
            print(f"screenshot: {args.screenshot}")
        finally:
            if not args.leave_running:
                process.kill()
                process.wait(timeout=5)
    finally:
        if restore_config is not None:
            restore_config[0].write_bytes(restore_config[1])

    return 0


if __name__ == "__main__":
    sys.exit(main())
