#!/usr/bin/env python3
"""Boot rsa_bench.asm on a 286 (ibmat) in 86Box and time one RSA-2048 verify.

Reuses run86box's boot loader + crafted IBM-AT CMOS + serial readback. The AT POST
is slow, so we poll COM1 for DONE up to 120 s. Usage: python3 run_rsa_286.py [MHz]
(default 6 -- the lowest 286, the threshold machine). ck must be 54F2.
"""
import sys, os, re, time, signal, subprocess
import run86box as rb

MHZ = int(sys.argv[1]) if len(sys.argv) > 1 else 6
BD = rb.BENCH_BUILD


def build_image():
    subprocess.run(["nasm", "-f", "bin", "-o", str(BD / "bench_boot.bin"),
                    "tools/crypto-bench/bench_boot.asm"], check=True, cwd=rb.ROOT)
    subprocess.run(["nasm", "-f", "bin", "-Itargets/ibm_pc_5150/boot/",
                    "-Itools/crypto-bench/", "-o", str(BD / "rsa.bin"),
                    "tools/crypto-bench/rsa_bench.asm"], check=True, cwd=rb.ROOT)
    boot = (BD / "bench_boot.bin").read_bytes()
    bench = (BD / "rsa.bin").read_bytes()
    sectors = (len(bench) + 511) // 512
    if sectors > 28:
        raise SystemExit(f"rsa.bin is {sectors} sectors > 28 the boot loader reads")
    img = bytearray(368640)
    img[0:512] = boot
    img[512:512 + len(bench)] = bench
    out = BD / "crypto-bench-360.img"
    out.write_bytes(img)
    print(f"rsa.bin {len(bench)} B ({sectors} sectors)")
    return out


def craft_cmos():
    c = bytearray(64)
    c[0x0A] = 0x26; c[0x0B] = 0x02; c[0x0D] = 0x80
    c[0x04] = 0x12; c[0x07] = 0x01; c[0x08] = 0x06; c[0x09] = 0x26
    c[0x10] = 0x10; c[0x14] = 0x21; c[0x15] = 0x00; c[0x16] = 0x02
    chk = sum(c[0x10:0x2E]) & 0xFFFF
    c[0x2E] = (chk >> 8) & 0xFF; c[0x2F] = chk & 0xFF
    (rb.VM_PATH / "nvr").mkdir(exist_ok=True)
    (rb.VM_PATH / "nvr" / "ibm5170_111585.nvr").write_bytes(bytes(c))


def write_cfg(img):
    (rb.VM_PATH / "86box.cfg").write_text(f"""[General]
emu_build_num = 8200
sound_muted = 1
vid_renderer = qt_software
[Machine]
machine = ibmat
cpu_family = 286
cpu_multi = 1
cpu_speed = {MHZ * 1000000}
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
[Storage controllers]

[Floppy and CD-ROM drives]
fdd_01_fn = {img}
fdd_01_type = 525_2dd
fdd_02_type = none
""")


def main():
    img = build_image()
    craft_cmos()
    write_cfg(img)
    subprocess.run(["pkill", "-f", "86Box"], capture_output=True)
    time.sleep(1)
    cap = rb.ComCapture()
    proc = subprocess.Popen(
        [rb.emulator_path(), "--vmpath", str(rb.VM_PATH), "--image", f"A:{img}"],
        cwd=rb.ROOT, env={**os.environ, "SEED_NO_IMAGE": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        start_new_session=True)
    cap.start(proc)
    dl = time.monotonic() + 120
    while time.monotonic() < dl:
        if "DONE" in cap.text():
            break
        time.sleep(1)
    cap.finish()
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        pass
    txt = cap.text()
    m = re.search(r'dt=(\d+).*?ck=([0-9A-Fa-f]{4})', txt, re.S)
    print(f"raw: {txt[:80]!r}")
    if m:
        ticks = int(m.group(1)); ck = m.group(2).upper()
        secs = ticks * rb.TICK_MS / 1000
        ok = "OK" if ck == "54F2" else f"BAD ck (want 54F2)"
        print(f"286@{MHZ}MHz: RSA-2048 verify = {ticks} ticks = {secs:.2f} s  ck={ck} [{ok}]")
    else:
        print(f"286@{MHZ}MHz: no result parsed")


if __name__ == "__main__":
    main()
