#!/usr/bin/env python3
"""Sweep the 086-class CPU ladder x {no-FPU, 8087} with class_bench.asm.

One bench image, one boot per cell; the BIOS-tick dt/N is the real per-machine
time. Prints SHA-256 block, integer 32x32 multiply, and 8087 32x32 multiply per
cell so we can see how far a maxed-out 086 config gets the crypto.
"""
from __future__ import annotations
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run86box as rb

TICK_MS = rb.TICK_MS

# (label, machine, cpu_family, cpu_speed_hz). 86Box clamps speed to the nearest
# the machine allows; the measured dt reveals the real rate regardless.
CONFIGS = [
    ("8088 @4.77 (8b bus)", "ibmpc",  "8088",   4772728),
    ("V20  @8   (8b bus)",  "xi8088", "necv20", 8000000),
    ("8086 @8   (16b bus)", "m24",    "8086",   8000000),
    ("V30  @9.5 (16b bus)", "europc", "necv30", 9545456),
]
FPUS = ["none", "8087"]

CFG = """[General]
emu_build_num = 8200
sound_muted = 1
vid_renderer = qt_software
video_filter_method = 0

[Machine]
machine = {machine}
cpu_family = {cpu}
cpu_multi = 1
cpu_speed = {speed}
cpu_use_dynarec = 0
fpu_type = {fpu}
mem_size = 256

[Video]
gfxcard = cga

[Input devices]
keyboard_type = keyboard_pc_xt
mouse_type = none

[Ports (COM & LPT)]
serial1_passthrough_enabled = 1

[Storage controllers]
fdc = fdc_xt

[Floppy and CD-ROM drives]
fdd_01_fn = {image}
fdd_01_type = 525_1dd
fdd_02_type = none
"""

CFG_PATH = rb.VM_PATH / "86box.cfg"


def main():
    # build the bench image ONCE (same binary for every cell)
    core = rb.BENCH_BUILD / "bench.bin"
    size = rb.assemble(Path(__file__).resolve().parent / "class_bench.asm", core)
    rb.build_image(core)
    print(f"class_bench: {size} B; sweeping {len(CONFIGS)}x{len(FPUS)} cells\n")

    rows = {}
    for (label, machine, cpu, speed) in CONFIGS:
        for fpu in FPUS:
            CFG_PATH.write_text(CFG.format(machine=machine, cpu=cpu, speed=speed,
                                           fpu=fpu, image=rb.IMAGE))
            time.sleep(0.3)
            res = rb.run(timeout=80)
            ops = res.get("ops", {})
            rows[(label, fpu)] = (ops, res.get("done"))
            tags = " ".join(f"{k}={v['dt']}t/{v['N']}" for k, v in ops.items())
            print(f"[{label:22} fpu={fpu:4}] done={res.get('done')}  {tags or '(no serial)'}")

    # results table: ms/op per primitive
    def ms(ops, tag):
        o = ops.get(tag)
        return f"{o['dt']*TICK_MS/o['N']:.3f}" if o else "-"
    print("\n=== ms/op (lower = faster); real wall-clock on each machine ===")
    print(f"{'config':24}{'fpu':6}{'SHA-256 blk':>13}{'int 32x32':>12}{'fpu 32x32':>12}")
    for (label, machine, cpu, speed) in CONFIGS:
        for fpu in FPUS:
            ops, _ = rows.get((label, fpu), ({}, None))
            print(f"{label:24}{fpu:6}{ms(ops,'SHABLK'):>13}{ms(ops,'MUL88'):>12}{ms(ops,'FMUL87'):>12}")
    import json
    (rb.BENCH_BUILD / "class_matrix.json").write_text(json.dumps(
        {f"{l}|{f}": (o, d) for (l, f), (o, d) in rows.items()}, indent=2))


if __name__ == "__main__":
    main()
