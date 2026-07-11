#!/usr/bin/env python3
"""286 ladder: IBM AT (286) at 6..25 MHz x {no-FPU, 287}, booting the 360K bench
image. Crafted CMOS gets it past SETUP; long poll-for-DONE waits out the AT's slow
POST. Prints SHA block / integer-mul / FPU-mul ms per cell."""
import sys, time, subprocess, os, signal
sys.path.insert(0, "tools/crypto-bench")
import run86box as rb

IMG = rb.BENCH_BUILD / "crypto-bench-360.img"        # boot + class_bench, prebuilt
NVR = rb.VM_PATH / "nvr" / "ibm5170_111585.nvr"
CLOCKS = [6, 8, 12, 16, 20, 25]
FPUS = ["none", "287"]

def cmos(has_fpu):
    c = bytearray(64)
    c[0x0A]=0x26; c[0x0B]=0x02; c[0x0D]=0x80
    c[0x04]=0x12; c[0x07]=0x01; c[0x08]=0x06; c[0x09]=0x26
    c[0x10]=0x10                                # floppy A = 360K
    c[0x14]=0x23 if has_fpu else 0x21           # bit1 = math coprocessor
    c[0x15]=0x00; c[0x16]=0x02                  # 512K base
    chk=sum(c[0x10:0x2E])&0xFFFF; c[0x2E]=(chk>>8)&0xFF; c[0x2F]=chk&0xFF
    return bytes(c)

CFG = """[General]
emu_build_num = 8200
sound_muted = 1
vid_renderer = qt_software
video_filter_method = 0
[Machine]
machine = ibmat
cpu_family = 286
cpu_multi = 1
cpu_speed = {speed}
cpu_use_dynarec = 0
fpu_type = {fpu}
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
"""

def parse(text):
    out={}
    import re
    for ln in text.splitlines():
        m=re.match(r'^([A-Z0-9]+)\s+N=(\d+)\s+dt=(\d+)', ln.strip())
        if m: out[m.group(1)]=(int(m.group(2)),int(m.group(3)))
    return out

rows={}
for mhz in CLOCKS:
    for fpu in FPUS:
        NVR.parent.mkdir(exist_ok=True)
        NVR.write_bytes(cmos(fpu!="none"))
        (rb.VM_PATH/"86box.cfg").write_text(CFG.format(speed=mhz*1000000, fpu=fpu, img=IMG))
        subprocess.run(["pkill","-f","86Box"],capture_output=True); time.sleep(1)
        cap=rb.ComCapture()
        proc=subprocess.Popen([rb.emulator_path(),"--vmpath",str(rb.VM_PATH),"--image",f"A:{IMG}"],
            cwd=rb.ROOT, env={**os.environ,"SEED_NO_IMAGE":"1"}, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
        cap.start(proc)
        dl=time.monotonic()+80
        while time.monotonic()<dl:
            if "DONE" in cap.text(): break
            time.sleep(1)
        cap.finish()
        try: os.killpg(os.getpgid(proc.pid),signal.SIGKILL)
        except Exception: pass
        ops=parse(cap.text())
        rows[(mhz,fpu)]=ops
        def ms(t):
            v=ops.get(t); return f"{v[1]*rb.TICK_MS/v[0]:.3f}" if v else "-"
        print(f"[286 @{mhz:>2}MHz fpu={fpu:4}] SHA={ms('SHABLK')} int={ms('MUL88')} fpu={ms('FMUL87')}", flush=True)

print("\n=== 286 ladder ms/op (8088@4.77 ref: SHA 155.6, int 0.225) ===")
print(f"{'MHz':>4} {'fpu':5}{'SHA blk':>10}{'int 32x32':>11}{'fpu 32x32':>11}")
for mhz in CLOCKS:
    for fpu in FPUS:
        ops=rows.get((mhz,fpu),{})
        def ms(t):
            v=ops.get(t); return f"{v[1]*rb.TICK_MS/v[0]:.3f}" if v else "-"
        print(f"{mhz:>4} {fpu:5}{ms('SHABLK'):>10}{ms('MUL88'):>11}{ms('FMUL87'):>11}")
import json
(rb.BENCH_BUILD/"at286_ladder.json").write_text(json.dumps({f"{m}|{f}":o for (m,f),o in rows.items()},default=list,indent=2))
