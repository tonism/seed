# Build 12 — Memory Scaling Attempts

Branch context: Build 12 on `work/scaling`, after the capability-tiered layout
and native Responses tool-calling work. The stable design record is
`../memory-scaling-design.md`; reader-facing maps live in `../../docs/memory.md`.

## 2026-06-29 00:00:00 - M1 far-log streaming and the >64K gate

The first far-memory path moved conversation history out of the tiny segment-0
window on machines with more than 64 KiB conventional RAM. At compaction time,
Seed freezes the low window into a far log and streams the full frozen log plus
the live window on later turns.

The important correction was the gate: flat `0x10000` is unbacked on 16 KiB and
32 KiB machines, so far logging only enables when BIOS-reported conventional RAM
exceeds 64 KiB. Smaller machines keep the Build 11 seg-0 window and model
summary path byte-for-byte.

Validation: a `ZEPHYR` needle planted in the first turn survived repeated
overflow/flush cycles on a 256 KiB profile, and the 32 KiB fallback still
recalled correctly.

## 2026-07-03 00:00:00 - M1 far split, arena separation, and the 1 MiB cap

The far conventional range `[0x10000..conv_top)` was split into context and
arena instead of letting them overlap. The context side uses
`min(region / 2, 1 MiB)`; the remaining upper half becomes the direct far arena.

Validation on a 256 KiB machine advertised `far@00028000-00040000`, matching a
`0x30000`-byte far region split into a `0x18000` context cap and a `0x18000`
arena. The 1 MiB cap math was verified offline because conventional memory
below 1 MiB cannot hit that cap.

One UI regression came with this work: the far-detection path clobbered `AH`
before splash centering. Reloading columns from `screen_cols` fixed the
mis-centered build marker.

## 2026-07-05 00:00:00 - M2 EMS arena/context inversion

EMS added a second backend with a synthetic flat address range above 1 MiB. On a
256 KiB + 4 MiB EMS profile, conventional memory stays executable/direct arena,
EMS holds the larger windowed storage, and the canonical conversation context
moves to the top of EMS with the 1 MiB cap.

The visible gotcha is address reporting: the model may request
`0x00100020`, while the physical access goes through the EMS page frame at
`0x000D0020`. Tool status now reports both only when they differ, for example
`write to 0x00100020 -> 0x000D0020`.

Validation: EMS write/read probes preserved bytes through the page-frame mapping.
Harness OCR was flaky, so the final evidence included manual screen checks.

## 2026-07-10 00:00:00 - M3/M4 HMA, native extended memory, and unreal mode

The 286 tier enables A20, advertises the HMA direct range, and reaches native
extended memory through BIOS `int 15h AH=87h` block moves. The 386 tier adds
unreal mode so Seed can directly address high memory while staying compatible
with BIOS calls that still expect real mode.

Tool read/write limits were made deliberately uniform at 4 bytes on every memory
tier while the native function-call loop is hardened. This keeps 16 KiB, 32 KiB,
EMS, 286, and 386 behavior aligned from the model's point of view.

Validation status at the doc checkpoint:

```text
16 KiB BASIC sidecar   write/read at the low arena, 4-byte cap, manual/OCR evidence
32 KiB direct boot     write/read at 0x7000, 4-byte cap, green
EMS profile            synthetic high address mapped through page frame, green/manual evidence
286 path               feature implemented; post-DPI runner still needs hardening
386 profile            unreal-capable profile added before landing the direct high-memory path
```

The remaining work after this entry is documentation and harness polish, not a
new memory tier.
