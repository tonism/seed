# 16KB Windowed Nucleus Attempts

Branch: `work/16kb-windowed-nucleus`

Starting point:

- `main` 24 KiB BASIC sidecar release at `3f49a3f`.
- One 160 KiB FAT12 floppy image.
- One visible `CORE.SYS` runtime.
- BIOS boot remains the path for machines with at least 32 KiB RAM.
- ROM BASIC sidecar entry remains the path for machines below 32 KiB.
- Current 24 KiB sidecar release keeps `CORE.SYS` loaded at `0x1000` and uses
  a runtime ceiling of `0x6000`.

Milestone target:

- First raw target is a 16 KiB BASIC sidecar run reaching returned `ok` on one
  representative NIC.
- Release target is representative NIC-family success under a 16 KiB ceiling,
  including 3c501 as the timing canary, while preserving 32 KiB+ BIOS boot from
  the same floppy and same `CORE.SYS`.

Design reference:

```text
notes/16kb-windowed-nucleus-design.md
```

Initial measured baseline from the 24 KiB release:

```text
CORE.SYS total bytes:       29696
CORE.SYS total sectors:     58
resident sectors:           37
resident bytes:             18944
resident load range:        0x1000..0x5a00
24 KiB ceiling:             0x6000
16 KiB ceiling:             0x4000
BASIC sidecar loader addr:  0x5a00
```

Initial implication:

- With `CORE.SYS` still loaded at `0x1000`, a 16 KiB machine leaves only
  `0x1000..0x4000`, or 12 KiB total.
- The current resident image alone is about 6.5 KiB too large before stack,
  scratch, and guard budgets are considered.
- This branch should not proceed as blind trimming. It should turn the current
  windowed runtime into a stricter windowed nucleus: small resident control,
  explicit reloadable windows, and one no-floppy provider critical window.

Attempt log:

- No implementation cuts yet.
