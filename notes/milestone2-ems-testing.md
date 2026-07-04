# Milestone 2 (EMS) — testing EMS on 86Box (and the cfg gotcha that cost a day)

**Bare-metal EMS works on STOCK 86Box (v6.0, build 9001).** No emulator patch, no int 67h/EMM, no
upstream fix. Validated end-to-end: `vm-net-ems` boots and the model reports `far@00028000-00040000` +
`ems@00100000-00500000` (the 4 MB Lo-tech board). seed drives the board's page registers directly.

## The gotcha (root cause of a long detour)
The 86Box `isamem` `frame` config value is **HEX20 read as exactly 5 hex digits**. Writing
`frame = 0D0000` (6 digits) is misparsed to `0xD000` (5 digits) = physical **0xD000 = 53 KB, i.e. seed's
low conventional RAM** — NOT the intended UMA frame at `0xD0000`. With the frame landing in low RAM, the
EMS mapping overlaid seed's own memory: every seed probe read the *wrong* address (open bus / garbage),
and once the mapping was actually consulted it corrupted seed → black screen.

**Correct value: `frame = D0000`** (5 digits) → `frame_addr[0] = 0xD0000` (UMA). Verify from the 86Box
log (`-L <file>`): it prints `ISAMEM: EMS #1 enabled, ... Frame[0]=D0000H`. If you see `0D000H` the
frame is wrong (low RAM). ALWAYS confirm `Frame[0]` before concluding anything about EMS behavior.

Lesson: when EMS "reads open bus", verify the *actual* `frame_addr` (via the 86Box `-L` log's
`Frame[0]=` line and the guest's own probe) BEFORE suspecting an emulator bug. The long "86Box bare-metal
EMS is broken" investigation (and a from-source patched build) was chasing this cfg typo. UMA defaults to
EXTERNAL state in 86Box, so an enabled EMS mapping at a correct UMA frame IS consulted with no patch.

## Test profile
`targets/ibm_pc_5150/86box/vm-net-ems/` — `machine = ibmpc82`, 256 KB conventional + Lo-tech EMS board
(`isamem0_type = lotechems`, base `0260`, **`frame = D0000`**, size `4096`). 256 pages = 4 MB.

## How to run
Standard harness (stock 86Box): `python3 tools/run-basic-bootstrap-86box.py --profile vm-net-ems
--entry direct --ram-kib 256 --screen-oracle --post-dpi-text "..." --screenshot ...`. NOTE: the harness
screenshot occasionally flakes ("could not capture 86Box window") — re-run; it's a macOS window-capture
timing issue, not a seed fault.

Low-level EMS diagnostics (if ever needed again): boot with `-L <log>` and grep `ISAMEM:` for the frame
address + page count. The `$r`/`$w`/`$x` tool contracts to EMS flat addresses (>= 0x100000) are the
real per-turn exercises (M2c/d) once wired.

See `notes/milestone2-ems-design.md` for the M2 design/charter.
