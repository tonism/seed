# 48KB OpenAI Attempts

## 2026-05-04 - Initial 48KB profile sweep

Branch: `work/48kb-slim`

Starting point:
- `CORE.SYS` size after rebuild: 36,338 bytes (`0x8df2`), loaded at
  `0x1000`, ending at about `0x9df2`.
- All remaining 86Box profiles were changed from `mem_size = 64` to
  `mem_size = 48`.

First result:
- `vm-net-ne2k8` initially showed a black screen and appeared not to boot.
- Root cause was a 64KB memory assumption: both the reserved loader and
  runtime used stack top `0xf000`, which is above installed RAM on a 48KB
  machine. A 48KB machine ends at `0xc000`.
- Changed `loader_stack_top` and `runtime_stack_top` to `0xc000`.

Result after stack relocation:
- `vm`: expected red `.` / `no network card`.
- `vm-mda`: expected red `.` / `no network card`.
- `vm-net-ne2k8`: reached `seed build 6` and displayed returned `ok`.
- `vm-net-3c503`: reached `seed build 6` and displayed returned `ok`.
- `vm-net-ne1k`: reached `seed build 6` and displayed returned `ok`.
- `vm-net-novell-ne1k`: reached `seed build 6` and displayed returned `ok`.
- `vm-net-wd8003e`: reached `seed build 6` and displayed returned `ok`.
- `vm-net-wd8003eb`: reached `seed build 6` and displayed returned `ok`.
- `vm-net-3c501`: red `o` / `agent setup failed`, matching the known 64KB
  baseline failure for this profile rather than a 48KB-specific regression.

Conclusion:
- No fundamental 48KB boot problem was found for the current flat `CORE.SYS`.
  The observed boot failure was caused by stack placement above installed RAM.
- With stacks moved to `0xc000`, all valid non-3c501 NIC profiles completed the
  direct OpenAI proof at 4.77 MHz / 48KB.
