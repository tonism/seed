# 48KB Slim Attempts

## 2026-05-04 22:46:52 - Initial 48KB profile sweep

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

## 2026-05-05 07:19:45 - 3c501 OpenAI timing fix

Branch: `work/48kb-slim`

Starting point:
- `vm-net-3c501` failed with red `o` / `agent setup failed` while the other
  valid 48KB NIC profiles reached the Build 6 splash and displayed `ok`.
- Relay probing with `/private/tmp/seed_tls_relay_probe.py` showed the 3c501
  TLS crypto was valid: the relay verified the client Finished and decrypted
  the OpenAI request. The failure was timing and receive pacing, not an invalid
  ECDHE/AEAD result.

Changes tried and kept:
- Precompute the non-EMS TLS key schedule for 3c501 immediately after
  ServerKeyExchange parsing, before waiting for ServerHelloDone.
- Send 3c501 ClientKeyExchange immediately after ServerHelloDone, then finish
  the local final-flight work and send CCS/encrypted Finished.
- Reduce the advertised TCP receive window only for 3c501 from 1024 bytes to
  512 bytes, pacing the server TLS/application response around the 3c501's
  single receive buffer.
- Clear the 3c501 receive pointer high byte during init/release paths.

Result:
- Relay test reached OpenAI, received `HTTP/1.1 200 OK`, and decrypted a
  response body containing `"text": "ok"`.
- Direct `vm-net-3c501` test reached `seed build 6` and displayed returned
  `ok`.
- Direct `vm-net-ne2k8` regression test also reached `seed build 6` and
  displayed returned `ok`.

Size:
- `CORE.SYS` after rebuild: 36,442 bytes (`0x8e5a`), ending at about `0x9e5a`
  when loaded at `0x1000`.
