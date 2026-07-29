# Read-only 8088 floppy-timing entropy PoC

`floppy_entropy_controller.asm` replaces operator-entered restart entropy in
the 16 KiB TLS 1.3 feasibility path. Collection is unattended, uses the
original machine only, and works with a write-protected floppy.

The controller performs 256 successful one-sector `INT 13h/AH=02h` BIOS reads,
alternating between CHS `0/0/1` and `39/0/8`. Those locations are valid on both
Seed's 160 KiB and 360 KiB floppy layouts. Each read is bracketed by latched
PIT channel-0 counts. The physical candidate source is mechanical seek,
settling, spindle, controller, and media completion jitter; the PIT only
measures the events. Elapsed seconds or milliseconds, BIOS ticks, and the
timer's nominal resolution are not themselves credited entropy.

The live PoC takes control after local packet-I/O initialization but before
the product's first DHCP call. It:

1. prepares the local NE2000 volatile vault without transmitting;
2. loads the checked KeyGen Keccak-f[1600] primitive and this one-sector
   collector;
3. absorbs each before-count, after-count, and sample index and
   SHA3-256-conditions all 256 events;
4. creates eight counter-separated 32-byte outputs, grouped as two one-shot
   128-byte attempt bundles;
5. duplicates all 256 output bytes into volatile NIC RAM; and
6. only then invokes DHCP and continues the existing TLS route.

The output ABI is:

| Address | Bytes | Use |
|---:|---:|---|
| `0x0700` | 32 | initial ML-KEM `d` |
| `0x0720` | 32 | initial ML-KEM `z` |
| `0x0740` | 32 | initial ClientHello random |
| `0x0760` | 32 | initial legacy session ID |
| `0x0780` | 32 | same-boot resumption ML-KEM `d` |
| `0x07a0` | 32 | same-boot resumption ML-KEM `z` |
| `0x07c0` | 32 | resumption ClientHello random |
| `0x07e0` | 32 | resumption legacy session ID |

The controller performs no disk write. A failed read, a folded timing symbol
repeated for more than 64 samples, or fewer than eight symbol changes fails
closed and scrubs the output, root, private controller state, and complete
shared Keccak work area. These are provisional stuck-source checks, not a
min-entropy estimate or a NIST SP 800-90B validation.

Run the assembly/oracle/hostile gate with:

```sh
python3 tools/crypto-bench/tls13-poc/floppy_entropy_check.py
```

The checker executes the exact `cpu 8086` controller in Unicorn, emulates only
read-only `INT 13h/AH=02h` operations and PIT latches, compares output with a
host SHA3 oracle, exercises replay/diversity/read/health failures, runs the real
8086 KeyGen from the derived `d||z`, and verifies zeroization bounds.

## Security status

86Box proves controller mechanics and the complete unattended TLS route only.
Virtual disk timing receives zero entropy security credit.

Crediting physical timing requires raw traces from representative drives,
controllers, media, machines, temperatures, and cold/warm restarts; a
conservative min-entropy model; calibrated startup and continuous health
tests; and enough accepted source entropy for the ML-KEM seed requirement.
Conditioning cannot create entropy that the physical source did not provide.

Two improvements remain candidates for the physical-hardware spike:

- use a silently free-running PIT channel 2 rather than BIOS-owned channel 0;
- timestamp at the earliest FDC completion point, ideally IRQ 6, instead of
  immediately after BIOS `INT 13h` returns.

If mechanical timing cannot meet the requirement at acceptable latency, the
fallback candidate is natural keystroke timing sampled at IRQ 1, not
user-entered random characters or values.
