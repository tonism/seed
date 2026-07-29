# K14 issuer-input relocation experiment

This isolated experiment resolves the issuer-authentication/ticket collision
without copying the ticket and without writing the floppy. It does not link or
replace the product runtime.

The native issuer overlay is assembled with:

```text
TLS13_POC_K14=1
TLS13_POC_READ_ONLY_INPUT=1
```

That profile moves the 175-byte, two-pass issuer input ABI from the ticket
range to half-open interval `0x3400..0x34af`. The issuer image contains 7,134
bytes, rounds to exactly 14 sectors, and a phase load at `0x1800` therefore
stops exactly at `0x3400`. Its 34 bytes of content slack are below the input;
the phase loader may replace the checker sentinel at `0x33f8`, but it cannot
replace the input.

## Required order

The relocation is safe only under this phase order:

1. the symmetric controller/runtime and its ticket parser finish;
2. the `0x3400..0x3600` controller and FO stream stage retire;
3. the certificate parser, hash, and trusted-time policy publish their bounded
   outputs;
4. the one-sector bridge copies the leaf input to `0x3400`;
5. the exact 14-sector issuer overlay loads and authenticates the leaf under
   WE1, committing the leaf at `0x3600`;
6. the bridge reloads, copies CertificateVerify input, and requires the
   same-generation leaf commit;
7. the issuer overlay reloads and authenticates CertificateVerify;
8. the separate two-sector read-only route gate validates the authenticated
   handoff plus the selected route's ticket contract, clears the 175-byte
   input, and publishes committed state last (this checker selects
   `LIVE_TICKET`).

The bridge copies parser outputs before pass 1 replaces their overlapping
`0x3600` prefix with the authenticated leaf commit. Pass 2 ignores the
point-shaped input capacity. A caller cannot stage pass 2 before the same
generation commits in pass 1.

The high checker guard is `0x3508..0x3510`; the former symmetric mutable suffix
begins at `0x3510`. Guards detect lifetime mistakes in the gate. They are not a
RAM MAC, and security still depends on trusted scheduler control flow.

## Measured comparison

| Property | Relocate issuer input | Relocate ticket |
|---|---:|---:|
| Volatile data copied | 175 B per pass | 269 B out and back |
| Ticket bytes moved | 0 | 269 |
| Reconnect block used | 0 | 330 B quarantine |
| Input bridge | 429 B / 1 sector | folded into the discarded monolithic draft |
| Separate atomic gate | 659 B / 2 sectors | folded into the discarded monolithic draft |
| Current split total | 1,088 B / 3 sectors | not directly comparable: the draft combined fewer checks |
| Product impact | extension input unavailable through auth, then retired atomically | precommit reconnect block unavailable |
| Read-only floppy | yes | yes if the quarantine is RAM-only |

Issuer-input relocation is smaller in live RAM and data movement, not yet in
total cold code: the current bridge plus the independently hostile-tested
atomic gate use three rounded sectors. The discarded ticket-relocation draft
combined staging, promotion, and unlock in roughly two sectors, so its raw
code-size comparison was not like-for-like. Folding the bridge into the commit
gate is a valid later size optimization once the live phase order stabilizes.

The relocation's main cost is a stronger layout dependency: every issuer load
must remain exactly 14 sectors and end at `0x3400`. If the issuer image ever
rounds to 15 sectors, or another live phase still owns the extension, this
option is invalid and the architecture must be revisited rather than silently
shifting the input.

## Gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/issuer_input_relocation_check.py
```

The checker assembles the actual native define, not a patched source copy. It
executes the checked-in real WE1 leaf signature and real TLS
CertificateVerify signature through the 8086 overlay, with the bridge and
issuer phases physically reloaded between calls. It verifies:

- the exact phase-load boundary and native symbol addresses;
- parser/hash/trusted-time and same-generation ordering;
- byte stability of ticket PSK, identity, nonce, and metadata;
- no change to resident/driver, reconnect/ESC, arena, or context state;
- no write into the symmetric extension-work suffix through atomic commit;
- low-work poisoning between issuer passes;
- handoff of the real authenticated output into the separate atomic commit
  gate, which retires the input before promotion;
- rejection before trusted time and rejection of CertificateVerify staging
  before issuer commit.

The result is frozen in
`issuer_input_relocation_results.json`.

## What this does not prove

This experiment proves the target memory lifetime and exact cryptographic
passes in isolation. It does not prove live protected-flight capture, bounded
certificate decompression, trusted-time establishment, fresh session entropy,
TCP/ticket recovery, cold restart behavior, or atomic credential unlock. Those
remain product-level secure-tier gates.
