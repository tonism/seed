# Seed Optimization Campaign

## Accepted product checkpoint: OPT-032 application executable headroom

The product application omits its unreachable legacy TLS 1.2 Finished wrapper,
recovering **77 executable bytes**: K uses **4,019 of 4,096 bytes**. All 1,689
surviving instructions and external references remain equivalent under
relocation. Runtime size, the eight-sector K load, its fixed file slot,
308/309 FAT allocation, user memory and stack budgets are unchanged. This is
code-space recovery, without a new elapsed-time or RAM-capacity claim.

The runtime is `5f068397521319be6ebe20f4427e03f7436f3d754a495bb031af56de34beac55`.
Build/inspection/BASIC, twenty final-image HTTP/2 gates, sixteen standalone
guards, both issuer fixtures and hostile checks, and 6,234 multiplication
executions pass. Both 4 KiB response fixtures retain their output, instruction
counts, 34 reads, eight outgoing records and 64-byte peak stack. All eight
serialized 286 payloads remain byte-identical to the accepted timing payloads.

Nine reviewed original-speed cases complete 27 prompted turns across 16 KiB
ROM BASIC, 32 KiB direct boot, 286/512 KiB and all seven ISA NIC profiles.
Each accepted main case performs exactly one native write, execute and read,
reports AX 42 and bytes `B8 2A 00 CB`, and returns to the prompt. Every owned
connection is accounted for, including the two payload-free preparation opens
on each 8088 case. All 36 TLS windows pass the deadline gate; the largest is
11.255 seconds. This is functional emulator acceptance, with no physical
entropy credit or broader provider-edge claim.

The 32 KiB native answer uses the documented format-mismatch review:
the values are correct but spelled out. The original detector miss and timed,
screenshot-bound review remain intact; numeric-format compliance is false.
The first 16 KiB attempt repeated execute and read and is excluded. Its one
unchanged full repeat passes the required functional scenario. The cause of
native repeats remains unproven; this change introduces no native-loop fix or
broader reliability claim.

A separate test-supervisor exit race interrupted the completed 16 KiB repeat's
reporting and the first WD8003EB startup. The native repeat's five original
automatic answer/prompt events, numeric result and complete capture pass; its
missing report is explicitly reconstructed from preserved evidence. WD8003EB's
interrupted startup is excluded, and one unchanged full repeat passes. Original
logs, events and supervisor records remain intact under the recovery audit.

The first final-audit pass rejected WD8003EB's 599.996709-second span between
UTC idle markers. The unchanged runner requests 600 seconds; the next prompt
is submitted 603.985832 seconds after idle start and the first client payload
follows at 610.779107 seconds. `integration/idle-window-audit.json` proves a
full 600-second quiet interval before each next prompt and payload in all nine
cases (minimum wire interval 604.763343 seconds). The original audit source,
failure and marker discrepancy remain preserved; no test interval is shortened.

`OPT-032/integration/final-audit.json` binds the image, source, offline checks,
live reviews, connection accounting, documentation and preservation. All VMs,
owned monitors and sleep guards are closed; overlap never exceeded three.
The same checkout, unrelated local changes, 49,957 earlier campaign files and
592 historical build files are preserved. Product capacity/testing docs and
this ledger are updated. The maintainer approved committing and pushing this
checkpoint after reviewing the result. The validation audit retains pre-commit
HEAD `f0ca175` and the validated documentation snapshot; `OPT-032/publication/`
binds the approval/status update and the commit that records this implementation.
Overall rocks turned remains **50% (rough 40–60%)**.

The next selected investigation is ChaCha20 response computation. OPT-029
attributed 25.06% of its baseline instruction hooks to the ChaCha routines;
that historical share is neither current elapsed time nor a promised gain.
Reprofile the accepted response path, then compare bounded fixed-work variants
within K's 77-byte headroom and unchanged RAM, stack and authentication bounds.
Use matched split/unsplit fixtures and original-speed component timing before
selecting a product change. This next investigation has not started.

## Previous committed checkpoint: OPT-031 issuer repair and OPT-030 multiplication

The fixed-work response multiplication unroll is integrated and functionally
verified. Byte-identical native timing payloads retain the measured controlled
4 KiB response-component gains of **3.30% unsplit and 3.27% fragmented** at
4.77 MHz: 394 -> 381 and 397 -> 384 BIOS ticks, saving 0.7140 seconds per
fixture. Synthetic external callbacks isolate that component; this is not a
whole-turn or live-provider latency claim. K uses all 4,096 executable bytes.
Measured RAM, stack, record/read counts and FAT allocation are unchanged.

The compatibility repair retains independently authenticated WE1/P-256/SHA-256
and YE2/P-384/SHA-384 issuer keys and refreshes the 8088 image-dated exact leaf.
The public points occupy existing pack-header space. Target TBS hashing,
strict span binding and full ECDSA verification preserve full FO, hostname,
UTC validity on the 286, CertificateVerify, status-last authority and erasure.
The CRC checks RAM corruption and grants no cryptographic authority. Both
routes remain target-local, conventional-RAM-only and compatible with
write-protected media.

The accepted runtime is
`bb0c1ce10d6e8f3096b6ebf60914f38f3ef33bc3994a233c6c100ac92737e6ba`,
150,016 bytes / 293 sectors, using 308/309 FAT clusters. Build/inspection/BASIC,
twenty final-image HTTP/2 gates, sixteen standalone guards, both issuer
fixtures and hostile checks, 6,234 application multiplication executions and
all eight serialized 286 timing components pass. The single stale optional
padding expectation in an unused HELLO-checker helper is corrected; the active
gate and fresh build pass with byte-identical artifacts.

Nine reviewed original-speed live cases complete 27 prompted turns across
16 KiB ROM BASIC, 32 KiB direct boot and 286/512 KiB, including all seven ISA
NICs, reuse and bounded reconnect after a ten-minute idle. The three main
cases each complete exactly one native write, execute and read, report AX 42
and bytes `B8 2A 00 CB`, and return to the input prompt. Every owned TCP attempt
is accounted for: four TLS connections per case, plus two payload-free
preparation connections on the 8088. No unexplained attempt is excluded.

The new uninstrumented `ne2k8-32k-repeat-4` passes the functional gate on the
unchanged frozen candidate through the documented manual format-mismatch
review. Its final answer correctly spells out AX and the hex bytes, but does
not follow the request for digits. The original literal-42 detector miss,
correct full answer and returned prompt are bound to the saved screenshot;
completion was observed within the original budget. No numeric-format
compliance is claimed. All five prior exclusions remain intact: the
original 32 KiB repeated write, its outage-interrupted repeat, two repeats
with a second execute, and the NE1000 failure spanning confirmed host sleep.
NE1000's separate unchanged full repeat passes. The successful private serial
diagnostic remains separate from product acceptance. It captured intact
native journal, read output, context and prompt metadata. Synthetic comparisons
and the two previously approved host probes are retained. **The cause of the
earlier repeated native actions remains unproven**; no native-loop fix was
made, and the later successful run does not establish broader reliability.

`OPT-031/integration/final-audit.json` binds the accepted image, source,
screenshots, wire/connection accounting, documentation and preserved evidence.
The pause checkpoint and `integration/resume-2026-11-20/` retain the resume
authorization, matching provider certificate, independent monitor history and
cleanup. All VMs and owned monitors/idle guards are closed. The resumed run
used one VM; the campaign maximum remains three. All 46,033 earlier campaign
files, 592 historical build files and unrelated local changes are preserved.

Product and target docs describe the dual-issuer capability, RAM lifetime,
layout and validation. This is functional emulator acceptance; physical entropy
characterization and broader provider-edge repetition remain separate, and
86Box receives no entropy credit. The maintainer approved committing and
pushing this checkpoint after reviewing the result. The validation audit
retains pre-commit HEAD `3410dd7`; the commit containing this section records
the accepted implementation. Overall rocks turned remains **50% (rough 40–60%)**.
The next optimization is to recover K executable headroom before further
code growth.

### Preserved OPT-030 integration before the compatibility repair

The following is chronological pre-repair history. OPT-031 completes
the authorized compatibility repair and acceptance; original evidence
and earlier limitations remain recorded.

The retained fixed-work multiplication unroll reduces controlled 4 KiB response
processing by **3.30% unsplit and 3.27% fragmented** at 4.77 MHz: 394 -> 381 and
397 -> 384 BIOS ticks, respectively. All three repetitions of each image and
shape agree, saving 0.7140 seconds per fixture. This is emitted response-code
timing with synthetic disk, NIC, provider and display callbacks in a private
64 KiB test rig; separate correctness gates enforce the product's 16 KiB
bounds. It is not a whole-turn or live-provider speed claim.

Arithmetic, fixed-work, full AEAD, credit and loader guards pass. K grows
4,081 -> 4,096 bytes, consuming its last 15 bytes; measured RAM, stack,
read/record counts and private runtime size are unchanged. The committed
baseline is `3410dd7`. OPT-030 implementation and testing are now
authorized and active; product acceptance is pending. OPT-029's measurement
used at most one VM and closed all of them. Its frozen evidence is preserved.
No new commit or push is authorized.
Overall rocks turned is **50% (rough 40–60%)**.

The local integration image is now
`ca4c22dc18be4186e8b698ea199725dfe96e49d97ecf817dbaeee6bb9ddbda52`.
Build/inspect/BASIC, twenty final-image HTTP/2 gates, sixteen standalone guards,
the 6,234-execution application arithmetic gate and eight serialized 286
components pass. Its ordinary response fixtures produce byte-identical native
timing payloads to OPT-029, retaining the measured component gain. Cold
controller sectors 162 and 165 have regenerated application references. All
eight NIC driver files, boot/loader bytes and FAT allocation remain unchanged.
One private replay assembly attempt omitted a copied `serial.inc`; its failed
log is retained, the exact retained include was restored, and the preflight
passed without product changes.

Live acceptance stopped after setup failure `00/12` on 16 KiB BASIC, 32 KiB
direct boot and 286/512 KiB. The unchanged committed baseline reproduces the
failure on 32 KiB and 286. All five VMs closed, overlap never exceeded three,
and no other NIC cases or prompted turns were launched. Credential-free,
system-CA/hostname/time-verified probes on both observed provider addresses
receive the same new leaf, issued November 3, 2026 under Google Trust Services
WE1 (P-256/SHA-256), rather than the November 2 leaf and YE2 issuer supported
by the current image. The current leaf fails verification under YE2.
`OPT-030/provider-diagnostic/diagnosis.json` binds the probe evidence, baseline
controls and visually reviewed failures. Encrypted VM captures do not identify
the exact peer certificate or first rejected target check; the independent
trust mismatch and baseline reproduction establish the compatibility blocker.

The optimization and its successful offline evidence are preserved locally.
No live-product acceptance is claimed. A scope decision is pending: retain
both independently authenticated issuer keys in the 286 route, refresh the
8088 exact leaf, and repeat full acceptance. That compatibility work has not
started, and no trust asset or authentication rule has been changed. Overall
rocks turned remains **50% (rough 40–60%)**.

## Previous committed checkpoint: OPT-028 issuer repair and OPT-027 DATA fast path

The issuer repair is integrated and functionally verified on the same checkout.
The 8088 route uses the independently authenticated current exact leaf; the
286 route verifies the YE2 P-384/SHA-384 issuer on target, then the P-256 leaf's
CertificateVerify. Both routes retain their existing authority, RAM, read-only
media, entropy and bounded-reconnect boundaries. The current runtime is
`9d83b0e2f3bf0293530cd344bb2e2a55144be19f380a5648d3d68e9567f04ea1`,
150,016 bytes / 293 sectors. The two selected OPT-027 request/response sectors
are byte-identical to the preserved candidate.

Fresh build/inspect/BASIC, twenty HTTP/2 gates, sixteen standalone TLS/fixture
guards and eight serialized 286 components pass. Nine reviewed original-speed
live cases complete 27 prompted turns on 16 KiB BASIC, 32 KiB direct boot and
286/512 KiB, including all seven ISA NIC profiles, ten-minute idle recovery,
one bounded reconnect, and native write/execute/read on the three main paths.
The 286 native OCR omission and 32 KiB numeric-format mismatch have separate
timed visual reviews; their automatic misses remain intact. The first 16 KiB
attempt repeated native actions and is excluded. One unchanged full repeat
passes automatically with exactly one write, execute and read, the correct
AX/bytes, and a returned prompt. No failure is relabeled as a pass.

`build/optimization-campaign/OPT-028/integration/final-audit.json` binds the
accepted image, source, captures, reviews and documentation. All ten attempted
live cases are retained, all VMs are closed, and overlap never exceeded three.
All 42,368 prior evidence files and unrelated local changes are preserved.
Fifteen directly affected product/target docs now describe the current issuer
and layout. This is functional emulator acceptance, with no physical entropy
credit or new whole-dialogue latency claim.

The maintainer requested this repair and successful verification in this same
chat before considering new work in a fresh chat. That verification is now
complete. This checkpoint was committed and pushed as `3410dd7`,
`fix: restore provider trust and validate HTTP/2 fast path`, on
`codex/build-13-tls13-rearchitecture-spike`. Its predecessor `b5402f6` remains
the audit's recorded pre-commit HEAD. Overall rocks turned was **48% (rough
38–58%)** at that product checkpoint; OPT-029's later measurement is above.

## Previous committed checkpoint: OPT-026 response-credit batching

OPT-026 was validated against the committed `29bca48` baseline. Its frozen image
is retained alongside the now-accepted local OPT-027/028 image described above.
The controlled fragmented 4 KiB response uses 12.42% fewer instruction hooks,
40.88% fewer sector reads and half as many outgoing records. The unsplit case
adds 99 hooks (0.0013%) with unchanged reads and records. Only the response-owner
sector changes; there is no RAM, stack or FAT growth. These are exact-code
synthetic measurements, not a live dialogue-latency gain.

Build/inspect/BASIC, nineteen HTTP/2 gates, thirteen standalone guards and the
strengthened fourteen-case credit gate pass. Nine reviewed original-speed live
cases complete 27 prompted turns across all three CPU/RAM paths and seven ISA
NICs, with reuse, ten minutes idle, bounded reconnect and fresh native-tool
coverage on the three main paths. Separate reviews retain the 16 KiB native OCR
omission and 32 KiB numeric-format mismatch; neither automatic miss is hidden.
All VMs are closed, overlap never exceeded three, and protected inputs and prior
evidence match. `build/optimization-campaign/OPT-026/integration/final-audit.json`
binds the pre-commit validation checkpoint. The maintainer approved committing
and pushing this implementation and its documentation as
`perf: batch HTTP/2 response receive credit` on the current work branch.
That checkpoint's runtime is
`707f614c955194abc486d31882ab978abbb2236f8facd9450bafe4a3d9ebd54f`.
Overall rocks turned remains **48% (rough 38–58%)**.

The maintainer stopped wider optimization work until the original 4.77 MHz
8088 / exactly 16 KiB floor was reliable. OPT-017 and OPT-020 now satisfy the
functional emulator repair gate on the shipping-source implementation. The
8088/16 KiB ROM BASIC, 8088/32 KiB direct-boot and 286/512 KiB paths complete
four dependent replies, ten minutes idle, one bounded reconnect and native
write/execute/read with the correct result. All seven original-speed ISA NIC
profiles pass first-response/reuse/reconnect checks, including 3c503/MDA and
two separate 3c501 runs.

The committed reliability runtime is
`e3e0b888fa41e2ea72db3854e54da6a28226752f84c6c0a5a25da94e0815574f`.
`OPT-020/final-audit.json` binds all ten reviewed runs and 29 prompted turns to
that runtime, the canonical images, exact owned captures and unchanged
read-only/protected inputs. The build, 18 HTTP/2 composition gates, standalone
TLS guards, RAM/erasure, ENV/cancel, failure menus and serialized 286 components
pass. Earlier failed and partial experiments below remain historical evidence.

This is functional acceptance with explicit limits: the 32 KiB model spelled
out the correct native result instead of following the numeric-format request;
the automatic result is preserved and independently reviewed completion is
recorded. At 16 KiB, text replies took about 4–13 minutes and the post-idle
native sequence about 32 minutes. Physical entropy validation and broader
provider-edge characterization remain separate security work. This is not an
unconditional secure-floor or release claim.

The reliability investigation is 100% complete for this gate; the wider
campaign's rocks-turned estimate is approximately 44%. The validated
checkpoint was committed as `38b2f40` and pushed to
`codex/build-13-tls13-rearchitecture-spike` with the maintainer's approval.
The subsequently requested OPT-016 source cleanup is now validated locally.
Its runtime is
`2e5d631fa81bb575343fb52782195672e0fc3e4d797a905c9142b329cf3e65b1`;
`OPT-016/integration/final-audit.json` accepts nine cases and 27 prompted turns
across all three CPU/RAM paths and seven ISA NIC profiles. The 32 KiB
numeric-format caveat remains explicitly recorded. The build and current
offline gates pass; all VMs used for this validation are closed.

The OPT-016 cleanup and its campaign checkpoint were committed as `831170c`
and pushed to the current work branch with the maintainer's approval. Later
implementation checkpoints still require their own commit and push approval. The maintainer requested a fresh
context and continuation with OPT-022 after this cleanup. The selected FO
rotation helper is now a validated local working improvement on this same
checkout. Its runtime is
`866fba3b4cdf77f6fce9830791f409cfb78e6ee6f7e768bea038a41a328a6b0a`.
Original-speed target A/B measures 415 -> 334 BIOS ticks for the complete FO
worker: 22.7940 -> 18.3451 s, 19.52% less elapsed time. The worker is 2,915 B
inside the same six sectors, with unchanged 26-B stack, RAM layout, FAT size
and phase-read geometry. Shipping build, inspection, BASIC helper generation,
18 HTTP/2 and 13 standalone TLS gates pass. Eight serialized 286 payloads
remain byte-identical to their accepted timing baseline.

`OPT-022/integration/final-audit.json` accepts nine reviewed cases and 24 text
replies across all three CPU/RAM paths and seven original-speed ISA NICs,
with reuse, a ten-minute idle window and one bounded reconnect per case.
Native/ENV acceptance is retained separately from OPT-016 by unchanged bytes.
The initial 3c501 early-peer-close failure and WD8003EB UI timeout remain
unaccepted evidence; unchanged repeats pass. The WD8003EB repeat used a
1,800-second UI observer budget and actually completed its second turn in
1,011.68 s; its earlier 1,200-second timeout is not relabeled as success.
Earlier interrupted/invalid observations are retained too. Their underlying
causes remain unestablished. All VMs are closed and protected inputs match.
This is functional emulator acceptance and FO computation timing, with zero
physical entropy credit and no whole-proof speed claim. OPT-022 finished
uncommitted, as originally requested. The separate OPT-016 checkpoint changed
no protected source or runtime bytes.
Future concurrent tests must keep at most three VMs open and close each VM as
soon as its test finishes. Historical entries retaining VMs do not override
that request.

OPT-023 then attributed the composed 8088 proof and measured regeneration on
this exact baseline. OPT-024 is now a second validated local improvement:
full runtime-root KeyGen takes 417 -> 332 BIOS ticks, 22.903892 -> 18.235233 s,
**20.38% less worker computation time**. Code grows 84 B inside the same seven
sectors; stack, mutable RAM, phase reads and FAT size are unchanged. Only the
KeyGen slot and its conditioner's relocated references change. The shipping
runtime is
`3790f719c938f48f4e2e5c5070e413a90a64a52e841d51dbe72cee6b4fa2a74a`.
Build/inspect/BASIC, 18 HTTP/2 and 13 standalone TLS gates pass, and eight 286
payloads remain byte-identical. `OPT-024/integration/final-audit.json` accepts
nine cases / 24 text replies with reuse and bounded post-idle reconnect across
all three CPU/RAM paths and seven ISA NICs. Native/ENV acceptance is retained
by unchanged bytes. The original NE1000 1,200-second post-idle observer timeout
remains failed evidence; one unchanged repeat passes in 948.83 s under the same
limit. Its cause remains unestablished. All VMs are closed, overlap never
exceeded three, and prior source/config/evidence is preserved. This is worker
timing and functional emulator acceptance, with no whole-route latency or
physical entropy claim. Overall rocks turned is **46% (rough 36–56%)**.
OPT-022 and OPT-024 were uncommitted at validation. With the maintainer's
approval, the combined rotation checkpoint was committed and pushed as
`29bca48` on the current work branch. It includes both verified helpers, the
required Makefile prerequisite and this ledger. Existing VM cfg/NVR,
screenshots, captures and ignored evidence stayed outside the commit. Later
implementation checkpoints still require their own commit and push approval.

This file is the durable controller for an open-ended Seed optimization
campaign. It exists so a maintainer can start or resume the campaign with one
short instruction instead of reconstructing its constraints, measurements, and
prior decisions in every model context.

The product baseline is commit `e34f3c4`. A later documentation-only commit may
add or update this controller without changing that product baseline.

This is a wishlist, not a prescribed sequence of three large work packages.
The campaign model owns decomposition: it should turn the wishes into small,
testable spikes and choose their order from evidence and dependencies. Spikes
normally run sequentially in the campaign task. When a genuinely fresh context
would improve a substantial spike, the model must request one from the
maintainer with an exact handoff prompt. Commit and push remain explicit
maintainer gates.

## How to start or resume

Initial instruction:

> Read `docs/optimization-campaign.md` completely and run the optimization
> campaign autonomously. Begin with the next campaign action, not a summary of
> the file.

The same instruction works in a fresh context. In an existing campaign context,
this shorter instruction is sufficient:

> Continue the optimization campaign.

At the start of every context, the model must read this file, `AGENTS.md`, and
the current state recorded below. It must then inspect the actual branch,
worktree, HEAD, image, and relevant source before acting. The file is a routing
brief, not a substitute for current evidence.

## Automation boundary

The model should continue automatically through ordinary investigation,
experiments, implementation, validation, rejected hypotheses, and selection of
the next spike. It should not stop merely to explain what it plans to inspect or
to ask which wishlist item comes next.

It must pause when:

- `AGENTS.md` requires explicit approval before a commit;
- a push has not been explicitly requested;
- representative physical hardware or another unavailable external resource is
  essential;
- a substantial spike genuinely needs a fresh top-level context; or
- a change would alter a hard invariant below; or
- two materially different product directions require a maintainer decision.

When a spike produces no worthwhile code change, record the negative result and
move to the next spike automatically. When it produces a validated working
checkpoint, give a concise before/after report and proposed commit message, then
wait for approval. After the maintainer commits or says `continue`, select the
next action from this file without requiring the campaign context to be
re-explained.

Never commit or push as part of an automatic handoff between spikes.

## Context and spike protocol

The campaign task is the controller and the default execution context. A spike
is a logical unit of work, not automatically a new chat. Run ordinary and
closely related spikes sequentially in the campaign task; normal context
compaction is not by itself a reason to stop.

The model must not assume it can jump into another chat. For deep algorithmic
work, an independent security argument, or a spike likely to consume a large
fresh context, it should first record the spike in the ledger and then ask the
maintainer for a new context using exactly this compact form:

```text
Fresh context requested for spike <id>: <one-line reason>.
Start it with: Read AGENTS.md and docs/optimization-campaign.md, then execute
spike <id> from the ledger. Do not commit or push.
```

That request is a handoff, not a claim that the new context already exists. The
maintainer creates the context on the same checkout/working tree and sends the
supplied instruction. A separate worktree is safe only when the campaign record
and spike entry have already been committed and the handoff names that commit;
otherwise it will not see uncommitted state. The new context reads the shared
ledger, performs the spike, and records its result. The campaign controller
resumes only after that result is available or the maintainer tells it to
proceed elsewhere.

Before starting a spike, append a compact entry to the spike ledger containing:

```text
spike id
wishlist item(s)
one falsifiable question
baseline metric or behavior
allowed source surface
required evidence
exit condition
status and owning context, if separate
```

A spike should test one coherent hypothesis. Do not create one context per file,
primitive, or trivial edit. Do not run code-editing spikes concurrently in the
same worktree. Parallel read-only research is safe only when its ownership is
clear and it cannot race generated artifacts or emulator state.

The controller must inspect and validate returned work rather than accepting a
subtask's conclusion on trust. Detailed generated traces, reports, and temporary
binaries belong under `build/optimization-campaign/`. Durable conclusions and
the minimum information needed by the next context belong in this file or in
the existing authoritative product document.

## Hard invariants

Every proposal and implementation must retain all of these unless the
maintainer explicitly changes scope:

- one self-selecting `SEED.SYS` for the IBM-compatible target;
- the functional 4.77 MHz 8088 / 16 KiB ROM BASIC floor;
- the conforming 6 MHz 286 / 512 KiB `X25519MLKEM768` floor;
- OpenAI at `api.openai.com` as the only current provider route;
- TLS 1.3 only, with no TLS 1.2 fallback or downgrade;
- the documented distinction between the bounded 8088 credential-release
  boundary and the conforming 286 route;
- target-local private work and operation from a write-protected floppy;
- no helper machine, persisted private key, writable crypto scratch, mutable
  leaf file, trust-on-first-use, or unauthenticated time source;
- conventional system RAM as the only TLS memory; video RAM remains display
  state and adapter RAM remains device state;
- the existing status-last authority transitions, full FO checks, strict
  Finished checks, zeroization, and bounded reconnect/replay policy;
- the documented root configuration and prompt paths, current ENV contract, and
  target-local native memory tools;
- external independently selectable NIC drivers, with inactive drivers using
  no resident RAM;
- non-fatal station-address PROM reads and established no-card/no-driver
  recovery behavior;
- the 8086 instruction lock, real mode, current text mode, BIOS text output,
  handoff ABI, cursor behavior, and UI rules; and
- no general OS-style infrastructure or unrequested 64-bit/no-BIOS rewrite.

An apparent speedup does not count if it moves work past an authority boundary,
removes a rejection check, makes a provisional value authoritative, consumes
uncredited emulator entropy, borrows device memory, assumes writable media, or
special-cases one NIC at the expense of another.

## Current measured baseline

The block below records campaign-entry measurements at `e34f3c4`. Later
accepted changes and qualifications appear in the wishlist state and spike
ledger. Use current source and regenerated artifacts before attributing a new
improvement; OPT-005 in particular qualifies the short-turn reuse baseline.

```text
8088 floor                 4.77 MHz, exactly 16 KiB, ROM BASIC, read-only
8088 fresh worst case      13.7898 s ServerHello -> client Finished
8088 cold                  404.3 s harnessed power-on -> DPI
8088 Seed runtime          345.2 s runtime boundary -> DPI
8088 first offline proof   154.6 s
8088 resumed proof/commit   69.4 s
8088 reused short turn      64.3 s submit -> DPI
  target response work      53.3 s
8088 arena/context          96 B / 96 B

286 floor                  6 MHz, 512 KiB, direct boot, read-only
286 strict live intervals  8.8880 / 8.6428 / 8.9518 / 8.6425 s
286 normalized cold        186.7 s power-on -> DPI

SEED.SYS                   150,016 B / 293 sectors
auxiliary files            15 sectors
FAT use                    308 / 309 data sectors
usable runtime growth      0 sectors after the required free-cluster guard
resident nucleus           4 sectors / 2,048 B
active NIC driver          fourth resident sector / 512 B
K executable               5,310 B, rounds to 11 sectors in a 15-sector slot
```

The architecture timing monitor is authoritative for phase definitions. Live
emulator timing is not physical entropy evidence and the observed provider
close is not an SLA.

## Required evidence for every spike

Record:

```text
current cost             cycles/ticks, seconds, bytes, sectors, reads, or behavior
measured hot path        exact functions, phases, and source files
hypothesis and mechanism
expected benefit         derived estimate or target
actual result            same baseline and measurement method
RAM/floppy tradeoff
security-boundary effect
compatibility effect
validation performed
disposition              accepted, rejected, superseded, blocked, or follow-up
```

Prefer target-derived measurements, instruction counts, emitted binary sizes,
and exact-floor live traces. A modern-host microbenchmark is not evidence of an
8088 or 286 improvement unless its target instruction model is validated.
Measure the complete affected route: a primitive-level win that adds phase
loads, FAT sectors, reconnect latency, or another hot-path cost may be a net
loss.

## Wishlist

The numbering preserves the original discussion. Item 7, the isolated 286
provider-edge retry investigation, is intentionally outside this campaign. The
controller may reorder the included wishes, split them into multiple spikes, or
combine tightly coupled hypotheses. It must record why.

### 1. Increase the 8088 handshake margin

Reduce the seven-NIC worst case from 13.7898 seconds to below 12 seconds;
10–11 seconds is the stretch target. Profile every operation from ServerHello
through client Finished, especially ML-KEM candidate processing, transcript
SHA-256, ChaCha20-Poly1305, record parsing, receive pacing, copies, phase
transitions, and driver interactions. Preserve the credential-free provisional
boundary and every later proof.

### 2. Optimize the 8088 normal dialogue loop

Reduce the 64.3-second reused short turn, initially targeting less than 35
seconds. Approximately 53.3 seconds is target response authentication, SSE
scanning, rendering, and prompt restoration while provider wait and wire arrival
are under two seconds. Investigate a single-pass authenticated SSE/JSON path,
fewer copies, faster record opening, phase retention, contiguous loading,
overlap of work, and safe BIOS text batching. Preserve family-specific
ACK/render pacing and exact response semantics.

### 3. Reduce 8088 offline proof time

Reduce the approximately 154.6-second first full-FO/exact-leaf/CV span and the
69.4-second resumed proof/commit span. Audit ML-KEM re-encryption, NTT,
polynomial comparison, SHAKE/Keccak, P-256 verification, immutable public-data
precomputation, repeated derivations, table representations, and phase reloads.
These spans are outside provider handshake windows, but secret and
connection-dependent lifetime independence remains mandatory.

### 4. Recover floppy capacity

Recover at least 10 FAT sectors if possible and identify a credible path toward
20. Search for cross-phase routine and immutable-table duplication, safe
cold-phase compression, compact constants, removable padding, and file-layout
waste. Preserve documented configuration/prompt paths and independently
selectable drivers. A contract-changing asset container is a proposal requiring
maintainer approval, not an automatic implementation. Distinguish K-slot
padding from actual FAT capacity: consuming its 2,370 internal padding bytes
does not itself free sectors after the fixed slot.

### 5. Recover 16 KiB arena/context or executable space

Seek at least 256 additional safe persistent bytes, with 512 as the stretch
target, and separately identify executable-window gains. Perform byte-level
lifetime analysis of TLS state, reconnect scratch, buffers, status fields,
stack high-water, active-driver representation, and cold-phase windows. The
fourth resident sector contains the selected NIC driver; it is not unused
padding. Recovered memory must survive bounded reconnect and complete
success/abort zeroization.

### 6. Reduce interactive floppy activity

Inventory successful reads and seeks for cold boot, first dialogue, reused
dialogue, tool continuation, reconnect, and failure. Add no entropy-only reads.
Reduce or regularize activity after the DPI appears through phase retention,
safe prefetch, contiguous placement, fewer reloads, or work moved into an
already-required noninteractive cold phase. Prioritize interactive behavior over
offline load time.

### 8. Seek fully conforming hybrid TLS at the 8088 floor

Determine whether genuine server-dependent X25519 can fit with ML-KEM-768 and
the rest of client Finished inside the provider window on a 4.77 MHz 8088. The
prior variable-base X25519 measurement is about 45.75 seconds by itself;
precomputation depending on the unknown server share does not count.

Use isolated PoCs first. Explore 8088 field representation, multiplication and
reduction, inversion, ladder scheduling, register allocation, generated
assembly, and joint critical-path optimization. Also inspect genuinely
standards-conforming provider-supported schedules. Do not relabel fixed-share,
KEM-only, or nonconforming bootstrap behavior as conforming hybrid TLS.

A valid disposition is either a reproducible target PoC with a credible
complete sub-15-second schedule, or a bounded infeasibility result quantifying
the missing speedup/provider capability.

### 9. Improve 8088 identity freshness and rotation

Investigate whether the dated exact-leaf object can gain an issuer-authorized
rotation path and meaningful freshness without trusted RTC hardware, a helper,
writable state, TOFU, unauthenticated time, or allowing an expired compromised
leaf to assert its own time. Model the trust graph explicitly. Deliver a sound
self-contained construction or the precise impossibility and smallest
additional assumption that resolves it, including byte, cycle, RAM, and
operational costs.

### 10. Perform a whole-system Pareto audit

This is both a wishlist item and a periodic reconciliation tool. Run it after
meaningful accepted changes or when local spikes stop producing wins. Search for
duplication and simplification across primitives, phase boundaries, file
geometry, buffer ownership, dispatch, and the driver ABI. Check that a local win
did not worsen another dimension.

Maintain a Pareto table covering:

```text
8088 fresh-handshake worst case and margin
8088 cold and reused-turn time
286 cold time and handshake margin
resident and active-driver bytes
largest executable window and phase
16 KiB arena/context bytes
SEED.SYS and auxiliary sectors, free FAT clusters
interactive and cold floppy reads
security assumptions and assurance
NIC/display/reconnect compatibility
```

Rank remaining work by expected benefit, confidence, engineering cost, and
regression radius. Explicitly identify attractive ideas that should not be
pursued.

## Wishlist state

Use `backlog`, `active`, `partially solved`, `complete`, `blocked`, or `rejected`.
“Complete” means the wish has no remaining worthwhile in-scope opportunity, not
merely that one spike ran.

| Wish | State | Best current result | Active/next spike |
| --- | --- | --- | --- |
| 1. 8088 handshake margin | partially solved | seven-NIC matrix worst 11.2196 s; matched 3c503 13.7220 -> 11.2317 s; under-12 target observed | OPT-002 committed as `de9cf53` |
| 2. 8088 dialogue loop | partially solved | The prior accepted OPT-030/031 layout measured 3.30% / 3.27% controlled response-component gains; OPT-032 retains equivalent surviving instructions and matched response work | OPT-032 recovers K code space and passes functional live gates; no new whole-dialogue latency claim |
| 3. 8088 offline proof | partially solved | OPT-022 FO: 415 -> 334 BIOS ticks; OPT-024 KeyGen: 417 -> 332 ticks, 22.9039 -> 18.2352 s, same sector/RAM/read budgets | OPT-022/024 committed as `29bca48`; P-256 and remaining Keccak costs remain open; no whole-route speed claim |
| 4. Floppy capacity | backlog | 308/309 FAT sectors remain allocated; K uses 4,019 bytes but retains eight loaded sectors inside its fixed fifteen-sector file slot | OPT-032 recovers executable headroom only; no FAT-sector saving |
| 5. 16 KiB memory/executable space | partially solved | OPT-032 recovers 77 K executable bytes, 4,096 -> 4,019; user arena/context remains 96/96 B and RAM/stack/load bounds are unchanged | OPT-032 integrated and validated; next measure bounded ChaCha work within the recovered headroom |
| 6. Interactive floppy activity | partially solved | OPT-027 controlled responses reach 34 reads from 146 unsplit / 162 fragmented; same RAM/FAT allocation and outgoing-record count | Functional live acceptance complete through OPT-028; no whole-turn floppy-free or elapsed-time claim |
| 8. Conforming hybrid TLS on 8088 | backlog | ~45.75 s X25519 blocker | — |
| 9. 8088 freshness/rotation | backlog | image refresh restores the exact leaf and bounded WE1/YE2 compatibility; general 8088 on-target freshness/rotation remains open | OPT-003 operational evidence and OPT-031 dual-issuer repair |
| 10. Whole-system Pareto audit | partially solved | OPT-009/010 receiver/overlay bounds and OPT-011/012 codec work reconciled with OPT-013 cache reconstruction: 509 named preserved bytes, 414-B component, 8-B stack; existing loader schedule still exceeds 16 KiB | OPT-013 audit complete; broader audit remains open |

## Progress reporting

The maintainer requests an overall completion estimate whenever the campaign
pauses or hands work back. Completion means **investigation coverage: rocks
turned**, including supported negative findings and bounded infeasibility.
It does not require every wish to be implementable or delivered in the product.
A failed construction closes only the question actually tested; it does not
automatically close its entire wish.

After this clarification, the estimate is rebased to approximately **35%
explored**, with a rough **25–45% range**. This replaces the former 20% estimate
that mixed exploration with implementation and validation; historical spike
estimates remain as recorded. Handshake and dialogue/record behavior have been
examined deeply, with partial memory/floppy/I/O accounting. Offline-proof
optimization, conforming 8088 TLS and freshness/rotation remain mostly
unexplored. Count resolved avenues and remaining worthwhile questions across
the campaign, not the number of spikes or successful implementations. Explain
material revisions as the remaining search space becomes clearer.

After the accepted reliability repair and OPT-016/021 measurements, the current
estimate was approximately **42% explored**, with a rough **32–52% range**.
This increase reflects the completed prefetch question and the first concrete
offline-proof attribution; it does not count an unimplemented rotation gain.

After OPT-022's equivalence, rejection, composition and original-speed timing
results, the current estimate is approximately **44% explored**, with a rough
**34–54% range**. The narrow public-count rotation avenue now has a measured
working improvement; its final nine-case live integration matrix is complete.
This counts investigation coverage, not completed product or whole-proof work.

After OPT-023's composed fresh/resumed proof attribution and original-speed
regeneration timing, the estimate is approximately **46% explored**, with a
rough **36–56% range**. The newly measured regeneration and phase-load costs
close an attribution gap; no unimplemented KeyGen speedup is counted.

After OPT-024's full equivalence, timing, composition and live regression, the
estimate remains **46% explored (rough 36–56%)**. This is a validated application
of the already identified rotation avenue, not a reason to count the wider
proof or dialogue questions as closed. The retained NE1000 observer timeout
also limits any broader reliability or latency inference.

After OPT-025's exact-flow dialogue attribution and emitted-code profiling,
the estimate is **48% explored (rough 38–58%)**. This closes a current-cost
attribution gap and identifies a bounded fragmentation question; it does not
count OPT-026's candidate as an accepted improvement.

After OPT-026's complete-route comparison, tradeoff check and live regression,
the estimate remains **48% explored (rough 38–58%)**. It validates the identified
fragmentation avenue; ordinary record processing, whole-dialogue latency and
the wider proof, memory and security questions remain open.

After OPT-027's selected DATA shortcut and OPT-028's issuer repair and full live
verification, the estimate remains **48% explored (rough 38–58%)**. These close
the selected implementation and compatibility checks, without closing general
rotation, physical entropy or the remaining optimization search space.

After OPT-029's matched original-speed response-component timings, the estimate
is **50% explored (rough 40–60%)**. This closes the retained fixed-work
multiplication timing question and establishes its complete affected-response
cost on the current path. It does not count the unintegrated candidate as a
product win or close the wider dialogue, code-space, proof or security wishes.

## Selection policy

The model chooses the next spike. Prefer, in order:

1. release/security reliability and handshake margin;
2. measured interactive user benefit;
3. blockers to future code growth or product capability;
4. high-confidence changes with narrow regression radius;
5. measurements that cheaply eliminate broad but weak hypotheses; and
6. moonshots whose value justifies a dedicated fresh context.

Dependencies override this order. Do not repeatedly choose the easiest byte
savings while a critical reliability question remains unmeasured. Conversely,
do not let the conforming-8088 moonshot consume the entire campaign while
practical improvements remain.

## Validation and checkpoint rule

Every accepted implementation must pass `make`, produce a fresh `SEED.SYS`, and
pass `make inspect`. Run the exact component, hostile-input, composition,
layout, RAM-lifetime, zeroization, and wire gates for what changed. Timing,
phase loading, packet, or TLS application changes require exact-floor live
evidence and the affected original-speed NIC profiles. Preserve read-only
operation, no-card/no-driver recovery, CGA/MDA behavior, and unchanged video and
adapter RAM outside normal device use.

Before requesting a commit, remove diagnostic scaffolding and report:

- spike disposition and affected wishlist state;
- exact before/after measurements;
- files changed;
- validation commands and results;
- regressions and open risks; and
- one proposed commit message.

Wait for explicit approval. A push requires a separate explicit request or an
approval that clearly includes it.

## Spike ledger

Append entries below. Keep them concise but sufficient for a fresh context to
resume without conversation history. Large evidence stays under
`build/optimization-campaign/`.

### OPT-001 — Attribute the 8088 handshake deadline cost

- Wishes: 1; supporting measurements for 2 and 10. Chosen first because the
  3c503 fresh handshake has the smallest measured margin.
- Question: does target instruction profiling identify at least 1.79 seconds
  of plausibly removable computation/stream-handling cost in the existing
  ServerHello-to-Finished route, without changing its security schedule?
- Baseline: product `e34f3c4`; seven-NIC worst fresh interval 13.7898 s;
  `SEED.SYS` 150,016 B. Rebuild and inspect before attributing any change.
- Allowed surface: campaign ledger and isolated measurement tools/artifacts
  under `build/optimization-campaign/OPT-001/`; product sources read-only.
- Required evidence: regenerated image identity/layout, current candidate and
  symmetric hot paths, target instruction/cycle attribution with its modeling
  limits, and a read-only 4.77 MHz / 16 KiB 3c503 live baseline if available.
- Exit: rank one narrow follow-up by measured benefit and regression radius,
  or record why the 1.79-second opportunity is unsupported. No product claims
  from a primitive model alone.
- Status: measurement completed in the campaign context. Initial checkout has pre-existing
  modified 286 cfg/NVR and untracked 3c501 screenshots and `wire.pcap`; preserve
  those. The campaign controller itself was untracked at entry.
- Result/disposition: **follow-up to OPT-002**. `make -B`, `make inspect`, and
  `make basic-bootstrap` pass. Regenerated runtime and image are byte-identical
  to entry (`SEED.SYS` SHA-256 `c97d3961fca9ac214992d77f335f8f9e87a3deb7a69dd8e6e07099a9f7b2d01c`),
  retaining 293 runtime sectors, 308/309 FAT use, and the 96 B / 96 B floor.
  The current read-only 3c503 pcap measures a 13.857140 s fresh interval.
  Its frozen-image dialogue capture exposed the OPT-003 prerequisite below;
  resume performance A/B from the repaired, authenticated baseline.
- Hot path: exact packed acquisition symmetric image, 6,128 B, executes
  2,577,729 instructions for the deterministic 1,925-byte flight and handshake
  schedule through client Finished. `poly1305_mul_acc_r` accounts for 823,732;
  `chacha_quarter_round` for 424,320. The exact 2,189-byte live ML-KEM candidate
  executes 360,052. Isolated profiling is reproducible with
  `python3 build/optimization-campaign/OPT-001/profile.py`.
- Mechanism tested in isolation: replace the 17-by-16 byte schoolbook product
  with nine-by-eight word rows, explicitly zero-extending the last accumulator
  byte. The product, reduction path, plaintext, and Finished remain exact.
  The prototype removes 694,068 symmetric-path instructions (26.9%), retains
  the 6,128-byte aligned image, and needs four additional peak stack bytes.
  The existing cycle model predicts 2.71 s saved but has byte-MUL, REP,
  CL-shift, and prefetch limitations; this is a ranking estimate, **not** an
  elapsed-time result. Target A/B timing must decide acceptance.
- Read-accounting correction: the former `architecture.md` annotation said
  F/R perform no floppy reads, but executed product composition proves 5 candidate +
  11 symmetric-prefix + 3 fresh / 2 resumed protected-controller sectors in
  the deadline terminal, plus its one-sector entry controller. No reads were
  added by this spike. OPT-003 includes the annotation correction.
- RAM/floppy/security/compatibility: product unchanged; no authority transition
  moved. All measurements/prototype sources are under
  `build/optimization-campaign/OPT-001/`. Defer broader ChaCha/SHA changes until
  the measured larger, narrower multiply opportunity is resolved.

### OPT-002 — Use word products in Poly1305

- Wishes: 1 and 2, with whole-route reconciliation for 10.
- Question: can exact wordwise multiplication recover at least 1.79 seconds
  in the 8088 fresh handshake without growing the shipped image, changing
  reduction/rejection behavior, or exhausting the current stack window?
- Baseline: committed OPT-003 (`b25c84a`) with the current authenticated pin;
  exact symmetric fixture 2,577,729 instructions, multiply 823,732 instructions.
  Keep OPT-001's original immutable image as historical evidence.
- Allowed surface: `boot/core/poly1305.inc`, a focused executable arithmetic
  gate and Makefile wiring, necessary existing gate expectations, campaign
  ledger and the documented deadline-read annotation. No phase, driver, trust,
  or record-protocol redesign.
- Required evidence: independent full-width product oracle over edge/carry
  cases, symmetric hostile-input/Finished gates, RAM/stack/zeroization guards,
  fresh build/inspect, exact-floor A/B, seven-NIC reuse/reconnect, 286 serialized
  and live regression, and read-only/recovery/CGA/MDA behavior.
- Exit: a validated working checkpoint if the complete route improves;
  otherwise revert the product edit, retain evidence, and select the next spike.
- Status/disposition: **accepted and committed** as `de9cf53` after explicit
  maintainer approval. Only the multiplier, arithmetic gate, and Makefile are
  committed; campaign and architecture Markdown remain local. No push performed.
  `committed-checkpoint.json` verifies the exact three-file scope, parent, and
  committed source hashes against the validated frozen images. Pre-existing
  286 cfg/NVR and other untracked files remain untouched. No further commit or
  push is approved.

Current implementation and binding:

- The row multiplier lives in preserved BP; DS is copied into ES through AX.
  Nine by eight word rows replace 17 by 16 byte rows. The final accumulator
  byte is explicitly zero-extended. The full carry bound is retained, reduction
  is unchanged, and operands do not spill to the stack.
- Primitive size: 115 -> 111 code bytes. Primitive stack including near return:
  18 -> 18 B; full symmetric peak: 52 -> 52 B. No new persistent storage,
  phase loads, FAT sectors, authority transitions, or trust assumptions.
- The 6,128-byte exact symmetric image has SHA-256
  `50c76c33b186a14fa1f690c4357d5119bbaeb255bf199c2ace93ec46242582dd`.
  It executes 1,881,357 instructions (696,372 fewer, 27.02%); multiply accounts
  for 127,360. These counts are exact for the fixture, not live elapsed time.
- Runtime remains 150,016 B / 293 sectors, SHA-256
  `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`.
  Frozen images and BASIC helper are at OPT-002's root, bound by
  `word-image.json` and `validation-source.json`. All eight DRVs are identical.
  The only resident difference is one linked-call displacement byte (-4), not
  a resident logic change. R/Y request/response phases are byte-identical;
  other linked references move with the smaller multiplier.

Completed exact-revision offline validation:

- The new build-wired integer oracle passes 3,117 operand pairs in both ordinary
  and distinct DS/SS segments (6,234 executions), with full-width products,
  all-register preservation, bounded reads/writes, near-return integrity, and
  identical stack bytes for fixed caller registers across all operands.
  Dropped-carry, high-byte-overread, and operand-dependent stack-residue
  mutations are rejected. See `multiply-register.json` and `mutations-register/`.
- All eleven existing component/hostile-input gates pass: existing-read
  sampler, warm restart, entropy, fresh/resumed HELLO, candidate, full FO,
  exact-leaf authentication, both RAM-only symmetric images, and full symmetric
  hostile-input/Finished checks. See `offline-register.json`.
- Fresh `make`, `make inspect`, and `make basic-bootstrap` pass, including
  composition, lifetime/zeroization, dispatch/config, application bounds,
  reconnect/replay, FAT, and 286 module/controller gates. Logs have the
  `*-register.log` suffix. Sources/images remain unchanged throughout live tests.
- Complete 6 MHz / 512 KiB serialized CPU gate passes: acquisition 147 ticks /
  8.0740 s; final resumption 165 ticks / 9.0627 s. The exact report is
  `286-serialized-register-report.json`. Its resident/NIC/I/O and complete
  offline-authentication exclusions remain; this is not live-product acceptance.

Current-revision live evidence and limits:

- Revised long-prompt 3c503: fresh/resumed/reconnect-fresh/reconnect-resumed
  Finished 11.231663 / 6.827783 / 11.013447 / 6.787113 s; strict four-flow pcap
  and unchanged read-only image hash pass. Greeting and first `FORTYTWO` pass.
  Launch-to-DPI 379.494 s, BASIC-RUN-to-DPI 324.873 s, first reused turn
  46.036 s. Matched baseline: 13.722039 / 7.034048 s, 407.007 / 352.662 /
  57.899 s respectively. Sequential single samples, same long prompt and
  2-second DPI polling; provider payload size varies, so cold/dialogue deltas
  are observations rather than fixed-workload cycle attribution.
- Long-prompt second answer fails: both this candidate and committed `b25c84a`
  answer the displayed ninety/nine question with `FORTYTWO` and reach clean DPI.
  Candidate has four TLS flows; baseline has six after a post-compaction
  connection close. Retain screenshots, pcaps and failure records under
  `matrix/vm-net-3c503/` and `reconnect-baseline/`. This repeated answer predates
  the multiplier change. The actual live compacted note was not captured;
  its causal role is a hypothesis, recorded for OPT-004.
- Exact emitted R/X diagnostic with a synthetic credential and note preserves
  the new question across reconnect while placing the prior note in request
  `instructions` (`note-request-result.json`). It proves input preservation in
  that fixture, not the cause of the live repeated answer.
- TLS matrix uses distinct shorter arithmetic questions from
  `short-prompt-contract.json`: `6*7` and `90+9`, A-Z words only; neither
  expected answer is in its question. Existing keyboard injection lowercases
  A-Z to a-z, so visible answers are `fortytwo` / `ninetynine`. Expected-text
  matching is case-insensitive; direct image inspection remains required.
  Source-checked first-turn storage is 49 B, next preflight 89 B and stored
  prefix before answer 91 B, all within the 96-byte cap; 49 B is below the
  72-byte compaction trigger. Cold greeting text is not stored.
- Every short case uses frozen read-only media, 4.77 MHz / exactly 16 KiB ROM
  BASIC, greeting, immediate first-answer reuse, 500-second idle, distinct second
  answer after one reconnect, strict four-flow pcap, final image inspection,
  and unchanged image hash. A case is accepted only when `verdict.json` passes
  and `visual_inspection_pending` is false. `aggregate-register.py` summarizes
  completed/partial cases without relabeling failures.

| Short case | Fresh / resumed / reconnect fresh / resumed (seconds) | State |
| --- | --- | --- |
| 3c503 | 11.039792 / 6.784898 / 11.011743 / 6.766514 | Pass, inspected |
| NE2000 | 11.022054 / 6.782806 / 11.017779 / 6.786861 | Pass, inspected |
| 3c501 | 10.435306 / 6.196370 / 10.452289 / 6.045011 | Pass, inspected |
| NE1000 | 11.020124 / 6.739979 / 11.076236 / 6.774365 | Pass, inspected |
| Novell NE1000 | 11.019796 / 6.748265 / 11.047854 / 6.809210 | Repeat passes, inspected |
| WD8003E | 11.026969 / 6.843651 / 11.219148 / 6.757537 | Pass, inspected |
| WD8003EB | 11.219607 / 6.786808 / 11.054778 / 6.760608 | Pass, inspected |
| NE2000 / MDA | 11.047932 / 6.810721 / 11.212508 / 6.791210 | Pass, inspected |

- **OPT-005 qualification:** these are passes of the original answer/flow
  topology gates. A later canonical record-cap audit finds one oversized
  server application record on the first short turn in all seven NIC cases
  and MDA (2,915–4,251 wire bytes versus the 2,069-byte ceiling). New diagnostic
  captures and exact shipped-code execution establish the corresponding
  post-text failure path: retain the displayed answer, erase the application
  capability and return to DPI without replay. The forced 500-second idle
  did not distinguish this already-retired session from a healthy idle one.
  Keep the timings and handshake evidence, but do not treat this matrix as
  certification of a reusable session after its first answer. See OPT-005;
  future dialogue gates must check record bounds and immediate follow-up reuse.

- Novell's first attempt had a provider connection close during the first
  reused answer. One fresh/resumed recovery returned correct `fortytwo` and
  clean DPI, directly inspected. Stop there: this cannot meet the planned
  immediate-reuse/four-flow idle-reconnect contract. Preserve it under
  `matrix-short-attempts/novell-ne1k-early-close-1/`; image unchanged, cause
  unestablished. The successful repeat does not erase this observation.
- All thirteen required live cases are complete and visually inspected: seven
  ISA NICs, MDA, 286 live, 32 KiB direct boot, CGA/MDA no-card and no-driver.
  Recovery cases reach readable retry/restart menus with their expected clean-
  failure exit 2. Every read-only image is unchanged. All tests used isolated
  profiles. `aggregate-register.json` contains case timings and verdicts.
  `final-checkpoint.json` binds the proposed three-file checkpoint to the exact
  sources/images, checks an empty index and stopped campaign VMs, preserves
  original user cfg/NVR hashes, and records limits and the proposed message.
- Display limitation: a greeting can contain UTF-8 waving-hand bytes displayed
  as CP437 by the unchanged BIOS byte renderer. Expected ASCII answers remain
  readable; no encoding fix is part of this spike. Emulator timing supplies
  no physical entropy credit or new security-floor claim.

- The 6 MHz / 512 KiB read-only direct-boot 286 live gate passes with both
  answers and clean DPI directly inspected. The dedicated strict 286 analyzer
  passes four flows, independent hybrid shares, acquisition close, reuse and
  one reconnect. Finished intervals: 8.098887 / 8.600794 / 8.149059 /
  8.600072 s. Image hash is unchanged; original user 286 cfg/NVR hashes remain
  untouched. Evidence is `extra-register/286/`; the remaining direct/recovery
  runs also completed in `extra-register-run.log`.

- Read-only 4.77 MHz / 32 KiB direct boot also passes greeting, expected
  first answer, strict two-flow reuse and final DPI, directly inspected.
  Finished intervals are 11.021815 / 6.779109 s. Evidence is
  `extra-register/direct32/`. CGA/MDA no-card and missing-driver recovery
  subsequently passed, with final screens directly inspected.

Superseded evidence, kept for audit:

- OPT-001's initial prototype estimate overstated stack growth as four bytes.
  The first product stack-operand variant measured +2 B (20 B including return)
  and explicitly erased its row temporary. Its exact symmetric instruction
  count was 1,884,813; emitted multiply grew 2 B, within padding.
- That variant passed offline/serialized and matched 3c503 A/B: fresh baseline
  13.722039 -> 11.210950 s, resumed 7.034048 -> 6.778222 s; launch-to-DPI
  407.007 -> 378.485 s, BASIC RUN 352.662 -> 323.623 s, reused turn
  57.899 -> 40.195 s. Its partial NE2000 matrix stopped after the first answer
  during idle (11.217657 / 6.858159 s). Sources, images and reports are in
  `stack-variant/`, partial matrix in `matrix-stack-variant/`.
  These passes do not certify the current register revision. The pre-consolidation
  ledger is retained under OPT-002 for historical detail.

### OPT-003 — Restore a current authenticated exact-leaf baseline

- Wishes: 1 reliability prerequisite; 9 rotation operational evidence.
- Question: does an independently authenticated refresh of the immutable leaf
  asset restore current-provider dialogue, and does a mismatched leaf reach
  the documented fail-closed recovery path?
- Baseline: unchanged `e34f3c4` image reaches client Finished in 13.857140 s,
  then returns to ROM BASIC before DPI. Host TLS chain/hostname validation
  confirms the endpoint now presents a Sep 5–Dec 4 certificate with a different
  public key from the baked Jul 8–Oct 6 fixture; comparison saved under OPT-001.
- Allowed surface: isolated baseline/rejection diagnostics, existing immutable
  leaf fixtures and their derived program assets, narrowly necessary recovery
  corrections if proven, relevant gates, and campaign record. No trust-model,
  writable-state, clock, authority-boundary, or provider changes.
- Required evidence: repeated frozen-image behavior, current leaf verified
  against the existing issuer trust source and hostname/validity, exact-floor
  read-only live proof/DPI, explicit wrong-leaf rejection/recovery, full affected
  offline composition/zeroization and build/inspect gates.
- Exit: one validated maintenance checkpoint before resuming OPT-002; or
  record an actual unavailable resource/product-direction blocker and pause.
- Status/disposition: **accepted and committed** as `b25c84a` after explicit
  maintainer approval. The requested commit contains only the recovery fix,
  leaf assets/notes, and regression gates; campaign and architecture Markdown
  changes remain local and uncommitted. No push performed. OPT-002 resumes.
- Findings: a second unchanged-image run also returned to ROM BASIC. The
  actual rejected-auth continuation clears `1800..35a0`, then calls its helper
  at `3594`, which is already zero. A frozen-image Unicorn reproduction
  catches that execution with a coherent root frame. This is a recovery
  defect, not a stack exhaustion finding: direct stack-write tracing of real
  valid and rejected CV equations reaches `3fa8` (72 bytes below checker SP),
  preserving the return frame. The older component's printed 240-byte stack
  figure comes from comparing randomized guard bytes with an A5 sentinel.
- Validated implementation: restore prompt/capability state after the
  low clear and before erasing the helper. This reorders one call and adds no
  runtime bytes. The new product gate reproduces the old failure and passes
  five rejected/result/status/load cases plus the 32 KiB arena-restoration
  trampoline, complete owned-span retirement, and unchanged resident/driver,
  config, arena, video, and adapter guards.
- Current immutable pin/fixture: SPKI SHA-256
  `94655ad1e178ae4e1a28f7bfc97c0b0e48684f4b6370c639ab988a27d11e028f`,
  valid Sep 5–Dec 4. Captured without credentials/application data; independently
  verified under the existing tracked WE1 issuer, hostname, server purpose,
  capture-time validity, and real CertificateVerify. The host fixture uses
  X25519/ChaCha20-Poly1305/SHA-256 and supplies no target timing or runtime
  assistance. The legacy `AUTH_P256_LIVE_202607_PIN` build selector remains
  stable and selects the current image-dated asset.
- Offline validation: `system_ram_auth_check.py`, `issuer_auth_check.py`, and
  `auth_p256_check.py` pass with the refreshed real CV fixture. Fresh `make`,
  `make inspect`, and `make basic-bootstrap` pass, including exact product
  composition, high-abort tests, dispatch/config, application bounds,
  reconnect/replay, FAT budget, and 286 module/controller gates. Reports and
  logs are under `build/optimization-campaign/OPT-003/`.
- Exact-floor NE2000 live result: read-only ROM BASIC, 4.77 MHz, 16 KiB;
  fresh 13.511007 s and resumed 6.988781 s, followed by authenticated greeting
  and a verified `FORTYTWO` answer on the reused application connection.
  `live_k15_pcap.py --expect reuse` passes. These are current observations,
  not an optimization comparison against OPT-001's different NIC.
- Exact-floor 3c503 live result: the same read-only 4.77 MHz / 16 KiB entry
  passes fresh (13.722967 s), resumed (7.019561 s), authenticated greeting,
  expected `FORTYTWO` answer, and return to DPI on the reused connection.
  `live_k15_pcap.py --expect reuse` passes, and the final screenshot was
  inspected directly. OPT-001's same-profile fresh observation was 13.857140 s;
  this maintenance change does not attribute that variation to optimization.
- Wrong-pin live result: an isolated copy of the repaired image with only the
  previous immutable pin restored reaches the clean retry/restart menu on
  read-only 4.77 MHz / 16 KiB 3c503. It stops after the first rejected full
  identity proof. The pcap contains one fresh ClientHello (1,393 B), Finished
  (58 B), and fixed credential-free HEAD geometry (72 B), totaling 1,523
  outbound TLS bytes, with no later application record or resumed flow.
  The harness submits no DPI text and exits 2 as expected for a failure menu;
  direct screenshot inspection confirms readable recovery rather than ROM
  BASIC. Source/offline authority gates and wire geometry establish blocked
  credential release; the pcap itself is encrypted. Wrong-pin diagnostics
  never modified the source or shipping image.
- Image delta: `SEED.SYS` remains 150,016 B / 293 sectors, SHA-256
  `9c42c111c84c264491f34b9c73f62ac37c67faa1825404055377ca4efc2e23eb`;
  95 changed immutable authentication bytes and 30 reordered return-capsule
  bytes, with every other byte identical to the baseline. The resident core,
  drivers, other 8088 phases, and complete 286 tail are unchanged. No added
  runtime RAM, FAT sectors, or phase loads; use remains 308/309 FAT sectors.
- Source scope: `system_ram_product_controllers.asm`,
  `check_system_ram_product_pack.py`, immutable `auth_p256_pins.inc` and
  `issuer_auth_live_leaf.pem` / `issuer_auth_live_vector.json`, fixture notes
  in `issuer_auth_README.md` / `auth_p256_check.py`, `docs/architecture.md`,
  and this ledger. All diagnostics and faulted images remain under `build/`.
  Pre-existing 286 config/NVR hashes are unchanged; the timing prototype is
  absent from product source. Final image hashes also match after read-only
  live tests. `git diff --check` and Python compilation pass.
- Remaining limits: pin refresh is manual and another rotation can precede
  certificate expiry. Seven-NIC timing optimization/reconnect and new 286
  live measurements remain OPT-002 work; deadline, application, driver, and
  286 phase binaries are unchanged, and existing offline reconnect/replay and
  286 gates pass.
  No physical entropy claim or solved-freshness claim is added.
- Proposed commit: `fix: restore current exact-leaf TLS authentication and recovery`.

### Reconciliation after OPT-001 / OPT-003

This is a maintenance comparison, not an accepted speedup. Historical timing
values remain benchmarks to reproduce when their path is optimized.

| Dimension | Baseline / current evidence | Maintenance effect |
| --- | --- | --- |
| 8088 fresh / margin | OPT-001 3c503 13.857140 s / 1.142860 s; current 3c503 13.722967 s / 1.277033 s and NE2000 13.511007 s / 1.488993 s | Deadline code unchanged; no speedup attributed |
| 8088 cold / reused turn | Historical 404.3 s / 64.3 s; current authenticated NE2000 and 3c503 greetings and reused answers verified | Successful dialogue restored; end-to-end latency not remeasured |
| 286 cold / handshake | Historical 186.7 s; strict intervals 8.6425–8.9518 s | Complete 286 tail byte-identical; offline gates pass; no new live timing claim |
| Resident / active driver | 2,048 B total, including 512 B selected driver | Byte-identical |
| 8088 executable phases | Largest packed phase: authentication 6,592 B / 13 sectors; K 5,310 B / 11 sectors in its 15-sector slot | Same sizes and destinations |
| 16 KiB arena / context | 96 B / 96 B | Unchanged; abort guards and direct-tier arena restoration pass |
| Runtime / auxiliary / FAT | 293 / 15 sectors; 308 of 309 used, one free cluster | Unchanged; no usable sector growth |
| Floppy reads | Deadline inventory 20 fresh / 19 resumed sectors; full cold and interactive inventories still open | No added loads; prior no-read annotation corrected |
| Trust and assurance | Exact dated leaf, full FO/CV/Finished and status-last release; physical sampler characterization still separate | Current authenticated pin, rejected-identity recovery fixed; no new assumption or entropy credit |
| Compatibility | NE2000 and 3c503 successful reuse, 3c503 stale-pin failure menu; resident/driver and other phases identical | Recovery restored; config/arena/video/adapter guards pass; broader timing/NIC regression belongs to OPT-002 |

That earlier ranking selected OPT-002. Its validated result and next action
are recorded in the reconciliation below. Manual pin refresh remains operational
rotation evidence only; no new runtime trust path is authorized.

### Reconciliation after OPT-002 validation

The validated checkpoint was committed as `de9cf53` with explicit maintainer
approval: `perf: use word products for Poly1305`. It contains only `Makefile`,
`targets/ibm_pc_5150/boot/core/poly1305.inc`, and
`tools/crypto-bench/tls13-product/check_poly1305_multiply.py`. Campaign and
architecture Markdown stay local, as requested; nothing was pushed.

| Dimension | Before -> current | Interpretation |
| --- | --- | --- |
| 8088 fresh / margin | Matched 3c503 13.722039 -> 11.231663 s; seven-NIC matrix max 11.219607 s / 3.780393 s margin | 2.490376 s (18.15%) less on matched 3c503; under-12 target observed across all seven NICs. Across all current-revision observations, 11.231663 s is the maximum, including the long-prompt case |
| 8088 cold | Matched launch-to-DPI 407.007 -> 379.494 s; BASIC RUN-to-DPI 352.662 -> 324.873 s | Same boundaries and long prompt, sequential single samples; provider payloads vary |
| 8088 reused turn | Matched long turn 57.899 -> 46.036 s; current short matrix 37.454–53.443 s | Improvement observed; under-35 goal remains open. Two-second oracle polling and provider/payload variation limit attribution |
| 286 cold / margin | Current raw harness launch-to-DPI 181.123 s; live Finished 8.098887 / 8.600794 / 8.149059 / 8.600072 s, worst margin 6.399206 s; serialized gate 8.0740 / 9.0627 s | Read-only 6 MHz / 512 KiB greeting, reuse and reconnect pass. Raw launch timing is not the historical normalized cold boundary; no matched 286 speedup claim. Serialized exclusions remain explicit |
| Resident / active driver | 2,048 / 512 B -> unchanged; all eight DRVs byte-identical | One resident linked-call displacement changes; no added resident logic or active-driver RAM |
| Executable windows | K 5,310 -> 5,306 B, still 11 sectors in its 15-sector slot; largest packed auth 6,592 B / 13 sectors unchanged | Four code bytes saved; no new usable FAT capacity |
| Stack / persistent RAM | Multiplier 18 -> 18 B, full symmetric 52 -> 52 B; arena/context 96 / 96 B unchanged | No row-operand spill or new persistent scratch |
| Runtime / auxiliary / FAT | 293 / 15 sectors, 308/309 data sectors, one free cluster -> unchanged | No usable sector growth; four extra K padding bytes are not recovered FAT sectors |
| Reads | Deadline inventory 20 fresh / 19 resumed sectors -> unchanged | No load schedule or read changes; broader cold/interactive inventory remains open |
| Trust and assurance | Exact dated leaf / conforming 286 split, full FO/CV/Finished/status-last, conventional RAM and zeroization -> unchanged | All affected hostile/composition/dispatch/bounds/replay gates pass; emulator supplies zero physical entropy credit |
| Compatibility / findings | Seven NICs, CGA/MDA, direct32, 286, no-card/no-driver recovery pass | Retained early-close Novell attempt; repeat passes. Long-prompt repeated answer also exists on baseline, and UTF-8 greeting glyph limitation remains |

Validation commands include fresh `make`, `make inspect`, `make basic-bootstrap`,
the build-wired multiplication oracle, the eleven component commands in
`offline-register.json`, full serialized 286 timing, and the strict live wire
analyzers through `run-matrix-short.py` / `run-extra-register.py`. The final
source/image binding and whitespace/index/user-file checks pass. Detailed
commands, logs, pcaps, screenshots, and raw timings remain under OPT-002.

After the approved commit, OPT-004 investigated the repeated long-prompt answer
and reached the bounded negative disposition below. OPT-005 now attributes the
remaining reused-turn cost; the earlier correctness failures remain open.
Defer broad primitive rewrites and the conforming-8088 moonshot while this
narrower correctness/interactive work is unresolved. Do not remove K/track
padding on byte counts alone; actual deadline I/O geometry still matters.

### OPT-004 — Distinguish memory-note directives from the current question

- Wishes: 2 (response correctness) and 10. Follow-up selected from OPT-002's
  failed long-prompt reuse/reconnect validation. Active baseline is committed
  `de9cf53`, with frozen OPT-002 source/image bindings unchanged.
- Question: does promotion of a compacted note into request instructions make
  a prior one-turn answer directive override a different subsequent question?
- Baseline behavior: on both `b25c84a` and OPT-002's candidate, the first long
  question returns `FORTYTWO`; after a 500-second idle the displayed ninety/nine
  question also returns `FORTYTWO`. Optimized wire topology is four flows;
  baseline took six after a post-compaction connection close. Both reach DPI.
- Allowed initial surface: isolated request/compaction diagnostics, exact
  emitted request fixtures, and the ledger. Preserve current ENV, prompt paths,
  native tools, status-last authority and bounded replay. Do not infer a new
  memory/product contract before the cause is demonstrated.
- Required evidence: capture or reconstruct the actual compacted note and
  emitted next request, separate provider/model behavior from target input
  preservation, compare normal reuse and reconnect, and reproduce any proposed
  correction at the 16 KiB floor with recall and tool/replay regressions.
- Exit: a proven narrow correction with all affected gates, or a bounded
  negative result identifying the remaining cause/assumption. Any genuine
  product-direction choice goes to the maintainer.
- Status/disposition: **bounded negative result; no product change**. Both new
  live captures produce the note `FORTYTWO` and then correctly answer the new
  question with `NINETYNINE`. Earlier failures remain preserved and unexplained;
  neither the note's authority nor a target input/parser fault is established as
  their cause. Do not claim the response bug is fixed. Evidence is under
  `build/optimization-campaign/OPT-004/`; `disposition.json` binds the outcome.
  On recurrence, capture the restored pending prompt as well as the note before
  changing framing. Continue the campaign with OPT-005's latency attribution.

Initial OPT-004 diagnostic evidence:

- Isolated `note-diagnostic-floppy-160k.img` replaces R's unused 16 KiB
  far-context helper with a 74-byte COM1 snapshot shim and one five-byte call
  hook. It captures only the prior compaction flag, note length, used length,
  and used conversation bytes. The product sources/shipping images are unchanged;
  this image is restricted to the 16 KiB diagnostic and supplies no timing claim.
- All 194 valid length/compaction-state shim cases preserve caller registers,
  flags, and exact snapshot bytes. Exact R/X ordinary/reconnect fixtures with
  zero-, 29-, and 48-byte notes emit identical requests with and without the shim.
  See `note-diagnostic.json` and `diagnostic-preservation.json`.
- First live capture is the original-speed read-only 3c503 two-long-question
  case without forced idle (`note-reuse/`). The exact R/X reconstruction helper
  consumes captured note metadata with a synthetic credential; its output omits
  HTTP headers. The long first prompt exceeds the 96-byte context cap, so
  pre-compaction trimming is another cause to distinguish. Live result follows.

- First diagnostic live result: the pre-compaction 96-byte transcript exactly
  matches unchanged R/X/T execution (`first-turn-storage.json`), including loss
  of the initial `U:` marker. Captured compacted note is exactly `FORTYTWO`;
  the next request preserves the ninety/nine question and appends that note to
  instructions, but the live answer is correct `NINETYNINE`, with clean DPI
  directly inspected. This rules out deterministic repetition from that bare
  note alone. Read-only image unchanged; strict four-flow wire gate passes.
- The no-idle attempt nevertheless retired its application channel after the
  compaction exchange and took one fresh/resumed route before the final answer.
  Keep it as an observed recovery, not a two-flow ordinary-reuse control.
  Whether completion detection or another transport condition caused this
  retirement is unestablished. See `note-reuse/observation.json`.
- Exact reconstruction around a modeled no-output compaction failure shows
  note_len changes 0 -> 96 on rebuild but the emitted compaction body/records
  remain identical (`failed-compaction-rebuild.json`); this excludes that
  metadata change alone as the source of a changed request in this case.
- Next: repeat the original 500-second idle case with the same note capture
  (`note-reconnect/`) before choosing any product correction.

- Parser negative result: unchanged R/X/T executes a supplied summary
  `FORTYTWO` followed by the preserved ninety/nine question and supplied
  `NINETYNINE` response correctly for 1-, 7-, 17-, 31-, and 128-byte fragments.
  Summary stays hidden, reasoning deltas stay ignored, only the new answer
  renders, and the note remains stored. See `compaction-parser.json`. This
  excludes a deterministic stale-note render in the modeled path, not live
  provider/transport behavior. Existing source and gates also require record
  authentication before parser publication and retire invalid record sequences.
- Historical design explicitly placed the note in instructions to avoid the
  model continuing a summary as the latest dialogue (`core/data.inc` note_len
  comment). Any future correction must preserve that intent and recall/tool
  behavior; moving raw notes into input without context is not yet justified.

- Bounded host model comparison (not target evidence): the captured bare
  `FORTYTWO` note answers ninety/nine correctly in both repeats. Synthetic
  `Answer only FORTYTWO.` in instructions produces the wrong old answer in
  both repeats; moving it unchanged to a prior assistant item is inconsistent
  (one correct, one wrong). A role-only move is not justified by this test.
- Eight host compaction/answer chains using the reconstructed target bodies
  all answer the second question correctly; generated notes range from
  `FORTYTWO` to `forty+two uppercase, no separators=FORTYTWO`. Notes are normalized
  and capped exactly as the target stores them. See `host-comparison.json`,
  `host-note-authority/`, and `host-generated-notes/`. Host sockets are recorded
  explicitly; the strict pcap analyzer excludes their non-Seed TLS profiles.
  No target trust assistance, product change, or new performance claim follows.

- Original 500-second idle case also returns `NINETYNINE` after a captured
  `FORTYTWO` note. First answer, second answer and final DPI directly inspected;
  strict four-flow wire gate and unchanged read-only image pass. The no-idle
  case's spontaneous reconnect remains distinct. Both campaign VMs are stopped.
- Prepared fallback diagnostic `note-prompt-diagnostic-floppy-160k.img` captures
  the same used note plus the exact screen-restored prompt and marker. It uses
  two unreachable far-tier helper regions only at 16 KiB; nine offline combinations
  of note lengths 0/29/48 and prompt lengths 1/107/255 preserve the exact original
  ordinary/reconnect requests and snapshots. No live run of this second diagnostic
  was needed because the repeated answer did not recur. Keep it for recurrence;
  do not use either diagnostic image as a shipping or timing baseline.
- Shipping sources/images still match committed `de9cf53` and OPT-002's frozen
  validation hashes. Index is empty, user cfg/NVR hashes are unchanged, no new
  commit or push was made, and campaign Markdown stays local. This disposition
  narrows the hypotheses without erasing the original baseline/candidate failures.

### OPT-005 — Attribute the remaining 8088 reused-turn latency

- Wishes: 2, 6, and 10; preserve wish 1's accepted handshake margin.
- Question: how much of the 37.454–53.443-second short reused turn is target
  computation, phase/prompt I/O, rendering, or provider/transport wait, and
  which narrow change has credible savings without increasing RAM, FAT use,
  interactive seeks, or the fresh-handshake deadline?
- Baseline: committed `de9cf53`, frozen OPT-002 images/source binding and the
  seven-NIC short matrix. Matched long turn 57.899 -> 46.036 s; the under-35
  goal remains open. Use the exact short prompt from `short-prompt-contract.json`
  for comparable live timing; do not mix long prompts or compaction/reconnect
  into an ordinary reused-turn comparison.
- Allowed initial surface: isolated attribution fixtures and diagnostic tooling
  under `build/optimization-campaign/OPT-005/`, plus this ledger. Product source
  read-only until the measured opportunity selects a narrow implementation.
- First action: bind the committed runtime/listing/image, then inventory the
  successful phase/asset sector reads and executed R/X/K/T work for one short
  reused turn. Extend the exact request/reconnect and application-record gates
  as measurement fixtures; do not infer application cost from the handshake-only
  symmetric fixture. Keep host/model, BIOS/NIC waits and target CPU counts distinct.
- Required evidence: independent record/plaintext correctness oracle; exact
  shipped request/record/parser paths; byte, register/stack and RAM-lifetime
  accounting; successful read/seek inventory; identified limits of the 8088
  cycle/prefetch model; and a matched original-speed 4.77 MHz / 16 KiB read-only
  observation to bound the complete route. Count all required work rather than
  treating an omitted wait or display operation as zero cost.
- Candidate ranking: prioritize measured user-visible savings and narrow
  regression radius. R/X/T parsing/rendering, record crypto, repeated loads
  and provider payload overhead are hypotheses, not preselected fixes. Preserve
  full authentication, status-last release, native tool replay, ENV compatibility,
  note intent and the existing conventional-RAM ownership boundaries.
- Exit: ranked, quantified follow-up with a credible route to reducing turn
  latency (or a bounded negative finding). An accepted implementation later
  requires fresh build/inspect, relevant hostile/record/compaction/recall/tool
  gates, and affected exact-floor live NIC/display/reconnect validation; every
  commit/push still needs explicit approval.
- Carry-forward correctness condition: OPT-004 did not establish the prior
  repeated-answer cause. If it recurs, preserve the case and use the validated
  note-plus-prompt capture before attributing it to a performance change.
- Status/disposition: **attribution completed; follow-up to OPT-006**. No
  product implementation is accepted. Regenerated runtime/listing match the
  committed `de9cf53` frozen images exactly; runtime remains 150,016 B,
  SHA-256 `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`.
  Source, shipping images, HEAD/index and pre-existing user files are unchanged.
  All tools, isolated profiles, diagnostics, prototypes and detailed evidence
  are under `build/optimization-campaign/OPT-005/`; start with `REPORT.md`,
  `disposition.json`, `binding.json` and `evidence-binding.json`. All campaign
  VMs are stopped. No commit or push was made.

Reliability qualification and current live evidence:

- The canonical `tools/check-tls13-record-cap.py` rejects all eight historical
  short-matrix captures. First-turn-only analysis confirms that this is already
  present in the timed first answer, not merely the later idle/reconnect.
  See `matrix-record-cap/` and `matrix-turn-cap.json`. This invalidates treating
  37.454–53.443 s as a reliable ordinary-turn baseline that leaves the channel
  reusable. It does not invalidate the independently checked handshakes.
- Two new authenticated-prefix captures reproduce `fortytwo` followed by an
  oversized 2,942-byte record, before the complete HTTP terminal is published.
  Exact shipped scheduler/K/T execution of the captured prefix takes
  `agent_api_exchange.text_seen_fallback`, preserves prior text, zeroes the
  whole application key/IV/sequence band, clears ready, and returns to DPI
  without replay or a new connection (`oversized-retirement.json`). This is
  fail-closed retirement, not an authentication bypass. A gate that checks only
  the answer, DPI and an eventual reconnect can miss it.
- New **unmodified** 3c503 observation: 4,772,728 Hz 8088, exactly 16 KiB,
  ROM BASIC, CGA and write-protected frozen image; same 34-character short
  question and directly inspected answer/DPI. Submission-to-DPI is 48.665756 s:
  4.048221 to first request wire byte, 2.797596 request span, 0.419761 until
  first response, 0.659996 response arrival span, then 40.740182 until DPI.
  Six request records total 1,551 wire bytes; 15 response records total 11,715.
  Strict profile and record-cap gates pass; fresh/resumed intervals are
  11.094770 / 6.779050 s. Host SLiRP timestamps do not expose guest driver
  waits; work overlaps arrival and DPI includes two-second polling/OCR.
  No immediate second question was sent, so this single pass does not certify
  reuse after that answer. See `short-3c503/` and `attribution.json` inside it.
- An isolated 115200-baud diagnostic captures a **complete** authenticated
  HTTP/SSE response: 11,436 plaintext bytes, 22 records, 34 parser chunks,
  eight visible answer bytes and complete HTTP termination. Independent
  HTTP/SSE decoding and exact wire/plaintext lengths agree. Headers consume
  1,203 B, HTTP framing 103 B and SSE 10,130 B; `response.completed` alone is
  2,913 B and happens to be split across acceptable records in this run.
  Obfuscation contributes only about 91 JSON bytes. Do not assume provider
  write boundaries will fit the spool. The 135-byte authenticated-output shim
  uses already-loaded K padding, adds no reads/RAM/FAT sectors, and preserves
  registers, flags and exact-route outputs. It exports neither client requests
  nor keys. Serial captures are fixtures, not performance baselines.

Exact target-work and resource attribution:

- `measure.py` executes the shipped resident scheduler, R/K/X/T, no-tool M
  check and Y restoration through the next DPI keyboard wait, loading real
  sectors and prompt assets from the frozen image. Pure-Python AEAD and the
  independent `cryptography` ChaCha20-Poly1305 oracle agree on every request
  record and supplied response record/plaintext. The captured server bytes are
  re-encrypted with synthetic keys; no live private state is needed.
- The complete captured fixture executes 9,383,842 instructions/REP elements.
  The 4.77 MHz model attributes 15.938557 s to ChaCha20, 7.216546 to Poly1305,
  2.163667 to T parsing, 0.035492 to R/X construction and 1.117549 to remaining
  glue: 26.471809 model seconds total. Actual branches, REP elements, shift
  counts, operand widths and stack traffic are counted; phase-aware decoding
  handles reused overlay addresses. Prefetch queues, refresh, interrupts,
  BIOS bodies and NIC/device waits are not fully modeled. Same-record BDA/UART
  checks underestimate sampled non-UART spans by roughly 17–65%, with tick
  and UART-removal uncertainty; they do not calibrate Poly1305 or disk/NIC work.
  The 22-record fixture and 15-record unmodified live run cannot be subtracted
  to assign the unexplained wall time. An exact elapsed CPU/I/O split is open.
- Successful read order, as absolute LBAs: R 194–196; K 15–25; X 198–200;
  TOOLS 309; IDENTITY 307; T 201–202; M 204–206; Y 212; unused DPI R prefetch
  194–196. Total **28 sectors / 14,336 B**, nine track transitions / 76 track
  steps on the eight-sector single-head geometry. Same-track backward reads
  also matter; this inventory excludes retries and motor/media timing. T stays
  resident through all authenticated chunks. With 458-byte TCP payloads the
  fixture calls receive 27 times, ACK 48 times and send six times; external
  waits are not zero-cost evidence. 128-byte fragmentation preserves outputs,
  context, ready state and reads while increasing NIC calls.
- K is 5,306 executable bytes, 11 loaded sectors in a fixed 15-sector slot;
  selected driver is 512 B inside the 2,048 B nucleus. Spool `2E00–3600`,
  application state `3600–3668`, arena `3E40–3EA0` and context `3EA0–3F00`
  remain unchanged. Measured software stack reaches `3FC2` (62 B below
  `4000`), excluding BIOS/NIC/interrupt private stacks; this is not a new
  physical stack bound. Program writes stay below `4000`; higher reads are
  ordinary screen reads. BIOS glyph operations remain explicit external work.

Ranked opportunities and validation:

1. **Post-text terminal-record retirement:** reliability prerequisite, selected
   as OPT-006 below. It can force the next ordinary question into the costly
   fresh route. Do not raise the record limit beyond its backing storage,
   publish unauthenticated text, drop potential output/tool events or assume
   provider-side filtering is supported.
2. **Inline ChaCha rotations:** isolated byte-permutation prototype removes
   1,409,760 instructions/REP elements and 15,678,240 modeled cycles from the
   complete fixture, **3.286843 model seconds / 12.4%**. K grows 5 B to 5,311,
   within the same 11 sectors and unchanged 150,016 B runtime; no persistent
   RAM, software stack, FAT or read growth. Exact wire/plaintext/parser outputs
   match, and 128 block-oracle cases preserve all GP/DS/SS/ES registers with
   arbitrary caller CX. The earlier non-inlined prototype's +2 B stack peak
   is superseded. This is a ranked candidate, not an accepted live speedup.
3. **Remove unused DPI R prefetch:** isolated actual-code bypass preserves
   ready state, records, context, prompt and stack, reducing reads **28 -> 25**
   (1,536 B). Duration is unmeasured. The final track 26 -> 24 movement shifts
   to the next submission, so this alone is not a steady-state seek saving.
4. **K retention:** potentially 11 fewer reads, conditional on proving code
   lifetime through native writes/execute, reconnect and ENV save/restore.
   The TLS-ready flag alone does not prove executable bytes remain valid.
5. **Parser/rendering/provider payload:** T accounts for only 2.16 model
   seconds and output is eight glyphs. Large generic parser/render changes
   rank below measured primitive/I/O work. Do not remove response semantics,
   native tools or authenticated output to realize an apparent saving.

- Validation: fresh NASM runtime/listing identity, `make`, `make inspect`,
  existing application hostile-record and product reconnect/replay gates;
  independent complete-record oracles, 128/458-byte fragmentation, forged-tag
  no-publication/full-retirement, oversized-terminal prior-text preservation
  with no replay, diagnostic register/route preservation, and four directly
  inspected original-speed live cases. Profile gates pass all four; record-cap
  failures are retained for the two prefix captures and old matrix. No product
  source, trust boundary, native-tool/ENV contract, driver, device-RAM use or
  entropy assumption changes. The OPT-004 repeated-answer cause remains open;
  it did not recur in these short cases.

### OPT-006 — Resolve post-text terminal-record retirement at the 16 KiB floor

- Wishes: 2 reliability prerequisite, with 6 and 10 accounting.
- Question: can a larger target-local authenticated-record spool consume the
  observed terminal records and retain immediate reuse at 16 KiB without
  weakening authentication, output/tool semantics or bounded reconnect/replay?
- Baseline: committed `de9cf53`; 2,048 inner bytes / 2,069 wire bytes, historical
  records up to 4,251 wire bytes, two reproduced post-text retirements and the
  complete OPT-005 plaintext fixture. An answer and DPI alone are insufficient.
- Allowed surface: isolated lifetime/construction proofs first, then the narrow
  K application implementation, matching ClientHello limits and affected gates.
  Preserve provider/trust/16 KiB contracts, full FO/CV/Finished/status-last,
  conventional RAM, native tools, ENV and all rejection/zeroization boundaries.
- Required evidence: exact shipped-path independent record/plaintext oracles,
  hostile input and byte/stack/FAT/read accounting; full build/inspect/offline
  gates; distinct immediate reuse, compaction, record-cap and strict wire checks,
  then affected original-speed NIC/display/reconnect/direct/286/recovery gates.
- Exit: a validated narrow correction or bounded negative construction result.
  Inline rotations and unused DPI-prefetch removal remain later candidates.
- Status/disposition: **larger-spool candidate rejected**. The stronger live
  matrix found a 6,277-byte record during the 3c501 third-turn compaction
  exchange, exceeding the new 4,373-byte ceiling and followed by a fresh
  connection before any planned idle. The remaining matrix was stopped;
  repeating until provider records happen to fit would not validate reliability.
  Product/tool edits have been archived and restored to their bound pre-spike
  contents. Fresh baseline `make`, `make inspect` and BASIC generation pass;
  runtime, listing, floppy and helper match the initial hashes exactly.
  `restored-checkpoint.json` verifies sources, user files, empty index and
  stopped campaign VMs. The rejected candidate remains isolated under `build/`.
  No commit or push is authorized or performed.

Construction and exact-revision evidence, retained under
`build/optimization-campaign/OPT-006/`:

- Remove only the product application K's uncalled 1,801-byte SHA/HMAC copy,
  simplify obsolete alternate-spool branches and share the existing ChaCha XOR
  loop across send and block-aligned authenticated replay. Complete K shrinks
  **5,306 -> 3,314 B**, ending at `24f2`, with a new `2500–3600` spool holding
  **4,352 inner bytes / 4,373 wire bytes**. Both ClientHellos offer 4,352 in the
  unchanged-size field. Cold-phase semantic/staging limits remain separate.
- Whole-record tag verification still precedes type/padding inspection and
  every parser publication. Non-final replay chunks are 576 = 9 * 64 bytes;
  existing occupied-tail state inhibits keep-alive overwrites during replay.
  Complete-K and block-alignment assertions protect the construction. Rounded
  K loads touch initial spool padding only before receive. See `DESIGN.md`.
- K reads **11 -> 7 sectors**; fixed K file slot stays 15 sectors. Runtime
  remains 150,016 B / 293 sectors, FAT 308/309, arena/context 96/96 B.
  All eight drivers and every floppy byte outside SEED.SYS are unchanged.
  Exact complete scheduler reads **28 -> 24 sectors**, track transitions 9 -> 8,
  track steps unchanged at 76 and software stack peak unchanged at 62 B.
  These candidate savings are not accepted production improvements.
- Candidate runtime SHA-256
  `9b7aef9fcb75577e08f0bf16f12e1b12e2cd362a4e722e43d6190d949faa536e`;
  image `00b3fd19d23b76974eaec1956169c80b18742b9fc950b826e3c50f7144cda6d6`.
  `final/` retains its frozen artifacts; `final-binding.json` binds that
  candidate, not the restored shipping image. `rejected-candidate/` preserves
  the twelve changed tracked sources, added checker and product-only patch.
- Fresh candidate build/inspect/BASIC, all eleven additional offline gates,
  47 exact-16-KiB boundary/hostile cases, old/current wire-profile checks,
  compaction/parser fixtures at five fragment sizes, native continuation
  no-replay and restored-ENV admission pass. Earlier stale 286 oracle-literal
  build failure is retained and corrected in the successful final build.
- Identical complete captured records preserve exact request/parser/text/HTTP
  and ready state with **9,281,678 instructions / 124,916,937 modeled cycles**,
  down 102,164 instructions and 0.283772 model seconds. Repartitioned
  4,251-wire-byte records pass; forgery publishes nothing and retires keys;
  a 4,374-byte post-text record preserves prior text and retires without replay.
  See `models-final.json`. BIOS/NIC/interrupt bodies and physical disk/stack
  behavior remain outside those modeled counts.
- Serialized 6 MHz / 512 KiB 286 sweep passes, unchanged at acquisition
  147 ticks / 8.0740 s and resumption 165 ticks / 9.0627 s. Its resident/I/O/
  complete-offline-authentication exclusions remain; no 286 live pass follows.

Live disposition (frozen read-only image, 4.77 MHz / exactly 16 KiB BASIC):

| Case | Evidence | Disposition |
| --- | --- | --- |
| Focused 3c503 | Two correct immediate answers; max 2,944 wire B on second answer; strict two-flow/cap pass | Inspected pass of this case only; no third answer |
| Full 3c503 | Three immediate correct answers including compaction, 4,251-B records, fourth answer after 500 s and one reconnect | Strict four-flow/cap and direct inspection pass |
| NE2000 | Second answer has 4,251-B records; third reuses session; fourth succeeds after 500 s and one reconnect | Strict four-flow/cap and direct inspection pass |
| 3c501 | First two correct answers, max 4,152 / 4,251 B; third exchange receives 6,277 B and reconnects before idle | **Failure retained**, stopped during third-turn recovery |
| Remaining NICs, MDA, direct32, 286 live and recovery | Not run after established candidate failure | No acceptance claim |

Full 3c503 Finished intervals are 11.248684 / 6.786689 / 11.232978 / 6.770442 s;
turns 53.019923 / 43.740765 / 98.678946 / 353.389788 s. NE2000 Finished intervals
are 11.209322 / 6.751820 / 11.212020 / 6.741862 s; turns 53.606592 / 43.730850 /
88.461586 / 354.197539 s. Compaction/reconnect and variable provider payloads
prevent treating these as fixed-workload speed comparisons. Per-case checked
`observation.json` files and inspected images remain in `matrix/`.

The 3c501 violation arrives 57.982609 s after third submission; the fresh
reconnect starts at 93.153418 s, before any idle. First two turn times are
69.393533 / 79.445295 s. Its recovery fresh Finished is 12.284879 s, outside
the desired under-12 target, without a matched-cause attribution. The third
answer was not verified before deliberate interruption; no fourth question was
sent. `matrix/vm-net-3c501/failure.json`, failed cap/wire reports and pcap retain
this distinction. Encrypted metadata does not identify the offending plaintext.

Bounded negative conclusion and next action:

- The observed 6,256 inner bytes require 1,904 B more than this spool. Keeping
  its end at `3600` would start at `1d90`, overlapping 1,890 B of current K.
  This rules out another simple bound increase on this layout, not every
  possible 16-KiB receiver architecture.
- A whole-record buffer for the protocol's permitted 16,385 inner bytes already
  exceeds all installed 16-KiB RAM, before code/state. An unnegotiated record
  limit does not constrain the peer; see [RFC 8449 section 4](https://www.rfc-editor.org/rfc/rfc8449.html#section-4).
  Current credential-free, certificate/hostname-verified host probes to both
  resolved provider addresses also omit offered `max_fragment_length=1024`
  from EncryptedExtensions. See `negotiation-probe/result.json`; these are
  limited host observations, not a guarantee about all provider configurations.
- Do not chase the largest sampled record, alter semantic output, publish
  unauthenticated bytes, borrow device RAM or introduce writable storage.
  A different construction needs an independent proof of bounded tentative
  parser state and delayed publication. OPT-007 below is selected for that
  design question; no such product design is accepted yet.

### OPT-007 — Prove delayed publication without a whole-record buffer

- Wishes: 2 reliability prerequisite, with 5, 6 and 10 accounting.
- Question: can the exact 16-KiB target process larger TLS records using a
  bounded buffer of pending parser effects, then commit those effects only
  after whole-record authentication, preserving every currently accepted
  output/tool/compaction continuation and the reconnect/replay contract?
- Baseline: restored committed `de9cf53`; OPT-006's larger-spool construction
  failed on a 6,277-wire-byte third-turn record. Its isolated space recovery and
  passing component cases are reusable evidence, not an accepted implementation.
- Allowed initial surface: this ledger and isolated proofs under
  `build/optimization-campaign/OPT-007/`; product sources remain read-only.
  First bind the restored source/image and inventory every actual T/parser
  effect on display, context, notes, native calls, completion, pacing and state.
- Required evidence: an independent security and byte-lifetime argument;
  explicit bounds for pending effects and rollback; no pre-tag display, context,
  note, tool or authority publication; full invalid-tag/type/padding/length/
  split-record zeroization and rejection; exact plaintext/semantic equivalence
  for every previously accepted continuation. Identify any new rejection bound
  honestly. Do not assume that parsing arbitrary unauthenticated data is safe.
- Exit: a concrete bounded target-local design plus executable construction
  proof, or a precise missing assumption/product decision. Any later product
  implementation needs full affected offline and exact-floor live validation.
- Status/disposition: **bounded experiment complete; broader requirement selected**.
  The maintainer-created context completed the inventory and executable
  experiments. No product design is accepted for implementation. A journal
  can cover larger records with few effects, but arbitrary output still needs
  proportional retained information. An explicit effect limit preserves the
  old record envelope while rejecting some valid larger-record packings.
  The model does not prove target code fit, pre-tag timing security or IRQ/
  lifecycle integration. Detailed evidence is under
  `build/optimization-campaign/OPT-007/`; begin with `REPORT.md`,
  `parser-audit.json`, `journal-model.json` and `final-checkpoint.json`.

Exact-source findings and bounds:

- Fresh NASM runtime/listing match restored `de9cf53` exactly. Runtime remains
  150,016 B, SHA-256
  `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`.
  Shipping image/helper, 636 tracked files, pre-existing user files, HEAD and
  index are preserved. Only this ledger and isolated OPT-007 files changed;
  no VM, product edit, commit or push was made.
- Exact T has 18 mutable scalar bytes, 512 B raw function-call capture and
  96 B context, plus ordered display effects. T also invokes keepalive;
  completion/text/tool flags affect the resident scheduler. T does not write
  `note_len` or execute native tools directly, but its context/capture enables
  later R/M work. Deferring BIOS output alone is insufficient.
- A prior authenticated record can leave a delta string open. A following
  record then emits one character per content byte. The exact 16,384-byte
  output continuation passes the parser oracle when divided into old-envelope
  records; the context still stores only 96 B. For N independently chosen
  64-way ASCII characters, lossless delayed output needs at least
  `ceil(6*N/8)` bytes of total distinguishing state: 4,692 B for 6,255 content
  bytes (6,277 wire), or 12,288 B for 16,384. This rules out fitting arbitrary
  effects into OPT-006's 4,352-byte window, not every conceivable 16-KiB
  architecture. The observed 3c501 plaintext remains unknown.
- A host journal model retains 2,047 raw emit bytes, 524 B projected scalar/
  capture state and 576 B bounded NST/alert content: **3,147 B before other
  receive/crypto state, stack and additional code**. It uses the original
  emitter after successful whole-record tag/type validation. The captured
  11,436-byte response and a 14,759-byte mostly-metadata fixture preserve exact
  tested semantics. Repartitioning the long output into a record with 2,048
  or more effects rejects it. There is no smaller per-response text cap;
  the limit applies independently to each record. This is a logical model,
  not an assembled or accepted target construction.
- The rightmost-nonzero/type latch, embedded/trailing zeros, strict bounded
  NST shapes, and original AAD/ciphertext MAC are exercised with independent
  AEAD oracles. The 182 model cases include invalid tag/type/header/length,
  every truncation prefix of a representative record, sequence exhaustion,
  capacity failure, prior-effect preservation and modeled erasure. Exact T
  has 75 fixture/fragmentation comparisons covering output, compaction, notes,
  tool capture, escapes, completion, CGA/MDA and graceful-stop state. These
  finite cases do not prove arbitrary reachable-state or full native-tool/
  scheduler equivalence.

Security/lifetime conditions for any follow-up:

- Two equal-length invalid-tag records differing in one ciphertext byte take
  22,480 versus 35,889 tentative parser instructions before the tag. The
  unmodified emitter/scanner takes 107,855 versus 36,059 instructions on the
  corresponding 451-byte plaintext continuations. These are instruction
  differences, not a measured remote exploit or wall-time result. Snapshot
  isolation alone does not rule out an ACK/timing oracle; a fixed-work parser
  or a proved externally indistinguishable receive schedule is required.
- Executing the current resident retirement leaf erases the 104-byte
  application capability but leaves the current ciphertext spool unchanged.
  A new plaintext journal therefore needs explicit success/failure/cancel/
  ENV/reconnect erasure. This is an obligation for the new construction, not
  a claim that the shipping ciphertext spool contains unretired plaintext.
  INT 9 can change ESC/cap state or jump to `chat_loop`; a frozen snapshot
  must not overwrite user control or bypass cleanup. Keepalive/tail escrow,
  sequence advancement and committed-only retry decisions also need proof.
- Fresh isolated image/layout inspection and the existing application-record
  and product reconnect/replay gates pass, including the exact 16-KiB R/X
  rebuild and packaged 512-KiB ready turn. No live acceptance, speedup, full
  target stack bound or new entropy claim follows. Product implementation
  still requires the full affected offline and exact-floor live gates.

Maintainer decision after OPT-007: **require broader record handling**, independent
of how the server packs otherwise supported application data into valid TLS
records. The E=2,047 pending-effect profile is not accepted as the product
solution. The requirement concerns per-record packing; existing semantic limits
on context, tool capture and other application state remain in force. This is
an acceptance requirement for future work, not a claim about the shipping
receiver.

Next investigation: establish whether a target-local construction can meet that
requirement at the exact 16-KiB floor, with explicit storage/code/stack bounds,
authentication before publication, and the existing lifecycle and replay
contract. Keep all campaign hard invariants. Typical SSE sizes, token budgets
and an unnegotiated record-size offer do not establish a peer-enforced bound.
The controller owns the architecture research and selection of the next
falsifiable spike; the maintainer is not being asked to supply a technical
solution. Record any remaining feasibility obstacle precisely before proposing
a scope change. OPT-007's bounded model remains evidence, with no accepted
product implementation and no outstanding application-profile decision.

### OPT-008 — Test TCP retransmission as a source for authenticated replay

- Wishes: 2 reliability prerequisite, with 5, 6 and 10 accounting.
- Question: can the existing provider connection guarantee a second pass over
  a complete valid TLS record through ordinary TCP retransmission, allowing a
  16-KiB receiver to retain bounded ciphertext commitments instead of the whole
  record, without a helper, another connection or pre-authentication effects?
- Baseline: committed `de9cf53`, unchanged shipping artifacts; OPT-006's
  4,352-byte spool fails on 6,277 wire bytes and OPT-007's 2,047-effect journal
  does not meet the maintainer's broader record-packing requirement.
- Allowed surface: this ledger and isolated source audits/models/reports under
  `build/optimization-campaign/OPT-008/`. Product sources, shipping artifacts,
  prior evidence and VM state remain read-only. No provider credentials or live
  application request are needed for the initial transport feasibility test.
- Required evidence: bind current source/image; inspect exact SYN/window/ACK/
  duplicate handling; check primary TCP specifications for sender retention,
  congestion/window progress and SACK semantics; executable counterexamples
  for any assumed replay guarantee. Separate transport feasibility from the
  additional cryptographic commitment and publication proof it would require.
- Exit: a concrete transport contract sufficient for a later security proof,
  or a bounded negative result identifying the missing peer behavior and the
  next in-scope architecture investigation. Do not infer a guarantee from one
  provider capture or from a model that assumes a cooperative sender.
- Status/disposition: **bounded negative result; simple replay guarantee
  rejected**. Exact source audit and protocol counterexamples are complete.
  No product implementation is accepted. This does not establish that every
  hybrid replay scheme or every 16-KiB receiver architecture is impossible.
  Evidence is under `build/optimization-campaign/OPT-008/`; start with
  `REPORT.md`, `source-audit.json`, `transport-model.json` and
  `final-checkpoint.json`.

Findings and accounting:

- Fresh isolated NASM runtime/listing match the unchanged committed artifacts.
  Runtime remains 150,016 B / 293 sectors, SHA-256
  `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`;
  FAT 308/309, arena/context 96/96 B and shipping receive bounds remain unchanged.
  The 636 tracked files, pre-existing user files and prior OPT-007 evidence are
  preserved. No VM, provider request, product edit, commit or push occurred.
- Exact emitted SYN offers MSS=384 with no SACK-Permitted option; SYN and
  ordinary ACK advertise 256 bytes. Fourteen exact resident/C-phase cases
  verify packet checksums, ACK advancement before TLS, duplicate/future-sequence
  rejection, option skipping and sequence wrap. NIC transmission is a host
  leaf, not live NIC validation.
- Ordinary cumulative ACK progress releases the sender's retention obligation;
  an old ACK cannot rewind it. Withholding ACKs holds the window edge, and a
  larger advertised window cannot force a larger congestion window. The
  abstract model has 16 stalled-prefix cases and four ACK/reclaimed-data cases,
  plus ten hybrid cases and one favorable full-window control (31 total).
  [RFC 9293 §3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4)
  and [RFC 5681 §3.1](https://www.rfc-editor.org/rfc/rfc5681.html#section-3.1)
  ground these necessary-condition examples; the model is not a full TCP stack.
- An optimistic hybrid retains the cumulatively ACKed prefix locally. With
  MSS=384, unconstrained slow start, a 32,768-byte receive window and no further
  timeout, the model needs 8,011 prefix bytes for a 16,406-wire-byte record,
  before commitments/code/buffers/state/stack. This is a threshold of that
  model, not a universal minimum or proof against every hybrid architecture.
- SACK retains a sender-side copy until cumulative ACK, but the current SYN
  does not negotiate it. Its reneging and timeout schedule is not a proved
  replay service. Account for [verified erratum 1610](https://www.rfc-editor.org/errata/eid1610)
  and [RFC 6675 §5.1](https://www.rfc-editor.org/rfc/rfc6675.html#section-5.1):
  a sender need not unconditionally clear its old SACK scoreboard on timeout.
  No SACK-aware construction was implemented or ruled out universally.
- Even with available replay bytes, per-chunk commitment verification must
  precede their publication; checking another whole-record tag afterward is
  insufficient. Sequence/position binding, type/padding, exact effects,
  cancellation, complete retirement and the existing no-replay policy remain
  required. Perfect free commitments in the model intentionally grant no
  security, target byte-fit or timing proof.
- Baseline layout/core inspection and the new 14 exact-code / 31 model cases
  pass. No shipping cost, phase-read schedule, driver behavior, display state,
  trust or entropy assumption changes. This read-only result needs no new live
  matrix; existing live evidence is not relabeled as validation of a new design.

Next action: OPT-009 tests lossless effect encoding against a complete RAM
budget before another receiver implementation. The broader requirement is
settled; no maintainer product choice is pending.

### OPT-009 — Bound full-record effects against the 16-KiB execution footprint

- Wishes: 2 reliability prerequisite, with 5 and 10 accounting.
- Question: can a lossless representation of every otherwise-supported parser
  continuation in a maximum legal TLS application record coexist with the
  receive/authentication code, live state and stack in 16 KiB conventional RAM,
  while retaining authentication before every observable effect?
- Baseline: unchanged `de9cf53`; OPT-007 proves at least 12,288 distinguishing
  bytes for one 16,384-character, 64-way ASCII continuation. Its journal has
  only 2,047 effects and OPT-008 does not establish a guaranteed TCP second
  pass. The maintainer explicitly requires independence from server packing.
- Allowed surface: this ledger and isolated arguments, exact-code oracles and
  assembly/layout prototypes under `build/optimization-campaign/OPT-009/`.
  Product sources, shipping artifacts, prior evidence and VM/user state remain
  read-only until a construction is accepted for a separate implementation.
  Existing flat-file phase loading may be analyzed; no new runtime module ABI,
  device-memory storage, writable scratch, helper or floor change is authorized.
- Required evidence: independently verify the OPT-007 counterexample and the
  exact reachable parser alphabet/state, using valid application text for any
  stronger bound; account for all distinguishing state, including compressed
  effects, tags, registers, context and capture. Inventory mandatory BIOS/
  handoff/NIC/session/user state and executable/stack lifetimes with real byte
  counts. Distinguish fixed current-layout bounds from bounds that survive
  permitted reorganization. Typical compression ratios are not worst-case
  bounds. A positive construction needs executable lossless equivalence,
  complete maximum-record/type/padding coverage, no pre-tag timing/publication
  leak, cancellation/zeroization and composed 16-KiB fit. Explicitly account for
  any replay assumption rather than granting an external second pass.
- Exit: a concrete in-scope construction and falsifiable target budget, or a
  precise bounded infeasibility result identifying which footprint/semantic/
  peer assumption a different construction would have to change. Do not infer
  a universal impossibility merely from the current K/spool layout, and do not
  silently fall back to an effect cap or raise the RAM floor.
- Status/disposition: **bounded negative complete in the maintainer-created
  OPT-009 context**. Lossless effect encoding cannot fit beside the retained
  current nucleus, even after granting its padding and mutable bytes to the
  encoding. This is not a universal impossibility result for every permitted
  16-KiB execution schedule. No product construction is accepted. Evidence is
  under `build/optimization-campaign/OPT-009/`; start with `REPORT.md`,
  `information-bound.json`, `parser-oracle.json`, `footprint.json`,
  `proof-checks.json` and `final-checkpoint.json`.

Findings and complete-footprint accounting:

- Fresh isolated NASM runtime/listing and all four ISA-family driver payloads
  match the unchanged shipping artifacts. Runtime remains 150,016 B / 293
  sectors, SHA-256
  `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`;
  FAT 308/309 and arena/context 96/96 B. The 636 tracked files, user files,
  shipping artifacts and prior OPT-007/008 evidence are preserved. No VM,
  provider request, product edit, commit or push occurred.
- Independent exact T execution reproduces OPT-007's 16,384-byte 64-way
  counterexample. It also preserves complete output/context/capture/display/
  completion for valid larger-alphabet HTTP/SSE/JSON continuations split into
  the old <=2,047-content-byte records. Tests cover 512 byte transitions in
  reachable string/escape states, eight full-length cases, seven valid escapes
  and five UTF-8 fragmentation cases. The existing renderer emits literal
  UTF-8 bytes as glyph bytes; this is preserved behavior, not a Unicode fix.
- A 91-way printable non-space ASCII subset, excluding quote/backslash/period,
  needs at least **13,328 B**. A strict UTF-8 scalar subset excluding controls,
  surrogates, noncharacters and those parser-special ASCII bytes needs at least
  **111,783 distinguishing bits / 13,973 B** for 16,384 content bytes. No period
  or CR/LF can trigger an accidental completion pattern; every byte emits one
  glyph. The full event is valid UTF-8 JSON, including at scalar boundaries
  split across records. See [RFC 8259 §§7–8.1](https://www.rfc-editor.org/rfc/rfc8259.html#section-7)
  and [RFC 3629 §§3–4](https://www.rfc-editor.org/rfc/rfc3629.html#section-3).
- The exact recurrence is `C[n] = 91*C[n-1] + 1888*C[n-2] +
  61406*C[n-3] + 1048544*C[n-4]`, with `C[0]=1` and negative indices zero.
  Independent matrix exponentiation and all 1,111,929 scalar checks agree.
  A host enumerative codec round-trips the witness subset in **14,016 B**;
  its code, big-integer work area and variable timing are not a target fit.
  The 207 codec cases and ten small counting cross-checks pass. This is an
  exact worst-case counting result, not an average compression estimate.
- The bound counts all distinguishing state together, including tags, MACs,
  registers/flags/IP, stack, context/capture shadows, metadata and self-modified
  code. It assumes no guaranteed later peer copy and no early publication or
  externally visible timing storage. Tags are not charged twice or granted
  free information. Preserving the independent arbitrary 96-byte user arena,
  even by joint encoding, raises the bound to **14,069 B**.
- The new NASM export probe inventories all 16,384 conventional bytes and
  exact executable extents. Shared nucleus payload is 1,528 B plus 8 B
  padding; loaded driver slot 512 B, payloads 328–444 B. K remains 5,306 B
  (including the removable 1,801-B SHA/HMAC copy), T exactly 1,024 B, keys/
  IVs/sequences 104 B, model/key caches 256 B, reconnect/tool state 330 B,
  ESC code/vector 90 B and stack reserve 256 B. The new T-only software
  stack observation is 36 B; BIOS/NIC/IRQ stack bodies remain outside it.
- Even granting **32 extra CPU bytes**, a retained 2,048-B nucleus and the
  current 1,280-B BIOS band leave only 13,088 B for all record information:
  UTF-8 deficit 885 B before reserving anything else. Removing all resident/
  driver padding and crediting all 18 resident mutable bytes still leaves
  deficits **675–791 B** across the four ISA driver families. Relocation,
  K/T removal and padding recovery alone cannot satisfy that retained-code
  construction; this does not make current code sizes universal lower bounds.
- Across a different layout, retaining the existing BIOS band and arbitrary
  arena leaves at most **1,067 B** for everything else at the boundary after
  full authentication and before the first record effect. Keeping the 46-B
  handoff valid reduces that ceiling to **1,021 B**. Separately retaining
  today's 256-B caches, 104-B session state, 96-B context and 256-B stack would
  leave only **309 B**; that last subtraction is a current-allocation
  sensitivity, not an entropy minimum. The BIOS reservation is also an
  explicit compatibility assumption, not an independently proved minimum for
  all possible BIOS rewrites.
- Existing flat-file phase loading can discard/reload immutable code, but
  its loader, 512-B DMA destination, IRQ/BIOS stack and remaining effects need
  a composed lifetime budget. Post-authentication publication may progressively
  free encoded bytes. Neither possibility is prohibited or assumed solved by
  the bound. No new module ABI, device storage, writable scratch, smaller effect
  cap, semantic truncation or raised floor is selected.
- A separate exact no-publication scanner experiment takes 23,011 versus
  36,059 instructions for equal-length invalid-tag records differing in one
  ciphertext byte. This renews the timing-proof obligation, not a measured
  remote exploit. A future design still needs full tag/type/padding, rollback,
  cancellation/ENV retirement, sequence/tail escrow and bounded replay proofs.
  The legal maximum synthetic record agrees under two independent AEAD
  implementations and rejects tag mutation; no maximum-record target receiver
  is claimed. [RFC 8446 §§5.1–5.4](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1)
- Fresh baseline layout/core/FAT inspection and the existing product reconnect/
  replay gate pass, including the exact 16-KiB rebuild and packaged 512-KiB
  ready-turn case. Full live/TLS acceptance is not rerun for this read-only
  result. No shipping performance, RAM, floppy, phase-read, trust, NIC/display
  or entropy changes follow.

Next in-scope question: can a different application nucleus and phase schedule
meet the **1,021-B residual ceiling at that boundary**, with all remaining live
state, code, loader work and stack counted, and the security/lifecycle contract
composed? Otherwise identify a proved reduction of a specifically named
footprint assumption or an actual peer replay contract. The controller resumes
from this quantified obstacle; OPT-010 below investigates phase eviction. The
broader record-packing requirement remains settled, and no maintainer product
decision is pending.

### OPT-010 — Test eviction and sector overlays at a nearly full receiver

- Wishes: 2 reliability prerequisite, with 5, 6 and 10 accounting.
- Question: can an application-only nucleus, made by evicting boot/setup/
  scheduler code and phasing the existing receive/authentication routines,
  meet OPT-009's necessary memory ceiling throughout a maximum record,
  including a separately arriving final tag and the first publication?
- Baseline: unchanged `de9cf53`; a valid UTF-8 output family needs at least
  13,973 B of total distinguishing state. The independent 96-B arena, current
  BIOS reservation and valid handoff leave at most 1,021 B for everything
  else, generously crediting 32 CPU bytes. No target codec is established.
- Allowed surface: this ledger and isolated source-derived assembly probes,
  execution oracles and lifetime models under
  `build/optimization-campaign/OPT-010/`. Product sources/artifacts, prior
  evidence and VM/user state stay read-only. The investigation may relocate
  and split existing flat-file phases; it may not change the parser contract,
  floor, trust, driver selection, device-memory rules or replay assumption.
- Required evidence: bind the actual checkout and image; measure exact
  application-only routine closures and meaningful smaller boundaries; execute
  representative final-tag fragmentation and phase transitions; compose code,
  live state, stack and 512-B disk destinations at each relevant cut. Credit
  overlapping record-dependent storage only once. Separate a necessary bound
  with an ideal codec from an actual target construction, and count reloads.
- Exit: an executable and fully accounted candidate schedule for further
  security/codec work, or a bounded negative result identifying the concrete
  routines, allocations or load assumptions that need a different design.
  Do not infer that all smaller receivers are impossible from current sizes.
- Status/disposition: **bounded negative complete in the campaign task**.
  Boot/setup/scheduler eviction and existing-code sector overlays do not meet
  the necessary bound while retaining the named current allocations. A
  two-page arithmetic component works, but is not a receiver construction.
  Evidence is under `build/optimization-campaign/OPT-010/`; start with
  `REPORT.md`, `closures.json`, `tail-oracle.json`, `overlay-oracle.json`,
  `cancel-oracle.json`, `budget.json` and `final-checkpoint.json`.

Findings and accounting:

- Fresh NASM runtime/listing and four ISA driver wrappers match the shipping
  artifacts. Runtime remains 150,016 B / 293 sectors, SHA-256
  `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`;
  FAT 308/309 and arena/context 96/96 B. The 636 tracked files, user files,
  shipping artifacts and 93 prior OPT-007/008/009 evidence files are preserved.
  No VM, provider request, product edit, commit or push occurred.
- Exact reachable instruction unions, granting free placement and excluding
  data/padding/stack/glue, are **851–981 B for ACK + receive**, **507–572 B for
  receive alone**, and **354–450 B for ACK alone** across the four ISA driver
  families. The closures preserve packet checks, errors, waits and the selected
  fallback; inactive drivers cost nothing. They are current instruction sizes,
  not linked replacement kernels or universal lower bounds.
- Current crypto closures are ChaCha20 block 574 B, Poly1305 process-block
  472 B, multiply 111 B, reduction 322 B, application MAC finalization 573 B,
  tag emission 37 B and tag comparison 32 B. Constants and work are additional.
- Seven exact shipping-receiver cases at its 2,048-B inner envelope cover tags
  split 16, 15+1 and sixteen individual bytes, a mutated/missing last byte,
  64-byte padding and an authenticated unsupported type. The receiver still
  ACKs/polls/parses after all content arrives. Nothing is published before the
  complete tag/type passes; rejection preserves the sequence, success advances
  it once, and the arbitrary arena survives. NIC I/O and publication are host
  leaves in exactly 16 KiB; no maximum-record target receiver is claimed.
- Future tag bytes must be credited in a bound before authentication. With
  `Q = C[16384] * 2^768` from OPT-009 and `r` missing tag bytes, grant all their
  information and require only `ceil(Q / 2^(8*r))` distinct current states.
  The other-state ceilings are **1,037 B** with all 16 tag bytes missing,
  **1,022 B** with one missing, and **1,021 B** after authentication. This avoids
  incorrectly applying the final cut unchanged to an earlier receive.
- Keeping the raw 256-B model/key caches, 104-B application state, 96-B committed
  context and current 86-B ESC code costs **542 B**. A fixed 512-B immutable
  phase slot raises this to **1,054 B**, giving necessary deficits **17/32/33 B**
  at those cuts before charging any loader, stack, other state or codec. These
  pinned allocations are explicit assumptions, not entropy minima. The user
  arena is already counted in `Q`; tags and record-dependent workspace are not
  double-charged. Only one phase slot is charged, with no extra bounce buffer.
- For an arbitrary valid UTF-8 prefix followed by fixed ASCII content, granting
  all future tag bits, the same fixed-slot bound crosses between 16,364 and
  16,365 prefix bytes. Loading earlier and reusing padding later needs a complete
  remaining execution path; it is not independently ruled out. The figures do
  not establish that reclaiming 33 bytes is sufficient for an actual receiver.
- An isolated `cpu 8086` component executes add/multiply (148 B including a
  seven-byte caller) and reduction (322 B) through the same 512-B slot. Its
  arithmetic bodies are byte-identical after relocation. A 127-B controller
  retains the current floppy read and frozen-sampler path. Twenty-four integer
  oracle cases and six torn-read failures pass; failed pages never execute,
  high persistent state and the sampler marker remain unchanged. The controller,
  marker, slot and pinned ranges total **1,183 B**, a 162-B final-cut deficit
  while still granting stack and record-dependent scratch to the encoding.
- That particular naive split needs two reads per Poly1305 block: a maximum
  inner record requires 1,027 MAC blocks, hence **2,054 reads / 1,051,648 B**
  before other work. This is model accounting, not measured 8088 time or a
  lower bound on all overlays; batching and the combined 472-B closure remain
  possibilities. No candidate pages were added to the shipping FAT.
- Two exact Ctrl+ESC cases show the unchanged 86-B handler still jumps to
  `chat_loop` after its nucleus is evicted. A new architecture must invalidate,
  erase tentative state and restore the DPI continuation before transferring
  control. This is a new-journal obligation, not a claim that the current
  ciphertext spool contains plaintext. New software-stack observations (30 B
  for the arithmetic component, 42–44 B for receive) exclude real BIOS/NIC/IRQ
  bodies and are not physical stack bounds.
- Fresh baseline layout/core/FAT and product reconnect/replay checks pass,
  including the exact 16-KiB rebuild and packaged 512-KiB ready turn. No shipping
  speed, RAM, trust, entropy, NIC/display or phase-read improvement follows.

Next action: test the implementable cost of a bounded-work codec in OPT-011,
instead of granting a near-optimal journal for free. A future kernel must also
replace or reconstruct named persistent/control allocations and compose every
remaining lifetime. The broader packing requirement is settled; no semantic
cap, higher floor or maintainer product decision is introduced.

### OPT-011 — Test a bounded-work 8086 codec for the hard UTF-8 effect subset

- Wishes: 2 reliability prerequisite, with 5, 6 and 10 accounting.
- Question: can a streaming lossless 8086 codec for OPT-009's valid UTF-8 effect
  family retain any 16,384-byte continuation in at most 14,016 journal bytes,
  with at most 512 further conventional-RAM bytes for its code and mutable
  codec workspace, and a receive schedule indistinguishable before tag
  authentication for equal-length inputs?
- Baseline: unchanged `de9cf53`; OPT-009's host codec achieves 14,016 B only for
  its witness subset, using unbudgeted big integers and variable work. The
  information minimum is 13,973 B. OPT-010 shows that current state plus a
  sector window already exceeds necessary near-full bounds, so neither codec
  work nor phase reloads can be treated as free.
- Allowed surface: this ledger and isolated arguments, assembly, oracles and
  reports under `build/optimization-campaign/OPT-011/`. Product sources,
  shipping artifacts, prior evidence and VM/user state remain read-only. No
  effect cap, truncation, extra RAM, device storage, writable scratch, helper,
  unproved network replay or new runtime module ABI is authorized.
- Required evidence: bind current sources/artifacts; give an exact worst-case
  encoded-size bound including framing/carry/partial UTF-8 state; implement
  encoder and decoder under `cpu 8086`; independently check round-trip order,
  scalar/record boundary cases, maximum size and guarded conventional writes.
  Count constants, tables, counters, stack, registers and normalization work
  once, with no free host big integers or table reads. Test malformed and
  equal-length invalid-tag inputs and supply the work/scheduling argument;
  snapshots or valid-text-only timing comparisons are insufficient. Measure
  target instructions/cycles and any phase reads without presenting host time
  as target performance. Authentication remains over the original ciphertext.
- Exit: an executable codec component with a justified bound and explicit
  remaining full-parser/receiver obligations, or a bounded negative result
  identifying which journal/code/work/schedule target fails. A positive subset
  result is not an accepted application profile or product receiver: every
  otherwise-supported parser continuation, type/padding, tool/ENV/cancel path,
  network/crypto lifetime and full target budget still needs composition.
- Status/disposition: **bounded negative complete in the maintainer-created
  OPT-011 context**. An executable finite-word codec meets the journal bound;
  this construction misses the 512-B code/work target and has no justified
  pre-tag receive schedule. No product construction is accepted. Evidence is
  under `build/optimization-campaign/OPT-011/`; start with `REPORT.md`,
  `SECURITY.md`, `size-proof.json`, `independent-audit.json`, `roundtrip.json`,
  `security.json`, `footprint.json` and `final-checkpoint.json`.

Findings and accounting:

- Fresh isolated NASM runtime/listing and all eight driver binaries match
  shipping artifacts. Runtime remains 150,016 B / 293 sectors, SHA-256
  `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`;
  FAT 308/309 and arena/context 96/96 B. The 636 tracked files, user files,
  shipping artifacts and 145 prior OPT-007/008/009/010 evidence files are
  preserved. No VM, provider request, product edit, commit or push occurred.
- The streaming `cpu 8086` encoder/decoder use 16-bit interval arithmetic,
  short class/ordinal tables and binary payload events. Allowing 66 extra
  noncharacters simplifies the scalar counts to 91 / 1,888 / 61,440 /
  1,048,576. This is a superset of the hard witness, not a full parser or a
  product application profile. Input/output cross a one-byte AL ABI; there is
  no host rank, big-integer work, probability table or normalization service.
- Exact rational interval-loss bounds prove at most **14,008 B**, including
  a 12-B header with both raw partial scalar ends, termination, alignment and
  16 explicit decoder look-ahead bits. The normalized range is at least
  16,386; each width-w scalar retains an interval ratio at least `114^-w`.
  At 16,384 bytes there are at most 111,950 normalizations. A 32-bit pending
  counter is charged; a word is not assumed sufficient. Large integers occur
  only in the host proof. The 14,016-B journal target has eight spare bytes.
- Independent enumeration checks all 1,111,995 superset scalars, reproduces
  the strict 111,783-bit / 13,973-B minimum, and checks 8,404,821 interval
  cases across 171 cumulative classes and every normalized range. Sixty-six
  exact target/reference round-trips cover all ASCII and two-byte scalars,
  272 wider edges, 20 record cuts, boundary lengths and six maximum-length
  cases. Maximum observed frame is **13,990 B**, distinct from the proven
  bound. Raw leading/trailing bytes preserve scalar splits and output order;
  the full parser must maintain the initial continuation state.
- Encoder code/constants/work/software stack are **806 + 18 + 31 + 8 =
  863 B**; decoder **752 + 22 + 32 + 8 = 814 B**. Separate residency is already
  granted. Even removing cold init/wipe/finish code with free relocation leaves
  feed/pull closures plus tables/work/stack of **691 / 657 B**, exceeding the
  target by **179 / 145 B** before loader or caller glue. These are current
  implementation footprints, not universal lower bounds for every codec.
- The private 16-KiB machine maps no device RAM and guards every data access,
  but loads code over the BIOS region. It is not a bootable receiver. The
  28 architectural register bytes are inventoried; caller saves and BIOS/NIC/
  IRQ stacks are additional obligations. No phase reads execute. Ordinary
  rounded storage would take two sectors per direction before a loader; no
  phases are packaged or FAT capacity claimed.
- Maximum-case encoding executes **4,994,344–7,506,448 instructions** and
  decoding **5,288,529–8,353,208**, including component initialization and
  finalization. The uncalibrated campaign model gives **23.25–38.57 s** encode
  and **26.98–46.51 s** decode at 4,772,728 Hz, before crypto, caller, network,
  BIOS or disk work. These are target instruction/model results, not host
  elapsed times, physical timing, or a shipping performance claim.
- Two equal-length invalid-tag fixtures differing in one ciphertext byte
  execute **325,687 versus 25,363 encoder instructions**. Both independent
  AEAD oracles reject the original ciphertext/tag; no decoder is invoked.
  The work differs at equal public fragment cuts, so an immediate-return
  ACK/poll path would inherit it. Six detailed cases and 256 byte mutations
  cover valid-text and malformed paths. A finite total-work bound and delayed
  publication do not prove an indistinguishable receive schedule. Deferred
  bit flushing and real CPU/I/O/IRQ timing still need a new scheduling proof.
- Eighteen explicit malformed/overlength cases, sixteen journal-corruption
  cases and ten interrupted encode/decode erasure cuts pass their bounds and
  cleanup checks. The explicit leaf clears journal, workspace, expired stack
  spills and GP registers. It does not compose Ctrl+ESC, ENV, reconnect,
  committed context or full TLS retirement. The codec is not an integrity
  check, and subset rejection must not become a product semantic cap.
- Fresh read-only layout/core/FAT, application-record hostile-input and
  product reconnect/replay gates pass, including exact-16-KiB rebuild and the
  packaged 512-KiB ready turn. No shipping speed, RAM, trust, entropy, display,
  NIC or phase-read change follows; live acceptance is not rerun.

Next in-scope question: can a smaller byte-oriented grammar/coder fit its active
code/work while providing a content-independent receive schedule for arbitrary
pre-tag input? Splitting this codec inside byte calls instead owes explicit
loader, I/O and fixed scheduling costs. Either route still needs full parser,
type/padding, tool/ENV/cancel, network/crypto and target-budget composition.
This result does not prove every 512-B codec or every 16-KiB receiver impossible.
No effect cap, floor change, peer-packing assumption or maintainer product
decision is introduced. No next spike is started in this OPT-011 context.

### OPT-012 — Test a byte-oriented codec and fixed receive schedule

- Wishes: 2 reliability prerequisite, with 5, 6 and 10 accounting.
- Question: can a byte-oriented UTF-8 state machine replace OPT-011's scalar
  conversion and deferred-bit work, retaining the hard subset in at most
  14,016 journal bytes with at most 512 additional code/work/stack bytes and
  an input-independent public receive schedule before tag authentication?
- Baseline: unchanged `de9cf53`; OPT-011 proves 14,008 journal bytes but uses
  863/814 B for full encode/decode components, or 691/657 B for active
  feed/pull closures with free cold-code removal. Equal-length invalid-tag
  records take 325,687 versus 25,363 encoder instructions. No receiver is
  accepted; full record-packing independence remains required.
- Allowed surface: this ledger and isolated arguments, assembly, oracles and
  reports under `build/optimization-campaign/OPT-012/`. Product sources,
  shipping artifacts, earlier evidence and user/VM state remain read-only.
  Keep all campaign invariants. No helper, new runtime module ABI, device RAM,
  writable scratch, unproved peer replay, semantic cap or raised floor.
- Required evidence: bind sources/artifacts; exact worst-case journal bound
  including partial-byte/scalar state and normalization; `cpu 8086` encoder
  and decoder with independent byte-order/round-trip and hostile-input checks;
  count active/cold code, constants, workspace, registers, stack and phase
  loads. Bound work across every input byte, including malformed sequences
  and deferred normalization, and test equal-length invalid-tag records.
  Any schedule must account for its real code, timer/CPU/IRQ/I/O assumptions;
  host time or a padding model alone cannot certify target wire timing.
  Authentication stays over original ciphertext. A positive subset component
  still needs full parser, type/padding, tool/ENV/cancel, network/crypto and
  complete 16-KiB lifetime composition before product integration.
- Exit: a justified executable component meeting these targets, or a bounded
  negative result quantifying which part of this construction fails and what
  remains unproved. Do not infer a universal impossibility from one encoding.
- Status/disposition: **bounded negative complete in the existing campaign
  context**, explicitly authorized after OPT-011. The executable byte codec
  meets the journal bound and reduces code/work, but still misses 512 B. The
  emitted IRQ gate proves only its conditional release behavior, not a real
  receiver deadline or wire schedule. No product construction is accepted.
  Evidence is under `build/optimization-campaign/OPT-012/`; start with
  `REPORT.md`, `SECURITY.md`, `size-proof.json`, `independent-audit.json`,
  `roundtrip.json`, `work-bound.json`, `security.json`, `gate.json`,
  `footprint.json` and `final-checkpoint.json`.

Findings and accounting:

- Fresh isolated NASM runtime/listing and eight driver binaries match shipping
  artifacts. Runtime remains 150,016 B / 293 sectors, SHA-256
  `f3844b03da73c4b76772be45566ced67c0d1cff3dbc3c1c09791118bd814f228`;
  FAT 308/309 and arena/context 96/96 B. All 636 tracked files, user/VM state,
  shipping artifacts and 205 earlier evidence files are preserved. No VM,
  provider request, product edit, commit or push occurred.
- Nine byte-grammar states replace scalar reconstruction. A leading byte
  selects width and weighted head; each continuation uses one uniform event.
  Counts remain the witness superset 91 / 1,888 / 61,440 / 1,048,576, including
  66 noncharacters beyond the strict witness. A five-byte header records input
  length, payload length and initial state; partial scalar ends are encoded in
  order without raw prefix/suffix arrays. This is not a product semantic cap.
- Exact rational interval bounds give **14,004 B**, including termination,
  alignment, 16 look-ahead bits and up to three bytes of incomplete-scalar
  credit. The normalized range remains at least 16,386; each complete scalar
  retains at least `114^-width`. At 16,384 input bytes there are at most 111,970
  normalizations. The charged four-byte pending counter accommodates 111,971
  including termination. The 14,016-B journal has twelve spare bytes.
- Independent enumeration checks all 1,111,995 superset scalars, reproduces
  the strict 111,783-bit / 13,973-B minimum, validates all 2,304 state/byte
  transitions with an independent UTF-8 decoder and actual encoder/decoder,
  and checks 15,040,206 interval cases across 306 cumulative classes. Sixty-six
  round-trips cover all ASCII/two-byte scalars, 272 wider edges, 20 record cuts,
  boundary lengths and six maximum-length cases. Largest observed frame is
  **13,984 B**, distinct from the proven bound.
- Every input byte, including malformed data mapped to valid dummy transitions,
  executes at most two arithmetic events and **14 normalizations**. The error
  latch does not skip subsequent public-length work. Whole deferred output
  bytes use bounded REP STOSB; 144 directed tests cover both bits, every partial
  alignment and pending counts through 111,971. Conservative per-byte CFG
  bounds are 24,040 encoder / 2,528 decoder instructions. Those internal-state
  tests and instruction bounds do not prove physical deadlines or reachability
  of every injected state.
- Full encoder code/constants/work/owned stack is **673 + 105 + 19 + 8 =
  805 B**; decoder **596 + 101 + 17 + 8 = 722 B**. Favorable active closures
  with free cold-code removal are **658 / 588 B**, over 512 by **146 / 76 B**.
  Active decode uses its static six-byte call/push depth; its full wipe owns
  eight bytes. The active savings over OPT-011 are 33 / 69 B. This measures
  one implementation and is not a universal lower bound for every codec.
- Maximum-length cases execute **4,296,482–5,235,138 encode instructions** and
  **4,320,588–5,323,474 decode instructions** including init/finalization. The
  uncalibrated model gives **19.67–24.88 s / 22.07–28.48 s** at 4,772,728 Hz,
  before caller, AEAD, BIOS/IRQ, NIC, gate waits or disk. No shipping speed or
  physical timing claim follows. Registers, tables, workspace and stack are
  inventoried; no phase loader/read executes and no FAT space is claimed.
- Two 1,046-byte invalid-tag records differing in one ciphertext byte execute
  **336,773 versus 337,856 encoder instructions**; a valid-ASCII mutation also
  changes work. Equal public 128-byte cuts differ. Six detailed cases and 256
  mutations are rejected by two original-ciphertext AEAD oracles; no target
  decoder runs for them. Eighteen malformed/overlength, sixteen corrupt-journal
  and ten interrupted erasure cases pass their bounds. Erasure remains a
  caller-invoked component leaf, not full TLS/ENV/Ctrl+ESC/reconnect retirement.
- The separate emitted IRQ gate costs **110 B code + 8 B state**. It chains
  IRQ0, canonicalizes GP/FLAGS, then uses STI/HLT for a public deadline. Eight
  on-time arrival cases release at the same tick; three late cases reject;
  all restore the vector. This assumes work arrives at least two ticks early,
  bounded BIOS behavior, the same external IRQ history and gated caller I/O.
  Its synthetic IRET handler and separate overlapping test map do not prove
  those conditions for the product. Adding it already raises active totals
  to **782 / 712 B**, including only the additional six-byte hardware IRQ
  frame and still excluding real BIOS/NIC stack, loader and caller costs.
- Codec tests preserve IVT/BDA and guard exactly 16 KiB of conventional RAM,
  but their code overlaps the real 0600 handoff; no full receiver is composed.
  Fresh read-only layout/core/FAT, hostile application-record and reconnect/
  replay gates pass, including exact-16-KiB reconstruction and the packaged
  512-KiB ready turn. No live acceptance, trust/entropy, NIC/display, product
  floor, phase-read or complete zeroization claim is changed.

Remaining in-scope work needs a materially smaller active construction or an
explicitly costed phase schedule before full parser, type/padding, tool/ENV/
cancel, network/crypto and conventional-RAM lifetime composition. This result
does not prove either route impossible. No effect cap, floor change, peer
replay assumption or maintainer product decision is introduced. No next spike
is started in this bounded OPT-012 task.

### OPT-013 — Compact the preserved model cache and audit reconstruction cost

- Wishes: 2 reliability prerequisite, with 5, 6 and 10 accounting.
- Question: can the existing 64-B model/reasoning/prompt cache be represented
  in 31 B with exact request-visible behavior, no new input restriction or
  media dependency, and does the saving reopen the near-full receiver budget
  after reconstruction code and scratch are charged?
- Baseline: unchanged `de9cf53`; OPT-010's named 542-B preserved ranges plus
  a 512-B phase slot exceed the optimistic authenticated-cut ceiling by 33 B,
  or by 162 B with its loader/sampler. OPT-012's active codec remains 658/588 B.
  The current model cache stores up to 29 model bytes, a fixed JSON fragment,
  one of six supported efforts, a terminator and a live prompt-length byte.
- Allowed surface: this ledger, isolated evidence under
  `build/optimization-campaign/OPT-013/`, and correction of the existing
  `tools/check-tls13-product-config.py` oracle if its expected cache format is
  stale. Runtime sources, shipping artifacts, prior evidence and VM/user state
  remain read-only. No packed cache is integrated into the product in this spike.
- Required evidence: bind current sources/artifacts; execute the exact emitted
  cache publisher and request consumer; check every model length and effort,
  default/missing effort, malformed metadata, maximum values and preservation
  of credentials/prompt state. Implement bounded `cpu 8086` pack/restore leaves,
  guard memory/stack, check erasure and account code/constants/scratch plus all
  reload lifetimes. Audit why optional config files, existing TLS state,
  committed context and cancellation do or do not supply other free storage.
  Repair and validate a stale baseline checker without changing runtime behavior.
- Exit: a validated compact cache component with an exact lifetime/budget
  reconciliation, or a bounded negative finding; neither alone is a full
  receiver or a shipping RAM gain. Continue the campaign from the remaining
  quantified obstacle, keeping the record-packing and lifecycle requirements.
- Status/owner: **complete in the existing campaign context**. Validated
  isolated component and repaired checker checkpoint; the complete receiver
  remains open. No commit or push is authorized or performed.
- Result: a 31-B descriptor (29 model bytes, five-bit length/three-bit effort,
  prompt byte) restores the exact emitted V publisher's model/reasoning tail
  for the actual R bounded consumer. A reverse leaf recovers length/effort from
  that tail and repacks it, so repeated use needs neither retired config fields
  nor another persistent metadata byte. All 33 saved bytes are needed again
  while expanding into the existing 64-B cache. Full pack/restore/repack/erase
  payload is 414 B: 340 executable + 74 tables, with 8 B owned software stack.
  Caller mode, loading, IRQ/abort continuation and request buffers remain owed.
- Component evidence: 721 accepted repeated-use cases; all 256 metadata values
  (180 valid / 76 reserved); 40 bad model/effort/embedded-NUL cases; 309
  interrupted pack cuts and 1,519 restore/repack cuts; 38 malformed expanded
  tails. Guards keep IVT/BDA, handoff, credentials/context and other memory
  intact in private exact-16-KiB mappings. No original config reads are allowed
  during restore/repack; owned-region/spill/register erasure passes. Interruptions
  invoke a test ABI, not a product IRQ/abort scheduler. Metadata is not an
  integrity tag or TLS authority. No live request or product integration occurs.
- Target counts: pack 56–308, restore 179–310, repack 379–1,022 instructions;
  no calibrated elapsed-time claim. Current emitted V/R/X source sizes are
  223/1,527/1,531 B (one/three/three sectors). The isolated component makes zero
  phase reads; its single-page packaging and safe scheduling remain hypothetical.
- Budget: named preserved bytes fall 542 -> 509. With a 512-B phase this is
  exactly OPT-010's optimistic 1,021-B ceiling, before loader, work and stack.
  Existing 127-B controller + 2-B sampler leave a **129-B deficit**, down from
  162 B. With OPT-012's actual 14,004-B journal and no CPU storage credit,
  BIOS/handoff/arena/named-state/phase/controller/sampler need **16,576 B**,
  already **192 B over** before stack or crypto work. The 658/588-B active
  codec alternative is still 209/139 B over before networking/authentication.
  Another 330 B of reconnect/tool state and the 4-B old IRQ vector were already
  omitted from the optimistic bound; removing them cannot be credited twice.
  Optional media, arbitrary credential bytes, live application keys, committed
  context, and the existing ESC continuation supply no demonstrated free home.
  This is not universal impossibility or a shipping 33-B gain.
- Tooling checkpoint: the existing config checker's nominally valid 63-B model
  exceeded the current 29-B limit and its raw-cache expectation was stale.
  `tools/check-tls13-product-config.py` now exports current NASM symbols and
  validates the emitted model/reasoning tail, exact OpenAI/effort admission,
  overlapping 192-B credential copy, guards and DF/return behavior in 16 KiB.
  It passes **482 cases (465 accepted), stack <=4 B**. This checker is the only
  tracked code edit; runtime sources and the pre-existing worktree remain intact.
- Validation: fresh private `make ... all` and `make ... inspect` pass, including
  the ordinary 286 module/tail dependencies. A copied report first rejected its
  different private prefix path; the authoritative builder regenerated that
  report and the unchanged path checks passed. Runtime, three floppy images,
  both BASIC helpers and all eight drivers match the original build. Fresh
  layout/core/FAT/app/reconnect gates and independent driver assembly pass.
  No live timing, entropy, NIC/display, zeroization-composition or product
  acceptance claim changes. FAT remains 308/309 and arena/context remains 96/96 B.
- Evidence: `build/optimization-campaign/OPT-013/REPORT.md`, `binding.json`,
  `cache-tests.json`, `restore-cuts.json`, `source-audit.json`, `budget.json`,
  `build-checks.json` and `final-checkpoint.json`; prior evidence is read-only.
- Checkpoint disposition: pause at the validated checker checkpoint under the
  campaign rule, respecting the explicit no-commit/no-push instruction.
  Proposed checker-only message for a later maintainer decision:
  `test: align OpenAI config cache gate with current wire format`.
  Overall completion remains approximately **20%** (rough range **15–30%**).
  The next controller action is a complete receive/control lifetime schedule
  that addresses the measured loader/state and codec deficits while preserving
  authentication, record packing, tool/ENV/cancel and bounded reconnect. Do not
  integrate this cache alone and describe the full-record receiver as fixed.

### OPT-014 — Integrate the isolated application ChaCha rotations

- Wishes: 2, with 1, 5, 6 and 10 regression/accounting. The maintainer approved
  a focused product-improvement checkpoint before returning to the full-record
  receiver architecture. Prior rejected constructions and their evidence remain
  intact; this does not claim their reliability problem is solved.
- Question: does enabling the isolated inline byte-permutation rotations in
  product application K preserve exact ChaCha/record behavior and improve live
  original-speed dialogue processing without increasing RAM, stack, FAT sectors
  or reads, while leaving the already-optimized handshake implementation intact?
- Baseline: `de9cf53`, plus the preserved OPT-013 checker repair. K is 5,306 B
  / 11 loaded sectors; runtime 150,016 B / 293 sectors, FAT 308/309, arena/context
  96/96 B. OPT-005's isolated candidate has K 5,311 B and removes 1,409,760
  instructions/REP elements from its complete fixture, or 3.286843 modeled
  seconds (12.4%). These are prospective fixture results, not live speed claims.
- Allowed surface: product-K include selection in `boot/core.asm`, scoped
  rotation logic in `boot/core/chacha20.inc`, a focused persistent regression
  gate and its Makefile wiring, this ledger, and evidence under
  `build/optimization-campaign/OPT-014/`. Regenerate normal build artifacts.
  Keep handshake/286 crypto behavior, record limits, spool/parser semantics,
  native tools/ENV, config, drivers and all security boundaries intact.
  Preserve prior evidence, the existing checker repair and pre-existing
  architecture/VM/user state. Use isolated VM/profile copies for live gates.
- Required evidence: bind current source/artifacts; compare exact emitted K
  against the isolated prototype; independent known-answer/random/carry/bit
  ChaCha tests with arbitrary caller CX, memory/register/stack guards and hostile
  record/retirement checks; complete fixture attribution and binary/phase/read
  reconciliation. Pass fresh make/inspect and current TLS offline gates before
  live claims. Measure matched 4.77 MHz / 16 KiB read-only dialogue, distinguish
  provider/record-geometry variation and existing record-cap failures, and run
  affected seven-NIC, reconnect, display, direct32 and conforming286 regressions.
  Do not accept a passing answer/DPI as proof of immediate session reuse.
- Exit: a validated working product checkpoint with a narrowly supported live
  improvement, or retain the bounded result and undo only this spike's product
  edits if the benefit or required compatibility cannot be established.
- Status/owner: **complete as a narrow local performance checkpoint** in the
  existing campaign context.
  Retain the isolated product change locally. No commit or push is authorized.
  Exploration coverage remains approximately **35%** (25–45% range); this
  closes one investigated implementation avenue rather than an entire wish.
- Mechanism/result: select the existing byte-permutation rotations for product
  application K and inline ROL8 inside ROL12 to avoid a nested call. The block
  entry clears internal CX; public caller CX and registers remain preserved.
  The handshake's optimized implementation is unchanged. K grows 5,306 ->
  5,311 B, still 11 loaded sectors. Runtime stays 150,016 B / 293 sectors, FAT
  308/309, arena/context 96/96 B, with no added reads or stack. All eight driver
  files and handshake/286 crypto bytes are identical; other phase differences
  are only relocated calls into K.
- Deterministic evidence: the persistent emitted-block gate passes 431
  independent known-answer, random, carry and key/nonce-bit cases with arbitrary
  caller CX and register/memory/stack guards in exactly 16 KiB. Each block drops
  from 22,786 to 17,506 instructions/REP elements (23.17% fewer), with the same
  30-B software stack. Both complete runtime and floppy images exactly match
  OPT-005's corresponding baseline and inline prototype. Only after binding all
  images and inputs, reuse that earlier complete-fixture execution: 1,409,760
  fewer instructions/REP elements and 15,678,240 fewer modeled cycles, about
  3.3 seconds / 12.4% of its CPU model. Request, sealed records, response,
  rendering, retirement, loads and reads agree; fixture stack stays 62 B.
  This fixture was not reexecuted; BIOS/NIC/I/O/provider time is excluded.
- Fresh make, inspect, BASIC helpers and all 19 recorded build/offline commands
  pass, including current product pack, layout/dispatch, application bounds,
  hostile record/retirement, reconnect/replay, config, cold-send, FAT, sampler,
  RAM lifetime, warm restart, FO/authentication and 286 module/controller gates.
  Fresh serialized 286 models pass at 8.0740 / 9.0627 s, with their existing
  resident/I/O/complete-offline-auth/live-product exclusions.
- Matched read-only 4.77 MHz / 16 KiB 3c503 first-answer observations measure
  submission-to-DPI at 47.291 s baseline and 42.518 s candidate (4.772 s lower).
  Both return correct `fortytwo`; each receives 19 records, with 11,836 versus
  11,833 wire bytes and 7.315 versus 7.296 s to the first server record. This
  is one close-workload observation with two-second polling and small geometry
  differences, not fixed-work attribution or a universal percentage speed claim.
  Both immediate second answers fail on the existing record cap (maximum wire
  records 2,944 / 2,917 B). Keep those failed pairs; text/DPI do not certify
  post-answer session health.
- Seven-NIC first-answer observations are complete and visually inspected.
  NE2000, the 3c501 repeat, NE1000, Novell NE1000 and WD8003E pass the named
  single-answer/handshake/record-bound/read-only gates. WD8003EB displays the
  correct answer but fails the bound on a 2,942-B wire record. All seven have
  correct first text, including the failed 3c503 pair, but the matrix is not a
  universal dialogue/reuse/reconnect pass. Direct 32-KiB NE2000 passes its
  single-answer, handshake, record-bound and read-only gates.
- Retained startup limits: one candidate 3c503 launch never establishes Seed
  entry (BIOS `1C 301`) and is invalid for product/timing attribution. The local
  evidence wrapper now requires the ROM BASIC prompt before typing. The first
  3c501 attempt fails before captured TLS payload at setup `00/12`; baseline
  control and one candidate repeat pass. Its cause remains unestablished.
  Identical cold/driver bytes and the post-TLS application-call placement isolate
  the changed code statically; this is an inference, not an instruction trace.
- The 16-KiB MDA short-prompt case returns correct first text, then fails the
  immediate second answer on 2,537-, 2,518- and 4,251-B wire records. DPI returns
  without `ninetynine`; the planned third-turn idle gate is never reached.
- The first separate NE2000 idle case passes first-answer bounds, then fails
  after 500 seconds idle. Its old session sends 369 B 3.939 s after submission;
  the peer RST arrives 7.485 ms later. No new Seed-profile TLS flow or second
  answer appears; DPI returns. Cause remains unestablished. The baseline
  control and one bounded candidate repeat both return correct second answers
  through four strict flows, but their first answers already exceed the cap
  (4,251 / 4,152 wire bytes). Thus they show recovery after retirement and
  cannot isolate the original clean-session reset failure. All failed verdicts
  remain failed; no more repeats were run and no gate was weakened.
- The read-only 6 MHz / 512 KiB 286 passes both answers, 500-second idle,
  strict four-flow topology, independent ML-KEM/X25519/hello/ticket checks,
  record bounds and image preservation. Finished intervals are 8.0960 / 8.6009
  / 8.1525 / 8.5964 s. Its existing analyzer accepts the closed stale request
  only after the complete ordered reconnect sequence.
- No-card CGA, no-card MDA and no-driver NE2000 ROM BASIC checks pass the
  expected clean-failure and read-only-image gates. Screenshots show the correct
  errors and retry/restart menus. This adds boot/menu coverage, not retry-key,
  warm-restart-key or physical audio testing. The no-driver test image uses the
  exact candidate runtime and normal FAT builder.
- Disposition: retain the independent application performance change with the
  stated evidence and open compatibility limits. This does not qualify full
  receiver/reuse/reconnect reliability. The clean-session 8088 failure is not
  proven to be a regression or pre-existing; isolate it before claiming that
  route is qualified. No physical entropy credit or product acceptance claim
  changes. The existing OPT-013 checker repair, user state and prior rejected
  prototypes remain separate and preserved.
- Evidence: `build/optimization-campaign/OPT-014/REPORT.md`, `offline.json`,
  `candidate-binding.json`, `fixture-reconciliation.json`,
  `matched-first-turn.json`, `nic-matrix-summary.json`, `live/` and `recovery/`.
  `final-checkpoint.json` binds the validated source and shipping artifacts, all
  17 live/three recovery observations, pre-existing user state and 412 unchanged
  prior evidence files. HEAD is unchanged and the index empty.
- Proposed message: `perf: use inline ChaCha rotations for application records`.
- Next after the maintainer continues: investigate isolated TLS dead-code
  cleanup. Keep cache/codec/overlay integration with the full-record receiver
  and receive/control lifetime design; prefetch requires separate timing.


### Reconciliation after OPT-014

With explicit maintainer approval, the isolated ChaCha checkpoint was committed
as `28705e2` (`perf: use inline ChaCha rotations for application records`). The
commit contains only Makefile, core.asm, chacha20.inc and the persistent block
gate. Campaign/architecture Markdown and the prior OPT-013 checker repair remain
local; pre-existing VM/user state is preserved. Nothing was pushed. OPT-014's
pre-commit bindings remain immutable historical evidence. The maintainer asked
to continue with the next scoped improvement.

### OPT-015 — Remove the uncalled application SHA/HMAC copy

- Wishes: 6 and 5, with 2 and 10 accounting; wish 4 receives no sector-saving
  credit while the fixed K file slot remains unchanged.
- Question: can removing only application K's uncalled 1,801-B SHA/HMAC copy
  reduce its load from eleven sectors to seven while preserving exact live
  application behavior, all security/record/retirement boundaries, the handshake
  images, current memory layout and the deadline-sensitive FAT geometry?
- Baseline: committed `28705e2`, plus the preserved OPT-013 config-checker repair.
  K is 5,311 B / eleven loaded sectors within a fixed fifteen-sector file slot.
  Runtime remains 150,016 B / 293 sectors, FAT 308/309, arena/context 96/96 B.
  OPT-006 removed this copy in a rejected larger-spool construction; that
  construction's other changes and reliability claims are not included here.
- Allowed surface: only the product application include in core.asm and its
  explanatory comment, narrowly necessary existing gate adjustments if actual
  emitted-address assumptions are stale, this local ledger, and isolated
  evidence under `build/optimization-campaign/OPT-015/`. Regenerate ordinary
  artifacts. Keep legacy/handshake SHA implementations, spool/record limits,
  phase IDs/file placement, config/native tools/ENV, driver and security logic.
- Required evidence: bind all current source/artifacts/user state and previous
  evidence; establish zero callers of the removed copy; reconcile emitted
  relocation and phase tables; compare the exact full request/record/parser
  fixture, hostile/retirement/tool/reconnect gates, register/stack/RAM and read
  accounting. Fresh make/inspect/BASIC and current TLS offline gates precede
  affected original-speed NIC/display/direct32/286/recovery observations.
  Keep record-cap failures and the unexplained OPT-014 clean-session reset
  distinct; do not claim this cleanup resolves either. An elapsed speed claim
  requires a close-workload comparison and explicit provider/geometry limits.
- Exit: a narrowly validated local cleanup/read-reduction checkpoint, or revert
  only this spike's edits if removal changes behavior or does not reduce the
  actual loaded work. Record negative results and select the next bounded
  question under the campaign policy. Do not commit or push this new spike
  without separate maintainer approval.
- Status/owner: **validated local checkpoint; awaiting maintainer commit approval**. Investigation
  coverage starts at approximately **35%** (rough 25–45% range). No extra
  runtime RAM, broader receiver integration or physical entropy credit is claimed.
- Initial evidence: product pack-base assembles with K at 3,510 B / seven
  sectors. Removing the first include exposed the ChaCha gate's forty-line
  listing lookahead; it now uses the actual K phase table for file/load geometry
  and checks the complete rounded load. The standalone app-oracle image still
  uses the historical controller, so its SHA dependency is retained behind the
  non-product conditional. No app-oracle behavior or shipping record limit
  changes. The first two failed build attempts are retained under OPT-015;
  the corrected build/offline run passes all nineteen recorded commands.
- Built/frozen result: K is 3,510 B, seven loaded sectors; fixed slot/FAT,
  arena/context and all eight drivers are unchanged. Emitted comparison covers
  all 1,523 surviving K instructions, 20 internal relocation sites and 16
  external/key sites; only K metadata changes from eleven to seven sectors.
  All other phase bytes and floppy bytes outside the runtime are identical.
- Five fresh full-scheduler/fragmentation/forgery/oversized-record fixtures pass.
  Exact dialogue reads fall 28 -> 24 sectors, transitions 9 -> 8, track steps
  stay 76; only K LBAs 22–25 disappear. Outputs, state and 62-B software stack
  agree. CPU work changes by only 20 instructions/260 modeled cycles, so the
  claim is reduced I/O, with physical elapsed savings unmeasured.
- All nineteen fresh build/offline commands pass. The first serialized286
  attempt fails its initial ML-KEM benchmark; its image/payload are byte-identical
  to OPT-014's passing component. One bounded private-profile control passes
  all eight components with exact prior payload/image hashes and 147/165 ticks
  (8.0740/9.0627 s). The failed attempt remains recorded with cause unestablished;
  it contains none of the changed application K code. Live results are recorded below.
- Live progress: all seven original-speed read-only NIC profiles return correct
  first text/DPI and pass strict fresh/resumed wire checks; worst fresh Finished
  is 11.2213 s. Five named single-answer cases pass. 3c503 and WD8003EB stay
  failed on 4,251- and 2,942-B wire records despite visible correct answers.
  NE2000/NE1000/Novell greetings include garbled non-ASCII glyphs; no Unicode
  rendering claim follows. The direct 32-KiB NE2000 single-answer/wire/bound/
  read-only case passes, with the same greeting glyph limitation.
- The 16-KiB MDA short pair returns `fortytwo`, then fails the immediate second
  answer on 3,740- and 2,545-B wire records. DPI returns without `ninetynine`.
  The failed capture/screenshot and the owned-harness interruption after this
  conclusive failure remain explicit. No-card CGA/MDA and no-driver NE2000
  pass boot/menu/read-only checks; these do not exercise recovery keys or audio.
- The separate 8088 idle case has a correct, bound-clean first answer frozen
  before its 500-second idle. It then sends 369 B on the old session 2.928139 s
  after the second submission; peer RST follows in 12.060 ms. No new Seed TLS
  flow or `ninetynine` appears, and DPI returns. The record cap passes. A bound
  comparison confirms the same symptom in OPT-014's original clean-session
  failure (3.938602 s /7.484913 ms), so it predates SHA cleanup. Its cause and
  whether it predates the earlier rotations remain unknown. No further 8088
  control was run; cap-contaminated earlier controls retain their limitations.
- The read-only 6 MHz /512 KiB 286 passes both answers, 500-second idle,
  strict four-flow reconnect topology, record bounds and image preservation.
  Finished intervals are 8.0963 /8.5989 /8.1232 /8.5997 s. The unchanged analyzer
  accepts the unanswered stale request only after the complete ordered
  reconnect, not as an ordinary successful round.
- Disposition: retain the isolated cleanup/read reduction with the documented
  limits. It does not qualify full receiver/reuse/reconnect acceptance, add
  user arena/context, free a FAT sector or earn physical entropy credit. The
  initial serialized failure and all failed live cases remain explicit.
- Evidence: `build/optimization-campaign/OPT-015/REPORT.md`, `offline.json`,
  `candidate-binding.json`, `relocation.json`, `models.json`, `io-accounting.json`,
  `serialized-comparison.json`, `nic-matrix-summary.json`,
  `idle-reset-comparison.json`, `live/` and `recovery/`. `final-checkpoint.json`
  binds all 11 live/three recovery observations, the two expected source changes,
  shipping artifacts/eight drivers and 882 unchanged prior evidence files.
- Proposed message: `perf: stop loading unused application SHA code`.
  OPT-015 remains uncommitted; nothing was pushed. Exploration remains
  approximately **35%**, with the same rough **25–45%** range.
- Next after the maintainer continues: trace the 8088 clean-session
  send/reset/retirement path to explain why it returns to DPI without the
  bounded reconnect. The two bound-clean observations make this a concrete
  reliability question ahead of further unused-prefetch timing. Keep
  cache/codec/overlay integration with the full receiver/control lifetime design.


### Reconciliation after OPT-015

With explicit maintainer approval, OPT-015 was committed as `88175d7`
(`perf: stop loading unused application SHA code`). Only core.asm and the
existing emitted-block checker entered the commit. Its reviewed checkpoint,
source/image identities and all previous evidence were rechecked before staging;
no rebuild was needed because the validated source and artifacts were unchanged.
Campaign/architecture Markdown, the earlier OPT-013 config-checker repair and
pre-existing VM/user state remain local. Nothing was pushed. OPT-015's final
checkpoint and evidence remain immutable historical records.

The maintainer has explicitly tabled diagnosis of the intermittent 8088
idle-reconnect failure. Its cause remains unresolved and its existing evidence
and compatibility limits stay recorded. Do not select reset diagnosis or more
failure-isolation repeats as the next campaign work; this direction supersedes
the recommendation at the end of OPT-015. Deferral does not close the issue or
turn a failed observation into a pass.

The next selected question is the redundant request-phase load before DPI input.
OPT-005's isolated bypass eliminated three sector reads, but did not measure
elapsed benefit; a seek moved to the next submission. Evaluate the full cycle
before deciding whether this is worth product integration. Once that bounded
question is settled, profile the largely unexplored 8088 offline-proof spans
(approximately 154.6 s first proof and 69.4 s resumed proof in the entry baseline).
Exploration coverage remains approximately 35% (rough 25–45%).

### OPT-016 — Measure the redundant DPI request-phase prefetch

- Wishes: 6 and 2, with whole-route accounting for 10.
- Question: does removing the request-phase prefetch before the input prompt
  reduce complete 16 KiB dialogue work and observed wait, without moving the
  same cost into the next submission or changing prompt, tool/ENV, retirement
  and security behavior?
- Baseline: committed `88175d7`, plus the preserved OPT-013 checker repair.
  OPT-015's bound complete dialogue fixture reads 24 sectors with 8 track
  transitions / 76 steps. The old OPT-005 isolated bypass saved three reads on
  its then-current baseline, but duration and complete consecutive-turn timing
  remain unmeasured. A new 24 -> 21 read result is a hypothesis until rerun.
- Allowed surface: start with isolated evidence/measurement only under
  `build/optimization-campaign/OPT-016/` and this ledger. The candidate is the
  request-helper preload in `targets/ibm_pc_5150/boot/phases/dpi.inc`; preserve
  its save-prep order, readiness semantics, native auto-continuations and all
  hard invariants. Consider a product edit only after the complete-route
  measurement establishes a worthwhile benefit. Do not reopen the deferred
  reconnect diagnosis or integrate cache/codec/receiver prototypes here.
- Required evidence: fresh baseline binding; exact actual-code fixtures across
  consecutive turns with reads/loads/seeks and state/output/stack comparisons;
  distinguish prompt-restoration wait from next-submit wait and exclude user
  typing time. Include normal cached 32 KiB+ behavior and tool/ENV paths in the
  lifetime check. A retained product change requires the campaign's relevant
  build/offline/live regression gates; do not repeat broad live matrices for
  a hypothesis that can first be rejected by deterministic evidence.
- Exit: a measured, narrowly validated product improvement, or a bounded
  negative finding if the work only shifts or the benefit is not worthwhile.
  Record either result and then select the offline-proof profiling question.
- Status/owner: **complete; source cleanup committed with this checkpoint**,
  in the existing campaign context. The private baseline is byte-bound to the
  accepted HTTP/2 runtime; the old HTTP/1 counts above are historical.
  The maintainer's later cleanup request supersedes the measured deferral below.

#### OPT-016 measurement on the accepted HTTP/2 runtime

Twelve private actual-code runs compare the exact committed runtime against a
single layout-preserving branch over the DPI prefetch. All other bytes stay
identical. Two text turns read 145 -> 142 sectors; write/execute/read plus its
answer and the next human turn read 404 -> 401; a native `save_env` attempt on
write-protected media, its continuation and the next human turn read 223 -> 220.
Each pair removes three prompt-restoration reads, with no additional next-submit
work. Track transitions and total head steps do not change. The corresponding
cached-loader fixtures read 56 -> 56, 170 -> 170 and 91 -> 91 sectors, saving
only a RAM copy. These cached cases exercise the canonical 32 KiB cache with
the fixture's 16 KiB stack/arena, not a new full 32 KiB live acceptance.

The request documents, rendered output, display, live state/key/context/arena
hashes, native execution count, ENV write attempts, stack and segment/DF
contracts match at both returned prompts. Uncached instruction-hook counts drop
by only 100–103 among 4.31–14.14 million; cached counts by 802–805. Counts include
REP terminal hooks and external-leaf entries; no elapsed-time or calibrated
cycle saving has been established. The prototype uses the same sectors and RAM.

Disposition: **measurement complete; defer this small standalone integration**.
The 0.7–2.1% read-count reduction is real in these fixtures, but gives no seek
reduction, cached disk benefit or recovered FAT sector. It does not justify
another product phase-loading change and full live NIC matrix before profiling
the much larger unexplored offline-proof spans. This is a prioritization
judgment, not a claim that three removed reads have zero latency. No shipping
source changed and no live VM was started. Evidence: `OPT-016/prototype-binding.json`,
`measure.py`, `comparison.json`, and the twelve per-case reports. Continue with
OPT-021; revisit prefetch when it can accompany a larger measured phase-loading
improvement. Do not promote the old HTTP/1 24 -> 21 estimate to this baseline.

#### OPT-016 source integration

The maintainer explicitly requested the small OPT-016 cleanup before a fresh
context for the next optimization. This supersedes the prioritization deferral;
it does not authorize a commit or push. The candidate removes only DPI's
request-helper prefetch and its now-unused failure branch/macro. Save preparation
still precedes input or native continuation; the resident scheduler retains the
actual request load and its failure handling. Validation must bind the rebuilt
source candidate, rather than treating the earlier binary bypass as acceptance.
The source candidate is
`2e5d631fa81bb575343fb52782195672e0fc3e4d797a905c9142b329cf3e65b1`.
Only runtime sector 201 (DPI) changes; its emitted code shrinks from 511 to
480 bytes, with the same one-sector padding, 150,016-byte runtime, RAM contract
and FAT geometry. The full build, inspection, BASIC timer-quarantine checks,
18 HTTP/2 composition gates and 13 standalone RAM/config/erasure/cold-send gates
pass. All eight reassembled serialized 286 timing payloads are byte-identical
to the accepted measurements; those prior timings are retained, not rerun or
presented as new DPI timing.

Six source-candidate comparisons confirm the measured 145 -> 142, 404 -> 401
and 223 -> 220 uncached reads, with unchanged cached read counts, seeks and
both returned-prompt snapshots. Source removal saves 102–108 instruction hooks
uncached and 804–810 cached; these remain uncalibrated instruction counts.
Additional baseline/candidate pairs preserve ESC clearing, backspace editing,
the submitted request and cursor state. A partial request-helper read failure
produces the visible retry message, returns to input and accepts a successful
subsequent turn.

The initial cached ENV comparison mixed the old synthetic disk's 12 free
clusters with the shipping disk's one free cluster. It correctly reached the
full-media path before attempting a write. That failed fixture observation is
preserved under `integration/initial-shipping-media/`; the corrected comparison
uses identical synthetic media, replacing only the candidate runtime sector.
The separate shipping-image ENV gates passed unchanged. Evidence is under
`OPT-016/integration/`, including `candidate-binding.json`,
`comparison-media-binding.json`, `comparison.json`,
`request-phase-failure.json` and `offline-checkpoint.json`.

Current status: **offline and live integration acceptance complete**.
`integration/final-audit.json` passes all nine cases, 27 prompted turns and
seven distinct original-speed 16 KiB NIC profiles, binding their exact owned
captures, reviewed replies, unchanged read-only images and protected inputs to
the source candidate. Both `286-512k-02` and `ne2k8-16k-02` pass all five
visible turns, exact-flow TLS/reconnect checks, AX=42 and readback
`B8 2A 00 CB`. `ne2k8-32k-02` passes the functional and exact-flow gates through
the existing manual-completion path: the model spelled out the correct AX and
hex bytes despite the numeric request. Its literal-format failure and observer
stop remain preserved, with the reviewed screenshot and semantic result in
`manual-completion.json`; this is not an automatic numeric-format pass.

The six additional NIC cases (`3c503-16k-mda`, `wd8003e-16k`, `ne1k-16k`,
`3c501-16k`, `novell-ne1k-16k` and `wd8003eb-16k`) pass both visible dependent
turns and the post-idle reconnect, with their exact-flow gates accepted. All
test VMs are closed, the queue is empty and the three-VM cap was retained.
`integration/closure.json` records the final audit hash and zero active VM PIDs.
Local `gpt-6.1-sol` / `max` preferences and the pre-existing tracked VM config
and NVR state remain unchanged. No elapsed-time improvement is inferred from
this regression matrix.

The first three live observers were deliberately stopped and their VMs closed
after a harness mismatch: the revised question allowed ordinary word formatting,
the 286 visibly returned `Forty-two.` plus its input prompt, but the observer
expected the literal unpunctuated `FORTYTWO`. The private runner now tolerates
punctuation/spaces for the four arithmetic word answers, with wrong-answer
checks and literal native numeric matching retained. Initial captures/results
and `integration/initial-live-observer/reason.json` preserve this observer
failure. Replacement main-path cases have the `-02` suffix; no product change
or runtime failure is inferred from the stopped observers.

The copied runner initially used nonexistent canonical paths for two auxiliary
capture analyzers. Their original exit-2 logs remain preserved; completed
captures are reprocessed with the unchanged OPT-020 compatibility wrappers,
recorded in each affected case's `postprocess-repair.json`. The tracked
`check_live_h2_case.py` exact-owned-flow gate is the acceptance authority; the
generic analyzer may reject mixed captures containing other VMs/host traffic.

Disposition: retain the narrowly validated source cleanup in the maintainer-
approved checkpoint, `perf: remove redundant DPI request prefetch`. The
maintainer also approved pushing the current branch. OPT-022 is separate
ongoing work; preserve its edits and ignored evidence without including its
unfinished implementation in this checkpoint.

### Local testing model selection after OPT-015

At the maintainer's request, local `config/USER.CFG` now selects `gpt-6-astra`
with reasoning effort `max`, replacing `gpt-5.6-sol` / `xhigh`. All other config
bytes and permissions were preserved. The current 160/360/1440 KiB test images
were repacked with the unchanged validated OPT-015 runtime; each embedded
`USER.CFG` was verified byte-for-byte. The 482-case config gate, an exact
`gpt-6-astra` / `max` shipping-publisher case, FAT budget and ordinary offline
reconnect/replay gate pass. No live provider validation was performed.
Frozen campaign evidence remains historical; future live comparisons must bind
both baseline and candidate to the same model/effort. OPT-016 remains unstarted,
the intermittent reconnect diagnosis remains deferred, and exploration coverage
remains approximately 35% (rough 25–45%). Nothing was committed or pushed.

### Priority override after live Astra testing — paused by maintainer

The maintainer stopped the RAM-program experiment, requested a simpler chat
test, then explicitly paused all work and made the resulting chat failure the
next priority. Resume with OPT-017 before OPT-016 or further performance work.
Do not resume either experiment automatically while paused.

The unchanged product, configured for `gpt-6-astra` / `max`, produced a live
greeting and the correct `fortytwo` answer on the read-only 6 MHz / 512 KiB
286. The second prompt, asking to add eight, received 2,530- and 2,538-byte
TLSCiphertext records, exceeding the product's 2,064-byte bound. No `fifty`
answer appeared. Seed returned to a ready-looking prompt; the maintainer's
subsequent `continue`, `what did you reply previously?`, and `hello?` also
produced no visible answers. This is a failed repeated-chat test, not evidence
that the model cannot answer. The exact failure/recovery mechanism remains
unproven.

The earlier RAM-program experiment confirmed individual writes and reads but
no completed program or execution. Its first response exceeded the same
record limit, while a later tool continuation stopped without additional
oversized records. Do not attribute every continuation failure to record size
or present manual prompting as an autonomous tool-loop pass.

Evidence is under `build/optimization-campaign/astra-max-286-chat/attempt-01/`
(`binding.json`, `events.json`, `answer-1.png`, `current.png`, `wire.pcap`,
`progress-cap.json`, `result.json`) and `astra-max-286-e2e/`. Automatic prompt
progression and captures are stopped. The chat VM was left open at the
maintainer's request; only the maintainer closes it. Shared config/NVR, runtime,
shipping image and user config were verified unchanged. No product fix, commit
or push was made. Exploration remains approximately 35% (rough 25–45%).

### OPT-017 — Restore reliable repeated chat and failure recovery

- Priority/status: **functional emulator acceptance complete through OPT-020;
  checkpoint committed and pushed as `38b2f40`**. The current shipping-source receiver and native
  journal pass repeated conversation, bounded reconnect and native execution on
  all three CPU/RAM paths, plus the seven-profile NIC matrix. The earlier
  small-record and tool-continuation failures are preserved below as history.
  Physical-source security work remains separate. No commit or push.
- Wishes: 2 (response handling/reliability), with native-tool compatibility.
- Question: can repeated human turns complete after the current failure
  trigger, with explicit recoverable failures instead of a silently unusable
  ready prompt, while preserving authentication and bounded replay?
- Baseline: committed `88175d7`, preserved local OPT-013 checker repair,
  `gpt-6-astra` / `max`, and the bound 286 text-only failure above. Start from
  this capture and source rather than another long RAM-program demonstration.
- Allowed surface: response receive/parser state, session retirement,
  human-turn versus tool-continuation admission, and their existing UI/error
  handling. Inspect `core/tls13_app.inc`, `core/net_phase.inc`, `core/main.inc`,
  `phases/agent_response.inc`, and the relevant existing gates. These are
  investigation candidates, not established causes. Record fresh evidence
  under `build/optimization-campaign/OPT-017/`.
- Required evidence: reproduce the captured oversize rejection and subsequent
  human-turn behavior deterministically; establish whether incomplete parser
  or tool state blocks a new human turn; distinguish this from the separately
  observed tool-continuation failure. Preserve valid-record authentication,
  complete retirement/zeroization, the non-replayable tool-side-effect rule,
  bounded reconnect, all target memory floors and conventional-RAM-only state.
  Do not simply raise a length check without proving backing storage/lifetimes.
- Exit: a validated working fix with repeated simple live replies and relevant
  offline/failure-path coverage, plus honest remaining receiver/tool limits.
  Keep VM lifetime under the maintainer's control; no automatic close for an
  interactive demonstration. Commit still requires explicit approval.
- The previously deferred intermittent 8088 idle-reset diagnosis remains
  deferred; this new priority does not silently reopen that investigation.
- Resumption evidence: the unchanged 150,016-B runtime and current Astra/max
  images are frozen under `OPT-017/baseline/`; all nineteen fresh build/offline
  commands pass (`offline.json`). These passes do not certify repeated live
  chat. Exact-code probes confirm that incomplete tool states 4/5 survive M
  and prevent a new human request from establishing a route after retirement.
  A separate valid-tool fixture marks completion before the HTTP terminal;
  this is another concrete defect, not yet attribution of the text-only case.
- An isolated authenticated-response capture reproduces `fortytwo` followed
  by an unanswered second prompt. That run includes 2,104- and 4,246-byte
  TLSCiphertext records and no observed fresh reconnect. Its captured prefix
  contains no tool call, so the stale-tool explanation remains unproven for
  this failure. `diagnostic-live-01/` retains the failed run; its VM is left
  open. Diagnostic UART work changes timing and is not performance evidence.
- A second isolated diagnostic records six nonsecret turn-state flags. Its
  initial controller was blocked by an 86Box identity dialog: AppleScript
  process references stored by name can target the other open 86Box instance
  despite a PID-based lookup. The local evidence helper now keeps the PID
  query inline. The controller was interrupted, the VM retained, and capture
  reattached under `diagnostic-live-02/attached/`; startup failure is not a
  product result. No product source change has yet been accepted.
- Candidate implemented: the 286 application receiver reuses the existing
  arena-excluded handshake reservation for up to 16,624 inner bytes, with a
  separate 16,384-byte content bound and MAC/type-before-publication. The
  2,048-byte small-memory cap is unchanged. T no longer marks a captured tool
  item as rendered text or a completed HTTP response; API/M require the
  completion event and HTTP terminal. A final failed-turn flag survives the
  scheduler return until M clears incomplete state and fast-types
  `> response failed; try again`, preserving explicit stop and no tool replay.
  This is a candidate working fix, not yet an approved commit.
- The second baseline diagnostic eventually returned three correct short
  replies, but required a reconnect for the second and retired TLS after the
  third. Its captured prefixes contain no function call. Both baseline runs
  encounter records above the small spool limit; the exact reason the first
  run did not reconnect remains unproven. Do not attribute that text-only
  failure to the independently demonstrated stale-tool bug.
- Candidate `b42bdeb456d7a3bad372e01722cba82704cf178e514d2e51258888a0dcbddb0b`
  remains 150,016 bytes / 293 sectors, with unchanged driver bytes and floppy
  allocation. Twenty fresh build/offline commands pass. The permanent
  `check-tls13-chat-recovery.py` gate passes 29 boundary/recovery cases; all
  35 existing harness tests pass. Four complete 16 KiB scheduler fixtures
  reach DPI: ordinary/fragmented replies, forged-tag rejection with no
  publication, and post-text oversize retirement. Each retains 24 phase reads;
  synthetic fixtures are not live transport or elapsed-time evidence.
- The shipping candidate (no UART instrumentation) returns `fortytwo`,
  `fifty`, `twentyfive`, and `four` in four consecutive Astra/max human turns
  on a read-only 6 MHz / 512 KiB 286. The final screen was visually inspected.
  The strict 286 pcap gate passes reuse on two flows. Of 95 post-handshake
  records, 11 exceed the old ciphertext limit; the maximum is 6,294 bytes,
  within the new tier's bound. `candidate-live-01/` binds config, image,
  prompts, source, pcap, screenshots and VM lifetime. The VM is left open.
- The first new 16 KiB controller incorrectly ran its dense-glyph oracle before the
  BASIC listing cleared. Its capture is retained under
  `nic-live/vm-net-3c503-16k/`; the running VM subsequently reached an ordinary
  Seed screen. This is an invalid startup/controller result, not a product
  regression or a passing NIC test. Subsequent runs retain the documented
  35-second post-BASIC delay. No VM is automatically stopped or restarted.
- Fresh serialized 286 timing passes all eight components with unchanged
  conservative acquisition/resumption budgets of 147/165 ticks
  (8.0740/9.0627 seconds). `serialized-private/report.json` binds current
  source and component images; it remains a CPU model, not a complete
  product/physical timing or entropy claim. Each benchmark used a private
  read-only profile and its VM was retained.
- The corrected 16 KiB NE2000 candidate run reaches fresh client Finished in
  11.0476 seconds and sends the credential-free HEAD, then returns
  `agent setup failed 00/12` without a resumed connection or greeting.
  A matched frozen-baseline control reproduces the same screen and topology
  (11.2073 seconds to Finished). Both post-Finished record streams fit the
  small cap (maximum ciphertext 1,179/1,177 bytes). The public ECDSA
  certificate at both observed provider addresses still matches the baked
  image pin (`leaf-check/result.json`); this does not identify the failed
  target-side check. The original-speed NIC sweep was stopped, not marked
  passing. This cold-start failure is distinct from the deferred idle reset.
  The maintainer subsequently brought this 8088 cold-route failure into the
  current priority fix; the earlier proposed review checkpoint is superseded.
- Baseline evidence is under `nic-live/vm-net-ne2k8-16k-baseline-02/`; its raw
  capture includes two credential-free host certificate probes. The retained
  `seed-only.pcap` is filtered by the exact identified target TCP tuple, with
  source/derived hashes and filter in `filter.json`. Its strict reuse gate
  still fails for missing resumption; its record-cap gate passes. The candidate
  capture under `vm-net-ne2k8-16k-attached/` needs no such filtering. The initial
  NE2000 controller stopped at a late identity dialog; it was reattached at
  the untouched BASIC prompt before Seed boot, without restarting the VM.
- Earlier candidate scope/provenance: the phase map, driver bytes and embedded handshake
  code are unchanged. Product edits are the resident turn scheduler and
  K/V/X/T/M application phases; X's resolved shared addresses move with K.
  `binary-diff.json` and `candidate-binding.json` retain exact identities.
  User config and shared VM config/NVR remain unchanged. No diagnostic UART
  code is in the shipping candidate. `REPORT.md` in the evidence directory
  summarizes the validated result and limitations.
- Earlier checkpoint disposition: retain the product fix and permanent recovery gate for review.
  Do not claim complete 8088 live regression coverage, a solved small-memory
  record ceiling, a live native-tool program, or resolution of the older
  no-tool/no-reconnect failure mechanism. The four-turn 286 result demonstrates
  that larger records and repeated simple chat work on the requested local
  model. Proposed commit: `Fix repeated chat recovery and 286 record handling`.
  Ask before committing; OPT-016 remains deferred until this review checkpoint
  is accepted. Overall exploration remains approximately **35%**, with the
  same rough **25–45%** range: this resolves concrete defects in an already
  deeply explored area, rather than closing another broad campaign wish.
- Continued scope: the maintainer requires the 8088 fix too, and repeated
  actual model replies rather than accepting a failure message as completion.
  Diagnose cold setup, unexplained empty returns, record reception and bounded
  recovery on both targets without weakening authentication or replay rules.
  The local user preference is now `gpt-6.1-sol` / `max`; only those local
  preference bytes changed. Fresh evidence is under
  `OPT-017/continued-8088/`. VMs remain under maintainer lifetime control.
  No commit or push is authorized by this continuation.
- 8088 cold failure isolated: private stage-only UART reaches full FO,
  identity restore, and the authenticated post-HEAD receiver, then aborts.
  The former plaintext slice at `3400..35bf` overlaps live symmetric record
  state at `3510..355c`. The old 1,125-byte HEAD fixture misses it; a synthetic
  1,162-byte HEAD reproduces rejection with the exact baseline code. The live
  diagnostic retains `agent setup failed 00/12` and its read-only VM.
- Cold-route candidate: move the same 448-byte slice to retired handshake
  inputs at `3600..37bf`, below the application keys. No extra RAM, sector,
  record cap, crypto change or diagnostic code is needed. The strengthened
  composition gate passes fresh/resumed observed-size and full 1,433-byte
  inner-record cases, including ticket/PSK preservation, correct publication,
  retirement and existing memory guards. Broader build and live acceptance
  are still in progress; this is not yet a completed 8088 fix claim.
- Continued validation: the cold-route fix passes twenty build/offline commands.
  With the requested `gpt-6.1-sol` / `max`, the 286 returns four correct
  consecutive answers; strict reuse passes and the largest observed record
  is 5,116 bytes. The fixed 16 KiB NE2000 reaches greeting and answers
  `fortytwo`, then reconnects and answers `pleaseprovidethepreviousanswer` to
  the follow-up. This is a failed repeated-chat test. Its capture again has
  records above the small-memory limit (maximum 4,246 bytes). Evaluated with
  the correct four-flow reconnect expectation, its strict wire gate passes:
  11.267/6.792/11.017/6.774 seconds to client Finished. The original runner
  incorrectly requested the two-flow reuse topology; this correction does
  not change the failed recall or record-cap result.
- Evidence correction on continuation: the NE2000 controller's apparent
  second-turn success captured a different open 286 VM after the target window
  disappeared. `continued-8088/chat-live/ne2k8-16k-01/visual-review.json`
  supersedes that automated result while retaining the original evidence.
  The harness now refuses cross-PID window fallback and checks process
  lifetime again after OCR; all 37 harness tests pass. A vanished VM is never
  replaced by another screen for acceptance.
- Retry admission defect: unexecuted tool captures were treated as executed
  effects and denied the permitted human retry. The candidate permits states
  1/3/4/5, clears their stale parser state during the actual request rebuild,
  and retains the veto for executed state 2 and every agent-loop continuation.
  Build/offline validation is in progress. The missing context after an 8088
  reconnect remains under investigation; no completed reliability claim or
  commit is implied. Overall rocks turned remains approximately 35%.
- Retry candidate validation completed: runtime
  `eff8f21d0a287d5e0fc8bc0c6cd20348cbb2d8507d64b9aa0911101c83b8e0be`
  remains 150,016 bytes / 293 sectors, with 308/309 FAT data sectors used.
  All twenty build/offline commands pass, including 41 chat recovery cases
  and five exact 16 KiB R/X replay cases. The latter rebuild byte-identical
  complete requests after ordinary failure and states 1/3/4/5. Separate
  executed-output and pending-continuation tests retain the no-replay veto.
  `continued-8088/retry-fix/` contains the frozen candidate and gate results.
- A private 16 KiB diagnostic captures only the arithmetic conversation note
  and restored prompt before each request. Its nine exact-code preservation
  cases leave all outgoing request bytes unchanged. The unchanged R/X/T
  fixture stores the first short question and `fortytwo` correctly in 61
  bytes; live capture will test the subsequent compaction/reconnect path.
  Diagnostic code is absent from the shipping candidate and carries no
  timing or release claim. VM lifetime remains maintainer-controlled and
  existing evidence is retained.
- The new live diagnostic confirms a bounded retry of the identical first
  question after 2,828/4,147-byte records exceed the small spool. It answers
  `fortytwo` and stores the exact 61-byte dialogue. The next compaction turn
  encounters a 4,246-byte record and ends with `response failed; try again`;
  no completed note was captured, so this run does not attribute the earlier
  missing-context answer. The controller/captures were stopped at that visible
  failure and VM 5999 was retained. This diagnostic uses the cold-fix runtime,
  before the newly validated partial-tool retry correction.
- Compaction-policy counterexample: two host-only requests using the exact
  captured dialogue and current `gpt-6.1-sol/max` request body returned
  `6*7 a-z words: fortytwo` and `-`. Thus the old instruction to drop trivia
  permits discarding an answer needed by a follow-up. This is a demonstrated
  policy defect, not proof of the prior live failure's cause. A clearer
  policy preserves the latest answer, explains `~N/M`, and asks for ASCII.
  Six bounded host checks of the final policy preserve arithmetic, an
  arbitrary word, and exact memory bytes within 48 characters; all pass.
- The updated `prompts/compact.txt` is 362 bytes and fits its existing sector.
  `make`, `make inspect`, and `make basic-bootstrap` pass; runtime bytes remain
  `eff8f21d...`. `continued-8088/final-candidate/` freezes the updated images;
  `compact-policy-host/` and `compact-policy-final/` retain the bounded
  provider evidence. These host checks do not replace live 16 KiB compaction
  acceptance or remove the small-memory record ceiling.
- Final-runtime 286 regression: four consecutive `gpt-6.1-sol/max` answers
  are correct, with strict two-flow reuse passing at 8.095/8.602 seconds to
  Finished. Its 107 post-handshake records include 11 over the old small cap;
  the maximum is 6,293 bytes and all fit the new tier. The screenshot was
  inspected and VM 9211 retained. This run uses the final runtime and original
  compaction file; its large window does not compact during these four turns.
- Exact final-image R/X reconstruction confirms the revised compaction file,
  complete prior dialogue, size suffix, note promotion, and pending prompt
  are transmitted correctly. A host follow-up with the preserved answer
  returns `fifty`. The old `-` note yielded no text in that host probe, whose
  helper did not record function calls; that result must not be represented
  as an empty provider response. `continued-8088/compact-chain/` retains
  this evidence. Final uninstrumented 16 KiB testing is in progress.
- Final 16 KiB result: greeting and `fortytwo` succeed, but the follow-up ends
  in `response failed; try again`. The capture contains 4,121-, 4,246-, and
  2,735-byte records. The controller was stopped at the verified failure and
  VM 11252 retained. This is not a completed 8088 fix or a passing NIC matrix.
- Additional exact-code defects reproduced while tracing compaction: with
  61 bytes of dialogue and a pending follow-up, the first request selects
  compaction, but a no-output retry promotes the unchanged dialogue into a
  61-byte note and sends a different normal request. Also, an eight-byte
  replacement note after a 48-byte note is rejected by R before any send:
  validation compares the new used length against the obsolete note length.
  `continued-8088/compaction-state-before.json` records both reproductions.
  Next correction: distinguish pending compaction from captured summary text
  in the existing flag, replay pending compaction unchanged, and promote a
  replacement note before validating its new range. Preserve all phase/RAM
  ceilings and existing no-replay rules; no commit is authorized.
- Compaction-state correction: the existing flag now distinguishes pending
  compaction from captured summary text. R repeats a no-output compaction
  unchanged, and promotes a captured replacement before checking its length.
  T marks capture only on actual output text. The far-context mirror also
  preserves previously flushed dialogue while compaction is pending; its
  former nonzero test reproduced history loss on the 286 path. The changes
  fit the existing R/T/G sectors and allocate no additional state.
- Exact R/X reconstruction now passes both original counterexamples. The
  permanent floppy-backed gate checks two complete compaction/retry/question
  sequences, including an eight-byte replacement for a 48-byte note. The
  recovery gate passes 45 cases, adding actual T capture and all three
  far-mirror states. Full build/offline and new live acceptance are in
  progress under `continued-8088/compaction-fix/`; no completed 8088
  reliability or broad record-size claim follows from these local fixes.
- The prior final 16 KiB failure screenshot has now been inspected and saved
  as `final-chat-live/ne2k8-final-01/visual-review.json`. Its strict pcap
  passes with the correct reconnect topology (`wire-reconnect.json`), while
  the unanswered follow-up and oversize-record failures remain unchanged.
- The frozen compaction candidate is
  `7ccad9a25dedc1101b12b2de90f385110e0648e8c48361b305d650e625758177`,
  still 150,016 bytes / 293 sectors and 308/309 FAT data sectors. All twenty
  build/offline commands pass against the fixed source snapshot. R is
  1,536/1,536 bytes, T 1,024/1,024 and G 470/512; K and X only adjust the
  corresponding template/validator references. An intermediate build caught
  the mirror edit arriving after its prefix was assembled; its failure log
  is retained separately and its image was not tested live. The clean rebuild
  and frozen helpers match. New live checks use `compaction-final/`.
- New 16 KiB live progress: the frozen candidate greets, returns `fortytwo`
  in 42.97 seconds, then correctly returns `fifty` after compaction and fresh
  connections. The dependent turn takes 659.08 seconds; this is not an acceptable
  latency or general reliability claim. The inspected `answer-2.png` is
  recorded by `compaction-live/ne2k8-compaction-01/visual-progress.json`.
  The capture already includes 4,121- and 4,246-byte records. Further turns
  remain in progress; the 8088 receiver ceiling is still open.
- The third 16 KiB prompt ends with `response failed; try again`; the fourth
  is not attempted. The screen was inspected, the controller stopped, and
  VM 16074 retained. Final capture: six hybrid flows with each handshake
  individually passing, plus 4,121-, 4,246-, 4,246- and 3,548-byte record
  violations. The generic wire analyzer does not certify a six-flow
  multi-turn topology; do not relabel it as the strict two/four-flow gate.
  `visual-review.json` supersedes the interrupted runner's two-element turn
  list. Image, user config and shared profile hashes are unchanged. This is
  a failed repeated-chat run despite the newly successful dependent answer.
- A separate host-only feasibility probe used one synthetic
  `gpt-6.1-sol/max` background generation with `store=false`, followed by two
  GETs of the same event suffix. Both return all 14 expected events, identical
  after excluding obfuscation, and the same `SEEDREPLAY` text. The documented
  [background replay interface](https://developers.openai.com/api/docs/guides/background)
  is an application-level lead distinct from OPT-008's rejected TCP replay
  assumption. No product protocol changed. Temporary retention, exact
  event/chunk binding, authentication before publication, parser timing,
  RAM/code fit, cancellation, tool effects and bounded reconnect all still
  need proof. Evidence and an unselected design note are under
  `continued-8088/background-replay-host/` and `background-replay-notes.md`.
- Final 286 validation of the same frozen candidate: all four visible answers
  are correct (`fortytwo`, `fifty`, `twentyfive`, `four`), with submission-to-ready
  times 24.246, 20.943, 23.350 and 21.881 seconds. The read-only 6 MHz / 512 KiB
  VM uses `gpt-6.1-sol` / `max` and remains open. Its 108 post-handshake records
  include twelve above the small-RAM limit, with maximum ciphertext 4,932 B.
  Image, user config and shared profile hashes are unchanged. This short test
  does not exercise the 286's much larger compaction threshold; that correction
  has exact-code evidence, not a live forced-compaction claim.
- The raw 286 wire gate counts an extra tuple and fails. It contains fourteen
  delayed, payload-free FIN/RST packets from the preceding 8088 connection:
  the exact tuple and next client sequence match the earlier capture. Removing
  only that prior tuple leaves every new connection attempt intact; the strict
  `--expect reuse` gate then passes with two independent hybrid flows and
  8.097/8.599-second handshake phases. Raw/scoped captures, hashes, exact filter,
  sequence comparison and both analyzer results are retained under
  `continued-8088/compaction-286-live-01/`. No analyzer rule was weakened.
- Remaining attribution limit: the final 8088 capture shows the third turn's
  compaction request followed by oversize responses, but no subsequent SYN.
  It does not expose the internal state responsible for returning the failure
  status; do not claim that the record cap alone explains every missing retry.
  Existing captured-summary behavior also permits an authenticated partial
  summary after transport failure; this patch does not introduce an atomic
  full-summary transaction. The expected compaction status line was not visible
  in the reviewed live run and remains a UI gap, not a removed product rule.
- Disposition: retain the validated local corrections uncommitted. Full OPT-017
  acceptance, the seven-NIC regression sweep, and a live native-tool program
  remain incomplete. There is no general no-missing-response claim and no
  commit request while those acceptance obligations remain open. The earlier
  intermittent idle-reset investigation stays deferred. Overall investigation
  coverage remains approximately **35%** (rough **25–45%**). A current report
  and evidence binding are in `continued-8088/REPORT.md` and
  `continued-8088/handoff-binding.json`.

### OPT-018 — Test authenticated application replay within the 16 KiB floor

- Priority/status: **application replay set aside; OPT-020 supplies the accepted
  receiver**. The replay experiments below remain private and do not establish
  a target construction. The bounded cached-connect wait correction is part of
  the later combined repair, validated with its full NIC/reconnect matrix.
- Wishes: 2 (reliable replies), 5 (16 KiB storage/lifetimes), 10 (whole-system
  accounting).
- Question: can the documented background Response event replay interface
  support a receiver that authenticates complete records before any effect,
  then verifies replayed chunks against retained authenticated commitments,
  while fitting the actual 4.77 MHz / 16 KiB target and all existing contracts?
- Baseline: final OPT-017 image hash
  `7ccad9a25dedc1101b12b2de90f385110e0648e8c48361b305d650e625758177`;
  150,016 B, 308/309 FAT sectors, 96/96-B arena/context, 2,048-B small spool.
  The final 8088 run fails turn three with records up to 4,246 B; previous
  campaign evidence already rules out treating a 4 KiB effect bound as the
  full requirement. OPT-011–013's complete-journal budget remains over 16 KiB.
  A host-only `store=false` background generation replays the same fourteen
  parsed events twice, excluding obfuscation. That is finite feasibility
  evidence, not an API promise of byte-identical JSON, records or retention.
- Allowed surface: begin with read-only source/API audit and private design,
  threat model, exact-byte accounting and isolated `cpu 8086` PoCs under
  `build/optimization-campaign/OPT-018/`. Do not change shipping request mode,
  authentication, replay policy, retention preference or target floor before
  the construction is justified. Preserve the current OPT-017 sources and
  frozen evidence; do not commit, push, close or restart the retained VMs.
- Required evidence: establish the provider's precise response-ID/cursor and
  temporary-retention contract from primary documentation, then distinguish
  event equality from JSON/TLS byte equality. Bind commitments to response,
  event, position, length, type and order. A second TLS tag arriving after
  publication is insufficient. Reject substitution, truncation, cross-response
  reuse and invalid tags without display, context, tool, timing/ACK or other
  unauthorized effects. Account for arbitrary valid supported event content,
  record packing/boundaries and a full legal record; an ASCII-only fixture or
  a 2/4 KiB logical-effect cap is not acceptance.
- Required composition: exact code/constants/commitments/parser snapshots,
  active keys, request buffers, loader/IRQ/stack and old retained state in
  conventional RAM, with erasure and interrupted transitions. Prove any new
  keyed construction independently; do not assume key reuse or free hash code.
  Preserve ENV, graceful/hard stop, target-local tools, no replay of executed
  effects and the bounded reconnect policy. Include original-speed transfer,
  parsing and render cost against temporary retention; durable server storage,
  a helper or extra RAM requires a separate maintainer decision.
- Exit: either a credible security argument plus measured exact-target
  component/composition path worth implementing, or a bounded rejection with
  the specific remaining resource/API assumption. Neither exit alone completes
  OPT-017. Return to live repeated replies and affected NIC acceptance only
  after the receiver path is justified. Do not relabel the still-unexplained
  pre-SYN failure as solved by this hypothesis.
- Handoff reason: this introduces an independent authentication/publication
  construction and a new application transport schedule, materially different
  from the local compaction and receive-buffer corrections. Use the campaign's
  fresh-context protocol for that security argument; ordinary compaction or
  task duration is not the reason for the handoff.
- Resumed on 2026-10-07 in the controller after the maintainer asked to fix
  8088 reliability. No separate context was created. The exact 16 KiB contract
  remains in force while a RAM-scope clarification is pending; no answer is
  not authorization to raise the floor. Continue the existing pre-SYN failure
  diagnosis alongside the replay feasibility analysis, preserving prior source
  and frozen evidence. No commit, push or automatic VM shutdown is authorized.
- A private stage-at-M diagnostic repeats the exact 16 KiB NE2000 arithmetic
  failure. `fortytwo` returns in 43.832 s; `fifty` returns in 665.375 s; the
  third prompt displays `response failed; try again`. The third turn has
  captured 22 bytes of summary (`compacting=2`, text seen) against the prior
  25-byte note, then returns with TLS retired before R promotes the new note.
  This is an observation, not proof that the note lengths caused failure.
  Unlike the preceding uninstrumented run, this pcap contains new TCP attempts
  after the failed compaction. The last establishes host-side TCP but sends
  no TLS ClientHello before the peer closes at 15.006 s. SLiRP capture does
  not establish whether the guest accepted its SYN-ACK. The private diagnostic
  uses M native-parser space and is arithmetic-only; it is not a product image.
  `OPT-018/turn-live/state-01/visual-review.json` records inspected screens,
  states and limits. Only the controller was stopped; the VM remains open.
- A host-only authentication/replay model passes 27 fragmentation/length cases
  and associated tag/binding/chunk mutation checks. Full-size inner plaintext
  requires 33 SHA-256 receipts (1,056 B) at 512-byte chunks. Receipts become
  authoritative only after the original record tag/type pass. Reordered JSON
  keys preserve event meaning but fail raw receipt equality, so this does not
  justify API replay. No target parser, complete memory composition, constant
  timing, retention schedule, or tool/cancellation proof is supplied. See
  `OPT-018/replay-receipt-model.json`; no shipping request mode changed.
- Next attribution experiment: private HELLO stage markers around the cached
  connector, pending-fragment return and first TCP send, in the existing root
  and HELLO slots. `OPT-018/hello-diagnostic.json` binds the diagnostic. It
  adds no phase reads and changes timing; it is not acceptance evidence.
- That experiment reproduces the third-turn failure. The complete UART trace
  is `RABCDERABCDERABCDERAB!`: three fresh routes reach and return from their
  first TCP send; the fourth returns carry from `hello_cached_connect`, before
  the pending-fragment check or any ClientHello payload send. First/second
  answers remain correct; the second again takes roughly eleven minutes.
  This localizes the active failure to the cached opener, not the later R/X
  summary validation. Flush, SYN transmit, SYN-ACK wait/parse and final ACK
  still need separate attribution; increasing a timer is not yet justified
  as the proved fix. The controller detects the visible terminal error and
  finishes without closing the VM. See
  `OPT-018/hello-live/hello-01/visual-review.json`. Its raw capture also contains
  the concurrent 32 KiB comparison; do not claim strict raw topology acceptance.
- The first inner-connector diagnostic was invalid: its 3,933-byte HELLO
  crossed the `2700` first-fragment staging boundary despite fitting the
  eight-sector load slot. It failed during setup and supplies no product-fault
  evidence. The replacement keeps HELLO at 3,827 B, checks that boundary, and
  passes eight connector classifications plus exact transcript/staging gates.
  UART output waits for THRE so adjacent markers are not lost.
- The corrected diagnostic again greets, returns `fortytwo` and `fifty`, then
  fails turn three. Trace `RA5RA5RA4!R` identifies exhaustion of the fresh
  cached SYN-ACK wait; every poll in the final attempt was empty. It does not
  attribute the earlier attempts or prove why the NIC exposed no frame. The
  following root exits before its cached opener. See
  `OPT-018/connect2-live/connect-02/visual-review.json`; VM 54959 remains open.
- A private uninstrumented candidate changes the non-3c501 cached wait from
  four to 32 PIT wraps per attempt, retaining three SYN attempts and the
  existing 3c501 limit. It changes exactly two bytes of the frozen image and
  passes 22 delayed-delivery comparisons plus unchanged 3c501 bounds. Its
  exact-floor live test is running. This is still a hypothesis: empty NIC
  polls can also reflect receive-state failure, and the shared DP8390 driver
  has no explicit overflow recovery. Do not integrate a timer-only correction
  without checking the live result. Shipping sources remain unchanged by
  this experiment; candidate SHA-256 is
  `1c32f1782ea16f091e765629de3eed1819b0af4389aad5662bba26a94fe58a12`.
- The private wait candidate completes all four correct answers on the exact
  16 KiB / 4.77 MHz / NE2000 / read-only ROM BASIC floor, returning to DPI
  after each. Submission-to-ready times are 43.702, 359.506, 682.169 and
  675.212 s. VM 56722 remains open; its controller/capture finished normally.
  This is one successful trial, not proof that the shorter wait caused every
  earlier failure or that a timer-only change fixes reliability.
- Its capture contains six complete fresh/resumed pairs. Each individual
  wire gate passes; fresh ServerHello-to-Finished intervals remain about
  11.0–11.3 s. The strict aggregate topology gate still fails, as does the
  application record-cap gate: nine of 304 post-handshake records exceed the
  existing 2,064-B ciphertext ceiling, with maximum 4,246 B. Preserve these
  failures; four visible answers do not establish bounded retry acceptance.
  The long waits/repeated acquisition still make this unsuitable as the
  finished 16 KiB experience.
- Raw/scoped pcaps, exact self-owned host-probe exclusions, unchanged image/
  config hashes and the inspected final screenshot are recorded under
  `OPT-018/wait-live/wait-01/visual-review.json` and `scope.json`. Only the two
  explicitly attributed host HTTP/2 probe tuples are excluded; every other
  packet and every Seed attempt remains. Shipping sources remain unchanged
  by OPT-018. The wait candidate stays private pending affected NIC/reconnect
  validation; pursue OPT-020 for the independent record-storage blocker.

### OPT-019 — Bound a full-record receiver using the 32 KiB phase cache

- Status: **private comparison prototype; set aside**. The maintainer explicitly
  reaffirmed the functional 16 KiB floor on 2026-10-07 as Seed's headline
  capability. The positive 32 KiB comparison does not satisfy OPT-017 and will
  not replace work on its required floor.
- Wishes: 2, 5 and 6.
- Question: can an 8088 with 32 KiB receive the full legal TLS application
  record by combining the existing 2,048-byte low spool with 14,576 bytes of
  the evictable phase/prompt cache, preserving arena/context and stack?
- Baseline: OPT-017 candidate `7ccad9a25dedc1101b12b2de90f385110e0648e8c48361b305d650e625758177`.
  `2e00..3600` is the low spool; `4000..7a00` is tools/phase/prompt cache;
  the direct-boot stack guard begins at `7a00`. Cached loads and prompt/schema
  reads are gated by `loop_cache_count`; it must clear before any overwrite.
- Allowed surface: private copied source, generated images, oracles and reports
  under `build/optimization-campaign/OPT-019/`; shipping sources remain unchanged.
  No helper, new crypto path, device RAM, writes to media or early publication.
- Evidence: actual `cpu 8086` maximum-size, padding, split-boundary, invalid-tag,
  record-type and stack/arena guards; unchanged 16 KiB and 286 behavior; proof
  every cache consumer falls back safely after invalidation. A positive live
  32 KiB test is comparison evidence and does not validate 16 KiB reliability.
- Exit: a concrete safe implementation option and measured tradeoff, or a
  bounded rejection. Any product integration or changed reliability floor
  depends on the maintainer's answer; no commit or push is authorized.
- The private `cpu 8086` implementation uses `2e00..3600` plus `4000..78f0`,
  clears the cache count before overwrite, and maps authenticated replay
  across the split on ChaCha block boundaries. It passes 64 exact-machine
  receiver/recovery cases, including maximum content plus padding, corrupt
  tags, invalid types, split boundaries, 16/24 KiB rejection, the unchanged
  286 gate, and arena/stack/device-RAM guards. Publication occurs only after
  the full tag arrives. Layout inspection passes; K grows from seven to eight
  loaded sectors inside its existing file slot, and total file/FAT use is
  unchanged. A live 32 KiB NE2000 comparison is in progress. Native-tool,
  cancellation/ENV, reconnect, full-NIC and complete integration acceptance
  remain outstanding; these component checks are not a product claim.
- The private 32 KiB / 4.77 MHz / NE2000 read-only live comparison returns
  all four correct answers (`fortytwo`, `fifty`, `twentyfive`, `four`). Times
  from submission to ready are 48.303, 51.949, 53.080 and 114.660 s. The
  fourth request follows the expected compaction threshold from the emitted
  request/context code; this image has no internal compaction trace. Its 131
  post-handshake records include fifteen above the old small-RAM ceiling,
  with maximum ciphertext 6,406 B. The strict scoped `--expect reuse` gate
  passes; no reconnect occurs. Concurrent-VM load/provider variation prevent
  treating the timings as a controlled speed comparison.
- The raw capture includes the simultaneously running 16 KiB diagnostic and
  fails its topology gate. Saved exact-PID `lsof` snapshots attribute every
  tuple. Excluding only that other VM's three tuples preserves every 32 KiB
  attempt, including its empty preflight. Raw/scoped captures, original failed
  result, filter, owner snapshots and inspected final screenshot are retained
  in `OPT-019/live/ne2k8-32k-01/visual-review.json`; no analyzer rule changed.
  Both VMs remain open. This receiver is still a private comparison.
- Integration audit found the legacy ENV region extends through `4200`,
  including the first 512 bytes of the proposed upper spool. Exact W-phase
  execution confirms this (`OPT-019/env-overlap.json`). A separate private
  `env-safe` variant clears that overlap and invalidates the cache before
  serialization, including after an interrupted receive, without changing the
  ENV byte layout. Eight exact-code cases pass for live/invalidated cache,
  RAM gates, adjacent-state guards and unchanged 16 KiB/286 paths. Only W
  differs from the live-tested receiver image; all other bytes are identical.
  This is not a full ENV round-trip or native-tool acceptance claim. The
  receiver-only and ENV-safe hashes are respectively
  `b123716f3be5d5c6fd59f1f97e3266a1621ea4cfa52b96bd931fc1aa1df55ca0`
  and `e9a8c466eadf7678a4c9cfaa3a24baa6094fa78d301aee3fafd29b311fcdce8a`.
- Decision checkpoint: the 32 KiB comparison is positive, with 64 receiver/
  recovery cases, eight ENV-isolation cases, layout checks and four visible
  live answers. The shipping image remains the OPT-017 `7ccad9...` baseline;
  no source integration, commit or push was performed for OPT-019. The maintainer
  has since reaffirmed the functional 16 KiB floor; the RAM decision is closed.
  Continue OPT-018's receiver construction and the localized cached-opener
  diagnosis. Preserve this comparison as evidence, without integrating it as
  a replacement for the required floor. Overall rocks-turned estimate remains
  approximately **35%** (rough **25–45%**); reliability is not complete.

### OPT-020 — Test HTTP/2 flow control as a bounded authenticated receiver

- Status: **integrated; functional emulator acceptance complete; checkpoint
  committed and pushed as `38b2f40`**.
  The shipping-source OpenAI route uses HTTP/2 on both CPU profiles. Guarded
  authentication/publication composition, exact-floor repeated chat, native
  write/execute/read, bounded reconnect and all seven NIC profiles pass on the
  final candidate recorded at the top of this ledger. The 16 KiB memory floor
  and 96/96-byte user pool remain unchanged. Physical entropy and broader
  provider-edge characterization remain separate; the experiments below
  describe how this checkpoint was reached, including rejected candidates.
- Wishes: 2, 5, 6 and 10.
- Question: can one active HTTP/2 response stream, with a small advertised DATA
  window replenished only after TLS authentication and consumption, bound the
  required body storage independently of legal TLS record packing?
- Baseline: OPT-017 `7ccad9...`; the 2,048-B TLS spool rejects legitimate
  responses, while whole-record storage and prior complete-effect journals
  do not fit the current 16 KiB footprint. HTTP/2 has not been tested here.
- Mechanism to falsify: require acknowledged SETTINGS before opening a stream,
  disable push and dynamic header-table storage, allow only one active response,
  and advertise a 512-B stream window. Retain at most that outstanding DATA
  allowance provisionally while authenticating an entire legal TLS record.
  Non-DATA frames remain unbounded by that allowance and need a separately
  bounded, validated parser. No assumption that TLS records become small is
  permitted. [RFC 9113 §§5.2, 6.5 and 6.9](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2)
- Allowed surface: source/API/RFC audit, credential-free endpoint probes,
  small authorized model tests using the existing local preference, and private
  host/8086 proofs under `build/optimization-campaign/OPT-020/`. Preserve the
  shipping sources, request storage preference, crypto/trust gates, current
  ENV/native tools, and all retained VMs. No helper or memory-floor change.
- Required evidence: actual endpoint ALPN and SETTINGS behavior; frame/TLS
  boundary independence; flow-credit conservation; full legal record, padding,
  continuation, invalid-tag and hostile control-frame cases; no pre-tag output,
  state publication, control response or timing/ACK oracle. Account for HPACK,
  control state, code, crypto, stack and erasure in the complete 16 KiB map.
  Any implementation must preserve credential-free liveness, reuse, bounded
  failure reconnect and no replay of executed native effects on all affected
  targets/NICs.
- Exit: a concrete bounded construction with target evidence worth integrating,
  or a precise rejection. A host server-flow test alone is not an 8088 receiver
  or a product reliability claim.
- Host feasibility passes on IPv6 and the IPv4 route used by Seed. Both require
  SETTINGS acknowledgment, disable push/dynamic-table storage, verify that a
  zero DATA window blocks the credential-free response, then run two ordinary
  `store=false`, foreground `gpt-6.1-sol` / `max` responses. Each returns
  `FORTYTWO`, then `FIFTY`, without any authenticated TLS record containing
  more than 512 DATA payload bytes. Bodies are about 11 KiB each. These probes
  use host OpenSSL/AES-GCM, not Seed's ChaCha/ML-KEM trust route. See
  `OPT-020/checkpoint.json` and the two `host-h2-*` directories.
- A private `cpu 8086` DATA projection component passes 563 cases in a guarded
  16 KiB mapping. It occupies 458 code bytes, 198 state/metadata bytes and a
  512-byte journal. Cases cover every TLS split in a two-DATA-frame fixture,
  DATA padding, a full 16,384-byte content record plus 239 padding bytes,
  invalid tags/types/streams/window overruns, and 16 KiB of output across 32
  consecutive credit windows. A pre-last-nonzero state snapshot removes the
  TLS inner type/padding before commitment. The original AEAD verdict is
  supplied by the independent host oracle, not integrated target crypto.
- This component deliberately ignores non-DATA frames and is **not an HTTP/2
  receiver or a shipping fix**. HPACK/control semantics, ALPN and both fresh/
  resumed credential-free liveness, persistent state through R/X/M/ENV,
  authenticated END_STREAM completion, cancellation/erasure, FAT/RAM
  composition and all affected target/NIC gates remain. Equal-length forged
  inputs take 14,681 versus 55,641 projection instructions: a proved fixed
  receive/ACK schedule or equivalent constant-work construction is mandatory.
  PING echo queues and other non-flow-controlled effects also need explicit
  bounded handling; a small DATA window alone does not solve those obligations.
- A third host probe delays each flow-credit replenishment by two seconds.
  Both foreground model replies complete (44.986 and 88.753 s), with no more
  than 512 DATA payload bytes per authenticated record. This establishes
  endpoint tolerance of that particular slow-consumer schedule; it is not
  target timing, a provider guarantee, or Seed trust-path acceptance. Saved
  separately as `OPT-020/host-h2-slow-ipv4-01/`.
- A separate `cpu 8086` HPACK Huffman primitive uses canonical counts/symbols
  instead of a large decode table: 227 code bytes, 287 table bytes and 12
  bytes of state. It passes 68,211 comparisons against hpack's independent
  nibble-DFA, including all one- and two-byte encodings, every symbol,
  EOS/padding errors and longer strings. It does not implement HPACK field
  grammar or HTTP/2 header semantics. Its output remains tentative and its
  timing is data-dependent. Rebuilding reproduces the tested binary hash
  `77186a6bfa544a6845df196a89414404aeb49a11d8ea04fc483d5fa322e4706f`.
- The exact remaining construction, scripts, component limits and evidence
  are in `build/optimization-campaign/OPT-020/README.md` and `checkpoint.json`.
  Prioritize the complete control/HPACK state machine, credit conservation,
  fixed receive/ACK timing, full 16 KiB RAM/FAT lifetimes and complete erasure
  before product integration. Then preserve ALPN/transcript checks on both
  routes, fresh/resumed credential-free liveness, authenticated END_STREAM,
  the native-tool no-replay contract, ENV/cancel, and all affected NIC gates.
- Handoff remains on this same dirty checkout: ledger and research are not
  committed and would not appear in a new worktree. Shipping image remains
  `7ccad9a25dedc1101b12b2de90f385110e0648e8c48361b305d650e625758177`;
  no commit or push is authorized. All retained VMs stay open; no controller
  or capture remains running at this checkpoint. Overall rocks-turned estimate
  is approximately **40%** (rough **30–50%**), with functional 16 KiB
  reliability still incomplete.
- Continued repair after the maintainer's priority clarification: a separate
  `h2_retention.asm` prototype retains raw DATA plus frame headers/known control
  payloads for interpretation after authentication. Unknown extension payloads
  can be skipped. This keeps HPACK decoding out of the tentative byte path.
  Its 630 exact-8086 cases cover split control/DATA boundaries, padded DATA,
  all known frame-type retention, full legal records dominated by unknown
  payload, multi-record headers, repeated credit windows, control exhaustion,
  invalid types/tags and guard/rollback behavior.
- This variant has 514 code bytes and 1,990 bytes of state/journals inside
  `2e00..35c6`, within the existing 2 KiB spool. That does **not** account for
  the complete product or remaining post-tag protocol state. Retained DATA
  includes padding and is not display-ready. The 1,280-byte per-record control
  budget still needs an explicit authenticated resource-error policy. Complete
  HTTP/2/HPACK semantics, post-handshake TLS controls, timing/ACK isolation,
  product composition/lifetimes and all target gates remain. Shipping sources
  and image are unchanged by this component. See
  `build/optimization-campaign/OPT-020/retention-gate.json`; tested binary hash
  is `3ef0cb2ca1fb77cdf576ea8323dd39f397b93f1d2c9b8c640ab2460157baa582`.
- Continued repair now applies OPT-018's bounded cached-connect wait to the
  product source: non-3c501 waits 32 PIT wraps per attempt, with three attempts;
  the 3c501's 128-wrap allowance is unchanged. The exact connector gate adds
  delayed SYN-ACKs after 4, 18, 31, 32, 63 and 95 empty polls, stable retry
  port/ISN checks and the unchanged 3c501 timeout. `make` and `make inspect`
  pass. The resulting runtime is byte-identical to the previously live-tested
  wait candidate, SHA-256
  `1c32f1782ea16f091e765629de3eed1819b0af4389aad5662bba26a94fe58a12`.
  Exactly two bytes differ from the frozen receiver baseline, with unchanged
  150,016-byte extent and FAT 308/309. Evidence is in
  `OPT-018/cached-connect-source-{gate,binding}.json` and the build/inspect
  logs. This is a narrow connection correction, not resolution of the
  oversized-record failures or proof that every earlier timeout is explained.
- The new `h2_retention_ct.asm` removes input-dependent control flow from the
  speculative byte entry. Static inspection finds only one fixed 14-word
  snapshot loop; 52,648 guarded byte cases execute an identical 344-instruction
  trace. The complete 630-case retention matrix also passes. Code is 871 bytes;
  state/journals occupy 1,904 bytes at `2e00..3570`. This is a component path
  property, not a composed AEAD/IRQ/TCP-ACK timing proof. See
  `OPT-020/retention-ct-gate.json` and `retention-trace-gate.json`.
- `hpack_response.asm` adds post-authentication response-field decoding:
  zero dynamic table, indexed and literal fields, Huffman, status/pseudo-field
  ordering, forbidden connection fields, checked content length and trailers.
  Its 1,906 code/table bytes and 76 state bytes pass 491 independent-oracle
  cases. The 4,096-byte decoded header-list limit must be advertised; encoded
  string and decimal-value limits/error mapping are recorded explicitly.
  This is still a private decoder, not the complete HTTP/2 state machine.
- A combined gate runs collector and decoder in the same guarded 16 KiB
  machine, replacing their code window between phases. All 152 cases pass:
  header/TLS/CONTINUATION splits, long headers, full legal records with
  ignored extension bodies, and forged-record rollback without HPACK or body
  publication. State and journals together use 1,980 of the current spool's
  2,048 bytes. AEAD and HTTP/2 sequencing are still host oracles. Target
  control/reply handling, post-handshake TLS controls, complete lifetimes and
  erasure, ALPN/liveness and the live acceptance matrix remain required.
  `OPT-020/receiver-composition-gate.json` binds both images. The repair is
  incomplete; the wider campaign stays paused at roughly 40% rocks turned.
- The post-tag `h2_post.asm` controller now executes frame/control semantics
  on the target too. Its 3,957-byte image (including HPACK) passes 111 cases
  for initial SETTINGS/ACK, response/reused streams, continuation, padding,
  priority prefixes, PING replies, TX window changes, GOAWAY, RST, trailers,
  content-length completion and forged-record isolation. A 16-byte reply
  prefix handles a PING whose earlier 16 bytes arrived in the preceding
  record; guards reject any overwrite of unread control or DATA input.
- An independent h2 server then drives five packing/padding scenarios through
  three reused streams each: all 15 streams and 56,895 body bytes pass.
  Collector, controller and HPACK execute as 8086 bytes in guarded 16 KiB RAM.
  TLS AEAD, outgoing request encoding and WINDOW_UPDATE transmission are still
  host leaves. Evidence is `OPT-020/h2-post-gate.json` and
  `h2-interop-gate.json`; this is not a live product reliability claim.
- The remaining integration is concrete: validate the candidate 84-byte
  controller/reply alias at `062e..0682` through real application lifetimes;
  compose actual AEAD and TLS control handling without pre-tag timing/output;
  integrate ALPN, both liveness paths, request framing and END_STREAM; preserve
  native/ENV/cancel/reconnect behavior. The current K file slot cannot simply
  append these components: nine collector/K sectors plus eight controller
  sectors exceed its fixed 15 sectors. Replacing the obsolete receiver and
  accounting for a safe phase-transition path is necessary. Full link/FAT,
  zeroization, original-speed and all affected NIC/286 gates remain open.
  No new VM was opened or closed, no provider request was sent, and no commit
  or push was made during this construction pass.
- The next construction composes the collector with Seed's actual application
  ChaCha20/Poly1305 receiver in a mapping of exactly 16 KiB. A fixed-position
  577-byte prefix preserves the existing bounded NST/alert contract until the
  tag is checked. The saved 65-byte receive MAC moves into `35bc..35fd`; the
  next encrypted TCP tail stays in RX while authenticated DATA remains in its
  journal. Failed tentative state, the prefix and retired primitive work are
  erased. This is private source, not a new product capability.
- The combined forged-record trace test exposed variable work in the existing
  application Poly1305 reduction. A private fixed-work multiply/reduce path
  now passes 3,215 full-width operand pairs and 289 arbitrary 264-bit products
  in each of two data/stack-segment layouts, with bounded access, preserved
  registers and 24-byte primitive stack peak. Three equal-geometry forged
  records now have identical complete instruction traces and ACK positions.
  Physical timing, IRQ composition and complete stack/register erasure are
  still required; these results are not that proof. The failed earlier image
  and traces remain in `OPT-020/tls-receiver/pre-ct-poly/`.
- The actual-crypto receiver passes 28 cases: byte-fragmented TCP, maximum
  16,384-byte content with 239 padding bytes, invalid tags/types, truncation,
  resource exhaustion, alerts, and an NST during an HPACK continuation. A
  following encrypted record survives deliberate overwrite of the TX arena.
  See `OPT-020/tls-receiver/aead-gate.json`; image SHA-256 is
  `53b7e5466b9014ca5766d2120bf4ea9700ddd9d151f6171cb92a21b1d47f6068`.
- A real file-layout construction now fits: K plus its invocation leaf is
  4,085 bytes (eight loaded sectors). The 3,957-byte H2 controller uses seven
  former K-padding sectors and 373 bytes of existing S-phase padding; an
  83-byte low transition fits beside that last fragment. Runtime extent stays
  150,016 bytes, later sectors/286 tail are unchanged, and the free FAT cluster
  remains available. This uses the existing flat-file phase mechanism.
- Its 20-case composition executes the resident disk loader, actual AEAD and
  H2 phase, including all 16 read-failure positions with a partial destination
  overwrite. Before K replacement, failure returns CF into intact K. After
  replacement begins, failure clears protocol/key/record state and unwinds to
  a supplied resident return frame; it never returns into a partial K image.
  Real X/K callers still must set and validate that abort anchor. See
  `OPT-020/phase-bridge/gate.json`, image
  `f1d0af8081e13b6de0e940062394bfce91f84f7e10e229bee3e65d8573751ec9`.
- These images are explicitly **not bootable product integrations**. ALPN,
  fresh/final credential-free liveness, outgoing request/credit/control
  handling, END_STREAM plus model-completion wiring, whole-product lifetimes
  and all original-speed/NIC/286 acceptance remain. In particular, an unsent
  request fragment cannot coexist in TX with the receive control prefix:
  credit waiting must account for that lifetime. `OPT-020/INTEGRATION.md`
  records the next steps and exact map. Shipping remains `1c32f178...58a12`;
  no provider call, VM lifecycle action, commit or push occurred. Overall
  rocks turned is approximately **45%** (rough **35–55%**); the functional
  16 KiB reliability requirement remains open and wider optimizations paused.

- Continued the blocking 16 KiB construction through real 8088 h2 ALPN,
  transcript/binder and Finished/preface handling. The handshake and preface
  variants each pass 71 guarded cases. The real deadline phase chain preserves
  the larger 79-byte coalesced resumed flight (70 existing low bytes plus nine
  below configuration) and sends Finished plus the h2 preface. No bytes already
  acknowledged by the transport are discarded. The narrow 8088 EE shape still
  requires ALPN-only h2; optional EE extensions remain outside that profile.
- The new cold-only NST phase validates all bounded messages before retaining
  the first ticket, derives its PSK with actual SHA/HMAC, publishes status last
  and retires dead work/master/source state. It passes 378 cases and uses the
  six remaining cold-pack sectors. Its actual AEAD/disk/HPACK composition passes
  19 cases, including all 14 partial-sector failure positions and a following
  encrypted record. K fits exactly in its existing 4,096-byte loaded window.
  Evidence is under `OPT-020/h2-{bootstrap,nst,cold}/`; the cold receiver image
  is `e33332cf...32c5`. Ordinary callers are not yet wired, so this is not a
  bootable product integration or a live reliability claim.
- Both new cold liveness owners fit their existing slots and are undergoing
  composed validation. A larger control-reply test caught a real four-byte
  overrun into the low owner: 440 plaintext + 22 TLS + 54 network bytes exceed
  the 512-byte NIC scratch. The cold sender now fragments at 436 bytes. The
  corresponding normal sender lifetime remains part of request integration.
  A separate 286 ALPN draft is 105 compressed bytes over its existing slot;
  no storage limit or memory floor was relaxed. Overall rocks turned is about
  48%; broader optimizations remain paused. Shipping and retained VMs remain
  unchanged; no provider request, commit or push was made.

- The cold H2 liveness composition now passes 122 guarded 16 KiB cases,
  including all 96 partial-sector read failures, fragmented input, maximum
  legal TLS content, forgery and missing-ACK refusal, and 1,267 control-reply
  bytes across multiple sends. Fresh mode reaches the actual lifecycle
  preparation; final mode executes the existing success capsule. Evidence is
  `OPT-020/h2-liveness/gate.json`, image `0733dc28...a5b6bc`. This remains a
  private component integration: parent publication, ordinary requests,
  Responses completion, whole-product lifetimes and live acceptance are open.
- The packet-buffer overrun also reproduced in the normal product sender:
  437 plaintext bytes already write to `0900`, beyond its 512-byte packet
  scratch. The product now uses a separate 436-byte send limit, retaining the
  440-byte allocation and existing RAM/ENV offsets. A new 15-case guard runs
  actual TLS sealing and TCP framing, authenticates emitted records separately,
  and checks rejection before transmission at 437/439/440/441 bytes. Full
  `make` and the final-image guard pass. Runtime SHA-256 is
  `2efa4301f0969b74dd7a60f1c8ea71ca215f8c361242b77a127f652c515eb970`,
  still 150,016 bytes and FAT 308/309. This corrects the prior entry's statement
  that shipping sources were unchanged. It proves the overwrite fix, not that
  it caused all hangs; no new live reliability claim follows. Rocks turned is
  approximately **52%** (rough **45–65%**). Wider optimizations remain paused.
  No provider call, retained-VM lifecycle action, commit or push was made.

- The outbound H2 credit path now passes 37 guarded cases, including negative
  and zero windows, 512-byte source preservation while receiving controls and
  tickets, all sixteen phase-read failures, and a 70,012-byte request received
  identically by an independent h2 peer. Three forged record shapes have the
  same 1,805,235-instruction trace and ACK positions; this remains emulator
  evidence, not physical timing. Rebound cold controllers pass all 122 cases.
- Actual R/X request serialization is now composed too: seven cases cover the
  cold greeting, ordinary chat, one-byte/zero/wide credit, maximum key length
  and compaction. The real JSON keeps tools, identity, escaped prompt text and
  gpt-6.1-sol/max. A 401-byte request helper fits unused conventional-RAM code
  headroom and R's existing third file sector; X stays within three sectors.
  The image remains 150,016 bytes. Evidence is in `OPT-020/h2-requests/`, image
  `72edad5c...80bb3f`. This is still non-bootable: response/scheduler wiring,
  tool/far-source/error composition, complete lifetimes and original-speed
  acceptance remain. Current product stays `2efa4301...b970`; no provider call,
  VM lifecycle action, commit or push occurred. Roughly **55% rocks turned**
  (range **48–68%**); the 16 KiB blocker remains open.

- The private response owner now connects actual R/X, TLS/H2, T and the
  resident retry scheduler. It requires the model completion event plus
  authenticated END_STREAM, rejects non-200 bodies before T, and prevents
  replay after partial text or cancellation. The 23-case response gate caught
  and corrected a disk-swap unwind anchor two bytes too low. Eight scheduler
  cases cover identical no-output retry, visible failure and the next prompt,
  as well as compaction followed by the human answer.
- The actual M/O/DPI native loop now writes `b8 2a 00 cb`, executes MOV AX,42 /
  RETF, reads it back, receives an answer and returns to input across four
  reused streams. This exposed a second integration bug: a byte-copy helper
  changed carry and made a successful native continuation report send failure.
  It now preserves flags. Three native cases also prove the tested write is
  not repeated after a failed continuation and an incomplete unexecuted call
  retries before one dispatch. These are synthetic peer tests, not live model
  or original-speed emulator results.
- Four publication cases join the real root frame, final liveness controller,
  success/abort capsules and parent READY store to the first response. Missing
  acknowledgement or forged liveness sends no credentials; exhaustion reaches
  the visible failure message. The middle secure acquisition/resumption/FO
  flight remains a fixture in this gate, so full cryptographic boot composition
  is still open. All 122 cold-controller cases pass again with the response
  helper present in their shared third file sector.
- The exact latest private image passes **160 composed cases** and is SHA-256
  `d7e6e98499d41d164e684222a89cdcca234d2b2bd467339b3b3bf64a384dcfb9`;
  the separately rebuilt request-only image passes seven cases. Runtime extent
  remains 150,016 bytes, K is 4,096, R 1,536, X 1,495, T 957; the request and
  response helpers are 403 and 318 bytes. The 96-byte arena/context floor is
  preserved. Evidence and remaining protocol/lifetime/286/live gates are in
  `OPT-020/INTEGRATION.md` and `checkpoint.json`. H2 remains private; shipping
  stays `2efa4301...b970`. No provider call, retained-VM lifecycle action,
  commit or push occurred. Roughly **60% rocks turned** (range **53–72%**);
  functional 16 KiB reliability remains the blocker for wider optimizations.

- First live H2 boots reached the server but rejected its authenticated empty
  SNI acknowledgement before client Finished. The private 8088 handshake now
  accepts exactly h2 plus an optional empty SNI acknowledgement in either
  order. The resumed CCS/record handoff holds 83 bytes in the existing low
  span and configuration gap. All 131 handshake cases and both real ML-KEM
  deadline compositions pass. An additional 23 cases cross the formerly
  separate fresh deadline/protected-controller boundary. The header parser's
  code retires before the authenticated tail reuses its RAM; no RAM or file
  sector was added.
- The rebuilt private image is `37829626050b5a26854ceba97a57deea3f2bd30a0aa29e3a487acd780e85b3f1`.
  Its full 122-case cold-controller matrix and 25 bound root/FO/auth/lifecycle
  slots pass. On original-speed NE2000 with exactly 16 KiB and read-only media,
  the fresh client Finished arrived 11.168 seconds after ServerHello. The live
  VM subsequently rendered the model greeting and accepted its first follow-up
  prompt. Follow-up/reuse, other NICs, complete lifetimes and the 286 H2 route
  remain open; greeting alone is not reliability acceptance. Evidence is under
  `OPT-020/live/h2-ne2k8-16k-sni-01/`. The same image is now being tested on the
  32 KiB direct-entry path. All VMs are retained for the maintainer. Shipping
  remains `2efa4301...b970`; no commit or push was made.

- The private 286 H2 acquisition/resumption route now passes 43 actual-flight
  composition cases, including all nine partial parser/helper reads on each
  route, control-send failures, forgery, and protocol/ALPN refusal. A 334-byte
  adapter uses the unused third fresh-post sector and retired conventional RAM
  at `5500`; the shared parser remains byte-identical. HELLO is 5,630 stored
  bytes and flight is 3,041, retaining their 11- and 6-sector slots. The exact
  tail graph and 12 hostile packaging cases pass at 293 runtime sectors.
- Live 16 KiB runs consistently completed the greeting but stalled after the
  first human submission. Metadata plus wire records show six authenticated
  WINDOW_UPDATE records were consumed before the response header stopped.
  The receive loop acknowledged only while collecting a partial TLS record;
  complete short records could fill the advertised 256-byte TCP window without
  an ACK. A new actual-code peer-window test reproduces the stall with 245
  unacknowledged bytes and no rendered answer. The private receive path now
  acknowledges before waiting for a new TCP payload. Five backpressure cases
  (0/1/6/8/20 controls) and all 23 response/reuse/failure cases pass afterward.
  This is a reproduced transport fix; its live acceptance is still running.
- The 286 live probe also displayed a model greeting, then failed its follow-up.
  The 32 KiB probe completed final authenticated liveness but did not reach its
  direct-return trampoline. A separate return-frame trace is in progress.
  Two earlier 32 KiB waits were harness identity-dialog races, not product
  failures; the startup check now requires the exact PID's main VM menu, and
  its targeted regression passes. Shipping remains `2efa4301...b970` while
  these H2 changes are private. Current ACK-fixed universal candidate is
  `1cd78877b9206e6f863571f9571f2288e4e495d696c8f86d1837c432e4e36316`.
  Approximately **65% rocks turned**; all three paths still require repeated
  live turns and integration acceptance. VMs are retained; no commit or push.

- The ACK-fixed private universal image completed a live greeting plus four
  correct 286 turns: fortytwo, fifty, twentyfive, four. Screens show the prompt
  returned after each answer; model context was preserved. The host capture
  includes concurrent 8088 probes and needs per-flow H2-aware wire accounting;
  the old HTTP/1 dialogue checker cannot count H2 control replies as requests.
- The 32 KiB loss is now reproduced: cold NST retirement scrubbed `3f1c..SP`
  even on the `8000` stack, erasing the direct return trampoline and arena.
  Retirement now selects the direct stack floor `7a40`, preserving its live
  64-byte return reservation. The original fails at its first `3f1c` write;
  381 updated NST cases pass, including direct-tier success/failure/repeated
  ticket preservation. A corrected 32 KiB live run is in progress. Universal
  candidate is `f7a53351e2dfa2d514f7aaa2198d75475d902e6272fb312f374b32c205243614`.
  Approximately **70% rocks turned**; shipping integration and full floor
  reliability acceptance remain open. No commit or push; all VMs retained.


- After the maintainer's battery interruption, saved screens and captures
  confirm four correct dependent replies on the 286, 8088/32 KiB and 8088/16
  KiB NE2000 paths. The 16 KiB 3c503 also completed four replies; a diagnostic
  3c501 run completed them across one bounded reconnect. These are private
  candidate results, not final acceptance. The earlier ordinary 3c501 cold
  failure remains part of the repetition requirement. All old VMs had exited
  with the interrupted host session; new test runners close their own VM.
- H2 implementation is now promoted into canonical sources, retaining the
  293-sector flat runtime, eight-sector K, original driver/FAT contract and
  96-byte arena/context floor. Independent canonical gates cover authenticated
  receive, credit/backpressure, actual R/X requests, response completion,
  compaction/retry, native write/execute/read and root publication. Handshake
  Poly1305 remains byte-identical; only the application primitive uses the
  fixed-work reduction. The full build/regression chain is still running.
- A later 286 idle reconnect failed before a new SYN. This is reproduced:
  retiring a failed H2 request wipes temporary prompt length/buffer, while the
  286 bootstrap requires that length to match its durable resend length.
  The N phase now reconstructs the unexecuted human prompt from its ordinary
  display text before escrow, preserves video, and refuses executed/pending
  tools. Forty-three exact N/bootstrap cases pass across prompt lengths,
  CGA/MDA widths, poisoned temporary state and invalid/replay states.
- Fresh readonly runs are exercising four dependent replies plus a native
  four-byte program on all three target paths. The 286 additionally waits ten
  minutes before the program prompt to exercise the repaired idle reconnect.
  Their frozen candidate is `d39a473cf3b825b5c91fbdab3de9901a353cd3847dbbe4ec95d23531fffdfe51`.
  A subsequently observed non-ASCII greeting is traced to cold `Greet.` omitting
  the ordinary ASCII instruction; that request is now explicitly ASCII too.
  The final build and affected fresh live repeats must include this small
  request change. Do not report all three reliable until those gates finish.
- New exact larger-memory request tests preserve 32 KiB context and stream a
  65,543-byte conventional far context through JSON escaping and peer credit
  replenishment; 22,000-byte far compaction also passes. Wire evidence now
  scopes explicit ports and reviewed UI turns: encrypted H2 control traffic
  is never counted as model replies. Evidence is under
  `OPT-020/product-integration/` and `OPT-020/live/`. No commit or push.

- Canonical offline request composition exposed a cold-start edge case: R left
  dialogue offset/count as uninitialized BASIC scratch before X's new final
  bounds check. Cold R now explicitly clears all three words; poisoned-state
  cold/ready serialization passes. The seven normal request cases, far requests,
  response, retry, native, publication, backpressure, disk failures, NST,
  handshake and liveness gates pass on the isolated canonical candidate.
- The repaired 286 idle route now completes fresh acquisition/resumption and
  native write/execute/read. Its final answer nevertheless repeats the earlier
  word `four`, so the live case is a failure, not acceptance. It was stopped
  and its VM closed after evidence capture. A faithful BIOS-scroll regression
  reproduces two causes: native continuations omit the user label, and tool
  scrolls do not move the originating prompt marker. Later requests serialize
  blank cells or a tool-status line instead of the human request.
- X now labels the originating human request on every native continuation.
  Renderer/tool/save status scrolling tracks that prompt's display row. The
  exact four-request write/execute/read/answer gate now preserves the complete
  prompt both high on screen and after six BIOS scrolls. Runtime sectors and
  memory ceilings are unchanged. This candidate is
  `1bc86e85bbcecd73e0b461890174c9517de489db4ffb73b81f18fd7d5e5436ad`;
  full make and affected live repeats remain required. New cancellation cases
  also prove a visible stop without replay and a working next human request.

- ENV regression uncovered an existing alias bug: the save directory lookup
  wrote its cluster into `fs_file_cluster`, which is also the live
  `save_region_stored` word. The writer produced a header declaring 295 region
  bytes in a 174-byte file. The lookup now returns its cluster in AX without
  touching the trim size. Actual 16 KiB save/restore, header/payload corruption
  rejection, read-only failure, unchanged H2/key/user state, and stream-three
  reuse pass. This fixes the codec and lifetime boundary; it is not a live
  native save_env model test. Candidate is
  `9d1eda26f3f5ce271aede0b7c2685df11e2b60089e8468975d4da508d62d9051`;
  only W differs from the prompt-fixed live image, and no memory/file layout
  changes. Wider campaign remains about 40%; reliability repair investigation
  is roughly 80% with live acceptance outstanding.

- The full packaged ENV gate exposed a second real save failure: the allocator
  stopped at cluster 300 even though the last valid data cluster is 310. With
  the current full floppy, its one remaining free cluster was never visited.
  The bound is now derived from the 160 KiB geometry. The writable regression
  forces allocation of that last cluster; readonly and full-media cases pass.
  The intermediate candidate `184cd51693dbd3295bc6f52dc520a4b1524663eb01f07c2374cc84b5242e85b0`
  passed `make`, all 18 HTTP/2 gates, and the remaining standalone TLS guards.
- A later 286 native run correctly retained its prompt but repeatedly executed
  write/execute/read without a final answer. Exact synthetic requests sent to
  the configured model reproduced this: two retained tool pairs omit the
  original write after the read. Restoring that result, either as a full pair
  or a compact completed-result journal, produced AX 42 and the four bytes.
  These host diagnostics explain the failure; they are not target acceptance.
- The current candidate replaces the old prior-pair allocation with a bounded
  90-byte journal of whole result lines and preserves the current structured
  call/output. It requests one tool per response. After eight calls it sends
  the last output with tools disabled; an unexpected ninth call cannot execute.
  Exact 16 KiB request, native, budget, failed-continuation and BIOS-scroll gates
  pass. The 293-sector file, resident addresses and 96/96-byte floor are unchanged.
  Frozen candidate `e3e0b888fa41e2ea72db3854e54da6a28226752f84c6c0a5a25da94e0815574f`
  is undergoing the three main live runs and full build. Superseded runs are
  preserved as partial evidence and their VMs closed.
- Test launches now share a hard three-VM cap. No-card CGA/MDA and missing-driver
  menus were checked and all their VMs closed. The updated 286 serialized timing
  harness executes the current H2 preface/control exchange and locates its own
  code above the parser's RAM; its semantic gate passes. Fresh serialized timing
  and the batched ISA NIC matrix remain required. Reliability investigation is
  about 85%; the wider optimization campaign remains about 40%. No commit/push.

- The final journal candidate now passes `make`, `make inspect`, BASIC helper
  generation, all 18 H2 integration gates and the standalone TLS regressions.
  Canonical and frozen `SEED.SYS` are byte-identical. The 286 live run completed
  four correct dependent text replies, a ten-minute idle, one fresh reconnect,
  and exactly one write/execute/read sequence. Its final visible answer is
  `AX (decimal): 42` and `Bytes: B8 2A 00 CB`, followed by the input prompt.
  The explicit-flow capture gate passes for ports 56542/56588/57106/57127;
  all four ServerHello-to-Finished intervals are below 8.60 seconds. Its VM
  closed automatically and the read-only image and protected inputs remained
  unchanged. Evidence: `OPT-020/live/h2-286-tool-journal-01/`.
  Both 8088 main runs, the remaining NIC repetitions and serialized timing
  are still in progress; this is not yet three-path reliability acceptance.

- Fresh serialized 286 timing now passes all eight components on the exact
  6 MHz / 512 KiB profile. Conservative acquisition and resumption CPU sums
  are 147 ticks / 8.074 s and 170 ticks / 9.337 s. The input manifest remained
  unchanged, and all eight private VMs closed with unchanged read-only images.
  `OPT-020/serialized-final/report.json` records the remaining measurement
  limits: component CPU sums exclude NIC/TCP wall time and do not measure the
  whole offline certificate path as one interval. The separate reviewed live
  286 capture above supplies connection, application and reconnect evidence.

- The final 32 KiB direct-boot candidate completed four correct text replies,
  ten minutes idle, one fresh reconnect and one write/execute/read sequence,
  then returned to input. The model spelled the correct result as
  `axfortytwobytesbeighttwoazerozerocb`, carrying over the earlier letters-only
  request. Numeric format compliance failed; functional execution and response
  completion passed independent visual review. The literal `42` observer was
  stopped only after a fresh exact-PID screenshot showed the returned prompt,
  and its original interrupted result is preserved. The VM closed immediately.
  The flow gate's explicit manual-completion mode binds that review to its
  screenshot hash and time, retains the formatting caveat, and rejects actual
  runtime errors, wrong results, missing prompts and altered evidence. Six
  hostile review cases are rejected. Ports 56615/56662/57446/57560 pass, with
  fresh deadlines below 11.21 s and resumed deadlines below 6.79 s. Evidence:
  `OPT-020/live/h2-ne2k8-32k-tool-journal-01/`. The 16 KiB native run and the NIC
  matrix remain pending. Reliability investigation is about 88%; no commit/push.

- The current exact 16 KiB 3c503/MDA regression passes greeting, reused first
  response (`fortytwo`), ten-minute idle, one fresh reconnect and dependent
  second response (`fifty`), with returned input prompts. Its explicit four
  flows pass both fresh deadlines below 11.23 s and resumed deadlines below
  6.84 s. Read-only media and protected files are unchanged; the VM closed
  before the NE1000 case started. Evidence:
  `OPT-020/live/h2-nic-3c503-mda-journal-a1/`. Reliability investigation is
  about 89%; the 16 KiB native result and remaining NIC cases are still open.

- The final original-speed NE2000 / exactly 16 KiB ROM BASIC run now passes
  all five turns: four correct dependent text replies, ten minutes idle, one
  bounded fresh reconnect, then one write/execute/read of `B8 2A 00 CB`.
  The visible final answer is `AX = 42; Bytes: B8 2A 00 CB`, with the input
  prompt returned. Its ordinary automatic oracle and independent visual review
  both pass. Explicit flows 56723/56786/58107/58180 pass, with fresh deadlines
  below 11.20 s and resumed deadlines below 6.80 s. The image and protected
  inputs are unchanged, and its VM closed automatically. Evidence:
  `OPT-020/live/h2-ne2k8-16k-tool-journal-01/`.
  All three main CPU/RAM paths therefore have current functional acceptance,
  retaining the 32 KiB numeric-format caveat above. At 16 KiB, text turns took
  about 4–13 minutes and the post-idle native sequence about 32 minutes; these
  are measured slow completions, not latency improvements. Remaining ISA NIC
  cases still block closure of the whole repair gate. Reliability investigation
  is about 92%, wider campaign about 40%; no commit or push.

- WD8003EB now passes the same exact 16 KiB first-response/reuse/idle-reconnect
  regression, with `fortytwo` then `fifty` and the returned input prompt. Its
  four owned TLS flows are 58112/58187/58689/58772; fresh deadlines are below
  11.26 s and resumed deadlines below 6.80 s. The old socket accepted one send
  before its close was observed, returned no response records, and retired
  before the fresh acquisition. The NIC capture gate now accepts that permitted
  pending-turn retry, matching the main-path policy, while retaining the exact
  four-flow limit and new-session answer requirement. Extra/missing/reordered
  connection evidence is rejected; the clean-close 3c503 case still passes.
  The read-only image and protected inputs are unchanged, and the WD8003EB VM
  closed before the second 3c501 repetition opened. Evidence:
  `OPT-020/live/h2-nic-wd8003eb-journal-b3/`. Reliability investigation is
  about 93%; the remaining NIC cases continue under the three-VM limit.

- NE1000 now passes the exact 16 KiB first-response/reuse/idle-reconnect
  regression with both correct answers and the returned input prompt. Its
  four owned TLS flows are 58500/58568/59107/59171; fresh deadlines are below
  11.20 s and resumed deadlines below 6.79 s. The second reply completed in
  about 1,001 seconds after the idle. Read-only media and protected inputs
  remained unchanged, and its VM closed before WD8003E started. Evidence:
  `OPT-020/live/h2-nic-ne1k-journal-a2/`. Reliability investigation is about
  94%; WD8003E, two 3c501 runs and Novell NE1000 remain. No commit or push.

- The first current-candidate 3c501 run passes greeting, first-response reuse,
  ten-minute idle, one fresh reconnect, `fortytwo` / `fifty`, and returned
  input. Owned flows 58959/59024/59540/59617 pass, with fresh deadlines below
  10.45 s and resumed deadlines below 6.27 s. The read-only image and protected
  inputs are unchanged; its VM closed before Novell NE1000 started. Evidence:
  `OPT-020/live/h2-nic-3c501-journal-b1/`. The separate 3c501 repetition remains
  required because of the earlier intermittent cold failure. Reliability
  investigation is about 95%; WD8003E and Novell NE1000 also remain open.

- The separate 3c501 repetition also passes, including both correct replies,
  a ten-minute idle and returned input after one fresh reconnect. Its owned
  flows 59127/59203/59729/59814 pass fresh deadlines below 10.45 s and resumed
  deadlines below 6.36 s. This run exercised the permitted pending send on
  the old socket before its retirement; the answer completed on the new
  session. Read-only media and protected inputs remain unchanged. The VM
  closed automatically, leaving only the WD8003E and Novell NE1000 cases
  running. Evidence: `OPT-020/live/h2-nic-3c501-journal-b4/`. Reliability
  investigation is about 96%; no commit or push.

- WD8003E passes the exact-floor greeting, reused first response, ten-minute
  idle and bounded reconnect with `fortytwo` / `fifty` and returned input.
  Its owned flows 59542/59629/60182/60250 pass fresh deadlines below 11.18 s
  and resumed deadlines below 6.79 s. One pending send used the old socket
  before its retirement, then the answer completed on the new session. The
  image and protected inputs are unchanged; the VM closed automatically.
  Evidence: `OPT-020/live/h2-nic-wd8003e-journal-a3/`. Only Novell NE1000
  remains active. Reliability investigation is about 97%; wider campaign
  remains about 40%. No commit or push.

- Novell NE1000 completes the final NIC case with `fortytwo` / `fifty`,
  ten-minute idle, one bounded reconnect and returned input. Owned flows
  60016/60076/60613/60687 pass, with fresh deadlines below 11.17 s and resumed
  deadlines below 6.86 s. A pending send used the old socket before retirement;
  the answer completed on the new session. Read-only/protected inputs are
  unchanged, and the VM closed automatically. Evidence:
  `OPT-020/live/h2-nic-novell-ne1k-journal-b2/`. The queue reused the already
  completed WD8003EB and 3c501 cases without launching duplicate VMs.
- Final acceptance is complete on 2026-10-09: ten reviewed runs, 29 prompted
  turns, all three main CPU/RAM paths and all seven original-speed ISA NIC
  profiles, with a second 3c501 run. `OPT-020/final-audit.json` rechecks every
  scoped capture gate, extracts the same runtime through each image's FAT
  chain, verifies canonical/frozen/test image equality, and checks protected
  input and capture hashes. All 18 H2 gates, 13 standalone TLS guards and
  eight serialized 286 components are current; timing-measurement limits are
  retained. `vm-cleanup-final.json` confirms zero remaining 86Box processes.
  Functional reliability investigation: 100%; wider campaign: about 40%.
  The 32 KiB numeric-format caveat, slow 16 KiB timings and physical entropy
  limits remain explicit. No commit or push. Proposed checkpoint message:
  `Fix minimum-memory chat and native-tool reliability`.

### OPT-021 — Attribute the 8088 offline-proof workers

- Wishes: 3, with whole-route accounting for 1, 2 and 10.
- Question: do current, byte-bound full-FO and exact-leaf/CV worker profiles
  identify a concentrated computation cost worth a narrowly scoped follow-up?
- Baseline: `38b2f40`, runtime `e3e0b888fa41e2ea72db3854e54da6a28226752f84c6c0a5a25da94e0815574f`.
  Campaign-entry 154.6 s initial and 69.4 s resumed proof spans are historical,
  not measurements of this HTTP/2 revision or of either worker in isolation.
- Allowed surface: isolated measurement under `build/optimization-campaign/OPT-021/`
  and this ledger; no shipping crypto or trust changes. Start with exact packed
  FO and authentication workers, then account for regeneration/controllers and
  phase I/O before any whole-route performance claim.
- Required evidence: match emitted worker bytes to this runtime's actual pack
  slots; execute valid deterministic or recorded credential-free public vectors;
  attribute instructions to routines; retain the worker's result, RAM bounds,
  stack and preserved-state checks. State cycle-model and elapsed-time limits.
  Physical entropy, provider deadline and live-security claims stay separate.
- Exit: rank one measured follow-up with explicit missing evidence, or record
  why the supposed hotspot is not supported. Implementation still requires its
  own bounded spike and relevant acceptance; no optimization commit is approved.
- Status/owner: **scoped worker profiling complete**, in the existing campaign
  context; follow-up OPT-022 selected below.

#### OPT-021 result and selected follow-up

Both independently rebuilt workers match the bytes and SHA-256 in the committed
runtime's actual pack slots. The valid full-FO vector passes in 5,835,668
instruction hooks: `fo_rotl64_to` accounts for 3,053,688 (52.3%) and the remaining
`fo_keccak_f1600` body for 2,169,307 (37.2%). Together Keccak accounts for 89.5%.
The FO image is 2,829 bytes in its existing six-sector slot, leaving 243 bytes
of padding. Its stack low-water is `0x3fe6` (26 bytes below the floor stack top).

The recorded credential-free exact-leaf/CV vector passes in 9,906,882 hooks.
`p256_kmul8` accounts for 41.9%, reduction for 13.1%, and the other multiplication,
add/subtract and inversion helpers account for much of the rest. The auth image
is 6,592 bytes in thirteen sectors, with 64 bytes of padding; stack low-water
is `0x3fa8` (88 bytes). Both runs reject CPU instruction/data accesses at or
above `0x4000` while executing and retain the original checker result and
preserved-state assertions. The harness maps extra poison sentinels, not extra
usable target memory.

These are **worker instruction counts**, including REP terminal and callback
hooks. Variable-count shifts and multiplication make instruction percentages
especially unsuitable as wall-clock percentages. Regeneration, candidate work,
controllers, floppy loads and the complete current proof spans remain outside
these numbers. They do not imply a measured 89.5% proof-time opportunity.

Disposition: **profiling complete for the two scoped workers; select OPT-022**.
Prioritize FO rotations because FO repeats in both proof epochs, its hotspot is
concentrated, and its current slot has more implementation room than P-256.
Keep the P-256 result as a later measured avenue. Evidence is
`OPT-021/fo-profile.json`, `auth-profile.json`, `profile.py` and their exact
assembled worker/listing files. Product source, runtime, images and local model
configuration remain unchanged after the reliability commit.

### OPT-022 — Test faster 8088 full-FO Keccak rotations

- Wishes: 3; preserve whole-route and floppy accounting for 1, 2, 4 and 10.
- Question: can public-count specialization or less loop/address bookkeeping in
  `fo_rotl64_to` reduce complete full-FO target computation by at least 10%
  while retaining its six-sector slot and current RAM/stack contract?
- Baseline: the validated OPT-016 DPI cleanup committed with this entry;
  current runtime
  `2e5d631fa81bb575343fb52782195672e0fc3e4d797a905c9142b329cf3e65b1`.
  OPT-016 changes only runtime sector 201, so the packed FO and auth workers
  remain byte-identical to OPT-021. Bind prototypes to this current source
  using `OPT-016/integration/candidate-binding.json` and `final-audit.json`.
  OPT-021 exact packed FO is 2,829 bytes, 5,835,668 instruction hooks,
  rotation share 52.3%, stack low-water `0x3fe6`.
  No calibrated current elapsed time exists yet. The helper already decomposes
  rotations into whole words plus paired variable shifts; it is not a naive
  64-iteration bit loop.
- Allowed surface: first isolate prototypes/measurements under
  `build/optimization-campaign/OPT-022/`; only consider
  `tools/crypto-bench/tls13-poc/fo_tail_kernel.asm` for eventual integration.
  Do not propagate a candidate into keygen, candidate, P-256, deadline or
  application crypto copies without separate byte/cost/lifetime accounting.
- Required evidence: all rotation counts and word boundaries, register/source/
  destination/stack equivalence, complete valid and implicit-rejection FO,
  hostile/corrupted inputs, exact pack composition and zeroization. Preserve
  public-only addressing/control choices and all authority transitions.
  Count emitted bytes, full-worker instructions and variable-shift costs;
  use original-speed target A/B timing before claiming elapsed savings. Before
  integration run the relevant current build/offline/live gates, with no extra
  VM windows beyond the established cleanup policy.
- Exit: a narrowly validated working improvement, or a bounded negative if
  net full-worker benefit, slot size or security/memory checks do not hold.
  Later commit/push still require maintainer approval.
- Status/owner: **validated local working improvement; uncommitted as
  requested**. This fresh campaign context completed the carry/rotation rewrite,
  equivalence argument, original-speed timing and nine-case source integration.
  OPT-016 and OPT-021 evidence is retained by exact source/runtime bindings.
  Use this same checkout so the active OPT-022 edits and ignored measurement
  artifacts remain available. Preserve unrelated VM config/NVR,
  screenshots and capture state, and keep the local model preference unchanged.

#### OPT-022 private result and integration gate

The first prototype unrolls four residual-shift outputs with fixed source-word
loads and a public destination-word index, removing the offset-pair loads and
mutable loop bookkeeping. A second adds a public one-bit path for theta and
rho=1, using a carry chain without spilling lane operands. The selected worker
is 2,915 bytes, leaving 157 bytes in the same six-sector slot (baseline 2,829 /
243). Its full valid execution is 4,599,332 instruction hooks versus 5,835,668
(21.2% fewer), with unchanged stack low-water `0x3fe6`. The simpler unrolled
variant is 2,875 bytes / 4,735,556 hooks. CL-shift EU accounting is included in
the private ranking model; its common-instruction, REP/prefetch and IRQ limits
remain explicit. It is not a calibrated cycle total.

Each of the three variants passes 7,360 primitive cases: all 64 rotation counts,
all one-bit basis lanes, word/carry boundaries, zero/ones and deterministic
random lanes, high count bits, varied registers/CH and odd source/destination
addresses. Registers, source bytes, destination guards, exact write ranges and
caller-only stack residue agree. Both original and selected full workers pass
the same 31 valid/corruption/implicit-rejection and public-read-failure cases,
with floor memory guards and preserved config/capsule/video/device sentinels.
Addresses, branches and shift counts depend only on public rotation counts;
comparison, selection and authority transitions are unchanged.

Sequential read-only ROM BASIC A/B runs on the original 4.772728 MHz / exactly
16 KiB profile execute the exact packed bytes and real RAM public-object copies.
Three valid repeats plus one implicit-rejection run each measure 415 baseline
ticks and 334 candidate ticks: 22.7940 -> 18.3451 s, saving 4.4490 s / 19.52%.
Setup, serial and output verification are outside each interval; timer IRQs are
included. Both VMs closed immediately. These are emulator full-worker timings,
not whole-route, provider-deadline or physical entropy claims.

The private exact pack changes only FO. Its keys/destinations, 130-sector pack,
293-sector runtime, RAM ranges and fresh/resumed phase-load sequences stay
unchanged. Both real regeneration/candidate/full-FO chains, fresh exact-leaf/CV,
root status-last, abort cleanup and eight-entry lifecycle/erasure gates pass.
OPT-021's FO baseline and auth evidence remain bound to OPT-016's runtime by
exact slot bytes; auth was not reprofiled. The selected private runtime is
`866fba3b4cdf77f6fce9830791f409cfb78e6ee6f7e768bea038a41a328a6b0a`.
The initial private flat-runtime binding (`238e5105...`) incorrectly replaced
the final 286 adapter in reserved raw-pack sector 164 with zeroes. Shipping
Make preserved the adapter correctly. The private binder now replaces only
FO's actual six sectors and explicitly checks sector 164 preservation; the
corrected flat image equals the shipping build and differs only in 126–131.
This was caught before any product VM launch. The worker/vector/timing evidence
is unaffected; the corrected composition report supersedes the earlier log.

The source helper is now selected for integration in `fo_tail_kernel.asm` only.
`make`, `make inspect` and `make basic-bootstrap` pass on the corrected runtime,
along with 18 HTTP/2 composition and 13 standalone TLS gates. Eight serialized
286 payloads independently reassemble byte-identically to their accepted
baseline; prior timing acceptance is retained without a new timing claim.
The final live acceptance below passes; earlier incomplete observations are
retained as history. Live validation uses four dependent text turns with one
ten-minute idle/reconnect on the three CPU/RAM paths, and two turns with idle/reconnect on the remaining six original-speed
NIC profiles. Native/ENV/application workers are byte-identical; their OPT-016
acceptance is retained separately, not relabeled as newly exercised native
turns. Evidence and the equivalence argument are under
`OPT-022/REPORT.md`, `binding.json`, variant profiles/hostile results,
`equivalence.json`, private timing results and `composition/report.json`.

The first live queue accepted the 286/512 KiB and 8088/32 KiB cases: four visible
text replies each, exact owned TLS flows, deadline checks, reuse and one bounded
post-idle reconnect. The 8088/16 KiB case completed its first three dependent
replies, and 3c503/MDA completed its first reply. Their pending post-idle replies
and NE1000's first reply were interrupted when all three 86Box processes exited
within ten seconds, before the 1,200-second reply timeout. Logs report process
exit rather than a runtime failure screen; no new 86Box crash report was found.
The cause is unknown. The initial queue stopped
without launching remaining cases, and all its VMs closed. Protected entry
inputs and read-only images remain byte-identical. These captures remain
unaccepted in `integration/interrupted/` and `integration/interruption.json`.
The related campaign chat separately committed and pushed OPT-016 as `831170c`
while intending OPT-022 to continue. `integration/concurrent-checkpoint.json`
records unchanged protected source/runtime bytes across that checkpoint.
No pause instruction was received; the two accepted cases were retained and
the seven unfinished cases were rerun. The nine-case gate was incomplete at
that resume checkpoint and subsequently passes in the final audit below. This OPT-022 chat has made no commit or push.

The first NE2K retry hit a private observer failure: a ROM BASIC syntax error in
line 90 was mistaken for the greeting by the prompt-shape oracle. It never
established Seed acceptance and was closed and archived separately. Concurrent
host modifier-key sequences are a suspected injection cause. The private
runner now serializes exact-PID input, requires `Hello` at greeting and refuses
BASIC syntax-error frames. The other two retry VMs completed both replies and
passed their owned wire gates; NE2K was rerun with the stricter observer and
passed all four replies.
Product and tracked harness sources are unchanged. Details are in
`integration/observer-failure.json` and `integration/interrupted/`.

The first 3c501 attempt visibly fails at `agent setup failed 00/12`. Its exact
owned acquisition flow has 12 client retransmit payloads, and peer FIN precedes
client Finished by 1.7981 seconds. This failed gate is retained under
`integration/failures/3c501-before-greeting-01/`; the failure cause remains
unestablished. Full FO is scheduled after acquisition retirement, and the
failing deadline workers are byte-identical; this placement is a static
inference, not an instruction trace. The one bounded candidate repeat on the same
image/profile/model completed both replies and passed independent visual and
owned wire gates. Independent process inspection confirms closure;
the automatic report briefly retained the old PID, so the private runner now
waits for PID retirement after scoped closure. No wire gate is waived.

The initial WD8003EB second turn exceeded the private 1,200-second UI
observation budget. Its final screenshot contains the correct `Fifty` answer
but no returned input prompt, so the case closed without acceptance. The delay
cause is unestablished. `integration/wd8003eb-observer-timeout.json` binds its
result, screenshot and capture. One unchanged-image/profile/model repeat
completed as `wd8003eb-16k-02` with a 1,800-second UI observation budget; answer,
input-prompt, ownership and all TLS deadline/wire checks passed. No product
or tracked harness change was made for this observation budget.

#### OPT-022 final local checkpoint

`integration/final-audit.json` independently rechecks the exact candidate core,
all frozen read-only FAT images, protected source/config/capture inputs, complete
hash-bound visual reviews, owned TLS flows and post-idle connection ordering.
All nine cases / 24 text replies pass. It requires exactly four owned TLS flows
per case and the second acquisition after the full idle window; the main cases'
first three replies reuse the initial use connection. Every VM closed at its
test end, the shared launch guard kept at most three open, and zero remain.
The source integration changes only the FO helper and this campaign ledger;
unrelated cfg/NVR, original 3c501 screenshots, root capture and local model
preference remain preserved. HEAD is the independently approved OPT-016
checkpoint `831170c`, not a new OPT-022 commit.

The complete FO worker saves 4.4490 s / 19.52%, meets the >=10% question and
retains the six-sector/RAM/stack contract. This closes OPT-022 as a narrow working
improvement. Broader proof/dialogue latency, physical entropy and provider-edge
characterization remain separate work. Investigation coverage stays about
**44% explored** (rough **34–54%**), counting the resolved rotation avenue rather
than treating the wider wishes as solved. No further optimization, commit or
push is included in this request. A future coherent checkpoint title is
`perf: speed up 8088 full-FO Keccak rotations`; committing still requires the
maintainer's explicit go.

### OPT-023 — Attribute the composed 8088 offline proof after OPT-022

- Wishes: 3, with 1, 2, 4, 6 and 10 cost reconciliation.
- Question: after the accepted FO rotation change, which remaining worker or
  phase-loading cost dominates the fresh and resumed offline proof, and does
  that evidence favor a narrow regeneration/Keccak change over P-256 work?
- Baseline: HEAD `831170c` plus the uncommitted OPT-022 helper; current runtime
  `866fba3b4cdf77f6fce9830791f409cfb78e6ee6f7e768bea038a41a328a6b0a`.
  FO alone measures 334 BIOS ticks / 18.3451 s. OPT-021 omitted regeneration,
  candidate/controller execution and phase loads; the campaign-entry whole-
  proof times are not current-revision measurements.
- Allowed surface: this ledger and isolated evidence under
  `build/optimization-campaign/OPT-023/`. Shipping sources, current images,
  OPT-022's uncommitted helper, local config and all prior evidence stay intact.
- Required evidence: independently recheck OPT-022's recorded result; bind
  freshly assembled pack bytes to the shipping runtime; execute both actual
  offline chains with routine/phase attribution, exact successful load/sector
  accounting, preserved-state and conventional-RAM guards. Separate target
  instruction counts from elapsed time and modeled disk reads from real I/O.
  Use original-speed isolated timing if needed to rank the dominant workers;
  at most three VMs may be open and each closes when finished.
- Exit: a quantified next optimization with a bounded source/validation scope,
  or a supported negative result. No product gain follows from attribution
  alone. Continue ordinary investigation automatically; a substantial new
  algorithm/security construction follows the recorded fresh-context rule.
- Status/owner: **completed in the resumed campaign controller**. The designated
  OPT-022 chat is completed/idle, and process inspection found zero 86Box VMs.
  Preserve earlier failed observations. No commit or push is authorized.
  Overall rocks turned starts at approximately **44%** (rough **34–54%**).

#### OPT-023 result

Disposition: **attribution complete; select OPT-024**. The redirected OPT-022
audit rechecks all nine cases / 24 replies without rewriting prior evidence.
Freshly assembled pack bytes match the shipping runtime, allowing only its
already documented reserved 286-adapter sector. Both exact offline chains pass
their original output/status/lifetime guards plus below-16-KiB CPU access guards.

The fresh chain executes 20,857,974 instruction hooks: KeyGen 5,966,592, candidate
375,360, FO 4,598,900 and exact-leaf/CV 9,906,881. The resumed chain executes
10,950,948: KeyGen 5,966,488, candidate 375,377 and FO 4,598,796. Remaining hooks
are controllers, copies and host-service entries. KeyGen rotation and remaining
Keccak body account for 3,195,720 and 2,270,205 hooks, respectively (91.6% of
regeneration combined). Instruction percentages are not wall-time percentages.

The chains request 56 / 42 phase sectors; 53 / 39 are loaded before the fixture
stops at the next three-sector owner request. Adjacent requested-track transitions
are 16 / 12 and head steps 52 / 41. Initial entry loading, post-proof liveness,
BIOS/media/NIC time and IRQ work are excluded from these instruction/load counts.
This is the composed cryptographic offline interval, not the complete cold route.
The synthetic stack lows (3fb8h / 3fe6h) are not full product/BIOS stack bounds.

A separate read-only 4.772728 MHz / exactly 16 KiB ROM BASIC run times the exact
3,103-byte KeyGen worker. Three repeats each take 417 BIOS ticks / 22.903892 s;
all 2,400 output bytes match the independent oracle. Setup, serial and comparison
are outside timing; BIOS timer IRQs are included and INT 1Ch is quarantined.
Its VM closed immediately, leaving zero VMs. Shipping sources/images and prior
evidence are unchanged. `OPT-023/REPORT.md`, `comparison.json`, profiles, pack
binding and `keygen-timing/result.json` retain the details and host-profiler
failures. No physical entropy or whole-route speed claim follows.

KeyGen is the next narrow candidate because it repeats in both offline epochs,
has a measured 22.9-second cost and 481 bytes free in its seven-sector slot,
and can test the rotation mechanism already proved for FO. P-256 is larger in
the fresh instruction profile but has 64 bytes of slot padding and needs a
different arithmetic investigation. Overall rocks turned is about **46%**
(rough **36–56%**). No commit or push was made.

### OPT-024 — Test the FO rotation mechanism in 8088 runtime-root KeyGen

- Wishes: 3, with 1, 4, 6 and 10 regression/accounting.
- Question: can the accepted public-count rotation helper reduce full 8088
  runtime-root KeyGen computation by at least 10%, without adding sectors,
  stack, persistent RAM or phase reads, or changing any derived output?
- Baseline: OPT-023's byte-bound current runtime; KeyGen is 3,103 bytes / seven
  sectors, 417 ticks / 22.903892 s for its acquisition fixture. OPT-022 remains
  uncommitted and must be preserved.
- Allowed surface: private variants and evidence under
  `build/optimization-campaign/OPT-024/`; eventual selection only in the shared
  `tools/crypto-bench/tls13-spike/mlkem768_integrated_core.inc`, explicitly gated
  to the 8088 runtime-root KeyGen route. Scope includes narrowly necessary
  persistent checks and this ledger. Other candidate, deadline, FO, P-256 and
  286 arithmetic must remain byte-identical. Do not widen the optimization to
  those consumers automatically.
- Required evidence: all rotation counts/register/stack/write-range equivalence;
  both root epochs, complete KeyGen and nonce outputs, invalid-epoch refusal,
  conditioner output and erasure, preserved ciphertext/config/arena/device
  sentinels, and exact composed pack/lifetime/authority gates. Account for
  relocated conditioner references and every changed slot. Original-speed A/B
  timing must measure the full worker. A retained source change requires fresh
  build/inspect/BASIC, current offline gates, affected live CPU/RAM/NIC/reuse/
  reconnect regression and unchanged 286 payloads. Keep at most three VMs open
  and close each at completion; preserve all failed evidence.
- Exit: a narrowly validated working checkpoint, or revert only this spike's
  source edits and retain its supported negative result. No commit or push.
- Status/owner: **validated local working checkpoint**, after OPT-023 completed.
  No separate chat or agent is running this spike; no commit or push was made.

#### OPT-024 result — validated local working checkpoint

The runtime-root-only selection reduces full KeyGen from 417 to 332 BIOS
ticks: 22.903892 -> 18.235233 s, saving 4.668659 s / 20.38%. Three repeats of
each worker agree on the original 4.772728 MHz / exactly 16 KiB ROM BASIC
profile. Each checks all 2,400 derived-key bytes outside the timed interval;
setup and serial work are excluded, timer IRQs included, and INT 1Ch is
quarantined. Both timing VMs closed immediately. This is worker computation
timing, not a whole-proof, provider-deadline or physical entropy claim.

Each rotation implementation passes 7,360 primitive cases, including all
counts, one-bit basis lanes, high count bits, odd addresses, register and write
guards. Eight full-worker cases cover both public epochs on the baseline root
and three candidate roots; complete keys and nonces match independent oracles,
invalid AL epochs refuse without state mutation, and stack use stays 26 B.
The private report excludes an initially miscalculated nonce-hook estimate;
output/refusal/guard checks and measured KeyGen hooks are unaffected. Raw
observations are preserved in `OPT-024/full-results.json` and the qualified
result is `full-validation.json`.

KeyGen grows 3,103 -> 3,187 B inside the same seven sectors, leaving 397 B.
Only the KeyGen slot and its conditioner's relocated references change. Eight
packed-conditioner cases retain exact outputs, health refusal, freeze, abort
and shared-work erasure. Both real offline chains, exact-leaf/CV, root
status-last, abort and eight-entry lifetime gates pass on the private pack.
The candidate runtime is
`3790f719c938f48f4e2e5c5070e413a90a64a52e841d51dbe72cee6b4fa2a74a`;
its only changed sectors against OPT-022 are 57–61 and 64. Runtime length,
phase reads, slot geometry and all other workers remain unchanged.

The source selection is integrated only under `MLKEM_KEYGEN_RUNTIME_ROOT` in
the shared core; OPT-022's FO change remains intact. The first build stopped
because the default host Python lacked `cryptography`; its evidence remains,
and the existing OPT-011 environment supplied the dependency without a product
workaround. The resumed build's independent HTTP/2 image-binding guard then
caught a stale 8088 pack before any live launch. The shared core was a 286-tail
prerequisite but absent from common pack prerequisites. One necessary Makefile
line repairs that incremental dependency. Both rejected build logs and original
hashes remain; no check is bypassed.

The corrected shipping runtime matches the private candidate exactly. `make`,
`make inspect`, `make basic-bootstrap`, the incremental dependency check,
18 HTTP/2 composition gates and 13 standalone TLS gates pass. All eight
serialized 286 payloads independently reassemble byte-identically to OPT-022's
accepted baseline. Runtime length is still 150,016 B / 293 sectors, FAT use is
308/309 data sectors, and all phase-read geometry is unchanged.

`OPT-024/integration/final-audit.json` accepts nine independently reviewed
cases / 24 text replies. Exactly 16 KiB ROM BASIC, 32 KiB direct boot and
286/512 KiB each complete four replies, reuse, ten minutes idle and one bounded
reconnect. The six remaining original-speed NIC cases complete two dependent
replies around the same idle/reconnect test, covering all seven ISA NIC profiles
including 3c503/MDA. Every saved answer screen has the correct answer and
returned input prompt. Each capture is restricted to its exact recorded VM's
owned TLS flows. Local model/config and read-only images remain frozen.
Native/ENV and 286 timing acceptance are retained by explicit unchanged bytes;
these are new text-turn tests, not new native/ENV coverage.

The first NE1000 post-idle turn exceeded its fixed 1,200-second observer without
a second visible answer or returned input prompt. Its VM closed and the matrix
stopped launching new cases; the already active WD8003E and 3c501 cases finished
and passed. The failed capture passes all four exact-owned TLS boundaries,
contains complete records and shows application traffic within five seconds of
timeout without a peer close. Its cause remains unestablished; this cannot prove
eventual completion or provider semantics. All 343 failed-case files remain
hash-identical and unaccepted. One unchanged NE1000 repeat completed its second
turn in 948.83 s under the same 1,200-second limit. WD8003EB retained its
predeclared 1,800-second observer and completed its second turn in 947.00 s.
No timeout is relabeled as success and no product deadline is relaxed.

Ten live attempts submitted 26 prompts: the accepted nine cases contain 24
completed replies; the retained failed NE1000 case contains one completed and
one timed-out turn. All VMs closed at completion or timeout. Recorded live
lifetime intervals overlap by at most three, and final process inspection shows
zero VMs. The audit verifies 690 protected files, all 4,471 OPT-022 evidence
files and all 126 OPT-023 evidence files remain unchanged. Existing cfg/NVR,
screenshots, wire capture, local config and OPT-022 edits are preserved.

Overall rocks turned remains **46% (rough 36–56%)**. The measured gain is full
KeyGen computation; it does not establish whole-proof, dialogue-latency,
provider-deadline or physical entropy improvement. The source change is a
working checkpoint; at validation HEAD was `831170c` and no commit or push had
been performed. The maintainer subsequently approved committing and pushing
the combined OPT-022/024 checkpoint as
`perf: speed up 8088 Keccak rotations`.

Next after the maintainer continues: attribute current dialogue/return latency,
starting from these preserved captures and screens to separate proof,
application-record, provider and compaction costs. The long post-idle turns and
retained observer timeout make that a higher-priority measurement than assuming
another small arithmetic gain will materially shorten the full interaction.
P-256 and remaining Keccak-body work remain open; neither wish is closed.

### OPT-025 — Attribute current dialogue and post-idle return latency

- Wishes: 2 and 6, with 3 and 10 as supporting attribution. The combined
  OPT-022/024 rotation checkpoint is committed and pushed as `29bca48`.
- Question: do preserved current-runtime captures and source attribution locate
  a dominant avoidable local dialogue/return cost, distinct from reconnect
  proof and provider wait?
- Baseline: runtime
  `3790f719c938f48f4e2e5c5070e413a90a64a52e841d51dbe72cee6b4fa2a74a`;
  OPT-024's exact 16 KiB NE2000 turns take 293.42, 646.06, 745.29 and
  959.76 seconds to the returned prompt. The final turn follows ten minutes
  idle. Its original NE1000 observer timeout remains failed evidence.
- Allowed surface: this ledger and isolated scripts/reports under
  `build/optimization-campaign/OPT-025/`. Product code, local configuration,
  generated shipping artifacts and prior evidence remain read-only.
- Required evidence: exact owned-flow and runtime binding; record arrival and
  transmit timelines aligned with submitted/returned-prompt events; source
  attribution and explicit limits where encryption or missing target traces
  prevent separation. Compare the three CPU/RAM paths and retained timeout.
- Exit: identify one bounded follow-up with measured potential, or record why
  these observations cannot support the proposed attribution and select the
  next useful measurement. No latency win from record counts alone.
- Status/owner: completed in the current campaign chat, sequentially after the
  committed OPT-022/024 checkpoint. No new VM, commit or push authorized by
  this entry. Overall rocks turned remains **46% (rough 36–56%)**.

#### OPT-025 result — measurement complete; credit batching selected

All nine accepted OPT-024 captures and the retained NE1000 timeout are rebound
to their exact VM-owned flows and current runtime. Ordinary 543-byte incoming /
48-byte outgoing record cycles have median gaps of about 6.6 s at 16 KiB,
4.87 s at 32 KiB and 2.49 s on the 286; the next incoming record typically
follows in 13–15 ms. Disjoint incoming-to-outgoing gaps cover 89.3%, 92.9% and
94.3% of the three reused 16 KiB NE2000 turns. These are host-side wire
intervals combining local work, delivery and scheduling, not pure CPU or
provider-compute times. A provider-wait-only explanation is unsupported.

The retained NE1000 case repeats 58/516-byte incoming records, consistent with
27/485-byte DATA frames, and sends 68 credit-shaped records during its first
turn versus 35 on the unchanged repeat. Its failed post-idle turn spends most
of the observer window in response-shaped traffic before another request-shaped
burst at 1009.51 s. No eventual completion or sole cause is inferred; that
case remains unaccepted. Source and wire support compaction before later
16 KiB replies and the added post-idle route setup, but ciphertext and missing
target traces prevent an exact split of all provider/proof/compaction costs.

The exact emitted 993-byte synthetic response fixture executes 2,033,992
instruction hooks and 50 sector reads: two T reads plus three 16-sector H2/K
round trips. Fixed-work Poly1305 word multiplication is the largest hook group
(37.75%), followed by retention (17.57%) and ChaCha quarter rounds (16.57%,
excluding rotation helpers). Hook shares are not elapsed-time shares.
`OPT-025/REPORT.md`, `capture-attribution.json` and `two-window-profile.json`
retain methods, bindings and limits. No product or prior evidence changed,
and no VM or provider request was needed.

Select bounded credit batching next: the current immediate per-record
replenishment may sustain the observed two-part window fragmentation. Test
whether waiting for consumption of the full grant collapses that pattern,
with exact partial-frame accounting and end-of-stream connection credit.
[RFC 9113 §6.9.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.1)
permits the receiver to choose replenishment timing and advises against tiny
increments. Post-tag phase-load avoidance and fixed-work multiplication remain
ranked alternatives. Overall rocks turned is now **48% (rough 38–58%)** for the
attribution gap and tested source explanation, not an unimplemented gain.

### OPT-026 — Batch consumed HTTP/2 receive credit

- Wishes: 2 and 6, with 10 as a tradeoff check.
- Question: can authenticated, consumed-credit batching collapse a persistent
  27/485-byte response split into full 512-byte grants, reducing record work and
  phase reads while preserving exact flow-credit, rejection and lifetime rules?
- Baseline: committed `29bca48` and OPT-025's bound current-runtime attribution.
  The retained NE1000 first turn has 68 credit-shaped records and takes 424.89 s;
  its unchanged repeat has 35 and takes 291.99 s. This is observational context,
  not a controlled A/B or proof of identical provider bodies.
- Allowed surface: isolated experiments under `OPT-026/`, then the narrow
  receive-credit routine and directly affected HTTP/2 gates if justified.
  Preserve pre-tag crypto/retention, 512-B DATA capacity, all trust and memory
  invariants, model/config, prior evidence and unrelated checkout changes.
- Required evidence: independent peer reproduction; complete/split/padded DATA
  frames and TLS records; zero and final partial credit; hostile overrun and
  forgery; continued control processing; repeated streams, compaction, native,
  cancel/abort/reconnect; emitted size and read accounting. Any source checkpoint
  needs build/inspect, current composition gates and exact-floor live regression
  across the three CPU/RAM routes and affected original-speed ISA NICs.
- Exit: validated worthwhile working checkpoint, or a supported rejection and
  automatic selection of the next measured opportunity. No unvalidated timing
  claim or relaxed observer deadline. Commit and push require maintainer approval.
- Status/owner: integrated and validated in this campaign chat, sequentially
  after OPT-025. The maintainer approved this checkpoint's commit and push.
  All VMs are closed. Overall rocks turned remains **48% (rough 38–58%)**.

#### OPT-026 result — integrated and validated

The response owner now returns consumed DATA credit after the entire 512-byte
grant is consumed, or retires final connection credit at END_STREAM. It checks
both remaining budget and carried payload before replenishing; control frames
continue to be processed. No persistent counter or authority transition changes.
The owner grows 318 -> 360 bytes inside its existing sector. Only file sector
167 differs from `29bca48`; runtime length remains 150,016 bytes / 293 sectors,
FAT use 308/309, and RAM/stack allocation unchanged. Shipping runtime:
`707f614c955194abc486d31882ab978abbb2236f8facd9450bafe4a3d9ebd54f`.

The independent peer sends the identical 4,096-byte response through the actual
emitted R/X/K/H2/T route and real AEAD. With an initial 27/485-byte split, DATA
frames fall 16 -> 9, outgoing TLS records 16 -> 8, sector reads 274 -> 162,
and instruction hooks 8,765,564 -> 7,676,601 (12.42% fewer). The unsplit response
retains eight frames, eight outgoing records and 146 reads; hooks increase
7,614,896 -> 7,614,995, just 99 / 0.0013%. Both reach the same synthetic stack
low of 0x3fac. Measurement excludes request upload; BIOS, NIC, display and
provider are fixture leaves. This is neither target-cycle nor elapsed-time A/B.

Thirteen baseline and fourteen candidate cases cover split headers/payloads,
padding, trailers, carried PING, final partial credit, forged records and
ungranted DATA overrun. Credit conservation includes padding and no zero or
duplicate grants. The permanent gate's final strengthening explicitly checks
one matching PING ACK; all fourteen cases pass again on the frozen runtime.
The rejected K-slot placement and the observer's earlier complete-frame parser
failure on both variants remain preserved private evidence.

Fresh build, inspection and BASIC helper generation pass, with nineteen HTTP/2
composition gates and thirteen standalone TLS/RAM/config guards. Eight serialized
286 components reassemble byte-identically to their accepted timing baseline.
The final audit accepts nine cases / 27 prompted turns. Exactly 16 KiB ROM BASIC,
32 KiB direct boot and 286/512 KiB each complete four dependent text replies,
ten minutes idle, bounded reconnect and native write/execute/read with AX 42
and bytes B8 2A 00 CB. The six remaining original-speed NIC profiles complete
two dependent replies around the same idle/reconnect check, including 3c503/MDA.
Each gate uses the exact VM-owned four-flow capture and reviewed saved pixels.

The 32 KiB native model spells its correct result in words. The 16 KiB model
uses digits correctly, but the unchanged OCR detector omits its lower result
lines despite recognizing the input prompt. Both complete results and returned
prompts were reviewed before stopping their observers, within the original
2,400-second budget. Raw automatic misses remain `KeyboardInterrupt()` results;
separate timed, screenshot-hash-bound reviews establish functional completion.
The case validator and testing documentation now distinguish these two review
kinds; five test methods cover two positive cases and 23 refusals, including
runtime errors, missing prompts, wrong bindings and late completion. No timeout
is relabeled success. An incomplete-preview inference was corrected by decoded
pixels and exact image identity; all original PNGs and earlier review notes remain.

The initial supervisor stopped new launches after the first manual observer
stop. Its final global-empty assertion then saw the resumed NIC queue; that
exit and traceback remain recorded separately. The resumed supervisor finishes
successfully. The independent final audit verifies all nine VMs closed, maximum
overlap three and zero remaining processes, plus 688 protected files and all
8,058 prior evidence files unchanged. Existing cfg/NVR, screenshots, root capture
and user-local model/config remain preserved. At validation, HEAD was `29bca48`.
The subsequent documentation update describes batching in `docs/http2.md`;
all validated implementation, test and built-image bytes remain unchanged.

Disposition: retain this narrow response-credit improvement. No original-speed
dialogue gain, physical entropy credit or provider-deadline improvement is
claimed. Live full-record cycle medians remain about 6.6 s at 16 KiB, 4.88 s at
32 KiB and 2.49 s on the 286; these are observational intervals, not controlled
A/B. Next compare post-tag phase-load avoidance against fixed-work Poly1305
multiplication over the complete normal response route. Overall rocks turned
remains **48% (rough 38–58%)**. The maintainer subsequently approved commit and
push with the message `perf: batch HTTP/2 response receive credit`.

### OPT-027 — Compare ordinary response phase loads and fixed-work multiplication

- Wishes: 2 and 6, with 5 and 10 as footprint and whole-route checks.
- Question: which bounded construction removes more ordinary response work
  without growing the 16 KiB live footprint or changing authentication,
  protocol rejection, credit, native effects, or reconnect behavior?
- Baseline: committed `b5402f6`, runtime
  `707f614c955194abc486d31882ab978abbb2236f8facd9450bafe4a3d9ebd54f`.
  The controlled 4 KiB unsplit response takes 7,614,995 instruction hooks,
  146 sector reads and eight outgoing records; its fragmented counterpart
  takes 7,676,601 hooks and 162 reads. K uses 4,081 of 4,096 executable bytes;
  the response owner uses 360 of 512. These are synthetic instruction/read
  measurements, not target timing or a live latency claim.
- Allowed surface: isolated scripts, source copies and images under
  `build/optimization-campaign/OPT-027/`, plus this ledger. A justified narrow
  winner may then change its application implementation and directly affected
  gates. Preserve the shipping build during the comparison and all earlier
  evidence, local config and unrelated changes throughout.
- Required evidence: identical split/unsplit complete response fixtures;
  emitted size, phase reads/seeks, memory/stack lifetime and fixed-work checks;
  arithmetic or parser equivalence and hostile-input refusals appropriate to
  the candidate. A product checkpoint additionally needs fresh build/inspect,
  current offline gates and original-speed CPU/RAM/NIC live regression.
- Exit: select and validate a worthwhile narrow implementation, or record the
  supported negative result and select the next measured opportunity. Seek a
  fresh context only if the selected work needs a substantial independent
  algorithmic or security investigation. Do not commit or push.
- Status/owner: selected locally and functionally accepted through OPT-028 in
  the same campaign chat. Baseline and preservation inventory remain frozen in
  `OPT-027/`; the initial provider-compatibility failures below are retained.
  Overall rocks turned remains **48% (rough 38–58%)**.

#### OPT-027 selection — DATA fast path; live acceptance completed through OPT-028

The multiplication prototype doubles the fixed-loop body, growing K by its
remaining 15 bytes to 4,096. The identical unsplit 4 KiB response drops from
7,614,995 to 7,433,555 instruction hooks (2.38%) but keeps 146 reads. It is not
selected. The refined DATA fast path instead uses 7,403,450 hooks (2.78% fewer)
and 34 reads (76.71% fewer); requested adjacent track changes fall 45 to 10.
For the fragmented fixture, hooks fall 7,676,601 -> 7,464,013 and reads 162 ->
34 (79.01% fewer), with track changes 50 -> 10. Both keep eight outgoing
records and the same measured response stack low. These are synthetic emitted
instruction/read counts, not calibrated target timing, physical seeks or a
live latency gain.

Only a complete authenticated, unpadded, non-final DATA frame on an established
active stream can use the shortcut. Strict queue/header/state checks, body-count
overflow and content-length bounds precede publication; every other case uses
the unchanged shared parser. The differential gate compares full persistent
parser/queue state and output, with 746 accepted equivalence cases and 93
side-effect-free fallbacks. Strengthening that test to include a set direction
flag exposed a missing CLD in an intermediate prototype; the final one fixes
it and passes all 839 cases. Earlier artifacts and the failed audit remain.

The request helper grows 403 -> 510 bytes and the response owner 360 -> 455,
both within existing sectors. K stays 4,081 bytes, and no RAM, stack allocation
or FAT sector is added. The private final prototype changes only sectors 167
and 185, with runtime
`b34b33a098c8129315b7a50f6e977ea6dd7fa564aa3a2234bdeebff475dcfa6c`.
Its symbolic helper export and differential gate are now in the product source.
`OPT-027/comparison.json` and `DESIGN.md` retain the comparison and boundary
argument. The following integration result supersedes their earlier pending
build status. No commit or push; overall rocks turned remains **48% (rough
38–58%)**.

#### OPT-027 integration and provider compatibility pause

Fresh `make`, `make inspect` and `make basic-bootstrap` pass. The emitted
runtime exactly matches the selected prototype above. All 20 HTTP/2 gates
(including the 839-case differential and 14-case credit gates), 13 standalone
sampler/entropy/RAM/retirement/dispatch/cold-send guards and the eight unchanged
serialized 286 component bindings pass. `OPT-027/integration/` retains the
logs, immutable boot/test copies and source/artifact hashes. No additional
source change followed that validation.

The fallback tradeoff is bounded: the 200-byte final response takes 553,684 ->
553,728 instruction hooks (+0.00795%), with 34 reads and one outgoing record
unchanged. A padded 4 KiB response takes 7,888,804 -> 7,889,104 hooks (+0.00380%),
with 162 reads and nine outgoing records unchanged. Neither fixture uses the
shortcut; the added refusal checks do not introduce a phase read. These remain
synthetic response-only counts, not live elapsed time.

The fresh read-only live matrix stopped after its first three cases: original
4.77 MHz NE2000 at 16 KiB BASIC and 32 KiB direct boot, plus 6 MHz 286/512 KiB.
Each shows the pre-greeting setup failure. The unchanged frozen OPT-026 image
also fails before greeting on 16 KiB and 286. All five VMs closed when their
observations finished; no other NIC case was launched and no turn, reuse,
reconnect or native-tool acceptance is claimed. Raw failures, OCR, screenshots,
socket ownership and captures remain under `integration/live/`; the shared
config, user config and frozen images are unchanged.

Credential-free host probes on both observed provider addresses verify the
current certificate chain, hostname and validity, including a repeat with
Seed's TLS 1.3 ChaCha20-Poly1305, X25519MLKEM768, P-256 CertificateVerify and h2
selection. The observed leaf is valid from November 2, 2026 to January 31, 2027, with SPKI
SHA-256 `6ea3c81fbd1ba27325dfa35f3d518bc1b66076d6e9e74a09a86f5cef92a6d6c2`,
different from the image's `94655ad1...11e028f`. Its issuer is Let's Encrypt
YE2, whose key is P-384; the leaf certificate signature uses SHA-384. Verification
under the tracked WE1 anchor refuses the leaf. Public probe logs/certificates,
chain-link checks and exact-flow failure summaries are in `OPT-027/diagnosis/`.

The 8088 target captures contain only the fresh ClientHello, Finished and fixed
credential-free HEAD geometry, with no resumed connection. The 286 captures
stop after ClientHello and a larger protected server flight, before client
Finished. Those encrypted captures do not identify the first rejected target
check or independently reveal the peer certificate. The host-verified trust
mismatch is a concrete compatibility blocker; baseline reproduction prevents
attributing these failures to the DATA shortcut. Live candidate acceptance
still needs to be completed after compatibility is restored.

Disposition: preserve the local candidate and its evidence, leave product
capability claims unchanged, and pause for the trust-scope decision below.
`OPT-027/pause/checkpoint.json` binds the preserved candidate and records the
final preservation audit. Nothing is committed or pushed. Overall rocks turned
remains **48% (rough 38–58%)**.

### OPT-028 — Provider certificate and issuer compatibility repair

- Wishes: 1 and 9, as a live-acceptance prerequisite for OPT-027.
- Question: can the newly authenticated provider leaf and YE2 issuer route be
  supported on both existing floors, with strict on-target authentication and
  unchanged RAM/media/authority/entropy/reconnect boundaries?
- Baseline: frozen OPT-026 and local OPT-027 both fail before greeting; public
  host verification establishes the new P-256 leaf and P-384/SHA-384 issuer.
  See OPT-027's diagnosis and preservation checkpoint. The existing 286
  certificate-capture and signature bounds also need explicit review.
- Approved scope: replace the explicit WE1-only issuer
  constraint with an independently authenticated immutable current issuer;
  assess and implement the required bounded P-384/SHA-384 authentication,
  refresh the 8088 image-dated leaf through an independently verified fixture,
  and update directly affected composition, rejection, timing and product docs.
  Retain the conforming 286 route and every other hard invariant. A pin-only
  refresh does not repair the required 286 issuer path.
- Required evidence: current certificate/hostname/time/CV provenance; hostile
  arithmetic/parser/pack/authority/lifetime/zeroization checks; full target-local
  composition and footprint/timing accounting; fresh build/inspect; read-only
  16 KiB/32 KiB/286 first response, reuse, reconnect and original-speed NIC
  acceptance. Rerun OPT-027's live matrix after the repaired baseline works.
- Exit: validated compatibility checkpoint, or a concrete infeasibility or
  product-direction decision. No automatic commit, push, downgrade or relaxed
  verification.
- Status: **validated in this same campaign chat, explicitly authorized by the
  maintainer after the OPT-027 pause**. The maintainer requests repair and
  successful verification here before reconsidering a chat for new work.
  This supersedes the earlier fresh-context requirement for this spike. No new
  chat or agent has been started. `OPT-028/before.json` freezes the incoming
  checkout, OPT-027 candidate and all prior evidence. The final verification
  result below completes the repair; the maintainer subsequently approved
  committing and pushing the verified checkpoint.
  Overall rocks turned remains **48% (rough 38–58%)**.

#### OPT-028 chronological validation record

The repair is integrated locally and under full validation. The independently
verified November 2 credential-free fixture carries a 928-byte P-256 leaf,
the immutable YE2 P-384 anchor, and a 3,434-byte ordinary Certificate message.
The new SHA-384/P-384 verifier fits in the existing offline auth controller:
6,935 raw bytes and 6,121 stored bytes in twelve sectors. It shares one strict
signature-scalar parser with the X.509 profile and erases its public scratch
in the retired low module window before P-256 table generation. Historical
WE1 research fixtures remain unchanged; the product uses separate current
fixtures and the refreshed exact-leaf pin.

The module pack contracts from 44 to 41 sectors by removing unused padding.
Config escrow moves into that freed gap, allowing a 4 KiB Certificate
quarantine without increasing conventional RAM or moving private-state slots.
The 286 advertises the issuer's certificate algorithm separately from its
unchanged P-256 CertificateVerify offer, keeping ClientHello length constant.
The first full composition found HELLO five stored bytes over its sector
boundary; redundant carry clears and stronger host-side LZ4 packing recover
the existing eleven-sector allocation. This is not a relaxed FAT budget.

The independent target-code arithmetic/hash gate passes 900 field cases,
70 inverses, signature/DER/point failures and guarded-memory checks. The real
composed authentication gate passes full FO, YE2/hostname/UTC/CV proof,
status-last authority ordering, scratch retirement and altered-signature
rejections. Updated tablegen, ECDSA, root/pack and abort-restoration gates pass.
The exact issuer routine takes 1,572 BIOS ticks (86.3427 s) on the 6 MHz /
512 KiB 286, including SHA-384, P-384 and scratch erasure, with a separate
changed-signature refusal. Its VM closed. This is an offline component
measurement; full shipping build, serialized deadline timing and live matrix
acceptance are still pending. Evidence is in `OPT-028/`; no commit or push.

The current acquisition/resumption HELLO and protected-flight gates also pass,
including the 3,434-byte captured chain and correctly framed 4,096/4,097-byte
Certificate boundaries. The exact-leaf and publication gates pass. An optional
historical shared-parser regression initially stopped before executing target
code because it still hard-coded July lengths/dates against its unchanged
September fixture. Binding those expectations to the recorded capture and
independently decoded certificate dates restores its full tamper/time matrix;
the original failure remains recorded. A mid-repair audit confirms all 42,368
prior evidence files match, including the preserved OPT-027 checkpoint.

Fresh `make`, inspection and BASIC sidecar generation now pass, including all
twenty HTTP/2 gates and sixteen standalone TLS/fixture guards. The repaired
runtime is `9d83b0e2f3bf0293530cd344bb2e2a55144be19f380a5648d3d68e9567f04ea1`,
still 150,016 bytes / 293 sectors. Compared with the frozen OPT-027 image,
only the TLS loader, exact pin and 286 tail differ; the two OPT-027 HTTP/2
request/response sectors remain byte-identical.

The first serialized timing attempt stopped before opening a VM because the
larger certificate fixture exceeded the benchmark's reserved data area by
280 bytes. Moving its benchmark-only callbacks and timer support up one
512-byte page restores the checked separation. The semantic gate passes
unchanged shipping flight bytes, exact ciphertext, ticket export and final
key/sequence publication. The original failure remains recorded. All eight
serialized components now pass: the conservative current-controller CPU
totals are 158 ticks / 8.6782 s for acquisition and 170 ticks / 9.3373 s for
resumption. Disk, network and resident callback latency still require live
evidence. `OPT-028/integration/candidate-binding.json` binds the frozen image
and completed gates; the three main live cases are running with at most three
VMs. Product-documentation proposals are prepared but remain unapplied until
live acceptance. No new checkpoint is claimed yet.

Live verification is in progress on the frozen image. The 286, 32 KiB
NE2000 and 16 KiB 3c503/MDA cases pass their explicit owned-flow and visual
gates. The 286 native result needs the separately preserved OCR-omission
review; the 32 KiB model spells out its correct result, requiring the separate
numeric-format review. Neither raw automatic miss is relabeled success.

The first 16 KiB main run completes the four text turns, idle/reconnect and
correct native AX/bytes, but repeats native actions (three writes, three
executes, two reads). It is not accepted by the one-sequence gate. A private
exact-image diagnostic covers the actual 80-byte wrapped prompt, required
compaction, native journal and BIOS scrolling. Baseline and candidate produce
identical requests and tool results. Its initial incomplete fixture omitted the
compaction reply; that diagnostic failure and its requests are retained.
An unchanged full main-floor repeat is queued after the first VM closes.
Remaining ISA cases continue under the three-VM limit. Full acceptance and
product-documentation promotion are still pending; no commit or push.

The unchanged 16 KiB full repeat now passes automatic completion and independent
visual/owned-flow review: four correct text replies, ten minutes idle, bounded
reconnect, exactly one native write/execute/read, AX 42, bytes `B8 2A 00 CB`,
and returned input. The first repeated-action attempt remains excluded.
The 3c501, Novell NE1000, NE1000 and WD8003E cases also pass. Eight cases are
accepted and closed; only WD8003EB's post-idle dependent reply remains active.
Fifteen directly affected documentation files are prepared for promotion after
that gate. The image and shipping sources remain frozen. No commit or push;
overall rocks turned remains **48% (rough 38–58%)**.

#### OPT-028 final verification

All nine required cases pass on the frozen image: 16 KiB NE2000 (the unchanged
full repeat), 32 KiB NE2000, 286/512 KiB, 3c503/MDA, NE1000, WD8003E, 3c501,
Novell NE1000 and WD8003EB. The three main cases complete four text turns and
the native program; the six additional NIC cases complete two text turns each,
for 27 accepted prompted turns. Each case uses four exact-PID-owned TLS flows,
completes at least ten minutes idle and one bounded reconnect, and returns to
input with the correct replies. The main cases reuse their first final
connection for the first three text turns. Every 286 ClientHello carries the
separate P-384/SHA-384 certificate-signature offer.

Native acceptance retains the two reviewed observer exceptions: the 286's
correct numeric result was omitted by OCR, while the 32 KiB model spelled out
the correct value/bytes. Both complete within the original observer budget;
their raw automatic misses and timed screenshot-hash-bound reviews remain
separate. The first 16 KiB attempt's three writes, three executes and two reads
remain an explicit rejection despite its correct final result. The unchanged
full repeat passes automatically with one of each action, AX 42 and bytes
`B8 2A 00 CB`. The private wrapped-prompt comparison did not establish the cause
of the original repetition; no reliability or latency conclusion is drawn
from the repeat alone.

The private wire observer initially used the 8088 parser on the 286 capture and
included unrelated VM flows. Its failed output remains intact. The corrected
observer selects the bound CPU route and exact-PID-owned ports, reproduces a
preserved 8088 control, and agrees with the independently applied canonical
286 gate. This observer repair changes no shipping code or acceptance rule.

Both live controllers exit successfully. All ten attempted VMs are closed,
maximum overlap is three, and the original read-only images, protected config,
unrelated changes and 42,368 prior evidence files are preserved. The final
audit binds these checks, the 20 HTTP/2 and 16 standalone gates, all eight
serialized components, current source/image hashes, and 15 updated documentation
files. The 86.3427-second issuer measurement remains a component cost, not a
whole-route speed claim. Physical entropy and provider-edge repetition remain
separate open work.

The first final-audit attempt treated `capture_finished` logging timestamps as
exact VM exit times. Two completion records lagged slot reuse by 0.546 and
0.365 seconds, making four observation intervals overlap. The shared launch
lock and process-count history enforce/show at most three live VMs; the
completion log is written after shutdown, polling and evidence hashing. The
audit now records both quantities and reconciles those exact events with the
PID snapshots. Its initial source/failure and the reconciliation remain in
`OPT-028/audit-observation-repair/`; no live evidence or shipping code changed.

This was a validated local working checkpoint before commit approval; the
recorded audit remains that pre-commit evidence. The maintainer subsequently
approved commit and push. The next selected measurement is OPT-029; a new chat
is optional for that bounded work now that a verified checkpoint exists.
Overall rocks turned remains **48% (rough 38–58%)**.

Earlier proposed handoff, retained for history; the repair was completed here:

```text
Read AGENTS.md and docs/optimization-campaign.md, then execute spike OPT-028
from the ledger. The maintainer authorizes replacing the WE1-only issuer
constraint with the independently authenticated current provider issuer and
the bounded verification required for it. Preserve OPT-027 and all existing
changes/evidence. Keep at most three VMs open and close each when finished.
Report overall rocks-turned completion at every pause. Do not commit or push.
```

### OPT-029 — Time fixed-work response multiplication on the current path

- Wishes: 2 and 6, with 3 and 10 as cost and tradeoff checks.
- Question: after credit batching and the DATA shortcut, does the existing
  fixed-work Poly1305 multiplication prototype produce a worthwhile measured
  original-speed response gain within the unchanged code/RAM/stack/FAT budget?
- Baseline: the accepted OPT-027/028 checkpoint containing this entry, runtime
  `9d83b0e2f3bf0293530cd344bb2e2a55144be19f380a5648d3d68e9567f04ea1`.
  OPT-027's unsplit 4 KiB fixture uses 7,403,450 instruction hooks, 34 reads and
  eight outgoing records. Its unselected multiplication-only prototype reduced
  old-path hooks by 2.38% and occupied all 4,096 K-slot bytes; it has no measured
  elapsed-time gain and has not been accepted into the product.
- Allowed surface: isolated copies, harnesses and reports under
  `build/optimization-campaign/OPT-029/`, plus this ledger. Keep shipping source,
  images, local config, prior evidence and unrelated changes read-only.
  Reuse the existing prototype and profiling fixtures rather than duplicating
  OPT-025's attribution or claiming its old hook shares are current timings.
- Required evidence: exact baseline/candidate image binding; current response
  cost attribution; identical split/unsplit fixtures and full fixed-work AEAD
  behavior; emitted size, read/record counts, RAM/stack guards; repeated matched
  4.77 MHz target timing with provider/display substitutions stated explicitly.
  Keep forged-record and data-independent-work checks. New measurements must
  distinguish component timing from complete-turn latency.
- Exit: select a justified narrow implementation follow-up or record the
  bounded negative result and rank the next remaining cost. This measurement
  does not authorize a new crypto design, relaxed verification, product change,
  commit or push. Keep at most three VMs open and close each when finished.
- Status/disposition: **measurement complete; OPT-030 integration selected**.
  HEAD remains `3410dd7`. `OPT-029/before.json` freezes the source/image and
  preservation inventory; no other campaign process or VM was active at entry.
  Product source and images remain unchanged. No commit or push was made.

#### OPT-029 result and tradeoff

The isolated baseline is byte-identical to the accepted runtime. The ordinary
response candidate is
`4e40733c4dc9d75e58de90ba210debd892a3b3546a500c5aeabe443d412da84c`.
It repeats the same seven-instruction fixed-word body twice per public loop
iteration, reducing sixteen iterations to eight. It introduces no hardware
MUL premise, operand-dependent branch/address or new mutable scratch.

| Identical 4 KiB response | Baseline | Candidate | Reduction |
| --- | ---: | ---: | ---: |
| Unsplit instruction hooks | 7,403,450 | 7,222,010 | 2.45% |
| Fragmented instruction hooks | 7,464,013 | 7,280,845 | 2.45% |
| Unsplit BIOS ticks, each of three samples | 394 | 381 | 3.30% |
| Fragmented BIOS ticks, each of three samples | 397 | 384 | 3.27% |
| Unsplit component seconds | 21.6406 | 20.9266 | 0.7140 s |
| Fragmented component seconds | 21.8054 | 21.0914 | 0.7140 s |

Both shapes retain 34 sector reads, eight outgoing records, 99 fixture
callbacks and response stack low-water `0x3fc0`. The independent peer checks
the same full response, credit and exact encrypted outgoing packets. Current
baseline hook attribution is fixed-word multiplication 41.36%, all ChaCha
routines 25.06%, pre-tag retention 19.55%, and other work 14.03%. Those shares
are not elapsed-time shares. The measured candidate changes only the
fixed-word group's hook count.

K grows 4,081 -> 4,096 bytes. The helper remains 510 bytes, the owner 455, and
the isolated runtime 150,016 bytes / 293 sectors. The exact multiplication
frame remains 24 bytes, with no response RAM or stack growth. Shipping FAT use
remains 308/309 because the shipping image is untouched. Full product rebinding
and its final FAT/layout check belong to OPT-030: the measurement composition
does not regenerate or accept its cold-pack and 286 references.

For each exact image, 3,117 full-width operand pairs execute in two DS/SS
layouts (6,234 executions), preserving registers, access bounds and
operand-independent stack residue. Five arithmetic instruction/address traces
match within each image. Fourteen credit scenarios, the full 28-case AEAD
matrix, the focused 18-case hostile/trace matrix and twenty real-loader
composition/failure cases pass in guarded 16 KiB RAM. Equal-geometry forged
records retain identical pre-verification instruction/ACK schedules. The
initial equate-lookup and inherited cold-worker stack-bound fixture failures
are retained; the application frame is 24 bytes in both images.

Original-speed timing executes the actual lower-16-KiB response and phase
loader code. A private 64 KiB fixture stores the validated external transcript
and dispatcher above product memory. BIOS disk, NIC, provider and display are
substitutions; common dispatcher work is included, and UART/final CRC work is
outside the measured interval. Every callback checks input registers/SP and
outgoing packets, and the assembled fixture passes full lower-memory comparison
against the independent peer before VM use. Target CRC32 and transcript
exhaustion pass on every sample. This is component timing, not 16 KiB boot,
physical I/O, full-turn, entropy or live-provider acceptance.

Four accepted read-only VM runs provide twelve samples, with baseline-first
order for unsplit and candidate-first for fragmented. The initial high-density
drive attempt fell through to ROM BASIC and collected no timing; it remains
failed and excluded. Two offline native-fixture misses (scroll callback and
ordinary displayed prompt) also remain recorded. All VMs are closed, maximum
overlap is one, and all media hashes match. `comparison.json` and
`final-audit.json` under `OPT-029/` bind the results, ledger, unchanged 9,551
protected files (excluding the allowed ledger edit) and 44,543 prior evidence
files. Existing unrelated cfg/NVR, screenshot and pcap changes are preserved.

The measured, repeatable saving justifies the narrow two-round implementation
follow-up. Its zero remaining K headroom is an explicit cost: recover
executable space before larger unrolls or other code-expanding response work.
ChaCha is the next measured computation group to examine after that constraint;
pre-tag retention has a higher verification risk. Do not trade fixed work for
variable-time multiplication or weaken authentication to gain speed. Overall
rocks turned is **50% (rough 40–60%)**.

### OPT-030 — Integrate the measured fixed-work response multiplication

- Wishes: 2, with 5, 6 and 10 as budget and compatibility checks.
- Question: can the exact OPT-029 two-round unroll become a fully validated
  product checkpoint while retaining the measured component gain and every
  existing trust, RAM, stack, layout, read-only and reconnect boundary?
- Baseline: committed `3410dd7`, runtime `9d83b0e2f3bf0293530cd344bb2e2a55144be19f380a5648d3d68e9567f04ea1`.
  Reuse OPT-029's frozen images, oracle, response fixtures and native timings.
- Allowed surface: `boot/core/poly1305_app.inc`, focused exact-image arithmetic
  regression coverage and necessary build/test bindings, affected documentation,
  this ledger and isolated `build/optimization-campaign/OPT-030/` evidence.
  Preserve earlier evidence and all unrelated changes in this same checkout.
- Required evidence: regenerate all dependent product/cold/286 bindings;
  `make`, inspect and BASIC helpers; all current TLS/application offline gates,
  exact arithmetic and fixed-work checks, bounds/erasure/hostile inputs;
  unchanged FAT/RAM/stack/read/record budgets and K <=4,096 bytes. Reconcile
  the rebuilt ordinary route with the timed candidate before retaining its gain.
  Run relevant 16 KiB BASIC, 32 KiB direct and 286/512 KiB live gates, all seven
  original-speed ISA NICs, reuse, bounded reconnect, and affected native/ENV,
  cancellation, recovery and display lifetimes. Retain every failed attempt.
- Exit: a working, fully validated product checkpoint, or revert only this
  candidate's product edits and record why the integration cannot be accepted.
  No new crypto design, trust assumption, module system or relaxed verification.
  Keep at most three VMs open and close each when finished.
- Status: **implemented and accepted through OPT-031**,
  explicitly authorized in this campaign chat by the
  maintainer for implementation and testing. `OPT-030/before.json` freezes
  `3410dd7`, existing changes, canonical build hashes and all earlier evidence.
  No other campaign process or VM was active at entry. Commit and push were not
  authorized at entry. Overall rocks turned remains **50% (rough 40–60%)** during this
  integration and its required acceptance work.

The final-image offline checks and exact OPT-029 timing-payload reconciliation
are complete. `integration/candidate-binding.json` binds the integration image and
`integration/pre-live-invariants.json` confirms 699 unrelated protected inputs
are unchanged. The private replay's missing-include failure and successful
repair are preserved under `harness-repair/`.

The three main CPU/RAM cases all fail before greeting at `00/12`; unchanged
baseline controls on 32 KiB and 286 reproduce the failure. All five cases are
retained under `integration/live/`, with failed results, reviewed screenshots,
exact-PID ownership and raw pcaps. All VMs are closed and the maximum was three.
No other NIC case or prompted turn ran. Public probes on both provider
addresses verify a new November 3 WE1/P-256/SHA-256 leaf, whose SPKI SHA-256 is
`ce0265df44be9bacfcf32d6c12a74ffb5b7222e4aec845e44f527a740744657c`.
It differs from the frozen November 2 exact leaf and is refused under the
immutable YE2 key. The host probes establish compatibility evidence only;
their certificates and computations are not runtime helpers.

Pre-repair disposition, retained for history and resolved by OPT-031:
preserve the local implementation and completed checks while awaiting
the maintainer's trust-scope decision. The proposed follow-up retains
both independently authenticated WE1 and YE2 issuer keys, refreshes only the
8088 image-dated exact leaf, and keeps hostname/time/CV/FO/publication/erasure
and every RAM/media boundary intact. Its footprint must be measured: the 286
auth controller currently has 233 raw bytes and 23 packed bytes of headroom.
No compatibility implementation, trust-asset edit, commit or push has occurred.
All seven NIC profiles, reuse, idle reconnect, native completion and visual/wire
review remain required before accepting OPT-030. Overall rocks turned remains
**50% (rough 40–60%)**.

### OPT-031 — Restore both observed issuer routes and finish OPT-030 acceptance

- Wishes: compatibility and verification prerequisites for OPT-030; this does
  not count as another optimization avenue turned.
- Authorization: the maintainer selected “Repair compatibility and finish
  testing”: retain the independently authenticated WE1 and YE2 issuer keys,
  refresh the 8088 image-dated exact leaf, and complete the live matrix.
- Baseline: the preserved OPT-030 implementation on `3410dd7`, including its
  successful offline checks and five failed live/control runs. `OPT-031/before.json`
  freezes source, unrelated changes, boot artifacts and all earlier evidence.
- Scope: bounded dual issuer selection, the current exact-leaf asset and public
  provenance fixtures, necessary certificate/hash/wire-profile bindings, hostile
  gates and documentation. Preserve strict hostname, UTC validity, issuer/CV,
  full FO, status-last authority, erasure, conventional-RAM-only state and
  write-protected media. Reuse the existing phase/module architecture.
- Validation: measure emitted raw/packed/FAT/RAM budgets; prove both real issuer
  paths and hostile/mismatched inputs; run all current offline gates, serialized
  timing and the exact ordinary response implementation checks. Then complete
  16 KiB BASIC, 32 KiB direct, 286/512 KiB, all seven ISA NICs, reuse, bounded
  reconnect, native and affected lifetime gates, with actual screen/wire review.
- Status: **accepted product checkpoint**. Nine reviewed cases and
  27 prompted turns pass the exact frozen product image. The resumed
  `ne2k8-32k-repeat-4` completes four text turns, ten-minute idle recovery and
  exactly one native write/execute/read with AX 42, correct bytes and returned
  prompt. The final values are expressed in words; a separate timed visual
  review establishes functional completion while preserving the automatic
  literal-match miss and numeric-format noncompliance. All five excluded
  attempts and the separate instrumented diagnostic
  are preserved. Earlier repeated-action cause remains unproven; no native-loop
  fix was made. Product documentation is updated. All VMs are closed, with
  resumed overlap one and campaign overlap at most three. The maintainer has
  authorized this checkpoint's commit and push. Overall rocks turned remains
  **50% (rough 40–60%)**.

#### OPT-031 result and evidence

The 320-byte public-point object fits the existing 41-sector pack header.
Authentication occupies 7,156 raw / 6,143 stored bytes in twelve sectors;
the H2 helper remains one sector. Matching inner/outer signature algorithms
select WE1/SHA-256 or YE2/SHA-384. Exact encoded TBS capture follows acquisition
Finished and credential-free liveness. Strict offline parsing binds its span
and RAM-corruption guard before full issuer ECDSA verification. Temporary
capture state is wiped before promotion and on abort. No additional private
key, writable media or trusted runtime helper is introduced.

Both real issuer paths pass target execution and hostile input checks,
including altered algorithms, spans, digests, guards, points, signatures,
CV and rehashed unsigned certificates. Initial over-budget attempts, a
date-extraction sequencing failure and stale fixture assumptions are retained
in `rejected-attempts.json`; none are relabeled as passes.

Five excluded product attempts remain under their original case directories:
`ne2k8-32k` repeated a write; `ne2k8-32k-repeat-1` was stopped incomplete for
the planned outage; `ne2k8-32k-repeat-2` and `ne2k8-32k-repeat-3` repeated an
execute; `ne1k-16k` failed across a confirmed 136-second clamshell sleep.
The latter's unchanged full repeat passes. The three native-repeat captures
account for all their connections, but do not establish the encrypted
application's reason for repeating an action. No product fix was inferred
from that wire evidence.

Four synthetic cache/compaction/scrolling cases and two full lifecycle
comparisons produce identical baseline/candidate requests and tool results.
The two separately authorized host continuation probes returned the correct
AX and bytes without another tool call. The approved private serial diagnostic
then completed the full live scenario and showed intact journal, context,
read result and original prompt metadata. These remain diagnostic evidence;
they do not establish the earlier cause or count as canonical acceptance.
The maintainer subsequently resumed testing, and the independently reviewed
uninstrumented `ne2k8-32k-repeat-4` completed the missing functional product
case. Its final answer is "AX is forty-two. Hex bytes: bee eight, two ay,
zero zero, see bee." The saved pixels show one of each action and a returned
input prompt. The unchanged detector still misses literal `42`, so its
original automatic result is preserved and the documented numeric-format
mismatch review supplies functional completion only. The owned observer was
stopped after that review; its nonzero exit is not presented as an automatic
pass. A conservative cleanup guard first rejected the relative script argument;
the guard failure and exact-path resolution before scoped closure are retained.

`integration/candidate-binding.json`, `dual-issuer.json`,
`response-reconciliation.json`, `serialized-286.json`, each accepted case's
`connection-accounting.json` and `h2-live-gate.json`, and `final-audit.json`
bind this checkpoint. `integration/native-trace-pause-checkpoint.json`,
`target-native-trace/conclusion.json` and `integration/resume-2026-11-20/`
retain the pause, diagnostic and resumed verification separately. Monitor
histories are preserved without rewriting old observations. All owned VMs,
monitors and temporary idle guards closed. Current remaining limitations are
physical entropy, wider provider repetition, unexplained historical native
repeats and no executable headroom in K. The controlled 3.30% / 3.27% gain is
not a whole-dialogue latency claim.

### OPT-032 — Recover K space from an unreachable legacy Finished wrapper

- Wishes: 5, with 2, 4, 6 and 10 for full-route and layout accounting.
- Question: can omitting only the uncalled TLS 1.2 Finished-message wrapper
  from product application K recover at least 64 executable bytes while keeping
  every reachable operation, load count, RAM/stack budget and trust boundary?
- Baseline: committed and pushed `f0ca175`, runtime
  `bb0c1ce10d6e8f3096b6ebf60914f38f3ef33bc3994a233c6c100ac92737e6ba`.
  K is exactly 4,096 bytes in eight loaded sectors; its fifteen-sector file
  slot also contains the separately loaded HTTP/2 parser. Runtime is 293
  sectors, FAT use 308/309, and the 16 KiB arena/context remains 96/96 bytes.
- Allowed surface: this ledger and isolated evidence under
  `build/optimization-campaign/OPT-032/` first. After proving absence of callers,
  narrowly gate the legacy wrapper in `boot/core/poly1305_app.inc`; change
  existing check/binding code only if an emitted-address assumption needs a
  documented update. Update directly affected capacity/testing docs after
  acceptance. Keep legacy `poly1305.inc`, live arithmetic, phase geometry,
  trust assets, networking, driver selection and runtime interfaces unchanged.
- Required evidence: preserve source/artifacts/unrelated state and all prior
  evidence; exact product and non-product reference inventory; emitted size
  and instruction/relocation equivalence for all surviving code; private
  ordinary-route request/response, hostile/retirement/native/reconnect gates;
  unchanged RAM, stack, record/read counts, FAT and parser placement. If the
  result is worthwhile, integrate it and run fresh make/inspect/BASIC, current
  TLS/application gates and affected original-speed 16 KiB, 32 KiB and 286
  live acceptance across all seven ISA NICs. Preserve every failed attempt.
- Exit: a fully validated space-recovery checkpoint, or preserve the bounded
  negative finding and select another in-scope headroom hypothesis. Do not
  claim faster execution, extra arena/context, fewer reads or FAT savings
  without evidence. No commit or push without new maintainer approval.
- Status/owner: **complete; maintainer approved commit and push**. The same
  checkout and all earlier evidence are preserved.
  All VMs and owned monitors are closed; maximum overlap was three. Overall
  rocks turned remains **50% (rough 40–60%)**.

The private omission measures **4,096 -> 4,019 bytes**, recovering 77 bytes
without changing the eight-sector K load or its fixed file allocation.
`private-audit.json` accounts for all 1,689 surviving K instructions, relocated
references and three unchanged data bytes. The preceding instruction is a
return, and the only named callers belong to the historical TLS 1.2 source
with its separate `poly1305.inc`. Historical/non-product Poly1305 assembly
remains byte-identical. The first preprocessing comparator rejected two added
blank lines; that failure remains in `private-build.log`, and the emitted
comparison passes without changing any product code.

The private ordinary-route images were not live candidates: cold/286 references
required complete product regeneration after the narrow source edit.
`private-checks.json` passes arithmetic, AEAD, phase-bridge and complete
unsplit/fragmented response checks. `parser-range-correction.json` corrects
the original audit's misplaced range assertion; the original report remains
preserved. All 3,584 parser bytes at file offset 6,144 are unchanged.

The canonical runtime is now
`5f068397521319be6ebe20f4427e03f7436f3d754a495bb031af56de34beac55`.
`integration/composition-audit.json` binds the private K proof to that image
and accounts for all 37 changed bytes outside K: twenty-four near-call
operands and two keepalive-state addresses. Every surviving operation,
parser placement, boot/loader/BASIC helper, driver and non-runtime floppy byte
is unchanged under that relocation. Runtime is still 293 sectors with
308/309 FAT clusters; user arena/context and stack budgets are unchanged.

Build/inspection/BASIC, twenty final-image HTTP/2 gates, sixteen standalone
guards, both issuer fixtures and hostile checks, and 6,234 final multiplication
executions pass. Both 4 KiB response shapes match the accepted baseline in
instruction counts, output, 34 reads, eight outgoing records and 64-byte peak
stack use. All eight current serialized 286 payloads match their previously
measured bytes, retaining those timings without a new timing claim.
`integration/candidate-binding.json` freezes the checked images and 610
source/configuration hashes. Credential-free TLS checks matched the accepted
leaf on both resolved IPv4 provider edges before live testing.

Nine accepted cases complete 27 prompted turns: 286/512 KiB, 32 KiB NE2000,
the full 16 KiB NE2000 repeat, 3c503/MDA, NE1000, WD8003E, 3c501, Novell
NE1000 and WD8003EB. Each includes session reuse and one bounded reconnect
after a full ten-minute idle. Each accepted main native test performs exactly
one write, execute and read, reports the expected AX and bytes, and returns to
the prompt. All four TLS connections and, on the 8088, both empty preparation
opens are bound to each VM's socket ownership and capture. No unexplained
attempt is excluded. The largest accepted TLS window is 11.255 seconds.

The 32 KiB native answer spells out the correct AX and hexadecimal
bytes instead of following the request for digits. The documented functional
review retains the automatic literal-42 miss, observed returned prompt,
original time budget and exact screenshot hashes. Numeric-format compliance
is explicitly false. This does not waive any runtime error or repeated action.

The original 16 KiB attempt is excluded: its saved screen shows one write,
two executes and two reads. Only that invalid case's observer was interrupted;
its VM closed and its automatic result, capture and `nonacceptance.json` are
retained. The first stop helper refused an absolute-versus-relative process
path mismatch before sending any signal. Its failed source and result, the
corrected exact-path check and all failure screenshots remain intact.

`integration/repeat-decision.json` records the single unchanged complete
16 KiB repeat, from cold boot through the same prompts, idle and native gate.
That repeat passes. The cause of the earlier repeats remains unproven; neither
a native-loop fix nor a broader reliability improvement is claimed.

The 16 KiB repeat passes all five original automatic observations, including
its numeric native answer and returned prompt. During its subsequent shutdown,
the supervisor asserted a stale PID between inventory and identity lookup,
then sent duplicate interrupts in its cleanup path. This interrupted the
native runner's reporting and WD8003EB's first startup before its greeting.
The original supervisor records and logs remain unchanged. The recovery audit
reconstructs the two missing reports from unchanged events and captures;
WD8003EB's interrupted attempt is excluded without a target verdict. Its
orphaned read-only VM was closed by the normal SIGTERM/SIGKILL fallback.

The final one-case monitor tolerates a PID that retired after inventory and
sends only one cleanup interrupt. One unchanged complete WD8003EB repeat
passes. `integration/final-nic-decision.json` binds this bounded repeat; no
accepted native scenario is repeated for the reporting repair.

All four queues keep their separate original histories.
`integration/queue-audit.json` reconciles eleven distinct case claims, two
exclusions, report reconstruction, global VM counts, monitor ownership and
sleep guards. Earlier snapshots may contain another queue's VM, or the
explicitly recovered orphan. Final global VM count is zero. Maximum overlap
is three and no gap occurs during accepted case observations. The interval
between the failed supervisor and its replacement is documented separately;
no accepted case spans it. The same frozen image is used throughout.

Architecture, testing and build-history documentation describe the current
capacity and qualifications. `integration/final-audit.json` binds those docs,
all accepted gates and both excluded attempts, while the preservation audit
retains all 49,957 prior campaign files, 592 historical build files, original
artifacts and unrelated local changes. No physical entropy credit, extra
user memory, reduced read count, FAT-sector saving or new elapsed-time gain
is claimed. The maintainer approved commit and push after reviewing this
working checkpoint. The preserved validation snapshot and publication record
bind the status-only documentation update to the tested source and images.
Overall rocks turned remains **50% (rough 40–60%)**. The next selected
investigation is bounded ChaCha20 response work; it has not started.
