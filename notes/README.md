# Notes

This directory is Seed's build-by-build **implementation log** — the dated record
of how the runtime was actually built, mistakes and all. It is working memory, not
reference documentation.

- **Stable reference** (how Seed works, the contracts) lives in `docs/`:
  `architecture.md`, `memory.md`, `security.md`, `crypto-feasibility.md`.
- **Roadmap and forward-looking work** (the Build 13 plan and the backlog) live in
  `docs/builds.md`, not here.
- **Here** you get the attempt logs, plus two raw records that `docs/` and the boot
  core still cite as evidence.

Everything is archived under `old/`; each shipped build files its log there. The
current branch (`work/scaling`, Build 12) has no open top-level log.

## Attempt logs

Oldest at the top. Each is a chronological grind log for one target or build.

```text
16kb-windowed-nucleus-attempts.md      16 KiB windowed-nucleus floor
24kb-windowed-attempts.md              24 KiB windowed target
32kb-slim-attempts.md                  32 KiB slim target
48kb-slim-attempts.md                  48 KiB slim target
default-prompt-interface-attempts.md   Build 8  chat loop (DPI)
build9-context-attempts.md             Build 9  context management
build10-tool-calling-attempts.md       Build 10 RAM read/write/exec tool calling
build11-hardening-attempts.md          Build 11 FIFO, reconnect, compaction, ESC, rendering
build12-layout-redesign-attempts.md    Build 12 capability-tiered layout + 286 secure tier
build12-memory-scaling-attempts.md     Build 12 far / EMS / HMA / unreal memory ladder
auto-recertify-attempts.md             Build 12 silent leaf-rotation re-pin
```

## Raw records still cited elsewhere

Not an attempt log, kept because live references point at it:

```text
ecdsa-tier-scoping.md    the ECDSA secure-tier spike; the raw measurement record
                         behind docs/security.md and docs/crypto-feasibility.md
```

## Log format

```text
short branch context / baseline / target
chronological attempt log, oldest at the top and newest at the bottom
## YYYY-MM-DD HH:MM:SS - Short title
```

Timestamps are Europe/Tallinn local time. When a historical entry was
reconstructed from git history, use the commit timestamp for that entry.
