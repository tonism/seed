# Notes

This directory is working memory for active branch design and experiments.

Active docs (Build 12, branch `work/scaling`):

```text
native-tool-calling-design.md  HISTORY/HANDOVER. Build 12 native function_call support shipped on the
                               32 KiB loop-cache tier and the 16 KiB floppy-streamed tools path.
memory-scaling-design.md       ROADMAP. 8088 + EMS scaling (M1/M2) SHIPPED in Build 12; the 286/386
                               native extended memory + HMA continuation lives here (post-Codex work).
ui-unification-design.md       ROADMAP/HISTORY. Build 12 UI polish shipped except the larger
                               render-room-dependent renderer work, such as a guaranteed glyph map.
```

Completed/shipped design + attempt logs (Build 8-12: memory-layout redesign, 286 secure tier,
auto-recertify, ECDSA scoping, M2 EMS, env save/load, all prior builds) are archived in `old/`. Their
reader-facing summaries live in `docs/` (`architecture.md`, `memory.md`, `security.md`,
`crypto-feasibility.md`, `builds.md`). Per-build release summaries + the Build-13 roadmap are in
`docs/builds.md`. Each new build opens a fresh top-level log and archives the prior one to `old/`.

Use `docs/` for stable project documentation that should guide users and future
contributors. Use `notes/` for branch-local reasoning, measured attempts,
failed paths, and design sketches that may change quickly.

Attempts logs use this shape:

```text
short branch context / baseline / target
chronological attempt log, oldest at the top and newest at the bottom
## YYYY-MM-DD HH:MM:SS - Short title
```

Timestamps are Europe/Tallinn local time. When a historical entry was
reconstructed from git history, use the commit timestamp for that entry.
