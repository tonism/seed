# Notes

This directory is working memory for active branch design and experiments.

Active per-build implementation log: `build11-hardening-attempts.md` (Build 11, release
hardening; branch `work/draining-fifo`). Builds 8, 9, and 10 have shipped — their attempt logs and
design notes are archived in `old/`. Per-build release summaries live in `docs/builds.md`. Each new
build opens a fresh top-level log and archives the prior one to `old/`.

Completed or superseded branch logs and designs live in:

```text
old/
```

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
