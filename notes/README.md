# Notes

This directory is working memory for active branch design and experiments.

No active per-build implementation log right now: Build 8 (the Default Prompt
Interface chat loop) is complete and its working docs are archived in `old/`
(the build attempt logs and design notes). The Build 8 release
summary lives in `docs/builds.md`. The next build opens a fresh top-level log.

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
