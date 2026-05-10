# Notes

This directory is working memory for active branch design and experiments.

Current files stay at the top level:

```text
16kb-windowed-nucleus-design.md     current 16 KiB architecture reference
16kb-windowed-nucleus-attempts.md   current 16 KiB implementation log
```

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
