# Optional User Config

Seed can remember validated user answers to make later boots faster, but stored
configuration is always optional.

Core rule:

```text
missing config      -> ask
unreadable config   -> ask
unparseable config  -> ask
invalid value       -> ask
write failure       -> continue without storing
read-only media     -> continue without storing
```

The runtime must not turn config storage into a boot dependency. If a value is
needed and cannot be loaded, Seed asks the user through the minimal text prompt
flow, uses the answer in memory, and attempts to persist it only after the value
has been validated.

Writes are best-effort. A failed write is not an error state and should not
interrupt the user after the validated answer has already been accepted. This
keeps read-only boot media, write-protected floppy images, and emulator-mounted
images usable.

Only normalized, validated values should be stored. Raw failed input should not
be retained. For secrets, the default should be per-boot entry or a short-lived
token because early PC-class targets do not have trustworthy secret storage.
Persisting a credential should require an explicit user choice once that flow
exists.

The current IBM PC 5150 floppy is a raw boot image and intentionally has no
filesystem, so it does not yet expose a config file. When a filesystem-backed
environment exists, the config file should be treated as an acceleration path,
not as the source of truth.
