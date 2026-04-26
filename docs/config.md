# Agent And User Config

Seed now has two configuration files on the boot floppy:

```text
AGENTS.CFG  shipped, tracked agent interface declarations
SEED.CFG    ignored, optional local user choices and secrets
```

`AGENTS.CFG` is not general OS configuration. It only describes agent-facing
interfaces: gateways first, then direct vendors. The file is meant to stay
plain enough for both humans and later agents to edit.

`SEED.CFG` is user-local state. It should only contain values that were entered
by the user and validated by Seed, such as adapter choices, selected agent
interface, endpoint overrides, model names, and API credentials.

Seed can remember validated user answers to make later boots faster, but local
stored user configuration is always optional.

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
be retained. Early PC-class targets do not have trustworthy secret storage, so
persisted credentials must be treated as plaintext convenience state on the boot
medium.

The first filesystem target is FAT12 because it is period-appropriate, simple,
and widely compatible with early PC tooling. The initial filesystem discipline
is intentionally narrow:

```text
root directory only
uppercase 8.3 filenames
no subdirectories
no long filenames
no dependency on writes succeeding
```

The current build 6 checkpoint verifies that `AGENTS.CFG` exists in the FAT12
root directory and begins with an `agent ` declaration. Full parsing,
`SEED.CFG` reads and writes, credential prompts, TLS, and API calls are still
build 6 follow-up work.
