# Demo 04 — carve files out of a process memory dump

## Situation

During incident response on a host **you own and are authorized to analyze**,
you capture a process memory dump (`memory.dmp`). Artifacts often live in RAM
even when they were never written to disk: a captured screenshot, a config
archive a beacon unpacked in memory, and the loaded executable image. You want
to recover those resident files without re-running anything on the live host.

`memory.dmp` is regenerated deterministically by `make_demo.py` (committed
alongside it) and embeds, between heap-like non-magic padding:

1. A valid **PNG** (a 2x2 "screenshot"), with proper `IEND` footer.
2. A small **ZIP** holding `config.ini` (`beacon=300 / jitter=20`).
3. An inert **PE/EXE** stub (`MZ` header + the standard DOS-mode message).
   It is **not** malware — just enough bytes to trip the `MZ` rule.

## Run it

```sh
# List what is resident in the dump (writes nothing). Exit 1 = findings.
python -m filecarve scan demos/04-memory-dump/memory.dmp

# Recover the resident files
python -m filecarve carve demos/04-memory-dump/memory.dmp -o recovered

# Only chase executables (highest analyst priority)
python -m filecarve scan demos/04-memory-dump/memory.dmp --type exe
```

## What to expect

Three carves: the PNG (`method=footer`), the ZIP (`method=length` — the full
End-Of-Central-Directory record is included so the archive re-opens cleanly),
and the EXE (`method=bounded`, severity **high**). Executables resolve via the
bounded fallback because a PE has no trailing magic; review those byte ranges
manually. Diff the recovered `config.ini` against a known-good baseline.

## How to act

Hash the carved EXE (the SHA-256 is in the table / JSON / SARIF) and check it
against your threat-intel before doing anything else. Treat the `config.ini`
beacon/jitter values as candidate C2 indicators for your detections.
