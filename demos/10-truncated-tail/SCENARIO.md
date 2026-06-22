# Demo 10 — honest handling of a truncated / corrupt acquisition

## Situation

Real acquisitions are imperfect: a capture gets cut short, a transfer drops, a
sector goes bad. `partial.bin` simulates this — it contains a **PNG whose
trailing `IEND` footer was lost** because the acquisition ended mid-file. A good
carver must not silently hand you a file that looks complete when it is not.

`partial.bin` is regenerated deterministically by `make_demo.py`:

- Non-magic lead-in bytes.
- A PNG header + `IHDR` + `IDAT` … but **no `IEND` chunk** and then the stream
  simply ends.

## Run it

```sh
python -m filecarve scan demos/10-truncated-tail/partial.bin

# Recover what is there — knowing it may be incomplete
python -m filecarve carve demos/10-truncated-tail/partial.bin -o recovered

# JSON exposes the method so a pipeline can branch on incomplete carves
python -m filecarve --format json scan demos/10-truncated-tail/partial.bin \
  | jq '.findings[] | {ext, method, truncated}'
```

## What to expect

One carve: the **PNG** with `method=bounded` rather than `footer`, because no
end-marker was found — the carver fell back to a bounded read to the end of the
available data. The `method` field (and, when a size cap is hit mid-blob, the
`truncated` flag / `*` marker) tells you this recovery may be **incomplete**.

## How to act

Treat `bounded` carves as lower-confidence: the bytes are real but the file may
be cut short. Re-acquire the source if possible, and do not assert file
completeness in a report for any carve whose `method` is not `footer`/`length`.
