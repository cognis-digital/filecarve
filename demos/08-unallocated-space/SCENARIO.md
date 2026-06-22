# Demo 08 — carve deleted images from unallocated disk space

## Situation

You `dd`'d a region of unallocated space off a drive image **you are authorized
to examine**. When a file is deleted, its content lingers in unallocated /
slack clusters until overwritten, with no filesystem metadata pointing at it.
This is the canonical file-carving job: recover the bytes with no directory
entry to help you.

`unallocated.raw` is regenerated deterministically by `make_demo.py` and hides,
in cluster-slack-like padding:

1. A **GIF** image (resolved by its `0x3B` trailer → `method=length`).
2. A **BMP** image whose in-header 4-byte file-size field lets `filecarve`
   resolve the **exact** length (`method=length`) — no guessing.

## Run it

```sh
python -m filecarve scan demos/08-unallocated-space/unallocated.raw

# Recover the deleted pictures
python -m filecarve carve demos/08-unallocated-space/unallocated.raw -o recovered

# Shareable HTML report for the case file
python -m filecarve --format html -r case-report.html \
  scan demos/08-unallocated-space/unallocated.raw
```

## What to expect

Two carves (gif, bmp), both `method=length` — meaning the end was computed
precisely from each format's own header rather than a bounded guess, so the
recovered files are byte-exact and open normally.

## How to act

Add the recovered images to your evidence inventory with their offsets and
SHA-256 hashes (all in the report). Because both carves are length-resolved,
they are high-confidence recoveries suitable for review/disclosure.
