# Demo 07 — detect a JPEG+ZIP polyglot (hidden archive)

## Situation

A user submitted `photo.jpg`. It opens fine in any image viewer — but it is a
**polyglot**: a complete JPEG with a ZIP archive appended directly after the
JPEG `FF D9` end-of-image marker. This is exactly how `jpg+zip` smuggling,
many CTF stego challenges, and some real malware droppers hide a payload behind
a benign-looking picture. The OS shows a photo; a ZIP reader (and `filecarve`)
finds the hidden archive.

`photo.jpg` is regenerated deterministically by `make_demo.py`:

- A valid **JPEG** (SOI + JFIF APP0 + EOI).
- A **ZIP** appended after the EOI, containing `notes.txt`.

## Run it

```sh
# Reveal BOTH regions at their true offsets
python -m filecarve scan demos/07-polyglot-file/photo.jpg

# Extract the hidden archive — it re-opens as a real, valid zip
python -m filecarve carve demos/07-polyglot-file/photo.jpg -o extracted
python -c "import zipfile; print(zipfile.ZipFile('extracted/00001_0000002e.zip').namelist())"
```

## What to expect

Two carves at distinct offsets: the **JPEG** at `0x0` (`method=footer`) and the
**ZIP** right after it (`method=length`). Because the carver now includes the
ZIP's full End-Of-Central-Directory record, the extracted `.zip` is a genuine,
openable archive — not a truncated fragment.

## How to act

Any image that also carves as an archive/executable is suspicious by
construction — quarantine it. Inspect the hidden archive's contents and hash
them against threat intel. Add a CI rule that fails when an image file yields a
second carve of a different type.
