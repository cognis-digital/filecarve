"""Regenerate demos/07-polyglot-file/photo.jpg deterministically.

A polyglot: a file that is a VALID JPEG to a viewer but has a ZIP archive
appended after the JPEG EOI marker. This is exactly how `jpg+zip` smuggling and
some CTF/stego payloads work — the OS shows a picture, but a ZIP reader (and
filecarve) finds the hidden archive. filecarve reports BOTH regions at their
true offsets. Standard library only.
"""
import io
import os
import zipfile


def _jpeg() -> bytes:
    soi = b"\xff\xd8\xff"
    app0 = b"\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    eoi = b"\xff\xd9"
    return soi + app0 + b"\x11" * 24 + eoi


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes.txt", b"hidden archive appended after JPEG EOI\n")
    return buf.getvalue()


def build() -> bytes:
    # Real polyglot layout: complete JPEG, then a ZIP appended directly after.
    return _jpeg() + _zip()


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "photo.jpg")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
