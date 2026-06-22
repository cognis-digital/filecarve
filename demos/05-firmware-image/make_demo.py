"""Regenerate demos/05-firmware-image/firmware.bin deterministically.

Simulates an IoT/router firmware blob. Vendor firmware routinely concatenates a
boot logo (GIF), a packed root filesystem (GZIP), an embedded SQLite settings
DB, and an ELF userland binary into one flashable image with 0xFF erase-padding
between regions. Standard library only; the ELF is a truncated, inert header.
"""
import gzip
import io
import os


def _gif() -> bytes:
    # Tiny valid 1x1 GIF89a with proper trailer (0x00 0x3B).
    return (
        b"GIF89a"
        b"\x01\x00\x01\x00\x80\x00\x00"
        b"\x00\x00\x00\xff\xff\xff"
        b"\x21\xf9\x04\x00\x00\x00\x00\x00"
        b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        b"\x02\x02\x44\x01\x00"
        b"\x3b"
    )


def _gzip() -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(b"#!/bin/sh\n# squashfs placeholder rootfs\nexit 0\n")
    return buf.getvalue()


def _sqlite() -> bytes:
    # Real SQLite file header magic + a minimal (inert) page-1 remainder.
    header = b"SQLite format 3\x00"
    return header + bytes(100 - len(header)) + bytes(412)


def _elf_stub() -> bytes:
    # ELF64 LSB executable header (e_ident + a plausible header tail). Inert.
    e_ident = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    rest = bytes(48)  # zeroed remainder of the 64-byte ehdr
    return e_ident + rest


def build() -> bytes:
    erase = b"\xff" * 512  # NOR-flash erase padding
    parts = [erase, _gif(), erase, _gzip(), erase, _sqlite(), erase, _elf_stub(), erase]
    return b"".join(parts)


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "firmware.bin")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
