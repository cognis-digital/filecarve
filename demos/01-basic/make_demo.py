"""Regenerate demos/01-basic/evidence.blob deterministically.

Builds a single blob that embeds a real PNG, PDF, ZIP and GZIP separated by
deterministic padding, so FILECARVE has genuine signatures to recover.
Standard library only.
"""
import io
import os
import struct
import zipfile
import zlib


def _png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # 1x1 RGB
    raw = b"\x00\xff\x00\x00"  # one filtered scanline
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _pdf() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 0>>endobj\n"
        b"trailer<</Root 1 0 R>>\n"
        b"%%EOF"
    )


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hidden.txt", b"this file was hidden inside a blob\n")
    return buf.getvalue()


def _gzip() -> bytes:
    import gzip
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(b"secret gzip payload\n")
    return buf.getvalue()


def build() -> bytes:
    pad = bytes(range(256)) * 4  # 1 KB of deterministic non-magic padding
    parts = [pad, _png(), pad, _pdf(), pad, _zip(), pad, _gzip(), pad]
    return b"".join(parts)


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "evidence.blob")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
