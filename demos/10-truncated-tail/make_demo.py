"""Regenerate demos/10-truncated-tail/partial.bin deterministically.

Simulates a partial/corrupt acquisition: a PNG whose footer (IEND) was lost
because the capture was cut short. With no footer and no length field, filecarve
falls back to its bounded carve and FLAGS the result as truncated (method=
bounded, the `*` / &#9888; marker) so an analyst knows the recovered bytes may be
incomplete. Demonstrates honest handling of imperfect evidence. Stdlib only.
"""
import os
import struct
import zlib


def _png_no_footer() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00" + b"\x33\x66\x99" * 16)
    # Deliberately OMIT the IEND chunk -> no footer to find.
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat)


def build() -> bytes:
    lead = bytes(range(256))  # deterministic non-magic lead-in
    # PNG with missing footer, then the stream ends abruptly (truncated tail).
    return lead + _png_no_footer() + b"\x10\x20\x30\x40\x50\x60"


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "partial.bin")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
