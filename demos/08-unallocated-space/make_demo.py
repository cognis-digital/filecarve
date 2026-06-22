"""Regenerate demos/08-unallocated-space/unallocated.raw deterministically.

Simulates a chunk of unallocated disk space dd'd from a drive image. Deleted
files leave their content behind until overwritten; here a GIF and a BMP survive
in slack/unallocated clusters with no filesystem metadata pointing at them. The
BMP carve is resolved by its in-header file-size field (method=length); the GIF
by its trailer. Standard library only.
"""
import os
import struct


def _gif() -> bytes:
    return (
        b"GIF89a"
        b"\x02\x00\x02\x00\x80\x00\x00"
        b"\x00\x00\x00\xff\xff\xff"
        b"\x21\xf9\x04\x00\x00\x00\x00\x00"
        b"\x2c\x00\x00\x00\x00\x02\x00\x02\x00\x00"
        b"\x02\x03\x44\x02\x00"
        b"\x3b"
    )


def _bmp() -> bytes:
    # 2x2 24-bit BMP with a correct 4-byte little-endian file size at offset 2,
    # so filecarve resolves the exact length from the header (method=length).
    pixel = b"\x00\x00\xff" * 4  # 2x2 red (no row padding needed for 2px width*3=6 -> pad to 8)
    pixel_padded = (b"\x00\x00\xff\x00\x00\xff\x00\x00" * 2)  # 8 bytes/row * 2 rows
    data_off = 54
    size = data_off + len(pixel_padded)
    fileheader = b"BM" + struct.pack("<IHHI", size, 0, 0, data_off)
    infoheader = struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, len(pixel_padded), 2835, 2835, 0, 0)
    return fileheader + infoheader + pixel_padded


def build() -> bytes:
    slack = b"\x00" * 600 + bytes(range(256))  # deterministic cluster slack
    parts = [slack, _gif(), slack, _bmp(), slack]
    return b"".join(parts)


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "unallocated.raw")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
