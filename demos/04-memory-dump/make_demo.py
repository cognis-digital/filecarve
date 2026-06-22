"""Regenerate demos/04-memory-dump/memory.dmp deterministically.

Simulates a small slice of a process memory dump in which a screenshot (PNG),
a config archive (ZIP) and a Windows executable image (PE/MZ) are resident in
RAM among non-magic heap padding. Standard library only; no real malware — the
"executable" is a minimal, inert MZ stub.
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

    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)  # 2x2 RGB
    raw = b"\x00\x10\x20\x30\x40\x50\x00\x60\x70\x80\x90\xa0"
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.ini", b"[agent]\nbeacon=300\njitter=20\n")
    return buf.getvalue()


def _mz_stub() -> bytes:
    # Minimal, inert DOS/PE stub: 'MZ' header + classic "cannot be run in DOS"
    # message. Not executable malware — just enough bytes to trip the MZ rule.
    msg = b"This program cannot be run in DOS mode.\r\n$"
    stub = b"MZ" + b"\x90\x00" * 7 + msg
    return stub + bytes(64 - (len(stub) % 64))


def build() -> bytes:
    heap = bytes([0xCC]) * 800 + bytes(range(256)) * 2  # deterministic non-magic
    parts = [heap, _png(), heap, _zip(), heap, _mz_stub(), heap]
    return b"".join(parts)


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "memory.dmp")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
