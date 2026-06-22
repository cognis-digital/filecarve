"""Regenerate demos/09-email-attachments/mailbox.bin deterministically.

Simulates the raw bytes of a decoded mailbox region (an mbox slice after base64
attachment decoding) holding two recovered attachments: an invoice PDF and a
photo PNG. Recovering attachments straight from a mail spool — without parsing
MIME — is a common DFIR shortcut. Standard library only.
"""
import os
import struct
import zlib


def _pdf() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 0>>endobj\n"
        b"3 0 obj<</Length 20>>stream\nINVOICE 0042 PAID\nendstream endobj\n"
        b"trailer<</Root 1 0 R>>\n"
        b"%%EOF"
    )


def _png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 3, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33")
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def build() -> bytes:
    # mbox-ish text framing between the two decoded attachment byte runs.
    h1 = b"From sender@example.com Mon Jun 01 09:14:00 2026\nSubject: Invoice\n\n"
    h2 = b"\n--boundary\nContent-Type: image/png\n\n"
    tail = b"\n--boundary--\n"
    return h1 + _pdf() + h2 + _png() + tail


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "mailbox.bin")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
