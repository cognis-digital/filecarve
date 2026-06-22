"""Regenerate demos/06-pcap-exfil/capture.bin deterministically.

Simulates a raw packet-capture artifact saved off the wire (a PCAP file) that
itself carries a reassembled PDF and JPEG transferred over the session — the
classic "data exfiltrated as files inside captured traffic" case. filecarve
recovers both the PCAP container and the inner documents. Standard library only.
"""
import os
import struct
import zlib


def _pcap_header() -> bytes:
    # Classic libpcap global header: magic d4c3b2a1 (LE), v2.4, snaplen, LINKTYPE_ETHERNET(1)
    magic = b"\xd4\xc3\xb2\xa1"
    return magic + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)


def _jpeg() -> bytes:
    # Minimal JPEG: SOI + APP0/JFIF + EOI. Real markers, inert pixel content.
    soi = b"\xff\xd8\xff"
    app0 = b"\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    eoi = b"\xff\xd9"
    return soi + app0 + b"\x00" * 16 + eoi


def _pdf() -> bytes:
    return (
        b"%PDF-1.5\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 0>>endobj\n"
        b"trailer<</Root 1 0 R>>\n"
        b"%%EOF"
    )


def build() -> bytes:
    # PCAP container header, then "packet payload" bytes that reassemble into a
    # JPEG and a PDF (as a forensic tool would recover from the byte stream).
    pad = struct.pack("<I", 0xDEADBEEF) * 8  # deterministic non-magic filler
    parts = [_pcap_header(), pad, _jpeg(), pad, _pdf(), pad]
    return b"".join(parts)


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "capture.bin")
    with open(out, "wb") as fh:
        fh.write(build())
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
