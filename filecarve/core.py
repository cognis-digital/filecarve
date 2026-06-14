"""Core carving engine for FILECARVE.

The engine scans a byte blob for known file *signatures* (magic bytes). Each
signature optionally declares a footer (end marker) and/or a length-computing
function derived from the file's own header. When neither is available we fall
back to a bounded maximum carve size so a single hit cannot eat the whole blob.

Nothing here touches the network. All logic is real and self-contained.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

TOOL_NAME = "FILECARVE"
TOOL_VERSION = "0.1.0"


# --- length resolvers -------------------------------------------------------
# Given the full blob and the start offset of a header, return the carved
# length in bytes, or None if it cannot be determined from the header alone.

def _len_bmp(blob: bytes, start: int) -> Optional[int]:
    # BMP header: 'BM' + 4-byte little-endian file size at offset 2.
    if start + 6 > len(blob):
        return None
    size = struct.unpack_from("<I", blob, start + 2)[0]
    if 14 <= size <= (len(blob) - start):
        return size
    return None


def _len_riff(blob: bytes, start: int) -> Optional[int]:
    # RIFF (wav/avi/webp): 'RIFF' + 4-byte LE chunk size, total = size + 8.
    if start + 8 > len(blob):
        return None
    size = struct.unpack_from("<I", blob, start + 4)[0]
    total = size + 8
    if 8 < total <= (len(blob) - start):
        return total
    return None


def _len_gif(blob: bytes, start: int) -> Optional[int]:
    # GIF terminates with the trailer 0x3B after the last block. Scan forward
    # for the trailer that is preceded by a block terminator (0x00 0x3B is the
    # canonical end). Fall back to last 0x3B in window.
    window = blob[start : start + 50_000_000]
    idx = window.rfind(b"\x00\x3b")
    if idx != -1:
        return idx + 2
    return None


# --- signature model --------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    name: str
    ext: str
    header: bytes
    footer: Optional[bytes] = None
    footer_inclusive: bool = True
    length_fn: Optional[Callable[[bytes, int], Optional[int]]] = field(default=None, repr=False)
    max_size: int = 25_000_000  # bounded fallback so one hit can't eat the blob
    severity: str = "info"      # info|low|medium|high — analyst triage hint
    header_offset: int = 0      # bytes from match start to true file start


@dataclass
class Carved:
    name: str
    ext: str
    offset: int          # offset of file start within the blob
    size: int
    sha256: str
    severity: str
    method: str          # how the end was determined: footer|length|bounded
    truncated: bool      # True if bounded fallback may have cut the file short
    data: bytes = field(repr=False, default=b"")

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "ext": self.ext,
            "offset": self.offset,
            "size": self.size,
            "sha256": self.sha256,
            "severity": self.severity,
            "method": self.method,
            "truncated": self.truncated,
        }


# --- signature database -----------------------------------------------------
# Curated, conservative set. Header bytes chosen to minimise false positives.

SIGNATURES: list[Signature] = [
    Signature("JPEG image", "jpg", b"\xff\xd8\xff", footer=b"\xff\xd9",
              footer_inclusive=True, severity="low"),
    Signature("PNG image", "png", b"\x89PNG\r\n\x1a\n",
              footer=b"IEND\xaeB`\x82", footer_inclusive=True, severity="low"),
    Signature("GIF image", "gif", b"GIF89a", length_fn=_len_gif, severity="low"),
    Signature("GIF image", "gif", b"GIF87a", length_fn=_len_gif, severity="low"),
    Signature("BMP image", "bmp", b"BM", length_fn=_len_bmp, severity="low"),
    Signature("PDF document", "pdf", b"%PDF-", footer=b"%%EOF",
              footer_inclusive=True, severity="medium"),
    Signature("ZIP / Office / JAR", "zip", b"PK\x03\x04",
              footer=b"PK\x05\x06", footer_inclusive=True, severity="medium"),
    Signature("GZIP stream", "gz", b"\x1f\x8b\x08", severity="medium"),
    Signature("RAR archive", "rar", b"Rar!\x1a\x07\x00", severity="high"),
    Signature("RAR5 archive", "rar", b"Rar!\x1a\x07\x01\x00", severity="high"),
    Signature("7-Zip archive", "7z", b"7z\xbc\xaf\x27\x1c", severity="high"),
    Signature("ELF executable", "elf", b"\x7fELF", severity="high"),
    Signature("Windows PE/EXE", "exe", b"MZ", severity="high"),
    Signature("RIFF (wav/avi/webp)", "riff", b"RIFF", length_fn=_len_riff,
              severity="low"),
    Signature("SQLite database", "sqlite", b"SQLite format 3\x00",
              severity="medium"),
    Signature("PCAP capture", "pcap", b"\xd4\xc3\xb2\xa1", severity="medium"),
]

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_end(blob: bytes, sig: Signature, start: int) -> tuple[int, str, bool]:
    """Return (end_offset_exclusive, method, truncated) for a header at start."""
    n = len(blob)
    if sig.length_fn is not None:
        length = sig.length_fn(blob, start)
        if length is not None and length > 0:
            return min(start + length, n), "length", False
    if sig.footer is not None:
        fidx = blob.find(sig.footer, start + len(sig.header))
        if fidx != -1:
            end = fidx + (len(sig.footer) if sig.footer_inclusive else 0)
            return min(end, n), "footer", False
    # bounded fallback
    end = min(start + sig.max_size, n)
    truncated = (start + sig.max_size) < n
    return end, "bounded", truncated


def scan(
    blob: bytes,
    signatures: Optional[list[Signature]] = None,
    types: Optional[set[str]] = None,
    min_size: int = 1,
) -> list[Carved]:
    """Scan blob and return carved candidates sorted by offset.

    `types` optionally restricts to extensions (e.g. {"jpg", "pdf"}).
    Overlapping hits of the *same* signature are skipped: once a region is
    carved we advance past its start to avoid re-reporting nested headers of
    the identical type, while still allowing different types to overlap
    (e.g. a PNG embedded inside a ZIP).

    Raises:
        TypeError: if ``blob`` is not a :class:`bytes` object.
        ValueError: if ``min_size`` is less than 1.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError(
            f"scan() expects bytes, got {type(blob).__name__}"
        )
    if min_size < 1:
        raise ValueError(f"min_size must be >= 1, got {min_size}")
    sigs = signatures if signatures is not None else SIGNATURES
    if types is not None:
        sigs = [s for s in sigs if s.ext in types]

    results: list[Carved] = []
    for sig in sigs:
        pos = 0
        # track consumed regions per-signature to skip self-overlap
        consumed_until = -1
        while True:
            idx = blob.find(sig.header, pos)
            if idx == -1:
                break
            start = idx + sig.header_offset
            if start < 0:
                pos = idx + 1
                continue
            if start <= consumed_until:
                pos = idx + 1
                continue
            end, method, truncated = _resolve_end(blob, sig, start)
            size = end - start
            if size >= min_size:
                data = blob[start:end]
                results.append(
                    Carved(
                        name=sig.name,
                        ext=sig.ext,
                        offset=start,
                        size=size,
                        sha256=sha256_of(data),
                        severity=sig.severity,
                        method=method,
                        truncated=truncated,
                        data=data,
                    )
                )
                consumed_until = end - 1
                pos = max(idx + 1, end)
            else:
                pos = idx + 1
    results.sort(key=lambda c: (c.offset, -_SEVERITY_RANK.get(c.severity, 0)))
    return results


def carve(
    blob: bytes,
    out_dir: str,
    signatures: Optional[list[Signature]] = None,
    types: Optional[set[str]] = None,
    min_size: int = 1,
) -> list[Carved]:
    """Scan and write carved files to out_dir. Returns the carved list.

    Filenames are deterministic: <index>_<offset>.<ext>.

    Raises:
        TypeError: if ``blob`` is not bytes.
        ValueError: if ``min_size`` is less than 1 or ``out_dir`` is empty.
        OSError: if the output directory cannot be created or files cannot
            be written.
    """
    import os

    if not out_dir or not out_dir.strip():
        raise ValueError("out_dir must not be empty")
    found = scan(blob, signatures=signatures, types=types, min_size=min_size)
    os.makedirs(out_dir, exist_ok=True)
    for i, c in enumerate(found):
        fname = f"{i:05d}_{c.offset:08x}.{c.ext}"
        path = os.path.join(out_dir, fname)
        with open(path, "wb") as fh:
            fh.write(c.data)
    return found
