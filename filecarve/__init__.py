"""FILECARVE - carve embedded files from a blob by magic-byte signatures.

Defensive forensics utility (spirit of scalpel/foremost). Operates on artifacts
you own: disk images, memory dumps, packet captures, unknown blobs. Recovers
hidden/embedded files by scanning for known magic-byte headers (and footers
where available), then writes carved candidates to an output directory and/or
emits a report.

Standard library only. Python 3.10+.
"""
from .core import (
    Signature,
    Carved,
    SIGNATURES,
    scan,
    carve,
    sha256_of,
)

TOOL_NAME = "FILECARVE"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Signature",
    "Carved",
    "SIGNATURES",
    "scan",
    "carve",
    "sha256_of",
]
