"""FILECARVE MCP server — exposes scan() as an MCP tool for Cognis.Studio.

Passive/offline: the tool only reads a local file path you pass it and carves
in memory. It never opens a network socket. Defensive / authorized-use only.
"""
from __future__ import annotations

import json

from filecarve.core import scan


def _scan_path_to_json(target: str, min_size: int = 1) -> str:
    """Read a local file, carve it, and return the findings as JSON text."""
    with open(target, "rb") as fh:
        blob = fh.read()
    found = scan(blob, min_size=min_size)
    counts: dict[str, int] = {}
    for c in found:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    return json.dumps(
        {
            "tool": "FILECARVE",
            "source": target,
            "total": len(found),
            "severity_counts": counts,
            "findings": [c.as_dict() for c in found],
        },
        indent=2,
    )


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:

        pip install "cognis-filecarve[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-filecarve[mcp]'")
        return 1
    app = FastMCP("filecarve")

    @app.tool()
    def filecarve_scan(target: str, min_size: int = 1) -> str:
        """Carve embedded files from a local blob/image by magic-byte signature.

        `target` is a path to a file you own or are authorized to examine.
        Returns JSON findings (offset, size, sha256, severity, method).
        """
        return _scan_path_to_json(target, min_size=min_size)

    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(serve())
