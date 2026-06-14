"""FILECARVE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from filecarve.core import scan


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
    def filecarve_scan(target: str) -> str:
        """Carve embedded files from a blob by magic-byte signatures.

        ``target`` must be a file path.  Returns JSON findings.
        """
        try:
            with open(target, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            return json.dumps({"error": f"cannot read {target}: {exc}"})
        try:
            findings = scan(blob)
        except (TypeError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(
            {"total": len(findings), "findings": [c.as_dict() for c in findings]},
            indent=2,
        )

    app.run()
    return 0
