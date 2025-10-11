"""FILECARVE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from filecarve.core import scan, to_json

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
        """Carve embedded files from a blob by magic-byte signatures. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
