"""Command-line interface for FILECARVE.

Subcommands:
  scan   <blob>            list carved candidates (no files written)
  carve  <blob> -o <dir>   write carved files to a directory

Global:
  --version
  --format {table,json,html}
  --type   repeatable extension filter (e.g. --type jpg --type pdf)
  --min-size bytes

Exit codes: 0 = clean (no findings), 1 = findings present, 2 = error.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Carved, carve, scan

_SEV_COLOR = {
    "info": "#6b7280",
    "low": "#2563eb",
    "medium": "#d97706",
    "high": "#dc2626",
}


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.0f}{unit}" if unit == "B" else f"{f:.1f}{unit}"
        f /= 1024
    return f"{n}B"


def _render_table(found: list[Carved], src: str) -> str:
    lines = [f"{TOOL_NAME} {TOOL_VERSION} — source: {src}", ""]
    if not found:
        lines.append("No embedded files detected.")
        return "\n".join(lines)
    header = f"{'#':>3}  {'OFFSET':>10}  {'SIZE':>9}  {'SEV':<7} {'METHOD':<8} {'EXT':<6} NAME"
    lines.append(header)
    lines.append("-" * len(header))
    for i, c in enumerate(found):
        flag = "*" if c.truncated else " "
        lines.append(
            f"{i:>3}  0x{c.offset:08x}  {_human(c.size):>9}  "
            f"{c.severity:<7} {c.method:<8} {c.ext:<6} {c.name}{flag}"
        )
    counts: dict[str, int] = {}
    for c in found:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    lines.append("")
    lines.append(f"{len(found)} file(s) carved  [{summary}]  (* = bounded/truncated)")
    return "\n".join(lines)


def _render_json(found: list[Carved], src: str) -> str:
    counts: dict[str, int] = {}
    for c in found:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "source": src,
        "total": len(found),
        "severity_counts": counts,
        "findings": [c.as_dict() for c in found],
    }
    return json.dumps(payload, indent=2)


def _render_html(found: list[Carved], src: str) -> str:
    counts: dict[str, int] = {}
    for c in found:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    rows = []
    for i, c in enumerate(found):
        color = _SEV_COLOR.get(c.severity, "#6b7280")
        rows.append(
            "<tr>"
            f"<td>{i}</td>"
            f"<td class='mono'>0x{c.offset:08x}</td>"
            f"<td class='mono'>{_human(c.size)}</td>"
            f"<td><span class='pill' style='background:{color}'>{html.escape(c.severity)}</span></td>"
            f"<td>{html.escape(c.method)}{' &#9888;' if c.truncated else ''}</td>"
            f"<td class='mono'>{html.escape(c.ext)}</td>"
            f"<td>{html.escape(c.name)}</td>"
            f"<td class='mono small'>{html.escape(c.sha256)}</td>"
            "</tr>"
        )
    summary_cells = "".join(
        f"<div class='card' style='border-left:6px solid {_SEV_COLOR.get(k, \"#6b7280\")}'>"
        f"<div class='big'>{v}</div><div class='lbl'>{html.escape(k)}</div></div>"
        for k, v in sorted(counts.items(), key=lambda kv: kv[0])
    ) or "<div class='card'><div class='big'>0</div><div class='lbl'>findings</div></div>"
    body_rows = "\n".join(rows) or "<tr><td colspan='8'>No embedded files detected.</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#0f172a; color:#e2e8f0; }}
  header {{ padding: 22px 28px; background:#1e293b; border-bottom:1px solid #334155; }}
  h1 {{ margin:0; font-size:20px; letter-spacing:1px; }}
  .sub {{ color:#94a3b8; font-size:13px; margin-top:4px; word-break:break-all; }}
  .cards {{ display:flex; gap:14px; flex-wrap:wrap; padding:20px 28px; }}
  .card {{ background:#1e293b; border-radius:10px; padding:14px 20px; min-width:90px; }}
  .big {{ font-size:28px; font-weight:700; }}
  .lbl {{ color:#94a3b8; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  table {{ border-collapse:collapse; width:calc(100% - 56px); margin:0 28px 28px; background:#1e293b; border-radius:10px; overflow:hidden; }}
  th, td {{ text-align:left; padding:9px 12px; border-bottom:1px solid #334155; font-size:13px; }}
  th {{ background:#0b1220; color:#94a3b8; text-transform:uppercase; font-size:11px; letter-spacing:.5px; }}
  tr:hover td {{ background:#243044; }}
  .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; }}
  .small {{ font-size:11px; color:#94a3b8; }}
  .pill {{ color:#fff; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:600; text-transform:uppercase; }}
  footer {{ color:#64748b; font-size:12px; padding:0 28px 28px; }}
</style></head>
<body>
<header>
  <h1>{TOOL_NAME} <span style="color:#64748b;font-size:13px">v{TOOL_VERSION}</span></h1>
  <div class="sub">source: {html.escape(src)} &middot; {len(found)} embedded file(s) carved</div>
</header>
<div class="cards">{summary_cells}</div>
<table>
  <thead><tr><th>#</th><th>Offset</th><th>Size</th><th>Severity</th><th>Method</th><th>Ext</th><th>Type</th><th>SHA-256</th></tr></thead>
  <tbody>
{body_rows}
  </tbody>
</table>
<footer>&#9888; in Method column marks bounded/possibly-truncated carves (no footer/length found). Defensive forensics — analyze artifacts you own.</footer>
</body></html>
"""


def _read_blob(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="filecarve",
        description=f"{TOOL_NAME} — carve embedded files from a blob by magic-byte signatures.",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json", "html"], default="table",
                   help="output format (default: table)")
    p.add_argument("--type", action="append", dest="types", metavar="EXT",
                   help="restrict to extension (repeatable), e.g. --type jpg")
    p.add_argument("--min-size", type=int, default=1, metavar="N",
                   help="ignore carves smaller than N bytes")
    p.add_argument("-r", "--report", metavar="PATH",
                   help="write the formatted report to PATH instead of stdout")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp_scan = sub.add_parser("scan", help="list carved candidates (writes no files)")
    sp_scan.add_argument("blob", help="input file, or - for stdin")

    sp_carve = sub.add_parser("carve", help="carve and write files to a directory")
    sp_carve.add_argument("blob", help="input file, or - for stdin")
    sp_carve.add_argument("-o", "--out", required=True, metavar="DIR",
                          help="output directory for carved files")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    types = set(t.lower() for t in args.types) if args.types else None

    try:
        blob = _read_blob(args.blob)
    except OSError as e:
        print(f"{TOOL_NAME}: cannot read {args.blob}: {e}", file=sys.stderr)
        return 2

    try:
        if args.cmd == "carve":
            found = carve(blob, args.out, types=types, min_size=args.min_size)
        else:
            found = scan(blob, types=types, min_size=args.min_size)
    except Exception as e:  # pragma: no cover - defensive
        print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2

    src = args.blob if args.blob != "-" else "<stdin>"
    if args.format == "json":
        out = _render_json(found, src)
    elif args.format == "html":
        out = _render_html(found, src)
    else:
        out = _render_table(found, src)

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(out)
        except OSError as e:
            print(f"{TOOL_NAME}: cannot write report {args.report}: {e}", file=sys.stderr)
            return 2
        print(f"{TOOL_NAME}: report written to {args.report} ({len(found)} finding(s))")
    else:
        print(out)

    if args.cmd == "carve" and not args.report:
        print(f"\nCarved {len(found)} file(s) to {args.out}", file=sys.stderr)

    # non-zero exit when findings present (pipeline-friendly)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
