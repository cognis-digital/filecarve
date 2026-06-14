"""Smoke tests for FILECARVE. Standard library only, no network."""
import io
import os
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from filecarve import TOOL_NAME, TOOL_VERSION, scan, carve, sha256_of  # noqa: E402
from filecarve.cli import main, _render_html, _render_json  # noqa: E402


def _png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ, data):
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _pdf() -> bytes:
    return b"%PDF-1.4\nstuff\n%%EOF"


def _zip() -> bytes:
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hi")
    return buf.getvalue()


def _blob() -> bytes:
    pad = bytes(range(256))
    return pad + _png() + pad + _pdf() + pad + _zip() + pad


class TestCore(unittest.TestCase):
    def test_meta(self):
        self.assertEqual(TOOL_NAME, "FILECARVE")
        self.assertTrue(TOOL_VERSION)

    def test_finds_embedded_types(self):
        found = scan(_blob())
        exts = {c.ext for c in found}
        self.assertIn("png", exts)
        self.assertIn("pdf", exts)
        self.assertIn("zip", exts)

    def test_png_roundtrips_exactly(self):
        png = _png()
        blob = b"\x00\x01" + png + b"\x02\x03"
        found = [c for c in scan(blob) if c.ext == "png"]
        self.assertEqual(len(found), 1)
        c = found[0]
        self.assertEqual(c.data, png)
        self.assertEqual(c.method, "footer")
        self.assertEqual(c.sha256, sha256_of(png))
        self.assertFalse(c.truncated)

    def test_pdf_footer_inclusive(self):
        pdf = _pdf()
        found = [c for c in scan(pdf) if c.ext == "pdf"]
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].data.endswith(b"%%EOF"))

    def test_type_filter(self):
        found = scan(_blob(), types={"pdf"})
        self.assertTrue(found)
        self.assertTrue(all(c.ext == "pdf" for c in found))

    def test_min_size(self):
        found = scan(_blob(), min_size=10_000_000)
        self.assertEqual(found, [])

    def test_empty_blob_no_findings(self):
        self.assertEqual(scan(b""), [])

    def test_sorted_by_offset(self):
        found = scan(_blob())
        offs = [c.offset for c in found]
        self.assertEqual(offs, sorted(offs))

    def test_carve_writes_files(self):
        with tempfile.TemporaryDirectory() as d:
            found = carve(_blob(), d)
            self.assertTrue(found)
            files = os.listdir(d)
            self.assertEqual(len(files), len(found))
            for f in files:
                self.assertGreater(os.path.getsize(os.path.join(d, f)), 0)


class TestRenderers(unittest.TestCase):
    def test_json_valid(self):
        import json
        out = _render_json(scan(_blob()), "x")
        data = json.loads(out)
        self.assertEqual(data["tool"], "FILECARVE")
        self.assertEqual(data["total"], len(data["findings"]))
        self.assertGreater(data["total"], 0)

    def test_html_self_contained(self):
        out = _render_html(scan(_blob()), "x")
        self.assertIn("<!doctype html>", out)
        self.assertIn("<style>", out)
        self.assertIn("FILECARVE", out)
        self.assertNotIn("http://", out)
        self.assertNotIn("https://", out)


class TestCli(unittest.TestCase):
    def _write(self, data):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(os.remove, path)
        return path

    def test_scan_exit_findings(self):
        path = self._write(_blob())
        self.assertEqual(main(["scan", path]), 1)  # findings -> 1

    def test_scan_clean_exit_zero(self):
        path = self._write(b"no magic here, just text padding" * 4)
        self.assertEqual(main(["scan", path]), 0)

    def test_missing_file_exit_2(self):
        self.assertEqual(main(["scan", "/no/such/file/here.bin"]), 2)

    def test_carve_subcommand(self):
        path = self._write(_blob())
        with tempfile.TemporaryDirectory() as d:
            rc = main(["carve", path, "-o", d])
            self.assertEqual(rc, 1)
            self.assertTrue(os.listdir(d))

    def test_html_report_to_file(self):
        path = self._write(_blob())
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.html")
            rc = main(["scan", path, "--format", "html", "-r", report])
            self.assertEqual(rc, 1)
            with open(report, encoding="utf-8") as fh:
                self.assertIn("<!doctype html>", fh.read())


class TestHardening(unittest.TestCase):
    """Tests for the hardened input-validation and error-handling paths."""

    # --- core.scan() ---

    def test_scan_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            scan("not bytes")  # type: ignore[arg-type]

    def test_scan_none_raises_type_error(self):
        with self.assertRaises(TypeError):
            scan(None)  # type: ignore[arg-type]

    def test_scan_min_size_zero_raises_value_error(self):
        with self.assertRaises(ValueError):
            scan(b"\x00", min_size=0)

    def test_scan_min_size_negative_raises_value_error(self):
        with self.assertRaises(ValueError):
            scan(b"\xff\xd8\xff" + b"\x00" * 10, min_size=-5)

    def test_scan_bytearray_accepted(self):
        # bytearray is a valid bytes-like object
        result = scan(bytearray(b"\x00" * 16))
        self.assertIsInstance(result, list)

    # --- core.carve() ---

    def test_carve_empty_out_dir_raises_value_error(self):
        with self.assertRaises(ValueError):
            carve(b"\x00", "")

    def test_carve_whitespace_out_dir_raises_value_error(self):
        with self.assertRaises(ValueError):
            carve(b"\x00", "   ")

    # --- CLI ---

    def test_cli_min_size_zero_exits_2(self):
        """--min-size 0 is rejected before any I/O (argparse exits with 2)."""
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(b"\x00" * 8)
            # argparse raises SystemExit(2) for type-validation errors
            with self.assertRaises(SystemExit) as ctx:
                main(["--min-size", "0", "scan", path])
            self.assertEqual(ctx.exception.code, 2)
        finally:
            os.remove(path)

    def test_cli_min_size_negative_exits_2(self):
        """Negative --min-size is rejected by the argparse type converter."""
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(b"\x00" * 8)
            with self.assertRaises(SystemExit) as ctx:
                main(["--min-size", "-5", "scan", path])
            self.assertEqual(ctx.exception.code, 2)
        finally:
            os.remove(path)

    def test_mcp_server_importable(self):
        """mcp_server must import without raising (the broken to_json is fixed)."""
        import importlib
        mod = importlib.import_module("filecarve.mcp_server")
        self.assertTrue(callable(mod.serve))


class TestWebhook(unittest.TestCase):
    """Tests for webhook.py input validation (no network required)."""

    def _run_webhook(self, args, stdin_bytes=b"{}"):
        """Helper: invoke webhook.main() with patched argv and stdin."""
        import importlib
        import io
        wh = importlib.import_module("integrations.webhook")
        old_argv = sys.argv
        old_stdin = sys.stdin.buffer
        sys.argv = ["webhook"] + args
        sys.stdin = type("_FakeStdin", (), {"buffer": io.BytesIO(stdin_bytes)})()
        try:
            return wh.main()
        finally:
            sys.argv = old_argv
            sys.stdin = type("_RestoreStdin", (), {"buffer": old_stdin})()

    def test_bad_url_scheme_exits_2(self):
        rc = self._run_webhook(["--url", "ftp://example.com"])
        self.assertEqual(rc, 2)

    def test_empty_stdin_exits_2(self):
        rc = self._run_webhook(["--url", "https://example.com"], stdin_bytes=b"")
        self.assertEqual(rc, 2)

    def test_malformed_header_exits_2(self):
        # Header with no key (starts with colon)
        rc = self._run_webhook(
            ["--url", "https://example.com", "--header", ": value"],
            stdin_bytes=b"{}",
        )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
