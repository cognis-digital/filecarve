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


if __name__ == "__main__":
    unittest.main()
