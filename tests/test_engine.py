"""Extended engine, renderer, CLI and demo tests for FILECARVE.

Standard library only, no network. Every test runs offline and operates on
in-memory fixtures or the committed demo artifacts. Defensive / authorized-use
forensics only.
"""
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from filecarve import TOOL_NAME, TOOL_VERSION  # noqa: E402
from filecarve.core import (  # noqa: E402
    SIGNATURES,
    Carved,
    Signature,
    carve,
    scan,
    sha256_of,
    _len_bmp,
    _len_riff,
    _len_zip,
    _len_gif,
    _resolve_end,
)
from filecarve.cli import (  # noqa: E402
    build_parser,
    main,
    _human,
    _render_html,
    _render_json,
    _render_sarif,
    _render_table,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- fixtures ---------------------------------------------------------------

def _png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ, data):
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _jpeg() -> bytes:
    return b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00" + b"payload-bytes" + b"\xff\xd9"


def _pdf() -> bytes:
    return b"%PDF-1.4\nobjects here\n%%EOF"


def _gif() -> bytes:
    return b"GIF89a" + b"\x01\x00\x01\x00\x00" + b"\x21\xf9\x04" + b"image-data" + b"\x00\x3b"


def _bmp() -> bytes:
    body = b"X" * 10
    size = 2 + 4 + len(body)
    return b"BM" + struct.pack("<I", size) + body


def _riff() -> bytes:
    body = b"WAVEfmt payload"
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _zip(comment=b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("doc.txt", b"hello world")
        if comment:
            zf.comment = comment
    return buf.getvalue()


def _gz() -> bytes:
    return b"\x1f\x8b\x08" + b"\x00" * 7 + zlib.compress(b"data")[2:-4]


def _elf() -> bytes:
    return b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8 + b"machine code"


def _pe() -> bytes:
    return b"MZ" + b"\x90\x00\x03\x00" + b"this program cannot be run in DOS mode"


def _sqlite() -> bytes:
    return b"SQLite format 3\x00" + b"\x10\x00\x01\x01\x00\x40\x20\x20" + b"pagedata"


def _pcap() -> bytes:
    return b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1) + b"packet"


def _mixed() -> bytes:
    pad = bytes(range(256))
    return pad + _png() + pad + _pdf() + pad + _zip() + pad + _jpeg() + pad


# --- length resolvers -------------------------------------------------------

class TestLengthResolvers(unittest.TestCase):
    def test_bmp_length_exact(self):
        b = _bmp()
        self.assertEqual(_len_bmp(b, 0), len(b))

    def test_bmp_length_too_short(self):
        self.assertIsNone(_len_bmp(b"BM", 0))

    def test_bmp_length_rejects_oversize(self):
        # claimed size larger than available bytes -> None
        blob = b"BM" + struct.pack("<I", 1_000_000) + b"x"
        self.assertIsNone(_len_bmp(blob, 0))

    def test_riff_length_total_includes_8(self):
        r = _riff()
        self.assertEqual(_len_riff(r, 0), len(r))

    def test_riff_length_too_short(self):
        self.assertIsNone(_len_riff(b"RIFF", 0))

    def test_gif_length_finds_trailer(self):
        g = _gif()
        self.assertEqual(_len_gif(g, 0), len(g))

    def test_gif_length_none_without_trailer(self):
        self.assertIsNone(_len_gif(b"GIF89a no terminator here", 0))

    def test_zip_length_full_eocd(self):
        z = _zip()
        self.assertEqual(_len_zip(z, 0), len(z))

    def test_zip_length_includes_comment(self):
        z = _zip(comment=b"trailing-comment")
        self.assertEqual(_len_zip(z, 0), len(z))

    def test_zip_length_none_without_eocd(self):
        self.assertIsNone(_len_zip(b"PK\x03\x04 partial only", 0))


# --- _resolve_end semantics -------------------------------------------------

class TestResolveEnd(unittest.TestCase):
    def _sig(self, ext):
        return next(s for s in SIGNATURES if s.ext == ext)

    def test_footer_method_for_pdf(self):
        pdf = _pdf()
        end, method, trunc = _resolve_end(pdf, self._sig("pdf"), 0)
        self.assertEqual(method, "footer")
        self.assertFalse(trunc)
        self.assertEqual(end, len(pdf))

    def test_length_method_for_bmp(self):
        b = _bmp()
        end, method, trunc = _resolve_end(b, self._sig("bmp"), 0)
        self.assertEqual(method, "length")
        self.assertEqual(end, len(b))

    def test_bounded_method_for_gz(self):
        gz = _gz() + b"\x00" * 50
        end, method, trunc = _resolve_end(gz, self._sig("gz"), 0)
        self.assertEqual(method, "bounded")
        # whole remaining blob consumed when smaller than max_size
        self.assertEqual(end, len(gz))
        self.assertFalse(trunc)

    def test_bounded_truncation_flagged(self):
        sig = Signature("tiny", "bin", b"HDR", max_size=4)
        blob = b"HDR" + b"x" * 100
        end, method, trunc = _resolve_end(blob, sig, 0)
        self.assertEqual(method, "bounded")
        self.assertTrue(trunc)
        self.assertEqual(end, 4)


# --- core scan --------------------------------------------------------------

class TestScanCore(unittest.TestCase):
    def test_meta_identity(self):
        self.assertEqual(TOOL_NAME, "FILECARVE")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+")

    def test_signature_db_size(self):
        # 16 entries (two GIF variants share an ext) -> 14 distinct exts
        self.assertGreaterEqual(len(SIGNATURES), 16)
        exts = {s.ext for s in SIGNATURES}
        for must in {"jpg", "png", "gif", "bmp", "pdf", "zip", "gz",
                     "rar", "7z", "elf", "exe", "riff", "sqlite", "pcap"}:
            self.assertIn(must, exts)

    def test_each_signature_has_severity(self):
        for s in SIGNATURES:
            self.assertIn(s.severity, {"info", "low", "medium", "high"})

    def test_finds_all_core_types(self):
        exts = {c.ext for c in scan(_mixed())}
        for must in {"png", "pdf", "zip", "jpg"}:
            self.assertIn(must, exts)

    def test_png_byte_exact(self):
        png = _png()
        blob = b"\x00\x01" + png + b"\x02\x03"
        c = [c for c in scan(blob) if c.ext == "png"][0]
        self.assertEqual(c.data, png)
        self.assertEqual(c.offset, 2)
        self.assertEqual(c.size, len(png))
        self.assertEqual(c.method, "footer")
        self.assertFalse(c.truncated)

    def test_jpeg_footer(self):
        c = [c for c in scan(_jpeg()) if c.ext == "jpg"][0]
        self.assertTrue(c.data.endswith(b"\xff\xd9"))
        self.assertEqual(c.method, "footer")

    def test_pdf_footer_inclusive(self):
        c = [c for c in scan(_pdf()) if c.ext == "pdf"][0]
        self.assertTrue(c.data.endswith(b"%%EOF"))

    def test_gif_length(self):
        c = [c for c in scan(_gif()) if c.ext == "gif"][0]
        self.assertEqual(c.method, "length")
        self.assertTrue(c.data.endswith(b"\x3b"))

    def test_sqlite_high_severity_db(self):
        c = [c for c in scan(_sqlite()) if c.ext == "sqlite"][0]
        self.assertEqual(c.severity, "medium")

    def test_elf_and_pe_high_severity(self):
        elf = [c for c in scan(_elf()) if c.ext == "elf"][0]
        pe = [c for c in scan(_pe()) if c.ext == "exe"][0]
        self.assertEqual(elf.severity, "high")
        self.assertEqual(pe.severity, "high")

    def test_pcap_detected(self):
        self.assertTrue(any(c.ext == "pcap" for c in scan(_pcap())))

    def test_sha256_matches_data(self):
        for c in scan(_mixed()):
            self.assertEqual(c.sha256, sha256_of(c.data))
            self.assertEqual(len(c.sha256), 64)

    def test_results_sorted_by_offset(self):
        offs = [c.offset for c in scan(_mixed())]
        self.assertEqual(offs, sorted(offs))

    def test_type_filter_single(self):
        found = scan(_mixed(), types={"pdf"})
        self.assertTrue(found)
        self.assertTrue(all(c.ext == "pdf" for c in found))

    def test_type_filter_multi(self):
        found = scan(_mixed(), types={"pdf", "png"})
        exts = {c.ext for c in found}
        self.assertTrue(exts.issubset({"pdf", "png"}))
        self.assertIn("pdf", exts)
        self.assertIn("png", exts)

    def test_type_filter_unknown_ext_empty(self):
        self.assertEqual(scan(_mixed(), types={"docx"}), [])

    def test_min_size_filters(self):
        self.assertEqual(scan(_mixed(), min_size=10_000_000), [])

    def test_min_size_keeps_large(self):
        # everything is far below 10MB, but min_size=1 keeps all
        self.assertTrue(scan(_mixed(), min_size=1))

    def test_empty_blob(self):
        self.assertEqual(scan(b""), [])

    def test_no_magic_blob(self):
        self.assertEqual(scan(b"plain text with no magic bytes" * 8), [])

    def test_offset_nonzero_when_padded(self):
        pad = b"\x00" * 100
        c = [c for c in scan(pad + _png()) if c.ext == "png"][0]
        self.assertEqual(c.offset, 100)

    def test_as_dict_keys(self):
        c = scan(_png())[0]
        d = c.as_dict()
        self.assertEqual(set(d.keys()),
                         {"name", "ext", "offset", "size", "sha256",
                          "severity", "method", "truncated"})
        self.assertNotIn("data", d)  # raw bytes never serialized

    def test_custom_signature_list(self):
        sig = Signature("Custom marker", "cust", b"CUSTOMHDR", footer=b"END")
        blob = b"....CUSTOMHDR payload END...."
        found = scan(blob, signatures=[sig])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].ext, "cust")
        self.assertTrue(found[0].data.endswith(b"END"))


# --- ZIP integrity ----------------------------------------------------------

class TestZipIntegrity(unittest.TestCase):
    def test_carved_zip_reopens(self):
        zb = _zip()
        blob = b"\x00\x01\x02" + zb + b"\xaa\xbb"
        c = [c for c in scan(blob) if c.ext == "zip"][0]
        self.assertEqual(c.method, "length")
        zf = zipfile.ZipFile(io.BytesIO(c.data))
        self.assertEqual(zf.namelist(), ["doc.txt"])
        self.assertEqual(zf.read("doc.txt"), b"hello world")

    def test_carved_zip_preserves_comment(self):
        zb = _zip(comment=b"forensic-marker-1234")
        c = [c for c in scan(bytes(8) + zb + bytes(8)) if c.ext == "zip"][0]
        self.assertEqual(zipfile.ZipFile(io.BytesIO(c.data)).comment,
                         b"forensic-marker-1234")

    def test_polyglot_jpeg_zip(self):
        # a JPEG immediately followed by a ZIP — both must be carved
        blob = _jpeg() + _zip()
        exts = {c.ext for c in scan(blob)}
        self.assertIn("jpg", exts)
        self.assertIn("zip", exts)


# --- carve to disk ----------------------------------------------------------

class TestCarveToDisk(unittest.TestCase):
    def test_writes_one_file_per_finding(self):
        with tempfile.TemporaryDirectory() as d:
            found = carve(_mixed(), d)
            self.assertTrue(found)
            files = sorted(os.listdir(d))
            self.assertEqual(len(files), len(found))

    def test_written_bytes_match_data(self):
        with tempfile.TemporaryDirectory() as d:
            found = carve(_png(), d)
            f = os.listdir(d)[0]
            with open(os.path.join(d, f), "rb") as fh:
                self.assertEqual(fh.read(), found[0].data)

    def test_filename_encodes_offset_and_ext(self):
        with tempfile.TemporaryDirectory() as d:
            found = carve(b"\x00" * 16 + _png(), d)
            name = os.listdir(d)[0]
            self.assertTrue(name.endswith(".png"))
            self.assertIn(f"{found[0].offset:08x}", name)

    def test_carve_respects_type_filter(self):
        with tempfile.TemporaryDirectory() as d:
            carve(_mixed(), d, types={"pdf"})
            for f in os.listdir(d):
                self.assertTrue(f.endswith(".pdf"))

    def test_carve_creates_missing_dir(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "nested", "out")
            carve(_png(), target)
            self.assertTrue(os.path.isdir(target))


# --- renderers --------------------------------------------------------------

class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.found = scan(_mixed())

    def test_human_units(self):
        self.assertEqual(_human(512), "512B")
        self.assertTrue(_human(2048).endswith("KB"))
        self.assertTrue(_human(5 * 1024 * 1024).endswith("MB"))

    def test_table_has_header_and_summary(self):
        out = _render_table(self.found, "src.bin")
        self.assertIn(TOOL_NAME, out)
        self.assertIn("OFFSET", out)
        self.assertIn("file(s) carved", out)

    def test_table_empty(self):
        out = _render_table([], "x")
        self.assertIn("No embedded files detected.", out)

    def test_json_round_structure(self):
        data = json.loads(_render_json(self.found, "src.bin"))
        self.assertEqual(data["tool"], "FILECARVE")
        self.assertEqual(data["version"], TOOL_VERSION)
        self.assertEqual(data["source"], "src.bin")
        self.assertEqual(data["total"], len(self.found))
        self.assertEqual(len(data["findings"]), len(self.found))
        self.assertEqual(sum(data["severity_counts"].values()), len(self.found))

    def test_json_findings_have_required_fields(self):
        data = json.loads(_render_json(self.found, "x"))
        for f in data["findings"]:
            for k in ("name", "ext", "offset", "size", "sha256",
                      "severity", "method", "truncated"):
                self.assertIn(k, f)

    def test_json_empty(self):
        data = json.loads(_render_json([], "x"))
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["findings"], [])

    def test_html_self_contained(self):
        out = _render_html(self.found, "x")
        self.assertIn("<!doctype html>", out)
        self.assertIn("<style>", out)
        self.assertIn("FILECARVE", out)
        self.assertNotIn("http://", out)
        self.assertNotIn("https://", out)

    def test_html_escapes_source(self):
        out = _render_html(self.found, "<script>alert(1)</script>")
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_html_empty(self):
        out = _render_html([], "x")
        self.assertIn("No embedded files detected.", out)

    def test_sarif_schema_and_driver(self):
        sarif = json.loads(_render_sarif(self.found, "evidence.blob"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "FILECARVE")
        self.assertEqual(driver["version"], TOOL_VERSION)

    def test_sarif_results_map_to_findings(self):
        sarif = json.loads(_render_sarif(self.found, "evidence.blob"))
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), len(self.found))
        for r, c in zip(results, self.found):
            self.assertEqual(r["ruleId"], f"carve/{c.ext}")
            self.assertIn(r["level"], {"note", "warning", "error"})
            region = r["locations"][0]["physicalLocation"]["region"]
            self.assertEqual(region["byteOffset"], c.offset)
            self.assertEqual(region["byteLength"], c.size)
            self.assertEqual(r["partialFingerprints"]["sha256"], c.sha256)

    def test_sarif_rules_cover_exts(self):
        sarif = json.loads(_render_sarif(self.found, "x"))
        rule_ids = {ru["id"] for ru in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {f"carve/{c.ext}" for c in self.found})

    def test_sarif_level_mapping(self):
        sarif = json.loads(_render_sarif(self.found, "x"))
        for r, c in zip(sarif["runs"][0]["results"], self.found):
            expected = {"info": "note", "low": "note",
                        "medium": "warning", "high": "error"}[c.severity]
            self.assertEqual(r["level"], expected)

    def test_sarif_empty(self):
        sarif = json.loads(_render_sarif([], "x"))
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])


# --- CLI --------------------------------------------------------------------

class TestCli(unittest.TestCase):
    def _write(self, data):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(os.remove, path)
        return path

    def test_parser_builds(self):
        p = build_parser()
        self.assertIsNotNone(p)

    def test_scan_findings_exit_1(self):
        self.assertEqual(main(["scan", self._write(_mixed())]), 1)

    def test_scan_clean_exit_0(self):
        self.assertEqual(main(["scan", self._write(b"clean text " * 16)]), 0)

    def test_missing_file_exit_2(self):
        self.assertEqual(main(["scan", "/no/such/file.bin"]), 2)

    def test_carve_subcommand_writes(self):
        path = self._write(_mixed())
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["carve", path, "-o", d]), 1)
            self.assertTrue(os.listdir(d))

    def test_json_report_to_file(self):
        path = self._write(_mixed())
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "out.json")
            self.assertEqual(main(["scan", path, "--format", "json", "-r", report]), 1)
            with open(report, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["tool"], "FILECARVE")

    def test_sarif_report_to_file(self):
        path = self._write(_mixed())
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "out.sarif")
            self.assertEqual(main(["scan", path, "--format", "sarif", "-r", report]), 1)
            with open(report, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["version"], "2.1.0")

    def test_html_report_to_file(self):
        path = self._write(_mixed())
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "out.html")
            self.assertEqual(main(["scan", path, "--format", "html", "-r", report]), 1)
            with open(report, encoding="utf-8") as fh:
                self.assertIn("<!doctype html>", fh.read())

    def test_global_flag_before_subcommand(self):
        path = self._write(_mixed())
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.sarif")
            self.assertEqual(main(["--format", "sarif", "-r", report, "scan", path]), 1)
            with open(report, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["version"], "2.1.0")

    def test_global_flag_after_subcommand(self):
        path = self._write(_mixed())
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            self.assertEqual(main(["scan", path, "--format", "json", "-r", report]), 1)
            with open(report, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["tool"], "FILECARVE")

    def test_type_filter_via_cli(self):
        path = self._write(_mixed())
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            main(["scan", path, "--type", "pdf", "--format", "json", "-r", report])
            with open(report, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertTrue(all(f["ext"] == "pdf" for f in data["findings"]))

    def test_min_size_via_cli(self):
        path = self._write(_mixed())
        rc = main(["scan", path, "--min-size", "10000000"])
        self.assertEqual(rc, 0)  # nothing above 10MB -> clean

    def test_stdin_scan(self):
        class _Stdin:
            buffer = io.BytesIO(_mixed())
        old = sys.stdin
        sys.stdin = _Stdin()
        try:
            rc = main(["scan", "-"])
        finally:
            sys.stdin = old
        self.assertEqual(rc, 1)


# --- demo artifacts ---------------------------------------------------------

class TestDemos(unittest.TestCase):
    EXPECT = {
        "01-basic/evidence.blob": None,  # presence-only (may or may not ship a blob)
        "04-memory-dump/memory.dmp": {"png", "zip", "exe"},
        "05-firmware-image/firmware.bin": {"gif", "gz", "sqlite", "elf"},
        "06-pcap-exfil/capture.bin": {"pcap", "jpg", "pdf"},
        "07-polyglot-file/photo.jpg": {"jpg", "zip"},
        "08-unallocated-space/unallocated.raw": {"gif", "bmp"},
        "09-email-attachments/mailbox.bin": {"pdf", "png"},
        "10-truncated-tail/partial.bin": {"png"},
    }

    def test_demos_present_and_carve(self):
        for rel, expected in self.EXPECT.items():
            path = os.path.join(ROOT, "demos", *rel.split("/"))
            if expected is None:
                continue
            self.assertTrue(os.path.exists(path), f"missing {rel}")
            with open(path, "rb") as fh:
                exts = {c.ext for c in scan(fh.read())}
            self.assertTrue(expected.issubset(exts),
                            f"{rel}: expected {expected}, got {exts}")

    def test_truncated_demo_flags_truncation(self):
        # 10-truncated-tail is a footer-less PNG -> bounded, possibly truncated
        path = os.path.join(ROOT, "demos", "10-truncated-tail", "partial.bin")
        with open(path, "rb") as fh:
            found = [c for c in scan(fh.read()) if c.ext == "png"]
        self.assertTrue(found)
        # at least one PNG resolved by bounded fallback
        self.assertTrue(any(c.method == "bounded" for c in found))

    def test_polyglot_zip_is_valid(self):
        path = os.path.join(ROOT, "demos", "07-polyglot-file", "photo.jpg")
        with open(path, "rb") as fh:
            blob = fh.read()
        z = [c for c in scan(blob) if c.ext == "zip"][0]
        zf = zipfile.ZipFile(io.BytesIO(z.data))
        self.assertTrue(zf.namelist())

    def test_every_demo_has_scenario(self):
        demos_dir = os.path.join(ROOT, "demos")
        for d in os.listdir(demos_dir):
            full = os.path.join(demos_dir, d)
            if os.path.isdir(full):
                self.assertTrue(
                    os.path.exists(os.path.join(full, "SCENARIO.md")),
                    f"missing SCENARIO.md in {d}")


# --- safety / passive guarantees --------------------------------------------

class TestPassiveSafety(unittest.TestCase):
    """The carver must be fully offline: no socket/network imports in core."""

    def test_core_has_no_network_imports(self):
        core_path = os.path.join(ROOT, "filecarve", "core.py")
        with open(core_path, encoding="utf-8") as fh:
            src = fh.read()
        for banned in ("import socket", "import urllib", "import requests",
                       "import http", "socket.socket"):
            self.assertNotIn(banned, src, f"core.py must not use {banned}")

    def test_cli_has_no_network_imports(self):
        cli_path = os.path.join(ROOT, "filecarve", "cli.py")
        with open(cli_path, encoding="utf-8") as fh:
            src = fh.read()
        for banned in ("import socket", "import requests", "socket.socket"):
            self.assertNotIn(banned, src)


class TestMcpServer(unittest.TestCase):
    def test_scan_path_to_json_helper(self):
        from filecarve.mcp_server import _scan_path_to_json
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(_mixed())
        self.addCleanup(os.remove, path)
        data = json.loads(_scan_path_to_json(path))
        self.assertEqual(data["tool"], "FILECARVE")
        self.assertEqual(data["source"], path)
        self.assertEqual(data["total"], len(data["findings"]))
        self.assertGreater(data["total"], 0)

    def test_mcp_subcommand_parses(self):
        # `filecarve mcp` must be a recognized subcommand (routes to the server)
        p = build_parser()
        ns = p.parse_args(["mcp"])
        self.assertEqual(ns.cmd, "mcp")

    def test_mcp_without_extra_returns_1(self):
        # When the optional `mcp` extra is not installed, serve() exits 1 cleanly.
        import importlib.util
        if importlib.util.find_spec("mcp") is not None:
            self.skipTest("mcp extra installed; offline-degrade path not exercised")
        self.assertEqual(main(["mcp"]), 1)


if __name__ == "__main__":
    unittest.main()
