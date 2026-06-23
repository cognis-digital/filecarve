#!/usr/bin/env node
// JavaScript / Node port of the FILECARVE scan engine — same signatures, same
// JSON output shape as the Python reference.
//
// Scans a blob for embedded files by magic-byte signature. End-detection uses
// footer, header-derived length (BMP/RIFF/ZIP), or a bounded fallback that
// flags possible truncation. Passive/offline by nature: never touches the
// network; only reads the file (or stdin) you give it.
//
//   node index.js scan <blob>     # JSON to stdout, exit 1 if findings
//   node index.js scan -          # read blob from stdin
//   node index.js --version
//
// Defensive / authorized-use forensics only: analyze artifacts you own.
import { readFileSync } from "fs";
import { createHash } from "crypto";

export const TOOL_NAME = "FILECARVE";
export const TOOL_VERSION = "0.6.6";

const B = (s) => Buffer.from(s, "binary");

function lenGIF(blob, start) {
  // GIF terminates with trailer 0x3B; canonical end is block-terminator 0x00 0x3B.
  const window = blob.subarray(start, start + 50_000_000);
  const idx = window.lastIndexOf(B("\x00\x3b"));
  if (idx !== -1) return idx + 2;
  return null;
}
function lenBMP(blob, start) {
  if (start + 6 > blob.length) return null;
  const size = blob.readUInt32LE(start + 2);
  if (size >= 14 && size <= blob.length - start) return size;
  return null;
}
function lenRIFF(blob, start) {
  if (start + 8 > blob.length) return null;
  const size = blob.readUInt32LE(start + 4);
  const total = size + 8;
  if (total > 8 && total <= blob.length - start) return total;
  return null;
}
function lenZIP(blob, start) {
  const eocd = B("PK\x05\x06");
  // find the LAST EOCD at/after `start` (central directory is at the archive end)
  let found = -1, from = start;
  for (;;) {
    const i = blob.indexOf(eocd, from);
    if (i === -1) break;
    found = i; from = i + 1;
  }
  if (found === -1 || found + 22 > blob.length) return null;
  const commentLen = blob.readUInt16LE(found + 20);
  const end = found + 22 + commentLen;
  if (end <= blob.length && end > start) return end - start;
  return null;
}

const SIGNATURES = [
  { name: "JPEG image", ext: "jpg", header: B("\xff\xd8\xff"), footer: B("\xff\xd9"), footerInclusive: true, severity: "low" },
  { name: "PNG image", ext: "png", header: B("\x89PNG\r\n\x1a\n"), footer: B("IEND\xae\x42\x60\x82"), footerInclusive: true, severity: "low" },
  { name: "GIF image", ext: "gif", header: B("GIF89a"), lengthFn: lenGIF, severity: "low" },
  { name: "GIF image", ext: "gif", header: B("GIF87a"), lengthFn: lenGIF, severity: "low" },
  { name: "BMP image", ext: "bmp", header: B("BM"), lengthFn: lenBMP, severity: "low" },
  { name: "PDF document", ext: "pdf", header: B("%PDF-"), footer: B("%%EOF"), footerInclusive: true, severity: "medium" },
  { name: "ZIP / Office / JAR", ext: "zip", header: B("PK\x03\x04"), footer: B("PK\x05\x06"), footerInclusive: true, lengthFn: lenZIP, severity: "medium" },
  { name: "GZIP stream", ext: "gz", header: B("\x1f\x8b\x08"), severity: "medium" },
  { name: "RAR archive", ext: "rar", header: B("Rar!\x1a\x07\x00"), severity: "high" },
  { name: "RAR5 archive", ext: "rar", header: B("Rar!\x1a\x07\x01\x00"), severity: "high" },
  { name: "7-Zip archive", ext: "7z", header: B("\x37\x7a\xbc\xaf\x27\x1c"), severity: "high" },
  { name: "ELF executable", ext: "elf", header: B("\x7fELF"), severity: "high" },
  { name: "Windows PE/EXE", ext: "exe", header: B("MZ"), severity: "high" },
  { name: "RIFF (wav/avi/webp)", ext: "riff", header: B("RIFF"), lengthFn: lenRIFF, severity: "low" },
  { name: "SQLite database", ext: "sqlite", header: B("SQLite format 3\x00"), severity: "medium" },
  { name: "PCAP capture", ext: "pcap", header: B("\xd4\xc3\xb2\xa1"), severity: "medium" },
];

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3 };
const MAX_SIZE = 25_000_000;

function sha256of(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function resolveEnd(blob, sig, start) {
  const n = blob.length;
  if (sig.lengthFn) {
    const length = sig.lengthFn(blob, start);
    if (length !== null && length > 0) return [Math.min(start + length, n), "length", false];
  }
  if (sig.footer) {
    const fidx = blob.indexOf(sig.footer, start + sig.header.length);
    if (fidx !== -1) {
      const end = fidx + (sig.footerInclusive ? sig.footer.length : 0);
      return [Math.min(end, n), "footer", false];
    }
  }
  const end = Math.min(start + MAX_SIZE, n);
  return [end, "bounded", start + MAX_SIZE < n];
}

export function scan(blob, { minSize = 1, types = null } = {}) {
  if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);
  const results = [];
  for (const sig of SIGNATURES) {
    if (types && !types.has(sig.ext)) continue;
    let pos = 0, consumedUntil = -1;
    for (;;) {
      const idx = blob.indexOf(sig.header, pos);
      if (idx === -1) break;
      const start = idx;
      if (start <= consumedUntil) { pos = idx + 1; continue; }
      const [end, method, truncated] = resolveEnd(blob, sig, start);
      const size = end - start;
      if (size >= minSize) {
        const data = blob.subarray(start, end);
        results.push({
          name: sig.name, ext: sig.ext, offset: start, size,
          sha256: sha256of(data), severity: sig.severity, method, truncated,
        });
        consumedUntil = end - 1;
        pos = Math.max(idx + 1, end);
      } else {
        pos = idx + 1;
      }
    }
  }
  results.sort((a, b) => a.offset - b.offset || (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
  return results;
}

export function report(found, src) {
  const counts = {};
  for (const c of found) counts[c.severity] = (counts[c.severity] || 0) + 1;
  return { tool: TOOL_NAME, version: TOOL_VERSION, source: src, total: found.length, severity_counts: counts, findings: found };
}

function readBlob(path) {
  if (path === "-") return readFileSync(0);
  return readFileSync(path);
}

function cli(argv) {
  if (argv.includes("--version")) { console.log(`${TOOL_NAME} ${TOOL_VERSION}`); return 0; }
  if (argv[0] !== "scan" || !argv[1]) {
    process.stderr.write("usage: filecarve scan <blob>  (- for stdin)\n");
    return 2;
  }
  let blob;
  try { blob = readBlob(argv[1]); }
  catch (e) { process.stderr.write(`${TOOL_NAME}: cannot read ${argv[1]}: ${e.message}\n`); return 2; }
  const found = scan(blob);
  const src = argv[1] === "-" ? "<stdin>" : argv[1];
  console.log(JSON.stringify(report(found, src), null, 2));
  return found.length ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(cli(process.argv.slice(2)));
}
