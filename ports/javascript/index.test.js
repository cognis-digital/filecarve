// Smoke tests for the JS port. Node stdlib only (node:test + node:assert).
//   node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { scan, report, TOOL_NAME, TOOL_VERSION } from "./index.js";

const B = (s) => Buffer.from(s, "binary");

function png() {
  // signature + minimal IEND footer
  return Buffer.concat([B("\x89PNG\r\n\x1a\n"), B("\x00\x00\x00\x00IEND\xae\x42\x60\x82")]);
}
function pdf() { return Buffer.from("%PDF-1.4\nstuff\n%%EOF"); }
function bmp() {
  const b = Buffer.alloc(14);
  b.write("BM", 0, "binary");
  b.writeUInt32LE(14, 2);
  return b;
}

test("meta constants", () => {
  assert.equal(TOOL_NAME, "FILECARVE");
  assert.ok(TOOL_VERSION.length > 0);
});

test("finds embedded png by footer", () => {
  const blob = Buffer.concat([B("\x00\x01\x02"), png(), B("\x03\x04")]);
  const found = scan(blob).filter((c) => c.ext === "png");
  assert.equal(found.length, 1);
  assert.equal(found[0].method, "footer");
  assert.equal(found[0].offset, 3);
  assert.equal(found[0].truncated, false);
});

test("finds multiple types", () => {
  const pad = Buffer.alloc(16);
  const blob = Buffer.concat([pad, png(), pad, pdf(), pad]);
  const exts = new Set(scan(blob).map((c) => c.ext));
  assert.ok(exts.has("png"));
  assert.ok(exts.has("pdf"));
});

test("pdf footer inclusive", () => {
  const found = scan(pdf()).filter((c) => c.ext === "pdf");
  assert.equal(found.length, 1);
  const data = pdf().subarray(found[0].offset, found[0].offset + found[0].size);
  assert.ok(data.toString().endsWith("%%EOF"));
});

test("bmp resolved by length", () => {
  const found = scan(bmp()).filter((c) => c.ext === "bmp");
  assert.equal(found.length, 1);
  assert.equal(found[0].method, "length");
  assert.equal(found[0].size, 14);
});

test("type filter", () => {
  const blob = Buffer.concat([png(), pdf()]);
  const found = scan(blob, { types: new Set(["pdf"]) });
  assert.ok(found.every((c) => c.ext === "pdf"));
});

test("min size suppresses small carves", () => {
  assert.equal(scan(png(), { minSize: 10_000_000 }).length, 0);
});

test("empty blob has no findings", () => {
  assert.equal(scan(Buffer.alloc(0)).length, 0);
});

test("sorted by offset", () => {
  const pad = Buffer.alloc(8);
  const blob = Buffer.concat([pad, png(), pad, pdf()]);
  const offs = scan(blob).map((c) => c.offset);
  assert.deepEqual(offs, [...offs].sort((a, b) => a - b));
});

test("sha256 is 64 hex chars", () => {
  const found = scan(png());
  assert.ok(found.length > 0);
  assert.match(found[0].sha256, /^[0-9a-f]{64}$/);
});

test("report shape matches reference", () => {
  const found = scan(Buffer.concat([png(), pdf()]));
  const r = report(found, "x");
  assert.equal(r.tool, "FILECARVE");
  assert.equal(r.total, r.findings.length);
  assert.ok(r.severity_counts);
});
