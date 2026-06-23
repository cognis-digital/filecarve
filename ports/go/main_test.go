package main

import (
	"bytes"
	"testing"
)

// minimal valid PNG: signature + IEND footer
func pngBytes() []byte {
	sig := []byte("\x89PNG\r\n\x1a\n")
	body := []byte("\x00\x00\x00\x00IEND\xaeB`\x82")
	return append(sig, body...)
}

func pdfBytes() []byte { return []byte("%PDF-1.4\nstuff\n%%EOF") }

func bmpBytes() []byte {
	// 'BM' + 4-byte LE size (=14, just the header) + filler
	b := []byte("BM")
	b = append(b, 14, 0, 0, 0)
	b = append(b, make([]byte, 8)...)
	return b
}

func TestScanFindsPNG(t *testing.T) {
	blob := append([]byte{0, 1, 2}, pngBytes()...)
	blob = append(blob, 3, 4)
	found := Scan(blob, 1, nil)
	var pngs []Carved
	for _, c := range found {
		if c.Ext == "png" {
			pngs = append(pngs, c)
		}
	}
	if len(pngs) != 1 {
		t.Fatalf("expected 1 png, got %d", len(pngs))
	}
	if pngs[0].Method != "footer" {
		t.Errorf("expected footer method, got %s", pngs[0].Method)
	}
	if pngs[0].Offset != 3 {
		t.Errorf("expected offset 3, got %d", pngs[0].Offset)
	}
	if pngs[0].Truncated {
		t.Error("png should not be truncated")
	}
}

func TestScanFindsMultipleTypes(t *testing.T) {
	pad := make([]byte, 16)
	blob := append([]byte{}, pad...)
	blob = append(blob, pngBytes()...)
	blob = append(blob, pad...)
	blob = append(blob, pdfBytes()...)
	blob = append(blob, pad...)
	found := Scan(blob, 1, nil)
	exts := map[string]bool{}
	for _, c := range found {
		exts[c.Ext] = true
	}
	if !exts["png"] || !exts["pdf"] {
		t.Errorf("expected png and pdf, got %v", exts)
	}
}

func TestPDFFooterInclusive(t *testing.T) {
	found := Scan(pdfBytes(), 1, nil)
	if len(found) == 0 {
		t.Fatal("expected pdf finding")
	}
	if !bytes.HasSuffix([]byte(pdfBytes())[found[0].Offset:found[0].Offset+found[0].Size], []byte("%%EOF")) {
		t.Error("pdf carve should end with %%EOF")
	}
}

func TestBMPLength(t *testing.T) {
	found := Scan(bmpBytes(), 1, nil)
	var bmps []Carved
	for _, c := range found {
		if c.Ext == "bmp" {
			bmps = append(bmps, c)
		}
	}
	if len(bmps) != 1 || bmps[0].Method != "length" {
		t.Fatalf("expected 1 bmp via length, got %+v", bmps)
	}
	if bmps[0].Size != 14 {
		t.Errorf("expected size 14, got %d", bmps[0].Size)
	}
}

func TestTypeFilter(t *testing.T) {
	pad := make([]byte, 8)
	blob := append(pad, pngBytes()...)
	blob = append(blob, pdfBytes()...)
	found := Scan(blob, 1, map[string]bool{"pdf": true})
	for _, c := range found {
		if c.Ext != "pdf" {
			t.Errorf("type filter leaked %s", c.Ext)
		}
	}
}

func TestMinSize(t *testing.T) {
	found := Scan(pngBytes(), 10_000_000, nil)
	if len(found) != 0 {
		t.Errorf("expected no findings above min-size, got %d", len(found))
	}
}

func TestEmptyBlob(t *testing.T) {
	if found := Scan([]byte{}, 1, nil); len(found) != 0 {
		t.Errorf("empty blob should produce no findings, got %d", len(found))
	}
}

func TestSortedByOffset(t *testing.T) {
	pad := make([]byte, 8)
	blob := append(pad, pngBytes()...)
	blob = append(blob, pad...)
	blob = append(blob, pdfBytes()...)
	found := Scan(blob, 1, nil)
	for i := 1; i < len(found); i++ {
		if found[i].Offset < found[i-1].Offset {
			t.Error("findings not sorted by offset")
		}
	}
}

func TestSHA256Populated(t *testing.T) {
	found := Scan(pngBytes(), 1, nil)
	if len(found) == 0 || len(found[0].SHA256) != 64 {
		t.Errorf("expected 64-char sha256, got %+v", found)
	}
}
