// Go port of the FILECARVE scan engine — single static binary, zero deps.
//
// Mirrors the Python reference CLI's primary command: scan a blob for embedded
// files by magic-byte signature and emit JSON. End-detection uses footer,
// header-derived length (BMP/RIFF/ZIP), or a bounded fallback that flags
// possible truncation. Passive/offline by nature: this never touches the
// network and only reads the file (or stdin) you point it at.
//
// Usage:
//
//	filecarve-go scan <blob>        # JSON to stdout, exit 1 if findings
//	filecarve-go scan -             # read blob from stdin
//	filecarve-go --version
//
// Defensive / authorized-use forensics only: analyze artifacts you own.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

const (
	toolName    = "FILECARVE"
	toolVersion = "0.6.6"
)

// lengthFn derives the carved length from the header, or returns (0,false).
type lengthFn func(blob []byte, start int) (int, bool)

type signature struct {
	Name           string
	Ext            string
	Header         []byte
	Footer         []byte
	FooterInclusive bool
	Length         lengthFn
	MaxSize        int
	Severity       string
}

func lenGIF(blob []byte, start int) (int, bool) {
	// GIF terminates with trailer 0x3B; canonical end is 0x00 0x3B.
	end := start + 50_000_000
	if end > len(blob) {
		end = len(blob)
	}
	window := blob[start:end]
	idx := bytes.LastIndex(window, []byte{0x00, 0x3b})
	if idx != -1 {
		return idx + 2, true
	}
	return 0, false
}

func lenBMP(blob []byte, start int) (int, bool) {
	if start+6 > len(blob) {
		return 0, false
	}
	size := int(binary.LittleEndian.Uint32(blob[start+2 : start+6]))
	if size >= 14 && size <= len(blob)-start {
		return size, true
	}
	return 0, false
}

func lenRIFF(blob []byte, start int) (int, bool) {
	if start+8 > len(blob) {
		return 0, false
	}
	size := int(binary.LittleEndian.Uint32(blob[start+4 : start+8]))
	total := size + 8
	if total > 8 && total <= len(blob)-start {
		return total, true
	}
	return 0, false
}

func lenZIP(blob []byte, start int) (int, bool) {
	eocd := []byte("PK\x05\x06")
	idx := bytes.LastIndex(blob[start:], eocd)
	if idx == -1 {
		return 0, false
	}
	idx += start
	if idx+22 > len(blob) {
		return 0, false
	}
	commentLen := int(binary.LittleEndian.Uint16(blob[idx+20 : idx+22]))
	end := idx + 22 + commentLen
	if end <= len(blob) && end > start {
		return end - start, true
	}
	return 0, false
}

var signatures = []signature{
	{Name: "JPEG image", Ext: "jpg", Header: []byte{0xff, 0xd8, 0xff}, Footer: []byte{0xff, 0xd9}, FooterInclusive: true, Severity: "low"},
	{Name: "PNG image", Ext: "png", Header: []byte("\x89PNG\r\n\x1a\n"), Footer: []byte("IEND\xaeB`\x82"), FooterInclusive: true, Severity: "low"},
	{Name: "GIF image", Ext: "gif", Header: []byte("GIF89a"), Length: lenGIF, Severity: "low"},
	{Name: "GIF image", Ext: "gif", Header: []byte("GIF87a"), Length: lenGIF, Severity: "low"},
	{Name: "BMP image", Ext: "bmp", Header: []byte("BM"), Length: lenBMP, Severity: "low"},
	{Name: "PDF document", Ext: "pdf", Header: []byte("%PDF-"), Footer: []byte("%%EOF"), FooterInclusive: true, Severity: "medium"},
	{Name: "ZIP / Office / JAR", Ext: "zip", Header: []byte("PK\x03\x04"), Footer: []byte("PK\x05\x06"), FooterInclusive: true, Length: lenZIP, Severity: "medium"},
	{Name: "GZIP stream", Ext: "gz", Header: []byte{0x1f, 0x8b, 0x08}, Severity: "medium"},
	{Name: "RAR archive", Ext: "rar", Header: []byte("Rar!\x1a\x07\x00"), Severity: "high"},
	{Name: "RAR5 archive", Ext: "rar", Header: []byte("Rar!\x1a\x07\x01\x00"), Severity: "high"},
	{Name: "7-Zip archive", Ext: "7z", Header: []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, Severity: "high"},
	{Name: "ELF executable", Ext: "elf", Header: []byte("\x7fELF"), Severity: "high"},
	{Name: "Windows PE/EXE", Ext: "exe", Header: []byte("MZ"), Severity: "high"},
	{Name: "RIFF (wav/avi/webp)", Ext: "riff", Header: []byte("RIFF"), Length: lenRIFF, Severity: "low"},
	{Name: "SQLite database", Ext: "sqlite", Header: []byte("SQLite format 3\x00"), Severity: "medium"},
	{Name: "PCAP capture", Ext: "pcap", Header: []byte{0xd4, 0xc3, 0xb2, 0xa1}, Severity: "medium"},
}

// Carved is one carved region. JSON shape mirrors the Python reference.
type Carved struct {
	Name      string `json:"name"`
	Ext       string `json:"ext"`
	Offset    int    `json:"offset"`
	Size      int    `json:"size"`
	SHA256    string `json:"sha256"`
	Severity  string `json:"severity"`
	Method    string `json:"method"`
	Truncated bool   `json:"truncated"`
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func resolveEnd(blob []byte, sig signature, start int) (int, string, bool) {
	n := len(blob)
	maxSize := sig.MaxSize
	if maxSize == 0 {
		maxSize = 25_000_000
	}
	if sig.Length != nil {
		if length, ok := sig.Length(blob, start); ok && length > 0 {
			if start+length < n {
				return start + length, "length", false
			}
			return n, "length", false
		}
	}
	if sig.Footer != nil {
		fidx := bytes.Index(blob[start+len(sig.Header):], sig.Footer)
		if fidx != -1 {
			fidx += start + len(sig.Header)
			end := fidx
			if sig.FooterInclusive {
				end += len(sig.Footer)
			}
			if end > n {
				end = n
			}
			return end, "footer", false
		}
	}
	end := start + maxSize
	truncated := end < n
	if end > n {
		end = n
	}
	return end, "bounded", truncated
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}

// Scan returns carved candidates sorted by offset.
func Scan(blob []byte, minSize int, types map[string]bool) []Carved {
	var results []Carved
	for _, sig := range signatures {
		if types != nil && !types[sig.Ext] {
			continue
		}
		pos := 0
		consumedUntil := -1
		for {
			rel := bytes.Index(blob[pos:], sig.Header)
			if rel == -1 {
				break
			}
			idx := pos + rel
			start := idx
			if start <= consumedUntil {
				pos = idx + 1
				continue
			}
			end, method, truncated := resolveEnd(blob, sig, start)
			size := end - start
			if size >= minSize {
				data := blob[start:end]
				results = append(results, Carved{
					Name: sig.Name, Ext: sig.Ext, Offset: start, Size: size,
					SHA256: sha256hex(data), Severity: sig.Severity,
					Method: method, Truncated: truncated,
				})
				consumedUntil = end - 1
				if end > idx+1 {
					pos = end
				} else {
					pos = idx + 1
				}
			} else {
				pos = idx + 1
			}
		}
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Offset != results[j].Offset {
			return results[i].Offset < results[j].Offset
		}
		return sevRank[results[i].Severity] > sevRank[results[j].Severity]
	})
	return results
}

func readBlob(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func main() {
	args := os.Args[1:]
	for _, a := range args {
		if a == "--version" {
			fmt.Printf("%s %s\n", toolName, toolVersion)
			return
		}
	}
	if len(args) < 2 || args[0] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: filecarve-go scan <blob>  (- for stdin)")
		os.Exit(2)
	}
	blob, err := readBlob(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: cannot read %s: %v\n", toolName, args[1], err)
		os.Exit(2)
	}
	found := Scan(blob, 1, nil)
	counts := map[string]int{}
	for _, c := range found {
		counts[c.Severity]++
	}
	src := args[1]
	if src == "-" {
		src = "<stdin>"
	}
	payload := map[string]any{
		"tool":            toolName,
		"version":         toolVersion,
		"source":          src,
		"total":           len(found),
		"severity_counts": counts,
		"findings":        found,
	}
	out, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(out))
	if len(found) > 0 {
		os.Exit(1)
	}
}
