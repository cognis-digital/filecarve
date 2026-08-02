package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// FileCarver is a tool to carve files from raw data by signature.
type FileCarver struct {
	signatures map[string][]byte
}

// NewFileCarver creates a new FileCarver with the given signatures.
func NewFileCarver(signatures map[string][]byte) *FileCarver {
	return &FileCarver{
		signatures: signatures,
	}
}

// Carve processes input data and returns carved files based on known signatures.
func (fc *FileCarver) Carve(data []byte) map[string][]byte {
	result := make(map[string][]byte)
	for signatureName, signature := range fc.signatures {
		if len(signature) > len(data) {
			continue
		}
		if strings.EqualFold(string(signature), string(data[:len(signature)])) {
			// Found a match, extract the file
			result[signatureName] = data
		}
	}
	return result
}

func main() {
	// Example usage of FileCarver
	signatures := map[string][]byte{
		"txt": []byte{'#', '!', 'T', 'E', 'X', 'T', '\n'},
		"html": []byte{'<', 'h', 't', 'm', 'l', '>'},
	}

	carver := NewFileCarver(signatures)

	// Simulate reading from a disk image or memory dump
	diskImage := []byte{
		'#', '!', 'T', 'E', 'X', 'T', '\n',
		'W', 'e', 'l', 'c', 'o', 'm', 'e', ' ', 't', 'o', ' ', 'F', 'i', 'l', 'e', 'C', 'a', 'r', 'v', 'e', '\n',
		'<', 'h', 't', 'm', 'l', '>', ' ', 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '</', 'h', 't', 'm', 'l', '>',
	}

	carvedFiles := carver.Carve(diskImage)

	if len(carvedFiles) == 0 {
		fmt.Println("No files carved.")
		return
	}

	for name, content := range carvedFiles {
		fmt.Printf("Carved file: %s\n", name)
		fmt.Println(string(content))
	}
}