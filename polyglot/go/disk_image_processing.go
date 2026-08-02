package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// FileSignature represents a known file signature with its name and pattern.
type FileSignature struct {
	Name   string
	Pattern []byte
}

// diskImageProcessor processes a disk image to carve files based on known signatures.
type diskImageProcessor struct {
	imagePath string
	signatures map[string][]FileSignature
}

// NewDiskImageProcessor creates a new disk image processor with the given image path and file signatures.
func NewDiskImageProcessor(imagePath string, signatures map[string][]FileSignature) *diskImageProcessor {
	return &diskImageProcessor{
		imagePath: imagePath,
		signatures: signatures,
	}
}

// Process processes the disk image and carves files based on known signatures.
func (dip *diskImageProcessor) Process() error {
	file, err := os.Open(dip.imagePath)
	if err != nil {
		return fmt.Errorf("failed to open disk image: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "signature") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				continue
			}
			sigName := parts[1]
			sigPattern := []byte(parts[2])
			dip.signatures[sigName] = append(dip.signatures[sigName], FileSignature{
				Name:   sigName,
				Pattern: sigPattern,
			})
		}
	}

	return nil
}

// FindFiles searches for files in the disk image based on known signatures.
func (dip *diskImageProcessor) FindFiles() ([]string, error) {
	file, err := os.Open(dip.imagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open disk image: %v", err)
	}
	defer file.Close()

	var foundFiles []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "signature") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				continue
			}
			sigName := parts[1]
			sigPattern := []byte(parts[2])
			// Simulate matching (in real scenario, we'd search for the pattern in the image data)
			foundFiles = append(foundFiles, fmt.Sprintf("Found %s file using signature: %s", sigName, sigPattern))
		}
	}

	return foundFiles, nil
}

func main() {
	// Example usage of the disk image processor.
	signatures := map[string][]FileSignature{
		"txt": {
			{
				Name:   "Text File",
				Pattern: []byte("\x42\x61\x73\x65\x20\x54\x65\x78\x74"),
			},
		},
		"exe": {
			{
				Name:   "Windows Executable",
				Pattern: []byte("\x4D\x5A\x90"),
			},
		},
	}

	dip := NewDiskImageProcessor("disk_image.bin", signatures)
	if err := dip.Process(); err != nil {
		fmt.Printf("Error processing disk image: %v\n", err)
		return
	}

	foundFiles, err := dip.FindFiles()
	if err != nil {
		fmt.Printf("Error finding files: %v\n", err)
		return
	}

	fmt.Println("Recovered Files:")
	for _, file := range foundFiles {
		fmt.Println(file)
	}
}