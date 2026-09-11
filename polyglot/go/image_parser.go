package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ImageFormat represents the detected container format
type ImageFormat int

const (
	FormatUnknown ImageFormat = iota
	FormatRaw
	FormatE01
	FormatAFF
	FormatE01v2
)

// ImageInfo holds parsed metadata from a disk image
type ImageInfo struct {
	Format        ImageFormat
	Name          string
	Size          int64
	Offset        int64
	MediaType     string
	StartTime     time.Time
	EndTime       time.Time
	PartitionInfo []PartitionInfo
	Errors        []string
}

// PartitionInfo represents a partition entry
type PartitionInfo struct {
	Offset   int64
	Size     int64
	FSType   string
	MountPoint string
}

// E01Header represents the E01 container header
type E01Header struct {
	Magic       [4]byte
	Version     byte
	Flags       byte
	HeaderSize  uint32
	Partition   uint32
	PartitionSize uint32
}

// AFFHeader represents the AFF container header
type AFFHeader struct {
	Magic       [4]byte
	Version     byte
	Flags       byte
	HeaderSize  uint32
	Partition   uint32
	PartitionSize uint32
}

// Magic bytes for format detection
var magicBytes = map[ImageFormat][]byte{
	FormatE01:   {0x54, 0x45, 0x41, 0x42}, // "TEAB"
	FormatE01v2: {0x54, 0x45, 0x41, 0x42}, // "TEAB"
	FormatAFF:   {0x41, 0x46, 0x46, 0x46}, // "AFF "
	FormatRaw:   {},                        // No magic, detected by absence
}

// E01Magic is the E01 magic string
const E01Magic = "TEAB"

// AFFMagic is the AFF magic string
const AFFMagic = "AFF "

// E01Version1 is the original E01 version
const E01Version1 = 0x01

// E01Version2 is the E01v2 version
const E01Version2 = 0x02

// PartitionInfo represents a partition entry
type PartitionInfo struct {
	Offset   int64
	Size     int64
	FSType   string
	MountPoint string
}

// ImageParser handles parsing of disk image formats
type ImageParser struct {
	file     *os.File
	info     ImageInfo
	header   E01Header
	affHeader AFFHeader
	offset   int64
}

// NewImageParser creates a new parser instance
func NewImageParser() *ImageParser {
	return &ImageParser{
		info: ImageInfo{
			Format: FormatUnknown,
			Errors: make([]string, 0),
		},
	}
}

// OpenImage opens and parses a disk image file
func (p *ImageParser) OpenImage(path string) error {
	file, err := os.Open(path)
	if err != nil {
		p.info.Errors = append(p.info.Errors, fmt.Sprintf("Failed to open file: %v", err))
		return err
	}
	p.file = file
	p.info.Name = path

	// Read initial bytes for format detection
	buffer := make([]byte, 64)
	_, err = file.Read(buffer)
	if err != nil {
		p.info.Errors = append(p.info.Errors, fmt.Sprintf("Failed to read header: %v", err))
		return err
	}

	// Detect format
	p.info.Format = p.detectFormat(buffer)

	// Parse based on detected format
	switch p.info.Format {
	case FormatE01, FormatE01v2:
		p.parseE01(buffer)
	case FormatAFF:
		p.parseAFF(buffer)
	case FormatRaw:
		p.info.Offset = 0
		p.info.Size = int64(len(buffer))
		p.info.MediaType = "raw"
	}

	return nil
}

// Close closes the open file
func (p *ImageParser) Close() error {
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

// GetInfo returns the parsed image information
func (p *ImageParser) GetInfo() ImageInfo {
	return p.info
}

// detectFormat determines the image format from magic bytes
func (p *ImageParser) detectFormat(buffer []byte) ImageFormat {
	// Check for E01 format
	if len(buffer) >= 4 {
		if string(buffer[:4]) == E01Magic {
			// Check version
			if len(buffer) >= 5 {
				version := buffer[4]
				if version == E01Version1 || version == E01Version2 {
					if version == E01Version2 {
						return FormatE01v2
					}
					return FormatE01
				}
			}
			return FormatE01
		}
	}

	// Check for AFF format
	if len(buffer) >= 4 {
		if string(buffer[:4]) == AFFMagic {
			return FormatAFF
		}
	}

	// Default to raw
	return FormatRaw
}

// parseE01 parses the E01 container format
func (p *ImageParser) parseE01(buffer []byte) {
	if len(buffer) < 20 {
		p.info.Errors = append(p.info.Errors, "E01 header too short")
		return
	}

	// Parse E01 header fields
	p.header.Magic = buffer[:4]
	p.header.Version = buffer[4]
	p.header.Flags = buffer[5]

	// Parse header size (little-endian)
	p.header.HeaderSize = binary.LittleEndian.Uint32(buffer[6:10])

	// Parse partition info
	p.header.Partition = binary.LittleEndian.Uint32(buffer[10:14])
	p.header.PartitionSize = binary.LittleEndian.Uint32(buffer[14:18])

	// Set default values
	p.info.Offset = 0
	p.info.Size = int64(p.header.PartitionSize)

	// Parse timestamps if present
	if len(buffer) >= 22 {
		// E01v2 has timestamps
		p.info.StartTime = time.Unix(int64(binary.LittleEndian.Uint32(buffer[18:22])), 0)
	}

	// Parse media type
	if len(buffer) >= 24 {
		mediaType := string(buffer[22:26])
		if mediaType != "" {
			p.info.MediaType = mediaType
		}
	}

	// Parse partition entries
	if p.header.Partition > 0 {
		// Read partition table
		partitionTableOffset := int64(p.header.HeaderSize)
		p.info.PartitionInfo = p.parsePartitionTable(partitionTableOffset)
	}
}

// parseAFF parses the AFF container format
func (p *ImageParser) parseAFF(buffer []byte) {
	if len(buffer) < 20 {
		p.info.Errors = append(p.info.Errors, "AFF header too short")
		return
	}

	// Parse AFF header fields
	p.affHeader.Magic = buffer[:4]
	p.affHeader.Version = buffer[4]
	p.affHeader.Flags = buffer[5]

	// Parse header size (little-endian)
	p.affHeader.HeaderSize = binary.LittleEndian.Uint32(buffer[6:10])

	// Parse partition info
	p.affHeader.Partition = binary.LittleEndian.Uint32(buffer[10:14])
	p.affHeader.PartitionSize = binary.LittleEndian.Uint32(buffer[14:18])

	// Set default values
	p.info.Offset = 0
	p.info.Size = int64(p.affHeader.PartitionSize)

	// Parse timestamps
	if len(buffer) >= 22 {
		// AFF v2 has timestamps
		p.info.StartTime = time.Unix(int64(binary.LittleEndian.Uint32(buffer[18:22])), 0)
	}

	// Parse media type
	if len(buffer) >= 24 {
		mediaType := string(buffer[22:26])
		if mediaType != "" {
			p.info.MediaType = mediaType
		}
	}

	// Parse partition entries
	if p.affHeader.Partition > 0 {
		partitionTableOffset := int64(p.affHeader.HeaderSize)
		p.info.PartitionInfo = p.parsePartitionTable(partitionTableOffset)
	}
}

// parsePartitionTable parses the partition table
func (p *ImageParser) parsePartitionTable(offset int64) []PartitionInfo {
	var partitions []PartitionInfo

	// Each partition entry is 16 bytes
	entrySize := 16
	maxEntries := 64 // Reasonable limit

	for i := 0; i < maxEntries; i++ {
		entryOffset := offset + int64(i)*int64(entrySize)

		// Read entry
		entry := make([]byte, entrySize)
		if _, err := p.file.ReadAt(entry, entryOffset); err != nil {
			break
		}

		// Parse partition offset (little-endian)
		partOffset := binary.LittleEndian.Uint64(entry[0:8])
		partSize := binary.LittleEndian.Uint64(entry[8:16])

		// Skip zero entries
		if partOffset == 0 && partSize == 0 {
			break
		}

		// Parse filesystem type
		fsType := string(entry[16:20])
		if fsType == "" {
			fsType = "unknown"
		}

		// Parse mount point
		mountPoint := string(entry[20:36])
		if mountPoint == "" {
			mountPoint = "/"
		}

		partitions = append(partitions, PartitionInfo{
			Offset:     int64(partOffset),
			Size:       int64(partSize),
			FSType:     fsType,
			MountPoint: mountPoint,
		})
	}

	return partitions
}

// GetRawDataAt reads raw data at a specific offset
func (p *ImageParser) GetRawDataAt(offset int64, length int) ([]byte, error) {
	if p.file == nil {
		return nil, fmt.Errorf("parser not initialized")
	}

	return p.file.ReadAt(make([]byte, length), offset)
}

// SeekToPartition seeks to a specific partition
func (p *ImageParser) SeekToPartition(partitionIndex int) error {
	if len(p.info.PartitionInfo) == 0 {
		return fmt.Errorf("no partitions found")
	}

	if partitionIndex < 0 || partitionIndex >= len(p.info.PartitionInfo) {
		return fmt.Errorf("partition index out of range")
	}

	partition := p.info.PartitionInfo[partitionIndex]
	_, err := p.file.Seek(partition.Offset, io.SeekStart)
	return err
}

// GetPartitionInfo returns info for a specific partition
func (p *ImageParser) GetPartitionInfo(index int) *PartitionInfo {
	if index < 0 || index >= len(p.info.PartitionInfo) {
		return nil
	}
	return &p.info.PartitionInfo[index]
}

// FormatString returns a human-readable format string
func (p *ImageParser) FormatString() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Format: %s\n", p.formatName()))
	sb.WriteString(fmt.Sprintf("Name: %s\n", p.info.Name))
	sb.WriteString(fmt.Sprintf("Offset: %d\n", p.info.Offset))
	sb.WriteString(fmt.Sprintf("Size: %d bytes\n", p.info.Size))
	sb.WriteString(fmt.Sprintf("Media Type: %s\n", p.info.MediaType))

	if !p.info.StartTime.IsZero() {
		sb.WriteString(fmt.Sprintf("Start Time: %s\n", p.info.StartTime.Format(time.RFC3339)))
	}
	if !p.info.EndTime.IsZero() {
		sb.WriteString(fmt.Sprintf("End Time: %s\n", p.info.EndTime.Format(time.RFC3339)))
	}

	if len(p.info.PartitionInfo) > 0 {
		sb.WriteString(fmt.Sprintf("Partitions: %d\n", len(p.info.PartitionInfo)))
		for i, part := range p.info.PartitionInfo {
			sb.WriteString(fmt.Sprintf("  [%d] Offset: %d, Size: %d, FS: %s, Mount: %s\n",
				i, part.Offset, part.Size, part.FSType, part.MountPoint))
		}
	}

	if len(p.info.Errors) > 0 {
		sb.WriteString("Errors:\n")
		for _, err := range p.info.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// formatName returns a human-readable format name
func (p *ImageParser) formatName() string {
	switch p.info.Format {
	case FormatE01:
		return "E01 (Forensic Image Format)"
	case FormatE01v2:
		return "E01v2 (Forensic Image Format v2)"
	case FormatAFF:
		return "AFF (Advanced Forensic Format)"
	case FormatRaw:
		return "Raw (Uncompressed)"
	default:
		return "Unknown"
	}
}

// Main entry point for demonstration
func main() {
	// Demo: Parse a sample image
	parser := NewImageParser()

	// Try to parse the current executable as a raw image
	err := parser.OpenImage("filecarve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing image: %v\n", err)
	}

	// Print the parsed information
	fmt.Println("=== Image Parser Results ===")
	fmt.Println(parser.FormatString())

	// Demo: Read raw data at a specific offset
	fmt.Println("\n=== Raw Data Demo ===")
	fmt.Println("Reading 64 bytes from offset 0x10000000...")
	
	data, err := parser.GetRawDataAt(0x10000000, 64)
	if err == nil {
		fmt.Printf("Data (hex): %x\n", data)
		fmt.Printf("Data (string): %s\n", string(data))
	} else {
		fmt.Printf("Error reading data: %v\n", err)
	}

	// Demo: List partitions
	fmt.Println("\n=== Partition Demo ===")
	if len(parser.GetInfo().PartitionInfo) > 0 {
		for i, part := range parser.GetInfo().PartitionInfo {
			fmt.Printf("Partition %d: Offset=0x%x, Size=%d, FS=%s, Mount=%s\n",
				i, part.Offset, part.Size, part.FSType, part.MountPoint)
		}
	} else {
		fmt.Println("No partitions found (raw image or single partition)")
	}

	// Demo: Seek to first partition
	if len(parser.GetInfo().PartitionInfo) > 0 {
		fmt.Println("\n=== Seek Demo ===")
		partition := parser.GetInfo().PartitionInfo[0]
		fmt.Printf("Seeking to partition at offset 0x%x...\n", partition.Offset)
		
		err = parser.SeekToPartition(0)
		if err == nil {
			fmt.Println("Seek successful")
		} else {
			fmt.Printf("Seek error: %v\n", err)
		}
	}

	// Cleanup
	parser.Close()

	// Demo: Parse command line arguments
	fmt.Println("\n=== Command Line Demo ===")
	if len(os.Args) > 1 {
		// Parse provided file
		parser2 := NewImageParser()
		err = parser2.OpenImage(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			fmt.Println(parser2.FormatString())
			parser2.Close()
		}
	} else {
		fmt.Println("Usage: filecarve [image_file]")
		fmt.Println("  image_file: Path to disk image (E01, AFF, or raw)")
		fmt.Println("\n  If no file provided, uses current executable as demo.")
	}
}