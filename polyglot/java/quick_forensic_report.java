package polyglot.java;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Quick Forensic Report Generator for filecarve tool.
 * Scans raw images/dumps and produces a fast signature-based report.
 */
public class quick_forensic_report {

    private static final int DEFAULT_SCAN_SIZE = 1024 * 1024; // 1MB chunks
    private static final int MAGIC_HEADER_SIZE = 64;
    
    /** Known file signatures: offset -> (size, type name) */
    private Map<Integer, FileSignature> knownSignatures;

    public quick_forensic_report() {
        this.knownSignatures = new HashMap<>();
        initKnownSignatures();
    }

    private void initKnownSignatures() {
        // PE/EXE/DLL (Windows)
        addSig(0x4D50, "PE32+ Executable", 64);
        addSig(0x4D5A, "PE32 Executable", 64);
        
        // ELF (Linux/BSD)
        addSig(0x7F454C46, "ELF Executable", 16);
        addSig(0x7F454C46, "ELF Shared Object", 16);
        addSig(0x7F454C46, "ELF Relocatable", 16);
        
        // Mach-O (macOS)
        addSig(0xFAED, "Mach-O Fat Binary", 8);
        addSig(0xFEFD, "Mach-O Executable", 8);
        
        // ZIP/PEM (portable executable)
        addSig(0x50454D30, "ZIP Archive", 4);
        addSig(0x50454D30, "PEM Archive", 4);
        
        // Common data formats for quick detection
        addSig(0x25504446, "PDF Document", 4);
        addSig(0x7A616B20, "ZIP File", 4);
        addSig(0x30303030, "JPEG Image", 4); // JFIF marker
    }

    private void addSig(int magic, String typeName, int headerSize) {
        this.knownSignatures.put(magic, new FileSignature(headerSize, typeName));
    }

    /**
     * Main carving operation. Returns list of found files with offsets and sizes.
     */
    public List<FoundFile> carve(Path imagePath, long offsetHint) throws IOException {
        if (!Files.exists(imagePath)) {
            throw new IllegalArgumentException("Image path does not exist: " + imagePath);
        }

        FileChannel channel = FileChannel.open(imagePath);
        long fileSize = channel.size();
        
        List<FoundFile> results = new ArrayList<>();
        AtomicLong currentOffset = new AtomicLong(offsetHint > 0 ? offsetHint : 0);
        
        // Scan with reasonable chunk size for speed vs coverage tradeoff
        int chunkSize = (int) Math.min(DEFAULT_SCAN_SIZE, fileSize - currentOffset.get());
        
        while (currentOffset.get() < fileSize) {
            long scanStart = currentOffset.get();
            long scanEnd = Math.min(scanStart + chunkSize, fileSize);
            
            // Read header for signature detection
            ByteBuffer buffer = ByteBuffer.allocate(MAGIC_HEADER_SIZE);
            channel.position((int) scanStart);
            int bytesRead = channel.read(buffer);
            buffer.flip();
            
            if (bytesRead > 0) {
                int magic = buffer.getInt(0);
                
                // Check against known signatures
                FileSignature sig = this.knownSignatures.get(magic);
                if (sig != null) {
                    long estimatedSize = estimateFileSize(scanStart, scanEnd, sig.headerSize);
                    
                    FoundFile found = new FoundFile();
                    found.offset = scanStart;
                    found.size = (int) Math.min(estimatedSize, fileSize - scanStart);
                    found.typeName = sig.typeName;
                    results.add(found);
                }
            }
            
            currentOffset.set(scanEnd);
        }
        
        channel.close();
        return results;
    }

    /**
     * Estimate file size based on header patterns and typical sizes.
     */
    private long estimateFileSize(long start, long end, int headerSize) {
        // Heuristic: assume files are at least 4KB for executables
        if (headerSize > 64) return end - start;
        
        // For smaller headers, use typical minimum sizes
        switch (headerSize) {
            case 8:  // Mach-O
                return Math.max(1024L, end - start);
            case 16: // ELF
                return Math.max(16384L, end - start);
            case 64: // PE
                return Math.max(65536L, end - start);
            default:
                return end - start;
        }
    }

    /**
     * Generate a quick report summary.
     */
    public String generateReport(List<FoundFile> files) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("=== QUICK FORENSIC REPORT ===\n");
        sb.append(String.format("%-60s %12s %s\n", "OFFSET", "SIZE (bytes)", "TYPE"));
        sb.append("------------------------------------------------------------------------\n");
        
        if (files.isEmpty()) {
            sb.append("No known signatures found in the scanned region.\n");
        } else {
            // Sort by offset for readability
            files.sort((a, b) -> Long.compare(a.offset, b.offset));
            
            int totalSize = 0;
            for (FoundFile f : files) {
                sb.append(String.format("%-60d %12d %-40s\n", 
                    f.offset, f.size, f.typeName));
                totalSize += f.size;
            }
            
            sb.append("------------------------------------------------------------------------\n");
            sb.append(String.format("Total identified: %d files, %.3f MB\n", 
                files.size(), (totalSize / 1024.0 / 1024.0)));
        }
        
        return sb.toString();
    }

    /**
     * Convenience method for one-shot operation with report output.
     */
    public void runQuickScan(Path imagePath) throws IOException {
        List<FoundFile> results = carve(imagePath, 0);
        System.out.println(generateReport(results));
    }

    // ===========================================
    // Inner classes and data structures
    // ===========================================

    private static class FileSignature {
        final int headerSize;
        final String typeName;

        FileSignature(int h, String t) {
            this.headerSize = h;
            this.typeName = t;
        }
    }

    public static class FoundFile {
        long offset;
        int size;
        String typeName;

        @Override
        public String toString() {
            return "FoundFile{offset=" + offset + ", size=" + size + 
                   ", type='" + typeName + "'}";
        }
    }

    // ===========================================
    // Demo / Entry Point
    // ===========================================

    public static void main(String[] args) throws Exception {
        quick_forensic_report scanner = new quick_forensic_report();

        if (args.length == 0) {
            System.out.println("Usage: java polyglot.java.quick_forensic_report <image_path>");
            System.out.println("\nDemo with sample data...");
            
            // Create a minimal test image with embedded signatures
            Path tempImage = Files.createTempFile("test_image_", ".raw");
            
            try {
                ByteBuffer buffer = ByteBuffer.allocate(1024 * 64); // 64KB
                
                // Add PE header at offset 0x1000 (simulating a file inside)
                int peMagic = 0x4D50; // PE32+
                buffer.putInt(peMagic);
                
                // Add ELF header at offset 0x2000
                int elfMagic = 0x7F454C46;
                buffer.putInt(elfMagic);
                
                // Add PDF magic at offset 0x3000
                int pdfMagic = 0x25504446;
                buffer.putInt(pdfMagic);
                
                // Fill rest with zeros
                while (buffer.position() < buffer.capacity()) {
                    buffer.put((byte) 0);
                }
                
                buffer.flip();
                Files.write(tempImage, buffer.array());
                
                System.out.println("Created test image: " + tempImage.toAbsolutePath());
                System.out.println("\n--- Scanning test image ---\n");
                
                scanner.runQuickScan(tempImage);
                
            } finally {
                // Cleanup demo file
                Files.deleteIfExists(tempImage);
            }
        } else {
            Path imagePath = Paths.get(args[0]);
            System.out.println("Scanning: " + imagePath.toAbsolutePath());
            scanner.runQuickScan(imagePath);
        }
    }
}