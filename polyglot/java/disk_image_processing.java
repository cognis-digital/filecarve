package polyglot.java;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DiskImageProcessing {

    // Define known file signatures (magic numbers)
    private static final Map<String, byte[]> FILE_SIGNATURES = new HashMap<>();

    static {
        // Common file signatures
        FILE_SIGNATURES.put("JPEG", new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF});
        FILE_SIGNATURES.put("PNG", new byte[]{(byte) 0x89, (byte) 0x50, (byte) 0x4E, (byte) 0x47, (byte) 0x0D, (byte) 0x0A, (byte) 0x1A, (byte) 0x0A});
        FILE_SIGNATURES.put("ZIP", new byte[]{(byte) 0x50, (byte) 0x4B, (byte) 0x03, (byte) 0x04});
        FILE_SIGNATURES.put("PDF", new byte[]{(byte) 0x25, (byte) 0x50, (byte) 0x44, (byte) 0x46});
        FILE_SIGNATURES.put("MP3", new byte[]{(byte) 0x49, (byte) 0x44, (byte) 0x33});
        FILE_SIGNATURES.put("TXT", new byte[]{(byte) 0x42, (byte) 0x61, (byte) 0x73, (byte) 0x65});
        FILE_SIGNATURES.put("ELF", new byte[]{(byte) 0x7F, (byte) 0x45, (byte) 0x4C, (byte) 0x46});
        FILE_SIGNATURES.put("HTML", new byte[]{(byte) 0x3C, (byte) 0x21, (byte) 0x44, (byte) 0x4F, (byte) 0x43, (byte) 0x54, (byte) 0x59});
        FILE_SIGNATURES.put("GIF", new byte[]{(byte) 0x47, (byte) 0x49, (byte) 0x46, (byte) 0x38});
        FILE_SIGNATURES.put("BMP", new byte[]{(byte) 0x42, (byte) 0x4D});
    }

    // Carve files from a disk image by signature
    public static void carveFilesFromDiskImage(String diskImagePath, String outputDir) throws IOException {
        if (!Files.exists(Paths.get(diskImagePath))) {
            throw new FileNotFoundException("Disk image file not found: " + diskImagePath);
        }

        if (!Files.exists(Paths.get(outputDir))) {
            Files.createDirectories(Paths.get(outputDir));
        }

        try (RandomAccessFile raf = new RandomAccessFile(diskImagePath, "r")) {
            long fileSize = raf.length();
            byte[] buffer = new byte[1024 * 64]; // 64KB buffer for efficiency

            int fileCount = 0;
            long totalBytesProcessed = 0;

            for (long i = 0; i < fileSize; i++) {
                if (i + buffer.length > fileSize) {
                    buffer = Arrays.copyOf(buffer, (int) (fileSize - i));
                }

                raf.read(buffer, 0, buffer.length);

                // Search for file signatures
                for (Map.Entry<String, byte[]> entry : FILE_SIGNATURES.entrySet()) {
                    String fileType = entry.getKey();
                    byte[] signature = entry.getValue();

                    if (buffer.length >= signature.length) {
                        boolean match = true;
                        for (int j = 0; j < signature.length; j++) {
                            if (buffer[j] != signature[j]) {
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            // Found a file signature, start carving
                            long startPos = i - signature.length + 1;
                            long endPos = startPos + fileSize - i;

                            File outputFile = new File(outputDir, fileType + "_" + fileCount + "." + fileType.toLowerCase());
                            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                                raf.seek(startPos);
                                byte[] chunk = new byte[1024];
                                int bytesRead;
                                while ((bytesRead = raf.read(chunk)) != -1) {
                                    fos.write(chunk, 0, bytesRead);
                                    totalBytesProcessed += bytesRead;
                                }
                                fileCount++;
                                System.out.println("Recovered: " + outputFile.getName() + " (" + totalBytesProcessed + " bytes)");
                            }
                        }
                    }
                }
            }
        }
    }

    // Main entry point for demonstration
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java DiskImageProcessing <disk_image_path> <output_directory>");
            return;
        }

        String diskImagePath = args[0];
        String outputDir = args[1];

        try {
            System.out.println("Starting file carving from disk image...");
            carveFilesFromDiskImage(diskImagePath, outputDir);
            System.out.println("File carving completed.");
        } catch (Exception e) {
            System.err.println("Error during file carving: " + e.getMessage());
            e.printStackTrace();
        }
    }
}