import java.io.*;
import java.nio.file.*;
import java.util.*;

public class memory_dump_analysis {
    // Define common file signatures for common file types
    private static final Map<String, byte[]> FILE_SIGNATURES = new HashMap<>();

    static {
        // Common file signatures (first 4 bytes)
        FILE_SIGNATURES.put("PE", new byte[]{(byte)0x4D, 0x5A}); // PE header
        FILE_SIGNATURES.put("ELF", new byte[]{0x7F, 0x45, 0x4C, 0x46}); // ELF header
        FILE_SIGNATURES.put("ZIP", new byte[]{0x50, 0x4B, 0x03, 0x04}); // ZIP archive
        FILE_SIGNATURES.put("JPEG", new byte[]{0xFF, 0xD8, 0xFF, 0xE0}); // JPEG file
        FILE_SIGNATURES.put("PNG", new byte[]{0x89, 0x50, 0x4E, 0x47}); // PNG file
        FILE_SIGNATURES.put("PDF", new byte[]{0x25, 0x50, 0x44, 0x46}); // PDF file
        FILE_SIGNATURES.put("TXT", new byte[]{0x42, 0x4D}); // Not exact, but used for demo
        FILE_SIGNATURES.put("EXE", new byte[]{(byte)0x4D, 0x5A}); // Same as PE
        FILE_SIGNATURES.put("HTML", new byte[]{0x3C, 0x21, 0x44, 0x4F}); // <!DOCTYPE
        FILE_SIGNATURES.put("CSV", new byte[]{0x43, 0x57, 0x69, 0x64}); // CSV (not exact, but used for demo)
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java memory_dump_analysis <memory_dump_file>");
            return;
        }

        String dumpFilePath = args[0];
        try {
            carveFilesFromDump(dumpFilePath);
        } catch (IOException e) {
            System.err.println("Error processing memory dump: " + e.getMessage());
        }
    }

    private static void carveFilesFromDump(String dumpFilePath) throws IOException {
        Path dumpPath = Paths.get(dumpFilePath);
        if (!Files.exists(dumpPath)) {
            System.err.println("Memory dump file not found: " + dumpFilePath);
            return;
        }

        byte[] dumpData = Files.readAllBytes(dumpPath);
        int fileSize = dumpData.length;

        System.out.println("Analyzing memory dump of size: " + fileSize + " bytes");
        System.out.println("Looking for known file signatures...");

        // Search for file signatures in the memory dump
        Set<Integer> foundOffsets = new HashSet<>();
        for (int i = 0; i < fileSize - 3; i++) {
            byte[] signatureBytes = new byte[4];
            System.arraycopy(dumpData, i, signatureBytes, 0, 4);
            String signatureKey = getSignatureKey(signatureBytes);
            if (FILE_SIGNATURES.containsKey(signatureKey)) {
                foundOffsets.add(i);
            }
        }

        // Output found file signatures
        if (foundOffsets.isEmpty()) {
            System.out.println("No known file signatures found in memory dump.");
        } else {
            System.out.println("Found potential files at offsets: " + foundOffsets);
            System.out.println("Recovering files...");

            for (int offset : foundOffsets) {
                int fileSizeToExtract = 1024; // Example size, can be adjusted
                int endOffset = Math.min(offset + fileSizeToExtract, dumpData.length);
                byte[] extractedData = Arrays.copyOfRange(dumpData, offset, endOffset);

                String fileName = getFileNameFromSignature(FILE_SIGNATURES.keySet().stream()
                        .filter(k -> getSignatureKey(getSignatureBytesFromFileContent(extractedData)) != null)
                        .findFirst().orElse("unknown"));

                Path outputFilePath = Paths.get("recovered_files", fileName + ".carved");
                Files.createDirectories(outputFilePath.getParent());
                Files.write(outputFilePath, extractedData);

                System.out.println("Recovered file: " + outputFilePath);
            }
        }
    }

    private static String getSignatureKey(byte[] signatureBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : signatureBytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }

    private static byte[] getSignatureBytesFromFileContent(byte[] content) {
        return Arrays.copyOf(content, Math.min(4, content.length));
    }

    private static String getFileNameFromSignature(String signatureKey) {
        for (Map.Entry<String, byte[]> entry : FILE_SIGNATURES.entrySet()) {
            if (getSignatureKey(entry.getValue()).equals(signatureKey)) {
                return entry.getKey();
            }
        }
        return "unknown";
    }
}