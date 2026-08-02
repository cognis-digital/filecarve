import java.io.*;
import java.nio.file.*;
import java.util.*;

public class signature_scanning {
    // Define a list of known file signatures (magic numbers)
    private static final Map<String, String> FILE_SIGNATURES = new HashMap<>();

    static {
        // Common file signatures (magic numbers)
        FILE_SIGNATURES.put("757365722D696E666F", "text/plain"); // text/plain
        FILE_SIGNATURES.put("424D", "image/bmp");               // BMP
        FILE_SIGNATURES.put("504B0304", "application/zip");     // ZIP
        FILE_SIGNATURES.put("504B0102", "application/zip");     // ZIP (old)
        FILE_SIGNATURES.put("49492A00", "image/tiff");          // TIFF
        FILE_SIGNATURES.put("49492B00", "image/tiff");          // TIFF
        FILE_SIGNATURES.put("4D4D002A", "image/tiff");          // TIFF
        FILE_SIGNATURES.put("4D4D002B", "image/tiff");          // TIFF
        FILE_SIGNATURES.put("52617221", "application/zip");     // RAR (partial)
        FILE_SIGNATURES.put("53847261", "application/zip");     // RAR (partial)
        FILE_SIGNATURES.put("504B0506", "application/zip");     // ZIP (old)
        FILE_SIGNATURES.put("494E4441", "application/zip");     // ZIP (partial)
        FILE_SIGNATURES.put("4D5A9000", "application/pe");       // PE (Windows executable)
        FILE_SIGNATURES.put("504B0708", "application/zip");     // ZIP (old)
        FILE_SIGNATURES.put("424D", "image/bmp");               // BMP
        FILE_SIGNATURES.put("49492A00", "image/tiff");          // TIFF
        FILE_SIGNATURES.put("4D4D002A", "image/tiff");          // TIFF
        FILE_SIGNATURES.put("52617221", "application/zip");     // RAR (partial)
        FILE_SIGNATURES.put("53847261", "application/zip");     // RAR (partial)
        FILE_SIGNATURES.put("504B0304", "application/zip");     // ZIP
        FILE_SIGNATURES.put("504B0102", "application/zip");     // ZIP (old)
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java signature_scanning <file_path>");
            return;
        }

        Path filePath = Paths.get(args[0]);
        if (!Files.exists(filePath)) {
            System.err.println("File not found: " + filePath);
            return;
        }

        try (RandomAccessFile raf = new RandomAccessFile(filePath.toFile(), "r")) {
            long fileSize = raf.length();
            byte[] buffer = new byte[1024];
            int bytesRead;

            System.out.println("Scanning file: " + filePath.getFileName());
            System.out.println("Looking for known file signatures...");

            while ((bytesRead = raf.read(buffer)) != -1) {
                for (int i = 0; i <= bytesRead - 4; i++) {
                    String signature = bytesToHex(Arrays.copyOfRange(buffer, i, i + 4));
                    if (FILE_SIGNATURES.containsKey(signature)) {
                        String mimeType = FILE_SIGNATURES.get(signature);
                        long offset = raf.getFilePointer() - bytesRead + i;
                        System.out.println("Found file signature: " + signature + " (" + mimeType + ") at offset: " + offset);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}