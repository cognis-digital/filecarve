import java.io.*;
import java.nio.file.*;
import java.util.*;

public class FileCarving {
    private static final String[] SIGNATURES = {
        "\x00\x00\x01\xB2\x00\x0C\x00\x00", // JPEG
        "\x49\x49\x2A\x00",                  // TIFF
        "\x42\x4D",                          // BMP
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", // PNG
        "\x52\x61\x72\x21\x19\x00\x00\x00", // RAR
        "\x50\x4B\x03\x04",                  // ZIP
        "\x47\x49\x46\x38",                  // GIF
        "\x25\x50\x44\x46",                  // PDF
        "\x00\x00\x01\xBA",                  // MP3
        "\x44\x46\x53\x2D"                   // DTS
    };

    private static final Map<String, String> SIGNATURE_MAP = new HashMap<>();
    static {
        for (int i = 0; i < SIGNATURES.length; i++) {
            SIGNATURE_MAP.put(SIGNATURES[i], getExtension(i));
        }
    }

    private static String getExtension(int index) {
        switch (index) {
            case 0: return "jpg";
            case 1: return "tiff";
            case 2: return "bmp";
            case 3: return "png";
            case 4: return "rar";
            case 5: return "zip";
            case 6: return "gif";
            case 7: return "pdf";
            case 8: return "mp3";
            case 9: return "dts";
            default: return "unknown";
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java FileCarving <input_file> <output_dir>");
            return;
        }

        String inputPath = args[0];
        String outputPath = args[1];

        try {
            carveFiles(inputPath, outputPath);
            System.out.println("File carving completed.");
        } catch (IOException e) {
            System.err.println("Error during file carving: " + e.getMessage());
        }
    }

    public static void carveFiles(String inputFilePath, String outputDir) throws IOException {
        Path input = Paths.get(inputFilePath);
        if (!Files.exists(input)) {
            throw new FileNotFoundException("Input file not found: " + inputFilePath);
        }

        if (!Files.exists(Paths.get(outputDir))) {
            Files.createDirectories(Paths.get(outputDir));
        }

        byte[] buffer = new byte[4096];
        int bytesRead;
        List<byte[]> files = new ArrayList<>();

        try (RandomAccessFile raf = new RandomAccessFile(input.toFile(), "r")) {
            long fileLength = raf.length();
            long position = 0;

            while (position < fileLength) {
                bytesRead = raf.read(buffer, 0, buffer.length);
                if (bytesRead == -1) break;

                for (int i = 0; i < bytesRead - 3; i++) {
                    byte[] signatureBytes = new byte[4];
                    System.arraycopy(buffer, i, signatureBytes, 0, 4);
                    String signature = bytesToHex(signatureBytes);

                    if (SIGNATURE_MAP.containsKey(signature)) {
                        String ext = SIGNATURE_MAP.get(signature);
                        String fileName = "carved_" + ext + "_" + System.currentTimeMillis() + "." + ext;
                        Path outFile = Paths.get(outputDir, fileName);

                        // Extract file from buffer
                        int start = i;
                        int end = i + bytesRead;
                        byte[] content = new byte[end - start];
                        System.arraycopy(buffer, start, content, 0, content.length);
                        Files.write(outFile, content);
                    }
                }

                position += bytesRead;
            }
        }

        System.out.println("Carved files saved to: " + outputDir);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}