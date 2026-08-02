import java.io.*;
import java.util.*;

public class signature_database_management {
    // Signature database structure: Map of file extensions to List of byte arrays (signatures)
    private static final Map<String, List<byte[]>> signatureDatabase = new HashMap<>();

    // Load signatures from a file
    public static void loadSignatures(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                String[] parts = line.split("\\s+", 3);
                if (parts.length < 2) continue;

                String extension = parts[1];
                byte[] signature = hexStringToByteArray(parts[0]);

                signatureDatabase.putIfAbsent(extension, new ArrayList<>());
                signatureDatabase.get(extension).add(signature);
            }
        }
    }

    // Convert hex string to byte array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Search for signatures in a byte array
    public static Set<String> findSignatures(byte[] data) {
        Set<String> foundExtensions = new HashSet<>();
        for (Map.Entry<String, List<byte[]>> entry : signatureDatabase.entrySet()) {
            String extension = entry.getKey();
            for (byte[] signature : entry.getValue()) {
                if (matchSignature(data, signature)) {
                    foundExtensions.add(extension);
                    break; // No need to check other signatures for this extension
                }
            }
        }
        return foundExtensions;
    }

    // Match a signature against data
    private static boolean matchSignature(byte[] data, byte[] signature) {
        int dataLength = data.length;
        int sigLength = signature.length;

        if (sigLength > dataLength) return false;

        for (int i = 0; i <= dataLength - sigLength; i++) {
            boolean match = true;
            for (int j = 0; j < sigLength; j++) {
                if (data[i + j] != signature[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    // Main entry point for demonstration
    public static void main(String[] args) {
        try {
            // Load a sample signature database (format: hex_signature <extension>)
            loadSignatures("signatures.txt");

            // Simulate data to search
            byte[] testData = {
                0x42, 0x45, 0x47, 0x49, 0x4E, 0x46, 0x4F, 0x4C, 0x45, 0x20, 0x31, 0x32, 0x33, 0x20, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
            };

            // Find matching signatures
            Set<String> foundExtensions = findSignatures(testData);
            System.out.println("Found file extensions: " + foundExtensions);

        } catch (IOException e) {
            System.err.println("Error loading signature database: " + e.getMessage());
        }
    }
}