using System;
using System.IO;
using System.Collections.Generic;

namespace polyglot.csharp
{
    class DiskImageProcessor
    {
        // Represents a file signature with its name and byte pattern
        private class FileSignature
        {
            public string Name { get; }
            public byte[] Pattern { get; }
            public int Length { get; }

            public FileSignature(string name, byte[] pattern)
            {
                Name = name;
                Pattern = pattern;
                Length = pattern.Length;
            }
        }

        // List of known file signatures
        private static readonly List<FileSignature> KnownSignatures = new List<FileSignature>
        {
            new FileSignature("JPEG", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x45, 0x46, 0x49, 0x63, 0x00 }),
            new FileSignature("PNG", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }),
            new FileSignature("ZIP", new byte[] { 0x50, 0x4B, 0x03, 0x04 }),
            new FileSignature("PDF", new byte[] { 0x25, 0x50, 0x44, 0x46 }),
            new FileSignature("TXT", new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64 }),
            new FileSignature("MP3", new byte[] { 0x49, 0x44, 0x33, 0x03 }),
            new FileSignature("AVI", new byte[] { 0x41, 0x56, 0x49, 0x20, 0x33, 0x30, 0x31, 0x30 })
        };

        // Carve files from a disk image by known signatures
        public static void CarveFiles(string imagePath, string outputDir)
        {
            if (!Directory.Exists(outputDir))
                Directory.CreateDirectory(outputDir);

            using (var reader = new BinaryReader(File.OpenRead(imagePath)))
            {
                int offset = 0;
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    foreach (var signature in KnownSignatures)
                    {
                        if (reader.BaseStream.Position + signature.Length > reader.BaseStream.Length)
                            break;

                        byte[] buffer = new byte[signature.Length];
                        reader.Read(buffer, 0, buffer.Length);

                        if (CompareByteArrays(buffer, signature.Pattern))
                        {
                            string fileName = $"{signature.Name}_{offset}.carved";
                            string filePath = Path.Combine(outputDir, fileName);

                            // Carve the file by reading ahead until the end of the file
                            int fileSize = 0;
                            byte[] fileBuffer = new byte[4096];
                            using (var writer = new BinaryWriter(File.Create(filePath)))
                            {
                                while (true)
                                {
                                    int bytesRead = reader.Read(fileBuffer, 0, fileBuffer.Length);
                                    if (bytesRead == 0) break;

                                    writer.Write(fileBuffer, 0, bytesRead);
                                    fileSize += bytesRead;

                                    // Check for end of file signature or EOF
                                    if (fileSize > 1024 * 1024 * 10) // Limit to 10MB to prevent infinite loops
                                        break;
                                }
                            }

                            Console.WriteLine($"Found {signature.Name} at offset {offset} (size: {fileSize} bytes)");
                        }
                    }

                    offset += 1;
                }
            }
        }

        // Compare two byte arrays for equality
        private static bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }

            return true;
        }

        // Main entry point with demo
        public static void Main(string[] args)
        {
            string imagePath = "sample_disk_image.dd";
            string outputDir = "carved_files";

            Console.WriteLine("Starting disk image processing...");
            CarveFiles(imagePath, outputDir);
            Console.WriteLine("Processing complete.");
        }
    }
}