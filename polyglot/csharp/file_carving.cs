using System;
using System.IO;
using System.Collections.Generic;

namespace polyglot.csharp
{
    class FileCarving
    {
        // Define common file signatures for various file types
        private static readonly Dictionary<string, byte[]> FileSignatures = new Dictionary<string, byte[]>
        {
            { "JPEG", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x0 } },
            { "PNG", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } },
            { "PDF", new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E } },
            { "ZIP", new byte[] { 0x50, 0x4B, 0x03, 0x04 } },
            { "TXT", new byte[] { 0x42, 0x61, 0x74, 0x63, 0x68 } }, // "BATCH"
            { "HTML", new byte[] { 0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x79, 0x70, 0x61, 0x64 } } // "<!DOCTYPE"
        };

        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: FileCarving <input_file> <output_directory>");
                return;
            }

            string inputFilePath = args[0];
            string outputDirectory = args[1];

            if (!Directory.Exists(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }

            using (var reader = new BinaryReader(File.Open(inputFilePath, FileMode.Open)))
            {
                byte[] buffer = new byte[4096];
                int bytesRead;
                int offset = 0;

                while ((bytesRead = reader.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < bytesRead - 4; i++)
                    {
                        byte[] signatureBytes = new byte[4];
                        Array.Copy(buffer, i, signatureBytes, 0, 4);

                        foreach (var entry in FileSignatures)
                        {
                            if (entry.Value.Length == 4 && CompareByteArrays(signatureBytes, entry.Value))
                            {
                                string fileName = $"{outputDirectory}/{entry.Key}_{offset}.carved";
                                SaveFile(reader, fileName, buffer, i, offset);
                                offset += bytesRead;
                                break;
                            }
                        }
                    }
                }
            }

            Console.WriteLine("File carving completed.");
        }

        private static bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        private static void SaveFile(BinaryReader reader, string fileName, byte[] buffer, int startOffset, int offset)
        {
            int bytesRead = 0;
            List<byte> fileData = new List<byte>();

            while (true)
            {
                int read = reader.Read(buffer, 0, buffer.Length);
                if (read <= 0) break;

                bytesRead += read;

                for (int i = 0; i < read; i++)
                {
                    fileData.Add(buffer[i]);
                }

                // Check for end of file signature or EOF
                if (fileData.Count >= 4)
                {
                    byte[] endSignature = new byte[4];
                    Array.Copy(fileData.ToArray(), fileData.Count - 4, endSignature, 0, 4);

                    if (endSignature[0] == 0x49 && endSignature[1] == 0x49 && endSignature[2] == 0x20 && endSignature[3] == 0x36) // "II 6" for JPEG
                    {
                        break;
                    }
                }

                if (offset + bytesRead >= reader.BaseStream.Length)
                {
                    break;
                }
            }

            File.WriteAllBytes(fileName, fileData.ToArray());
            Console.WriteLine($"Saved: {fileName}");
        }
    }
}