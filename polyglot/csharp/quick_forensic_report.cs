using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace polyglot.csharp
{
    class QuickForensicReport
    {
        // Constants for supported file types and their signatures
        private static readonly Dictionary<string, string> FileSignatures = new Dictionary<string, string>
        {
            { "JPEG", "FFD8" },
            { "PNG", "89504E47" },
            { "PDF", "25504446" },
            { "ZIP", "504B0304" },
            { "MP4", "0000001866746D79" },
            { "TXT", "44464620" }, // ASCII text
            { "EXE", "4D5A9000" },
            { "ELF", "7F454C46" },
            { "HTML", "68746D6C" },
            { "CSV", "4354554C" }
        };

        // Main entry point
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: QuickForensicReport <image_path>");
                return;
            }

            string imagePath = args[0];
            if (!File.Exists(imagePath))
            {
                Console.WriteLine($"Error: File not found: {imagePath}");
                return;
            }

            Console.WriteLine($"Quick Forensic Report for: {imagePath}");
            Console.WriteLine("=========================================");
            Console.WriteLine("Searching for known file signatures...");

            using (var reader = new BinaryReader(File.Open(imagePath, FileMode.Open, FileAccess.Read)))
            {
                long fileSize = new FileInfo(imagePath).Length;
                byte[] buffer = new byte[4096];
                int bytesRead;

                // Process the file in chunks
                for (long offset = 0; offset < fileSize; offset += buffer.Length)
                {
                    bytesRead = reader.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    // Check for each signature
                    foreach (var entry in FileSignatures)
                    {
                        string signature = entry.Value;
                        int sigLength = signature.Length / 2;
                        byte[] sigBytes = new byte[sigLength];

                        for (int i = 0; i < sigLength; i++)
                        {
                            byte b = Convert.ToByte(signature.Substring(i * 2, 2), 16);
                            sigBytes[i] = b;
                        }

                        // Search for the signature in the current buffer
                        int pos = Array.IndexOf(buffer, sigBytes, 0, bytesRead);
                        if (pos >= 0)
                        {
                            long fileOffset = offset + pos;
                            Console.WriteLine($"Found {entry.Key} at offset: {fileOffset:X}");
                        }
                    }
                }
            }

            Console.WriteLine("=========================================");
            Console.WriteLine("End of report.");
        }
    }
}