using System;
using System.IO;
using System.Collections.Generic;

namespace polyglot.csharp
{
    class SignatureScanner
    {
        // Represents a file signature with name, description, and byte pattern
        public class FileSignature
        {
            public string Name { get; }
            public string Description { get; }
            public byte[] Pattern { get; }

            public FileSignature(string name, string description, byte[] pattern)
            {
                Name = name;
                Description = description;
                Pattern = pattern;
            }
        }

        // Main entry point for the signature scanning tool
        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: SignatureScanner <image_path> <signature_file>");
                return;
            }

            string imagePath = args[0];
            string signatureFilePath = args[1];

            try
            {
                // Load predefined signatures from a file
                List<FileSignature> signatures = LoadSignatures(signatureFilePath);

                // Read the image file
                byte[] imageData = File.ReadAllBytes(imagePath);
                int imageSize = imageData.Length;

                Console.WriteLine($"Scanning {imageSize} bytes for known file signatures...");

                // Scan the image for all signatures
                foreach (var signature in signatures)
                {
                    List<int> matches = FindMatches(imageData, signature.Pattern);
                    if (matches.Count > 0)
                    {
                        Console.WriteLine($"Found {signature.Name} ({signature.Description}) at offsets: {string.Join(", ", matches)}");
                    }
                }

                Console.WriteLine("Scan complete.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        // Load file signatures from a text file
        private static List<FileSignature> LoadSignatures(string filePath)
        {
            var signatures = new List<FileSignature>();
            try
            {
                string[] lines = File.ReadAllLines(filePath);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                    {
                        continue;
                    }

                    // Split the line into name, description, and pattern
                    string[] parts = line.Split(new[] { '\t', ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3)
                    {
                        Console.WriteLine($"Invalid signature line: {line}");
                        continue;
                    }

                    string name = parts[0];
                    string description = parts[1];
                    byte[] pattern = Convert.FromHexString(parts[2]);

                    signatures.Add(new FileSignature(name, description, pattern));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading signatures: {ex.Message}");
            }

            return signatures;
        }

        // Find all matches of a byte pattern in a byte array
        private static List<int> FindMatches(byte[] data, byte[] pattern)
        {
            int dataLength = data.Length;
            int patternLength = pattern.Length;
            List<int> matches = new List<int>();

            for (int i = 0; i <= dataLength - patternLength; i++)
            {
                bool match = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    matches.Add(i);
                }
            }

            return matches;
        }
    }
}