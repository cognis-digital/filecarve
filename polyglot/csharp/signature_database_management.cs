using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace polyglot.csharp
{
    public class SignatureDatabase
    {
        private readonly Dictionary<string, List<Signature>> _signaturesByExtension = new Dictionary<string, List<Signature>>();
        private readonly Dictionary<string, List<Signature>> _signaturesByMagic = new Dictionary<string, List<Signature>>();

        public void AddSignature(string extension, string magic, int length, string description)
        {
            var signature = new Signature(extension, magic, length, description);
            if (!_signaturesByExtension.ContainsKey(extension))
            {
                _signaturesByExtension[extension] = new List<Signature>();
            }
            _signaturesByExtension[extension].Add(signature);

            if (!_signaturesByMagic.ContainsKey(magic))
            {
                _signaturesByMagic[magic] = new List<Signature>();
            }
            _signaturesByMagic[magic].Add(signature);
        }

        public IEnumerable<Signature> FindByExtension(string extension)
        {
            if (_signaturesByExtension.TryGetValue(extension, out var signatures))
            {
                return signatures;
            }
            return Enumerable.Empty<Signature>();
        }

        public IEnumerable<Signature> FindByMagic(string magic)
        {
            if (_signaturesByMagic.TryGetValue(magic, out var signatures))
            {
                return signatures;
            }
            return Enumerable.Empty<Signature>();
        }

        public void LoadFromFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Signature file not found: {filePath}");
            }

            var lines = File.ReadAllLines(filePath);
            foreach (var line in lines)
            {
                var parts = line.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4)
                {
                    continue;
                }
                var extension = parts[0];
                var magic = parts[1];
                if (!int.TryParse(parts[2], out int length))
                {
                    continue;
                }
                var description = parts[3];
                AddSignature(extension, magic, length, description);
            }
        }

        public void SaveToFile(string filePath)
        {
            using (var writer = new StreamWriter(filePath))
            {
                foreach (var entry in _signaturesByExtension)
                {
                    foreach (var signature in entry.Value)
                    {
                        writer.WriteLine($"{signature.Extension}\t{signature.Magic}\t{signature.Length}\t{signature.Description}");
                    }
                }
            }
        }

        public class Signature
        {
            public string Extension { get; }
            public string Magic { get; }
            public int Length { get; }
            public string Description { get; }

            public Signature(string extension, string magic, int length, string description)
            {
                Extension = extension;
                Magic = magic;
                Length = length;
                Description = description;
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var db = new SignatureDatabase();

            // Example: Add some signatures
            db.AddSignature("txt", "ASCII", 1, "Text file");
            db.AddSignature("jpg", "JFIF", 4, "JPEG image");
            db.AddSignature("png", "PNG", 8, "Portable Network Graphics");

            Console.WriteLine("Loaded signatures:");
            foreach (var sig in db.FindByExtension("txt"))
            {
                Console.WriteLine($"- {sig.Description} ({sig.Magic}, length: {sig.Length})");
            }

            // Example: Save to file
            string tempFilePath = Path.GetTempFileName();
            db.SaveToFile(tempFilePath);
            Console.WriteLine($"Saved signature database to {tempFilePath}");

            // Example: Load from file
            var loadedDb = new SignatureDatabase();
            loadedDb.LoadFromFile(tempFilePath);
            Console.WriteLine("Loaded signatures from file:");
            foreach (var sig in loadedDb.FindByMagic("ASCII"))
            {
                Console.WriteLine($"- {sig.Description} ({sig.Extension}, length: {sig.Length})");
            }

            // Clean up
            File.Delete(tempFilePath);
        }
    }
}