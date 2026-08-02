// polyglot/typescript/memory_dump_analysis.ts

import { createReadStream, Readable } from 'fs';
import { pipeline } from 'stream/promises';
import { join } from 'path';

// Define the signature for a common file type (e.g., NTFS file record)
interface FileSignature {
  name: string;
  pattern: Uint8Array;
}

// List of known file signatures for memory dump analysis
const knownSignatures: FileSignature[] = [
  {
    name: "NTFS File Record",
    pattern: new Uint8Array([0x80, 0x00, 0x00, 0x00]), // NTFS file record signature
  },
  {
    name: "Windows Executable (PE)",
    pattern: new Uint8Array([0x4D, 0x5A, 0x90, 0x00]), // 'MZ' header
  },
  {
    name: "ELF Executable",
    pattern: new Uint8Array([0x7F, 0x45, 0x4C, 0x46]), // ELF magic number
  },
  {
    name: "ZIP Archive",
    pattern: new Uint8Array([0x50, 0x4B, 0x03, 0x04]), // ZIP local file header
  },
];

// Function to carve files by signature from a memory dump stream
async function carveBySignature(stream: Readable, signatures: FileSignature[]): Promise<{ [key: string]: Uint8Array }> {
  const carvedFiles: { [key: string]: Uint8Array } = {};

  let buffer: Uint8Array[] = [];
  let currentOffset = 0;

  for await (const chunk of stream) {
    const chunkBuffer = new Uint8Array(chunk);
    buffer.push(chunkBuffer);

    // Check for any signature in the current buffer
    for (const sig of signatures) {
      const pattern = sig.pattern;
      const bufferLength = buffer.length;
      const bufferView = new Uint8Array(buffer.flat());
      const end = bufferView.length - pattern.length;

      for (let i = 0; i <= end; i++) {
        let match = true;
        for (let j = 0; j < pattern.length; j++) {
          if (bufferView[i + j] !== pattern[j]) {
            match = false;
            break;
          }
        }

        if (match) {
          // Extract the file content from the buffer
          const start = i;
          const endOfFile = i + pattern.length;
          const fileContent = bufferView.slice(start, endOfFile);

          // Create a unique filename based on signature and offset
          const fileName = `${sig.name}_offset_${currentOffset}.bin`;
          carvedFiles[fileName] = fileContent;

          // Remove the processed part of the buffer to avoid duplication
          buffer = buffer.map(chunk => chunk.slice(endOfFile));
          currentOffset += endOfFile;
          break;
        }
      }
    }
  }

  return carvedFiles;
}

// Main function to run memory dump analysis
async function analyzeMemoryDump(filePath: string): Promise<void> {
  console.log(`Analyzing memory dump at: ${filePath}`);

  const readStream = createReadStream(filePath);
  const carvedFiles = await carveBySignature(readStream, knownSignatures);

  if (Object.keys(carvedFiles).length === 0) {
    console.log("No files found by signature.");
    return;
  }

  console.log("Found files by signature:");
  for (const [name, content] of Object.entries(carvedFiles)) {
    console.log(`- ${name} (${content.length} bytes)`);
  }

  // Optionally write carved files to disk
  for (const [name, content] of Object.entries(carvedFiles)) {
    const outputPath = join(__dirname, `carved_${name}`);
    const writerStream = createReadStream(new Uint8Array(content));
    await pipeline(writerStream, createWriteStream(outputPath));
    console.log(`Wrote ${name} to ${outputPath}`);
  }
}

// Entry point for demonstration
if (process.argv.length > 2) {
  const memoryDumpPath = process.argv[2];
  analyzeMemoryDump(memoryDumpPath).catch(console.error);
}