// polyglot/typescript/disk_image_processing.ts

import { createReadStream, Readable } from 'fs';
import { pipeline } from 'stream/promises';
import { join } from 'path';

// Define a signature-based file recovery function
async function carveFilesFromDiskImage(
  imagePath: string,
  signatures: Map<string, Uint8Array>,
  outputDir: string
): Promise<Map<string, string>> {
  const results = new Map<string, string>();

  // Process each signature
  for (const [signatureName, signature] of signatures.entries()) {
    const signatureBuffer = Buffer.from(signature);
    const signatureLength = signatureBuffer.length;

    let currentOffset = 0;
    const reader = createReadStream(imagePath);

    const buffer = Buffer.alloc(1024 * 64); // 64KB buffer for reading

    while (true) {
      const bytesRead = await new Promise<number>((resolve, reject) => {
        reader.read(buffer, 0, buffer.length, (err, bytesRead) => {
          if (err) reject(err);
          resolve(bytesRead);
        });
      });

      if (bytesRead === 0) break;

      // Check for signature in the current buffer
      let matchStart = -1;
      for (let i = 0; i <= bytesRead - signatureLength; i++) {
        let match = true;
        for (let j = 0; j < signatureLength; j++) {
          if (buffer[i + j] !== signatureBuffer[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          matchStart = i;
          break;
        }
      }

      if (matchStart !== -1) {
        // Found a match, carve the file
        const fileName = `${signatureName}_${currentOffset}.carved`;
        const outputPath = join(outputDir, fileName);

        const writer = createReadStream(imagePath, { start: currentOffset + matchStart, end: currentOffset + matchStart + 1024 * 64 });
        await pipeline(writer, createWriteStream(outputPath));

        results.set(signatureName, fileName);
        console.log(`Found ${signatureName} at offset ${currentOffset + matchStart}, saved to ${outputPath}`);
      }

      currentOffset += bytesRead;
    }
  }

  return results;
}

// Example usage
async function main() {
  const imagePath = 'disk_image.dd';
  const outputDir = 'carved_files';

  // Define some common file signatures (example: JPEG, PDF, ZIP)
  const signatures = new Map<string, Uint8Array>([
    ['JPEG', new Uint8Array([0xFF, 0xD8, 0xFF])],
    ['PDF', new Uint8Array([0x25, 0x50, 0x44, 0x46])],
    ['ZIP', new Uint8Array([0x50, 0x4B, 0x03, 0x04])],
  ]);

  try {
    await carveFilesFromDiskImage(imagePath, signatures, outputDir);
    console.log('File carving completed.');
  } catch (error) {
    console.error('Error during file carving:', error);
  }
}

// Run the demo
main();