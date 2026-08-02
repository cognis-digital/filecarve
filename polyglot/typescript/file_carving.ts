// polyglot/typescript/file_carving.ts

import { createReadStream, createWriteStream, Readable, Writable } from 'fs';
import { pipeline } from 'stream/promises';
import { join } from 'path';

// Define a signature-based file carver
interface FileSignature {
  name: string;
  signature: string;
  offset?: number;
  length?: number;
}

class FileCarver {
  private signatures: FileSignature[];
  private outputDir: string;

  constructor(signatures: FileSignature[], outputDir: string) {
    this.signatures = signatures;
    this.outputDir = outputDir;
  }

  async carve(inputPath: string): Promise<void> {
    const readStream = createReadStream(inputPath);
    const writeStream = createWriteStream(join(this.outputDir, 'carved_files.log'));

    let currentFileContent = '';
    let currentFileName = '';

    readStream.on('data', (chunk) => {
      for (const signature of this.signatures) {
        const match = chunk.toString().match(new RegExp(signature.signature, 'g'));
        if (match) {
          // Handle multiple matches in the same chunk
          for (const matchStr of match) {
            if (currentFileContent.length > 0) {
              // Write previous file if any
              this.writeToFile(currentFileName, currentFileContent);
              currentFileContent = '';
              currentFileName = '';
            }
            // Start new file
            currentFileName = `${signature.name}_${Date.now()}.carved`;
            currentFileContent += matchStr;
          }
        }
      }
    });

    readStream.on('end', () => {
      if (currentFileContent.length > 0) {
        this.writeToFile(currentFileName, currentFileContent);
      }
      writeStream.end();
    });

    readStream.on('error', (err) => {
      console.error(`Error reading input file: ${err.message}`);
    });

    writeStream.on('error', (err) => {
      console.error(`Error writing output log: ${err.message}`);
    });
  }

  private writeToFile(filename: string, content: string): void {
    if (filename && content.length > 0) {
      const filePath = join(this.outputDir, filename);
      const fileStream = createWriteStream(filePath);
      fileStream.write(content);
      fileStream.end();
    }
  }
}

// Demo entry point
async function runDemo(): Promise<void> {
  const outputDir = join(__dirname, 'output');
  const inputPath = join(__dirname, 'test_disk_image.bin');

  // Define some common file signatures for demonstration
  const signatures: FileSignature[] = [
    { name: 'JPEG', signature: '\xFF\xD8\xFF', offset: 0 },
    { name: 'PNG', signature: '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' },
    { name: 'ZIP', signature: '\x50\x4B\x03\x04' },
    { name: 'PDF', signature: '%PDF-' },
    { name: 'TXT', signature: '\x0D\x0A' }
  ];

  // Create output directory if it doesn't exist
  const fs = require('fs').promises;
  await fs.mkdir(outputDir, { recursive: true });

  console.log(`Carving files from ${inputPath}...`);
  const carver = new FileCarver(signatures, outputDir);
  await carver.carve(inputPath);
  console.log(`File carving completed. Results saved in ${outputDir}`);
}

// Run the demo
runDemo().catch((err) => {
  console.error(`Demo failed: ${err.message}`);
});