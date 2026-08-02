import os
import sys
import struct
from typing import BinaryIO, Optional, List, Tuple

# Constants for common file signatures
COMMON_SIGNATURES = {
    b'\x50\x4b\x03\x04': ('.zip', 'application/zip'),
    b'\x42\x4d': ('.bmp', 'image/bmp'),
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': ('.png', 'image/png'),
    b'\xff\xd8\xff': ('.jpg', 'image/jpeg'),
    b'\x49\x49\x2a': ('.tiff', 'image/tiff'),
    b'\x49\x49\x00\x00': ('.tiff', 'image/tiff'),
    b'\x4d\x5a': ('.exe', 'application/x-dosexec'),
    b'\x52\x61\x72\x21': ('.rar', 'application/x-rar-compressed'),
    b'\x00\x00\x01\x00': ('.wav', 'audio/x-wav'),
    b'\x43\x44\x30\x30': ('.cda', 'audio/cda'),
    b'\x28\x66\x67\x32': ('.gif', 'image/gif'),
    b'\x57\x49\x4e\x54': ('.tiff', 'image/tiff'),
    b'\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': ('.mp4', 'video/mp4'),
    b'\x1f\x8b\x08': ('.gz', 'application/gzip'),
    b'\x75\x73\x74\x61\x72\x00\x30\x30\x30\x30': ('.tar', 'application/x-tar'),
}

def read_chunk(file: BinaryIO, size: int) -> bytes:
    """Read a chunk of data from the file."""
    return file.read(size)

def find_signature(file: BinaryIO, signature: bytes, offset: int = 0, max_search: int = 1024 * 1024) -> Optional[int]:
    """Find the first occurrence of a signature in the file starting from a given offset."""
    file.seek(offset)
    buffer = read_chunk(file, min(max_search, 16 * 1024))
    return buffer.find(signature) + offset if signature in buffer else None

def carve_files_from_memory_dump(memory_dump_path: str, output_dir: str, max_search: int = 1024 * 1024) -> List[Tuple[str, str]]:
    """Carve files from a memory dump by searching for common file signatures."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    carved_files = []

    with open(memory_dump_path, 'rb') as f:
        offset = 0
        while True:
            found_offsets = []
            for sig, (ext, mime) in COMMON_SIGNATURES.items():
                pos = find_signature(f, sig, offset, max_search)
                if pos is not None:
                    found_offsets.append((pos, sig, ext, mime))

            if not found_offsets:
                break

            # Sort by position to handle overlapping signatures
            found_offsets.sort()
            for pos, sig, ext, mime in found_offsets:
                if pos < offset:
                    continue  # Skip already processed positions

                # Determine the end of the file (or use max_search)
                end_pos = pos + len(sig)
                f.seek(pos)
                content = read_chunk(f, max_search)
                end = content.find(sig) + len(sig) if sig in content else pos + len(sig)

                # Extract the file
                file_name = os.path.join(output_dir, f"carved_{len(carved_files)}_{ext}")
                with open(file_name, 'wb') as out_file:
                    out_file.write(content[:end - pos])

                carved_files.append((file_name, mime))
                offset = end

    return carved_files

def main():
    if len(sys.argv) != 3:
        print("Usage: python memory_dump_analysis.py <memory_dump_path> <output_directory>")
        sys.exit(1)

    memory_dump_path = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(memory_dump_path):
        print(f"Error: Memory dump file '{memory_dump_path}' not found.")
        sys.exit(1)

    carved_files = carve_files_from_memory_dump(memory_dump_path, output_dir)
    print(f"Found and carved {len(carved_files)} files:")
    for file_name, mime in carved_files:
        print(f"  {file_name} ({mime})")

if __name__ == "__main__":
    main()