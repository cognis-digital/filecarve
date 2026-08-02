import os
import sys
from collections import defaultdict
from typing import BinaryIO, Dict, List, Optional, Tuple

def read_chunk(file: BinaryIO, size: int = 65536) -> bytes:
    """Read a chunk of data from the file."""
    return file.read(size)

def find_signatures_in_chunk(chunk: bytes, signatures: Dict[bytes, str]) -> Dict[str, List[int]]:
    """Find all matching signatures in a chunk."""
    matches = defaultdict(list)
    for sig, name in signatures.items():
        pos = 0
        while True:
            pos = chunk.find(sig, pos)
            if pos == -1:
                break
            matches[name].append(pos)
            pos += 1  # Avoid infinite loop with overlapping matches
    return matches

def find_signatures_in_file(file_path: str, signatures: Dict[bytes, str], buffer_size: int = 65536) -> Dict[str, List[int]]:
    """Find all matching signatures in a file."""
    matches = defaultdict(list)
    with open(file_path, "rb") as f:
        while True:
            chunk = read_chunk(f, buffer_size)
            if not chunk:
                break
            chunk_matches = find_signatures_in_chunk(chunk, signatures)
            for name, positions in chunk_matches.items():
                matches[name].extend(positions)
    return matches

def load_signatures(signature_file: str) -> Dict[bytes, str]:
    """Load a list of byte signatures from a file."""
    signatures = {}
    with open(signature_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) < 2:
                continue
            sig_str, name = parts[0], parts[1]
            try:
                sig_bytes = bytes.fromhex(sig_str)
                signatures[sig_bytes] = name
            except Exception as e:
                print(f"Error parsing signature: {e}", file=sys.stderr)
    return signatures

def carve_files_from_image(image_path: str, signature_file: str, output_dir: str) -> None:
    """Carve files from a disk image using provided signatures."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    signatures = load_signatures(signature_file)
    if not signatures:
        print("No valid signatures loaded.", file=sys.stderr)
        return

    with open(image_path, "rb") as f:
        buffer_size = 65536
        buffer = bytearray(buffer_size)
        offset = 0
        while True:
            bytes_read = f.readinto(buffer)
            if bytes_read == 0:
                break
            for sig, name in signatures.items():
                pos = 0
                while pos <= bytes_read - len(sig):
                    if buffer[pos:pos+len(sig)] == sig:
                        file_name = f"{name}_{offset}.carved"
                        file_path = os.path.join(output_dir, file_name)
                        with open(file_path, "wb") as out_file:
                            # Read the entire file starting from offset
                            f.seek(offset)
                            data = f.read()
                            out_file.write(data)
                        print(f"Found {name} at offset {offset}, saved to {file_path}")
                        break
                    pos += 1
            offset += bytes_read

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Carve files from disk images using signature matching.")
    parser.add_argument("image", help="Path to the disk image or memory dump")
    parser.add_argument("signatures", help="Path to the file containing signatures (hex strings)")
    parser.add_argument("--output", default="carved_files", help="Output directory for carved files")
    args = parser.parse_args()

    carve_files_from_image(args.image, args.signatures, args.output)

if __name__ == "__main__":
    main()