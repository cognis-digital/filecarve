import os
import sys
from typing import BinaryIO, Optional, List, Tuple
import argparse

def find_file_signature(data: bytes, signature: bytes) -> int:
    """Find the starting index of a signature in the data."""
    return data.find(signature)

def carve_files_from_data(data: bytes, signatures: List[Tuple[bytes, str]]) -> List[Tuple[int, int, str]]:
    """Carve files from data using provided signatures."""
    carved_files = []
    for sig, ext in signatures:
        start_idx = find_file_signature(data, sig)
        while start_idx != -1:
            # Find end of file (simple heuristic: look for signature again or end of data)
            end_idx = data.find(sig, start_idx + len(sig))
            if end_idx == -1:
                end_idx = len(data)
            file_data = data[start_idx:start_idx + (end_idx - start_idx)]
            carved_files.append((start_idx, len(file_data), ext))
            # Move past the current signature to avoid overlapping
            start_idx = end_idx
    return carved_files

def carve_from_file(file_path: str, signatures: List[Tuple[bytes, str]], output_dir: str) -> None:
    """Carve files from a file using provided signatures and save them to output directory."""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    carved_files = carve_files_from_data(data, signatures)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for start_idx, size, ext in carved_files:
        file_name = f"carved_{start_idx}_{size}.{ext}"
        output_path = os.path.join(output_dir, file_name)
        with open(output_path, 'wb') as out_f:
            out_f.write(data[start_idx:start_idx + size])
        print(f"Saved: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Carve files from disk images or memory dumps by signature.")
    parser.add_argument("input_file", help="Path to the input file (disk image or memory dump).")
    parser.add_argument("--signatures", nargs='+', required=True, help="List of signatures in format 'signature.extension' e.g. '504B0304.txt'.")
    parser.add_argument("--output", default="carved_files", help="Output directory for carved files.")
    
    args = parser.parse_args()
    
    # Parse signatures
    signatures = []
    for sig_str in args.signatures:
        if '.' in sig_str:
            sig, ext = sig_str.split('.', 1)
            signatures.append((bytes.fromhex(sig), ext))
        else:
            print(f"Invalid signature format: {sig_str}")
    
    carve_from_file(args.input_file, signatures, args.output)

if __name__ == "__main__":
    main()