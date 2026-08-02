import os
import sys
import struct
from typing import BinaryIO, Optional, List, Tuple

def carve_file_from_disk_image(image_path: str, signature: bytes, max_size: int = 1024 * 1024) -> List[Tuple[str, bytes]]:
    """
    Carve files from a disk image by searching for a given file signature.
    
    Args:
        image_path (str): Path to the disk image file.
        signature (bytes): File signature to search for.
        max_size (int): Maximum size of carved files in bytes.

    Returns:
        List[Tuple[str, bytes]]: List of tuples containing (filename, content) of carved files.
    """
    carved_files = []
    with open(image_path, 'rb') as image_file:
        buffer = bytearray()
        while True:
            chunk = image_file.read(4096)
            if not chunk:
                break
            buffer.extend(chunk)
            # Check for signature in the buffer
            pos = buffer.find(signature)
            while pos != -1:
                # Found a match, extract the file content
                start_pos = pos
                end_pos = start_pos + len(signature)
                # Find the end of the file (assuming it's at the end of the buffer or until max_size)
                end_pos = min(end_pos + max_size, len(buffer))
                file_content = buffer[start_pos:end_pos]
                # Generate a filename based on the signature
                filename = f"carved_{signature.hex()}.bin"
                carved_files.append((filename, file_content))
                # Remove the processed part from the buffer to avoid duplicates
                buffer = buffer[end_pos:]
                pos = buffer.find(signature)
    return carved_files

def main():
    """
    Entry point for demonstration of disk image processing.
    """
    if len(sys.argv) != 3:
        print("Usage: python disk_image_processing.py <image_path> <signature>")
        sys.exit(1)

    image_path = sys.argv[1]
    signature_str = sys.argv[2]
    try:
        signature = bytes.fromhex(signature_str)
    except ValueError:
        print(f"Invalid hex signature: {signature_str}")
        sys.exit(1)

    if not os.path.isfile(image_path):
        print(f"Image file not found: {image_path}")
        sys.exit(1)

    carved_files = carve_file_from_disk_image(image_path, signature)
    if not carved_files:
        print("No files carved.")
    else:
        print(f"{len(carved_files)} files carved:")
        for filename, content in carved_files:
            print(f" - {filename} ({len(content)} bytes)")

if __name__ == "__main__":
    main()