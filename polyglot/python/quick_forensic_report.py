import os
import argparse
from datetime import datetime
from collections import defaultdict

def parse_arguments():
    parser = argparse.ArgumentParser(description="Quick Forensic Report Tool for Filecarve")
    parser.add_argument("input_path", help="Path to the disk image or memory dump file")
    parser.add_argument("-o", "--output", default="forensic_report.html", help="Output HTML report file")
    parser.add_argument("--no-color", action="store_true", help="Disable color in output")
    return parser.parse_args()

def carve_files_from_image(image_path, signatures):
    """Carve files from a disk image using given file signatures."""
    carved_files = []
    with open(image_path, "rb") as f:
        buffer = f.read(1024 * 1024)  # Read in 1MB chunks
        while buffer:
            for sig, ext in signatures.items():
                if buffer.startswith(sig):
                    # Carve file starting from current position
                    f.seek(-len(sig), os.SEEK_CUR)
                    content = f.read()
                    carved_files.append((ext, content))
                    break  # Only carve one match per chunk
            buffer = f.read(1024 * 1024)
    return carved_files

def generate_report(carved_files, output_path):
    """Generate an HTML report of the carved files."""
    html = "<html><head><title>Quick Forensic Report</title></head><body>"
    html += "<h1>Quick Forensic Report</h1>"
    html += f"<p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
    html += "<h2>Carved Files</h2>"
    html += "<ul>"
    for ext, content in carved_files:
        html += f"<li><strong>{ext}</strong>: {len(content)} bytes</li>"
    html += "</ul>"
    html += "<h2>Summary</h2>"
    html += "<ul>"
    html += f"<li>Total Files Carved: {len(carved_files)}</li>"
    html += "</ul>"
    html += "</body></html>"
    
    with open(output_path, "w") as f:
        f.write(html)
    print(f"Report generated at: {output_path}")

def main():
    args = parse_arguments()
    # Define common file signatures (you can expand this)
    file_signatures = {
        b'\x50\x4b\x03\x04': ".zip",
        b'\x49\x49\x2A\x00': ".jpg",
        b'\xFF\xD8\xFF\xE0': ".jpeg",
        b'\x47\x49\x46\x38': ".gif",
        b'\x52\x49\x46\x46': ".rif",
        b'\x42\x4D': ".bmp",
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ".png",
        b'\x4D\x5A': ".exe",
        b'\x50\x4B\x01\x02': ".zip",
        b'\x00\x00\x01\xBA': ".mp3",
        b'\x21\xF9\x04\x1E': ".mpg",
        b'\x44\x46\x46\x48': ".wav"
    }

    carved_files = carve_files_from_image(args.input_path, file_signatures)
    generate_report(carved_files, args.output)

if __name__ == "__main__":
    main()