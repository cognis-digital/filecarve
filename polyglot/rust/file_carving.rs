use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;

fn main() {
    // Example usage: carve files from a disk image using known file signatures
    let input_path = "disk_image.raw";
    let output_dir = "carved_files";

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir).unwrap();

    // Open the disk image file
    let file = File::open(input_path).expect("Failed to open disk image");
    let reader = BufReader::new(file);

    // Known file signatures (magic numbers) for common file types
    let signatures = vec![
        ("PNG", b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"),
        ("JPEG", b"\xFF\xD8\xFF"),
        ("ZIP", b"\x50\x4B\x03\x04"),
        ("PDF", b"%PDF-"),
        ("MP3", b"ID3"),
        ("GIF", b"GIF87a"),
        ("TIFF", b"II*\x00"),
        ("BMP", b"BM"),
        ("TXT", b"\x0D\x0A"),
    ];

    // Process each line of the disk image
    for (line_idx, line_result) in reader.lines().enumerate() {
        let line = line_result.expect("Failed to read line");
        let bytes: Vec<u8> = line.bytes().collect();

        // Check for file signatures in the current line
        for (name, sig) in &signatures {
            if bytes.windows(sig.len()).any(|window| window == sig) {
                let filename = format!("{}_{}", name, line_idx);
                let output_path = Path::new(output_dir).join(filename);

                // Write the line to the output file
                let mut file = File::create(&output_path).expect("Failed to create output file");
                file.write_all(line.as_bytes()).expect("Failed to write carved file");

                println!("Carved {} from line {}", filename, line_idx);
            }
        }
    }

    println!("File carving complete.");
}