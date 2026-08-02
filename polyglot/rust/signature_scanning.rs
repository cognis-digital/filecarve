use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;

#[derive(Debug)]
enum ScanResult {
    Match(String),
    NoMatch,
    Error(String),
}

fn scan_for_signature(file_path: &str, signature: &[u8]) -> ScanResult {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return ScanResult::Error(format!("Failed to open file: {}", e)),
    };

    let reader = BufReader::new(file);
    let mut buffer = Vec::new();
    let mut found = false;

    for chunk in reader.chunks(4096) {
        buffer.extend_from_slice(&chunk);
        if buffer.len() >= signature.len() {
            // Check all possible positions in the current buffer
            for i in 0..(buffer.len() - signature.len() + 1) {
                let mut match_found = true;
                for j in 0..signature.len() {
                    if buffer[i + j] != signature[j] {
                        match_found = false;
                        break;
                    }
                }
                if match_found {
                    return ScanResult::Match(format!("Signature found at offset {}", i));
                }
            }
            // Trim buffer to keep only the last 4096 bytes for efficiency
            buffer.drain(0..buffer.len() - 4096);
        }
    }

    ScanResult::NoMatch
}

fn main() {
    let image_path = "test_disk_image.bin";
    let signature = b"\x50\x4b\x03\x04"; // PKZIP file signature

    match scan_for_signature(image_path, signature) {
        ScanResult::Match(offset) => println!("Signature found at offset: {}", offset),
        ScanResult::NoMatch => println!("Signature not found"),
        ScanResult::Error(e) => println!("Error: {}", e),
    }
}