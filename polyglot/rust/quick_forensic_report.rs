use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;

fn main() {
    // Example usage: quick_forensic_report "disk_image.raw"
    if let Some(path) = std::env::args().nth(1) {
        if Path::new(&path).exists() {
            match quick_forensic_report(&path) {
                Ok(report) => println!("{}", report),
                Err(e) => eprintln!("Error: {}", e),
            }
        } else {
            eprintln!("Error: File not found: {}", path);
        }
    } else {
        eprintln!("Usage: quick_forensic_report <file>");
    }
}

fn quick_forensic_report<P: AsRef<Path>>(path: P) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut report = String::new();
    report.push_str(&format!("Quick Forensic Report for {}\n", path.as_ref().display()));
    report.push_str("========================================\n");

    let mut file_count = 0;
    let mut total_size = 0;

    for line in reader.lines() {
        if let Ok(line) = line {
            // Example: simple signature-based detection (e.g., text files)
            if line.starts_with("This is a test") {
                file_count += 1;
                total_size += line.len();
                report.push_str(&format!("Found potential text file: {}\n", line));
            }
        }
    }

    report.push_str("\nSummary:\n");
    report.push_str(&format!("Number of potential files: {}\n", file_count));
    report.push_str(&format!("Total size of potential files: {} bytes\n", total_size));
    report.push_str("========================================\n");

    Ok(report)
}