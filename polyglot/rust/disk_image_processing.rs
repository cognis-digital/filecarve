use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;

/// Carve files from a disk image by signature.
///
/// This function reads a disk image file and searches for known file signatures.
/// When a signature is found, it carves out the file content and saves it to a new file.
fn carve_files_from_disk_image(input_path: &str, output_dir: &str) -> std::io::Result<()> {
    let file = File::open(input_path)?;
    let reader = BufReader::new(file);

    // Define some known file signatures (magic numbers)
    let signatures = vec![
        ("7F 45 4C 46", "ELF"),           // ELF executable
        ("23 54 65 73 74 20 32 30", "TST 20"), // Example custom signature
        ("FF 26", "SomeBinary"),          // Another example signature
    ];

    let mut file_count = 0;

    for (signature, file_type) in &signatures {
        let mut found_files = Vec::new();
        let mut current_file_data = Vec::new();

        for (_line_num, line_result) in reader.lines().enumerate() {
            let line = line_result?;
            let bytes: Vec<u8> = line.bytes().collect();

            // Check if the current line matches the signature
            if bytes.len() >= signature.split_whitespace().count() as usize {
                let mut match_found = true;
                for (i, part) in signature.split_whitespace().enumerate() {
                    let byte_value = u8::from_str_radix(part, 16).expect("Invalid hex");
                    if bytes[i] != byte_value {
                        match_found = false;
                        break;
                    }
                }

                if match_found {
                    // Start of a new file
                    current_file_data.clear();
                    current_file_data.extend_from_slice(&bytes);
                } else if !current_file_data.is_empty() {
                    // Continue collecting data until end of file (for simplicity, we'll assume 1024 bytes)
                    current_file_data.extend_from_slice(&bytes);
                    if current_file_data.len() >= 1024 {
                        let output_path = format!("{}/{}_{}", output_dir, file_count, file_type);
                        let mut output_file = File::create(output_path)?;
                        output_file.write_all(&current_file_data)?;
                        file_count += 1;
                        current_file_data.clear();
                    }
                }
            }
        }

        // Handle any remaining data
        if !current_file_data.is_empty() {
            let output_path = format!("{}/{}_{}", output_dir, file_count, file_type);
            let mut output_file = File::create(output_path)?;
            output_file.write_all(&current_file_data)?;
            file_count += 1;
        }
    }

    println!("Found {} files carved from disk image.", file_count);
    Ok(())
}

fn main() -> std::io::Result<()> {
    // Example usage: carve files from a disk image
    let input_path = "disk_image.bin";
    let output_dir = "carved_files";

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)?;

    // Carve files from the disk image
    carve_files_from_disk_image(input_path, output_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_files_from_disk_image() -> std::io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let input_path = temp_dir.path().join("disk_image.bin");
        let output_dir = temp_dir.path().join("carved_files");

        // Create a sample disk image with known signatures
        let mut file = File::create(&input_path)?;
        let elf_signature = b"\x7FELF"; // Simple ELF signature
        let custom_signature = b"\x23TST 20\x20";
        let some_binary_signature = b"\xFF&";

        // Write some data to simulate a disk image
        file.write_all(elf_signature)?;
        file.write_all(b"ELF content...")?;
        file.write_all(custom_signature)?;
        file.write_all(b"Custom content...")?;
        file.write_all(some_binary_signature)?;
        file.write_all(b"SomeBinary content...")?;

        // Run the carving function
        carve_files_from_disk_image(input_path.to_str().unwrap(), output_dir.to_str().unwrap())?;

        // Check if files were carved
        let elf_file = output_dir.join("0_ELFP");
        let custom_file = output_dir.join("1_TST 20");
        let some_binary_file = output_dir.join("2_SomeBinary");

        assert!(elf_file.exists());
        assert!(custom_file.exists());
        assert!(some_binary_file.exists());

        Ok(())
    }
}