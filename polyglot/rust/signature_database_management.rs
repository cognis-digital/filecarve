use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Signature {
    pub name: String,
    pub pattern: Vec<u8>,
    pub offset: usize,
}

#[derive(Debug)]
pub struct SignatureDatabase {
    signatures: HashMap<String, Signature>,
    all_signatures: HashSet<String>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        SignatureDatabase {
            signatures: HashMap::new(),
            all_signatures: HashSet::new(),
        }
    }

    pub fn add_signature(&mut self, name: &str, pattern: &[u8], offset: usize) {
        let signature = Signature {
            name: name.to_string(),
            pattern: pattern.to_vec(),
            offset,
        };
        self.signatures.insert(name.to_string(), signature);
        self.all_signatures.insert(name.to_string());
    }

    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let name = parts[0];
            let offset_str = parts[1];
            let pattern_str = parts[2..].join(" ");

            let offset = offset_str.parse::<usize>().ok()?;
            let pattern: Vec<u8> = pattern_str
                .as_bytes()
                .iter()
                .filter(|&&b| b != b' ')
                .map(|&b| b)
                .collect();

            self.add_signature(name, &pattern, offset);
        }

        Ok(())
    }

    pub fn get_signatures(&self) -> &HashMap<String, Signature> {
        &self.signatures
    }

    pub fn get_all_names(&self) -> &[String] {
        &self.all_signatures
    }
}

fn main() {
    let mut db = SignatureDatabase::new();
    // Example: Load signatures from a file
    if let Err(e) = db.load_from_file("signatures.txt") {
        eprintln!("Error loading signature database: {}", e);
        return;
    }

    println!("Loaded {} signatures:", db.get_all_names().len());
    for name in db.get_all_names() {
        println!("- {}", name);
    }

    // Example: Retrieve a signature by name
    if let Some(sig) = db.signatures.get("example_signature") {
        println!("Signature 'example_signature' has pattern: {:?}", sig.pattern);
        println!("Offset: {}", sig.offset);
    } else {
        println!("Signature 'example_signature' not found.");
    }
}