use std::io::{self, Read, Seek, SeekFrom, Cursor, BufReader};
use std::mem;
use std::cmp;

/// Represents a raw disk image or memory dump.
#[derive(Debug, Clone)]
pub struct RawImage {
    /// Raw bytes of the image.
    data: Vec<u8>,
    /// Offset where carving should start (e.g., after MBR).
    start_offset: u64,
    /// Size to limit carving (0 = unlimited).
    limit_size: u64,
    /// Block size for chunked reading (default 64KB).
    block_size: usize,
}

impl RawImage {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            start_offset: 0,
            limit_size: 0,
            block_size: 65536,
        }
    }

    pub fn from_cursor(cursor: Cursor<Vec<u8>>) -> Self {
        let data = mem::replace(&mut cursor.into_inner(), Vec::new());
        Self {
            data,
            start_offset: 0,
            limit_size: 0,
            block_size: 65536,
        }
    }

    pub fn with_start_offset(mut self, offset: u64) -> Self {
        self.start_offset = offset;
        self
    }

    pub fn with_limit(mut self, size: u64) -> Self {
        self.limit_size = size;
        self
    }

    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn remaining(&self) -> u64 {
        let start = self.start_offset as usize;
        let end = self.start_offset.saturating_add(self.limit_size) as usize;
        end.saturating_sub(start)
    }

    pub fn read_at(&self, offset: u64, len: usize) -> io::Result<&[u8]> {
        let start = self.start_offset as usize + offset as usize;
        let end = cmp::min(start + len, self.data.len());
        Ok(&self.data[start..end])
    }

    pub fn read_at_mut(&mut self, offset: u64, len: usize) -> io::Result<&mut [u8]> {
        let start = self.start_offset as usize + offset as usize;
        let end = cmp::min(start + len, self.data.len());
        Ok(&mut self.data[start..end])
    }

    pub fn chunked_reader(&self) -> impl Iterator<Item = io::Result<&[u8]>> {
        let start = self.start_offset as usize;
        let end = self.start_offset.saturating_add(self.limit_size) as usize;
        let mut offset = start;
        
        while offset < end {
            let chunk_len = cmp::min(self.block_size, end - offset);
            yield Ok(&self.data[offset..offset + chunk_len]);
            offset += chunk_len;
        }
    }

    pub fn chunked_reader_mut(&mut self) -> impl Iterator<Item = io::Result<&mut [u8]>> {
        let start = self.start_offset as usize;
        let end = self.start_offset.saturating_add(self.limit_size) as usize;
        let mut offset = start;
        
        while offset < end {
            let chunk_len = cmp::min(self.block_size, end - offset);
            yield Ok(&mut self.data[offset..offset + chunk_len]);
            offset += chunk_len;
        }
    }

    pub fn cursor(&self) -> Cursor<&[u8]> {
        Cursor::new(&self.data[self.start_offset as usize..])
    }

    pub fn cursor_mut(&mut self) -> Cursor<&mut [u8]> {
        Cursor::new(&mut self.data[self.start_offset as usize..])
    }
}

/// Represents a detected file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// Windows PE executable (EXE, DLL, etc.)
    Pe,
    /// Linux ELF binary
    Elf,
    /// macOS Mach-O binary
    MachO,
    /// FAT filesystem (FAT12/16/32/64)
    Fat,
    /// NTFS filesystem boot sector
    Ntfs,
    /// HFS+ filesystem
    HfsPlus,
    /// ISO 9660 CD-ROM
    Iso9660,
    /// Raw/unknown data
    Raw,
}

impl FileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileType::Pe => "PE",
            FileType::Elf => "ELF",
            FileType::MachO => "Mach-O",
            FileType::Fat => "FAT",
            FileType::Ntfs => "NTFS",
            FileType::HfsPlus => "HFS+",
            FileType::Iso9660 => "ISO9660",
            FileType::Raw => "RAW",
        }
    }
}

/// Trait for file type signature detection.
pub trait Signature: Send + Sync {
    /// Magic bytes for this file type.
    fn magic() -> &'static [u8];
    
    /// Minimum length required to detect this type.
    fn min_length() -> usize;
    
    /// Check if the given bytes match this signature.
    fn check(data: &[u8]) -> bool;
    
    /// Optional: Extract metadata from the header.
    fn extract_metadata<'a>(data: &'a [u8]) -> Option<Metadata<'a>> {
        None
    }
}

/// Metadata extracted from a file header.
pub struct Metadata<'a> {
    pub file_type: FileType,
    pub offset: u64,
    pub size: u64,
    pub name: Option<&'a str>,
}

/// Main parser that orchestrates signature detection and carving.
pub struct Parser {
    /// Image to parse.
    image: RawImage,
    /// Minimum file size to consider valid (default 4KB).
    min_file_size: u64,
    /// Maximum file size to consider (default 1GB).
    max_file_size: u64,
    /// Overlap between scans (default 512 bytes).
    scan_overlap: u64,
    /// Whether to scan the entire image or just data regions.
    scan_full: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            image: RawImage::new(Vec::new()),
            min_file_size: 4096,
            max_file_size: 1073741824,
            scan_overlap: 512,
            scan_full: true,
        }
    }
}

impl Parser {
    pub fn new(image: RawImage) -> Self {
        Self {
            image,
            min_file_size: 4096,
            max_file_size: 1073741824,
            scan_overlap: 512,
            scan_full: true,
        }
    }

    pub fn with_min_file_size(mut self, size: u64) -> Self {
        self.min_file_size = size;
        self
    }

    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn with_scan_overlap(mut self, overlap: u64) -> Self {
        self.scan_overlap = overlap;
        self
    }

    pub fn with_scan_full(mut self, full: bool) -> Self {
        self.scan_full = full;
        self
    }

    pub fn with_image(mut self, image: RawImage) -> Self {
        self.image = image;
        self
    }

    pub fn image(&self) -> &RawImage {
        &self.image
    }

    pub fn image_mut(&mut self) -> &mut RawImage {
        &mut self.image
    }

    /// Detect file types present in the image.
    pub fn detect_types(&self) -> Vec<FileType> {
        let mut types = Vec::new();
        
        if self.image.is_empty() {
            return types;
        }

        // Check each signature
        if Self::check_signature(FileType::Pe, &self.image.data) {
            types.push(FileType::Pe);
        }
        if Self::check_signature(FileType::Elf, &self.image.data) {
            types.push(FileType::Elf);
        }
        if Self::check_signature(FileType::MachO, &self.image.data) {
            types.push(FileType::MachO);
        }
        if Self::check_signature(FileType::Fat, &self.image.data) {
            types.push(FileType::Fat);
        }
        if Self::check_signature(FileType::Ntfs, &self.image.data) {
            types.push(FileType::Ntfs);
        }
        if Self::check_signature(FileType::HfsPlus, &self.image.data) {
            types.push(FileType::HfsPlus);
        }
        if Self::check_signature(FileType::Iso9660, &self.image.data) {
            types.push(FileType::Iso9660);
        }

        types
    }

    /// Check if a signature exists at any offset in the image.
    fn check_signature(file_type: FileType, data: &[u8]) -> bool {
        let magic = Signature::magic(file_type);
        let min_len = Signature::min_length(file_type);
        
        if data.len() < min_len {
            return false;
        }

        // Check from start offset
        let start = self.image.start_offset as usize;
        let end = self.image.start_offset.saturating_add(self.image.limit_size) as usize;
        
        for offset in start..end.saturating_sub(min_len) {
            if data[offset..offset + min_len] == *magic {
                return true;
            }
        }

        false
    }

    /// Find all occurrences of a signature.
    fn find_signatures(file_type: FileType) -> Vec<u64> {
        let magic = Signature::magic(file_type);
        let min_len = Signature::min_length(file_type);
        
        if self.image.is_empty() || self.image.len() < min_len {
            return Vec::new();
        }

        let start = self.image.start_offset as usize;
        let end = self.image.start_offset.saturating_add(self.image.limit_size) as usize;
        
        let mut offsets = Vec::new();
        let mut offset = start;
        
        while offset + min_len <= end {
            if self.image.read_at(offset as u64, min_len).unwrap() == *magic {
                offsets.push(offset as u64);
            }
            offset += 1;
        }

        offsets
    }

    /// Carve files based on detected signatures.
    pub fn carve(&mut self) -> Vec<CarvedFile> {
        let mut results = Vec::new();

        if self.image.is_empty() {
            return results;
        }

        // Detect what types we're looking for
        let types = self.detect_types();
        
        if types.is_empty() {
            // No known signatures, treat as raw data
            return self.carve_raw();
        }

        // Carve each known type
        for file_type in types {
            if let Some(carved) = self.carve_type(file_type) {
                results.extend(carved);
            }
        }

        results
    }

    /// Carve a specific file type.
    fn carve_type(&mut self, file_type: FileType) -> Option<Vec<CarvedFile>> {
        let offsets = Self::find_signatures(file_type);
        
        if offsets.is_empty() {
            return None;
        }

        let start = self.image.start_offset as usize;
        let end = self.image.start_offset.saturating_add(self.image.limit_size) as usize;
        
        let mut carved = Vec::new();
        
        for offset in offsets {
            let offset = offset as usize;
            let remaining = end.saturating_sub(offset);
            
            // Estimate size based on file type
            let size = Self::estimate_size(file_type, offset, remaining);
            
            if size >= self.min_file_size && size <= self.max_file_size {
                carved.push(CarvedFile {
                    file_type,
                    offset: offset as u64,
                    size,
                    name: None,
                });
            }
        }

        Some(carved)
    }

    /// Estimate file size based on signature and context.
    fn estimate_size(file_type: FileType, offset: usize, remaining: usize) -> u64 {
        match file_type {
            FileType::Pe => {
                // PE headers are typically 64-256 bytes
                let header_size = Self::read_pe_header_size(&self.image, offset as u64);
                if header_size > 0 {
                    // Use header size as minimum, estimate rest
                    header_size as u64 + 1024
                } else {
                    remaining as u64
                }
            }
            FileType::Elf => {
                // ELF headers are 52-64 bytes
                let header_size = Self::read_elf_header_size(&self.image, offset as u64);
                if header_size > 0 {
                    header_size as u64 + 1024
                } else {
                    remaining as u64
                }
            }
            FileType::MachO => {
                // Mach-O headers are 32-56 bytes
                let header_size = Self::read_macho_header_size(&self.image, offset as u64);
                if header_size > 0 {
                    header_size as u64 + 1024
                } else {
                    remaining as u64
                }
            }
            FileType::Fat => {
                // FAT headers are 512 bytes
                512 as u64 + 1024
            }
            FileType::Ntfs => {
                // NTFS boot sector is 512 bytes
                512 as u64 + 1024
            }
            FileType::HfsPlus => {
                // HFS+ boot sector is 512 bytes
                512 as u64 + 1024
            }
            FileType::Iso9660 => {
                // ISO 9660 header is 2048 bytes
                2048 as u64 + 1024
            }
            FileType::Raw => {
                remaining as u64
            }
        }
    }

    /// Carve as raw data (no signature).
    fn carve_raw(&mut self) -> Vec<CarvedFile> {
        let start = self.image.start_offset as usize;
        let end = self.image.start_offset.saturating_add(self.image.limit_size) as usize;
        
        if start >= end {
            return Vec::new();
        }

        let size = end.saturating_sub(start) as u64;
        
        if size >= self.min_file_size && size <= self.max_file_size {
            return vec![CarvedFile {
                file_type: FileType::Raw,
                offset: self.image.start_offset,
                size,
                name: None,
            }];
        }

        Vec::new()
    }

    /// Read PE header size from an offset.
    fn read_pe_header_size(image: &RawImage, offset: u64) -> usize {
        let mut pe = image.cursor();
        pe.seek(SeekFrom::Start(offset)).ok