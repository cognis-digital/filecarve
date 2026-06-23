// Rust port of the FILECARVE scan engine — fast, single static binary, zero deps.
//
// Scans a blob for embedded files by magic-byte signature and emits JSON whose
// shape mirrors the Python reference. End-detection uses footer, header-derived
// length (BMP/RIFF/ZIP), or a bounded fallback that flags possible truncation.
//
// Passive/offline by nature: never touches the network; only reads the file (or
// stdin) you point it at. Defensive / authorized-use forensics only.
//
//   filecarve scan <blob>     # JSON to stdout, exit 1 if findings
//   filecarve scan -          # read blob from stdin
//   filecarve --version
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::exit;

const TOOL_NAME: &str = "FILECARVE";
const TOOL_VERSION: &str = "0.6.6";
const MAX_SIZE: usize = 25_000_000;

type LenFn = fn(&[u8], usize) -> Option<usize>;

struct Signature {
    name: &'static str,
    ext: &'static str,
    header: &'static [u8],
    footer: Option<&'static [u8]>,
    footer_inclusive: bool,
    length_fn: Option<LenFn>,
    severity: &'static str,
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

fn len_gif(blob: &[u8], start: usize) -> Option<usize> {
    // GIF terminates with trailer 0x3B; canonical end is 0x00 0x3B.
    let end = (start + 50_000_000).min(blob.len());
    let window = &blob[start..end];
    rfind(window, &[0x00, 0x3b]).map(|i| i + 2)
}

fn len_bmp(blob: &[u8], start: usize) -> Option<usize> {
    if start + 6 > blob.len() {
        return None;
    }
    let size = u32::from_le_bytes([blob[start + 2], blob[start + 3], blob[start + 4], blob[start + 5]]) as usize;
    if size >= 14 && size <= blob.len() - start {
        Some(size)
    } else {
        None
    }
}

fn len_riff(blob: &[u8], start: usize) -> Option<usize> {
    if start + 8 > blob.len() {
        return None;
    }
    let size = u32::from_le_bytes([blob[start + 4], blob[start + 5], blob[start + 6], blob[start + 7]]) as usize;
    let total = size + 8;
    if total > 8 && total <= blob.len() - start {
        Some(total)
    } else {
        None
    }
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn len_zip(blob: &[u8], start: usize) -> Option<usize> {
    let eocd = b"PK\x05\x06";
    // find the LAST EOCD at/after start
    let mut found: Option<usize> = None;
    let mut from = start;
    while let Some(i) = find_from(blob, eocd, from) {
        found = Some(i);
        from = i + 1;
    }
    let idx = found?;
    if idx + 22 > blob.len() {
        return None;
    }
    let comment_len = u16::from_le_bytes([blob[idx + 20], blob[idx + 21]]) as usize;
    let end = idx + 22 + comment_len;
    if end <= blob.len() && end > start {
        Some(end - start)
    } else {
        None
    }
}

fn signatures() -> Vec<Signature> {
    vec![
        Signature { name: "JPEG image", ext: "jpg", header: b"\xff\xd8\xff", footer: Some(b"\xff\xd9"), footer_inclusive: true, length_fn: None, severity: "low" },
        Signature { name: "PNG image", ext: "png", header: b"\x89PNG\r\n\x1a\n", footer: Some(b"IEND\xae\x42\x60\x82"), footer_inclusive: true, length_fn: None, severity: "low" },
        Signature { name: "GIF image", ext: "gif", header: b"GIF89a", footer: None, footer_inclusive: true, length_fn: Some(len_gif), severity: "low" },
        Signature { name: "GIF image", ext: "gif", header: b"GIF87a", footer: None, footer_inclusive: true, length_fn: Some(len_gif), severity: "low" },
        Signature { name: "BMP image", ext: "bmp", header: b"BM", footer: None, footer_inclusive: true, length_fn: Some(len_bmp), severity: "low" },
        Signature { name: "PDF document", ext: "pdf", header: b"%PDF-", footer: Some(b"%%EOF"), footer_inclusive: true, length_fn: None, severity: "medium" },
        Signature { name: "ZIP / Office / JAR", ext: "zip", header: b"PK\x03\x04", footer: Some(b"PK\x05\x06"), footer_inclusive: true, length_fn: Some(len_zip), severity: "medium" },
        Signature { name: "GZIP stream", ext: "gz", header: b"\x1f\x8b\x08", footer: None, footer_inclusive: true, length_fn: None, severity: "medium" },
        Signature { name: "RAR archive", ext: "rar", header: b"Rar!\x1a\x07\x00", footer: None, footer_inclusive: true, length_fn: None, severity: "high" },
        Signature { name: "RAR5 archive", ext: "rar", header: b"Rar!\x1a\x07\x01\x00", footer: None, footer_inclusive: true, length_fn: None, severity: "high" },
        Signature { name: "7-Zip archive", ext: "7z", header: b"\x37\x7a\xbc\xaf\x27\x1c", footer: None, footer_inclusive: true, length_fn: None, severity: "high" },
        Signature { name: "ELF executable", ext: "elf", header: b"\x7fELF", footer: None, footer_inclusive: true, length_fn: None, severity: "high" },
        Signature { name: "Windows PE/EXE", ext: "exe", header: b"MZ", footer: None, footer_inclusive: true, length_fn: None, severity: "high" },
        Signature { name: "RIFF (wav/avi/webp)", ext: "riff", header: b"RIFF", footer: None, footer_inclusive: true, length_fn: Some(len_riff), severity: "low" },
        Signature { name: "SQLite database", ext: "sqlite", header: b"SQLite format 3\x00", footer: None, footer_inclusive: true, length_fn: None, severity: "medium" },
        Signature { name: "PCAP capture", ext: "pcap", header: b"\xd4\xc3\xb2\xa1", footer: None, footer_inclusive: true, length_fn: None, severity: "medium" },
    ]
}

#[derive(Clone)]
pub struct Carved {
    pub name: &'static str,
    pub ext: &'static str,
    pub offset: usize,
    pub size: usize,
    pub sha256: String,
    pub severity: &'static str,
    pub method: &'static str,
    pub truncated: bool,
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        _ => 0,
    }
}

fn resolve_end(blob: &[u8], sig: &Signature, start: usize) -> (usize, &'static str, bool) {
    let n = blob.len();
    if let Some(f) = sig.length_fn {
        if let Some(length) = f(blob, start) {
            if length > 0 {
                return ((start + length).min(n), "length", false);
            }
        }
    }
    if let Some(footer) = sig.footer {
        if let Some(fidx) = find_from(blob, footer, start + sig.header.len()) {
            let end = fidx + if sig.footer_inclusive { footer.len() } else { 0 };
            return (end.min(n), "footer", false);
        }
    }
    let end = (start + MAX_SIZE).min(n);
    (end, "bounded", start + MAX_SIZE < n)
}

pub fn scan(blob: &[u8], min_size: usize, types: Option<&[&str]>) -> Vec<Carved> {
    let sigs = signatures();
    let mut results: Vec<Carved> = Vec::new();
    for sig in &sigs {
        if let Some(t) = types {
            if !t.contains(&sig.ext) {
                continue;
            }
        }
        let mut pos = 0usize;
        let mut consumed_until: isize = -1;
        while let Some(idx) = find_from(blob, sig.header, pos) {
            let start = idx;
            if (start as isize) <= consumed_until {
                pos = idx + 1;
                continue;
            }
            let (end, method, truncated) = resolve_end(blob, sig, start);
            let size = end - start;
            if size >= min_size {
                results.push(Carved {
                    name: sig.name,
                    ext: sig.ext,
                    offset: start,
                    size,
                    sha256: sha256_hex(&blob[start..end]),
                    severity: sig.severity,
                    method,
                    truncated,
                });
                consumed_until = end as isize - 1;
                pos = std::cmp::max(idx + 1, end);
            } else {
                pos = idx + 1;
            }
        }
    }
    results.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| sev_rank(b.severity).cmp(&sev_rank(a.severity)))
    });
    results
}

// --- minimal dependency-free SHA-256 -------------------------------------
fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{:08x}", x)).collect()
}

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn read_blob(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        fs::read(path)
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version") {
        println!("{} {}", TOOL_NAME, TOOL_VERSION);
        return;
    }
    if args.len() < 2 || args[0] != "scan" {
        eprintln!("usage: filecarve scan <blob>  (- for stdin)");
        exit(2);
    }
    let blob = match read_blob(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: cannot read {}: {}", TOOL_NAME, args[1], e);
            exit(2);
        }
    };
    let found = scan(&blob, 1, None);
    let src = if args[1] == "-" { "<stdin>" } else { &args[1] };

    let mut findings_json = String::from("[");
    for (i, c) in found.iter().enumerate() {
        if i > 0 {
            findings_json.push(',');
        }
        findings_json.push_str(&format!(
            "\n    {{\"name\": \"{}\", \"ext\": \"{}\", \"offset\": {}, \"size\": {}, \"sha256\": \"{}\", \"severity\": \"{}\", \"method\": \"{}\", \"truncated\": {}}}",
            json_escape(c.name), c.ext, c.offset, c.size, c.sha256, c.severity, c.method, c.truncated
        ));
    }
    if !found.is_empty() {
        findings_json.push_str("\n  ");
    }
    findings_json.push(']');

    println!(
        "{{\n  \"tool\": \"{}\",\n  \"version\": \"{}\",\n  \"source\": \"{}\",\n  \"total\": {},\n  \"findings\": {}\n}}",
        TOOL_NAME, TOOL_VERSION, json_escape(src), found.len(), findings_json
    );
    if !found.is_empty() {
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png() -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(b"\x00\x00\x00\x00IEND\xae\x42\x60\x82");
        v
    }
    fn pdf() -> Vec<u8> {
        b"%PDF-1.4\nstuff\n%%EOF".to_vec()
    }
    fn bmp() -> Vec<u8> {
        let mut v = b"BM".to_vec();
        v.extend_from_slice(&14u32.to_le_bytes());
        v.extend_from_slice(&[0u8; 8]);
        v
    }

    #[test]
    fn finds_png_by_footer() {
        let mut blob = vec![0u8, 1, 2];
        blob.extend_from_slice(&png());
        blob.extend_from_slice(&[3u8, 4]);
        let found: Vec<_> = scan(&blob, 1, None).into_iter().filter(|c| c.ext == "png").collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "footer");
        assert_eq!(found[0].offset, 3);
        assert!(!found[0].truncated);
    }

    #[test]
    fn finds_multiple_types() {
        let pad = [0u8; 16];
        let mut blob = pad.to_vec();
        blob.extend_from_slice(&png());
        blob.extend_from_slice(&pad);
        blob.extend_from_slice(&pdf());
        let exts: std::collections::HashSet<_> = scan(&blob, 1, None).into_iter().map(|c| c.ext).collect();
        assert!(exts.contains("png"));
        assert!(exts.contains("pdf"));
    }

    #[test]
    fn pdf_footer_inclusive() {
        let p = pdf();
        let found: Vec<_> = scan(&p, 1, None).into_iter().filter(|c| c.ext == "pdf").collect();
        assert_eq!(found.len(), 1);
        let data = &p[found[0].offset..found[0].offset + found[0].size];
        assert!(data.ends_with(b"%%EOF"));
    }

    #[test]
    fn bmp_by_length() {
        let b = bmp();
        let found: Vec<_> = scan(&b, 1, None).into_iter().filter(|c| c.ext == "bmp").collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "length");
        assert_eq!(found[0].size, 14);
    }

    #[test]
    fn type_filter() {
        let mut blob = png();
        blob.extend_from_slice(&pdf());
        let found = scan(&blob, 1, Some(&["pdf"]));
        assert!(found.iter().all(|c| c.ext == "pdf"));
    }

    #[test]
    fn min_size_suppresses() {
        assert_eq!(scan(&png(), 10_000_000, None).len(), 0);
    }

    #[test]
    fn empty_blob() {
        assert_eq!(scan(&[], 1, None).len(), 0);
    }

    #[test]
    fn sorted_by_offset() {
        let pad = [0u8; 8];
        let mut blob = pad.to_vec();
        blob.extend_from_slice(&png());
        blob.extend_from_slice(&pad);
        blob.extend_from_slice(&pdf());
        let offs: Vec<usize> = scan(&blob, 1, None).iter().map(|c| c.offset).collect();
        let mut sorted = offs.clone();
        sorted.sort();
        assert_eq!(offs, sorted);
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of the empty string
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256 of "abc"
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_is_64_hex() {
        let found = scan(&png(), 1, None);
        assert!(!found.is_empty());
        assert_eq!(found[0].sha256.len(), 64);
    }
}
