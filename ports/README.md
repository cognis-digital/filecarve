# Ports of filecarve

The same **carving engine** — magic-byte signature scan with footer / header-length
/ bounded end-detection — ported across languages so you can drop filecarve into
any stack or ship a single static binary. All ports mirror the Python reference's
primary `scan` command, share the 16-signature database, and emit the **same JSON
shape** (`tool`, `version`, `source`, `total`, `findings[]` with
`name/ext/offset/size/sha256/severity/method/truncated`).

Each port is verified for byte-for-byte parity with the Python reference against
the committed demo artifacts (same offsets, sizes, SHA-256s, and end-detection
methods).

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | [`../filecarve/`](../filecarve/) | `filecarve scan disk.img` | `python -m pytest` |
| JavaScript / Node | [`javascript/`](javascript/) | `node ports/javascript/index.js scan disk.img` | `node --test` (in `ports/javascript/`) |
| Go | [`go/`](go/) | `cd ports/go && go run . scan ../../disk.img` | `go test ./...` |
| Rust | [`rust/`](rust/) | `cd ports/rust && cargo run -- scan ../../disk.img` | `cargo test` |

All ports:

- are **passive / offline** — they never open a socket; they only read the file
  (or stdin via `-`) you point them at;
- exit **`1` when findings are present, `0` when clean, `2` on a read error** —
  pipeline-friendly, identical to the Python CLI;
- depend only on their language's standard library (the Rust port ships its own
  dependency-free SHA-256, so `cargo build` needs no crates and works air-gapped).

```bash
# JSON inventory of embedded files, any port:
node ports/javascript/index.js scan demos/07-polyglot-file/photo.jpg
cd ports/go   && go run . scan ../../demos/07-polyglot-file/photo.jpg
cd ports/rust && cargo run -- scan ../../demos/07-polyglot-file/photo.jpg
```

The Go and Rust ports are built and tested in CI on every push
([`.github/workflows/ports.yml`](../.github/workflows/ports.yml)) so they are
real and verifiable even where the toolchain isn't installed locally.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md). Defensive / authorized-use forensics only.
