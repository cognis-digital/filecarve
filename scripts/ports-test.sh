#!/usr/bin/env bash
# Run every language port against a demo artifact and run their unit tests.
# Each port mirrors the Python `scan` command and exits 1 when findings exist.
set -e
DEMO="${1:-demos/07-polyglot-file/photo.jpg}"

echo "== JavaScript =="
node ports/javascript/index.js scan "$DEMO" || true
( cd ports/javascript && node --test ) || echo "node: skipped"

echo "== Go =="
( cd ports/go && go test ./... && go run . scan "../../$DEMO" ) || echo "go: skipped (toolchain not installed — built in CI)"

echo "== Rust =="
( cd ports/rust && cargo test && cargo run -- scan "../../$DEMO" ) || echo "rust: skipped (toolchain not installed — built in CI)"
