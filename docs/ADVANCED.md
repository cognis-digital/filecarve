# filecarve — Advanced usage

## CI gate (fail the build when embedded files are found)
`filecarve` exits **1** when any embedded file is carved and **0** when the
artifact is clean, so the CI step fails on findings without a special flag.
Write the SARIF report with `-r/--report` and upload it to code-scanning:
```yaml
- run: pip install cognis-filecarve
- run: filecarve scan disk.img --format sarif -r filecarve.sarif   # exit 1 -> job fails on findings
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: filecarve.sarif }
```
To upload the report but **not** fail the build, append `|| true` to the scan step.

## Filter what you carve
```bash
filecarve scan disk.img --type exe --type elf      # only executables
filecarve scan disk.img --min-size 4096            # ignore tiny carves
filecarve carve disk.img -o out/ --type zip        # extract archives only
```

## Pipe into a SIEM / webhook
```bash
filecarve scan disk.img --format json | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
# or via the native cognis-connect emitter (STIX/MISP/Sigma/Splunk/Elastic/Slack):
filecarve scan disk.img --format json | filecarve-emit --to stix
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "filecarve": { "command": "filecarve", "args": ["mcp"] } } }
```

## Run a language port instead of Python
All ports mirror the `scan` command and emit the same JSON shape (verified
byte-for-byte against the demo artifacts). Each exits 1 on findings, 0 when clean.
```bash
node ports/javascript/index.js scan disk.img      # Node
( cd ports/go && go run . scan ../../disk.img )    # Go single binary
( cd ports/rust && cargo run -- scan ../../disk.img ) # Rust
```
