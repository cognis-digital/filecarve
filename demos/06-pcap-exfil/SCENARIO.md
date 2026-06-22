# Demo 06 — recover files transferred inside a packet capture

## Situation

You have a raw packet capture (`capture.bin`, a libpcap file) pulled from a tap
on a network **you are authorized to monitor**. You suspect files were moved
across a session and want to recover them straight from the capture's byte
stream — the "files-inside-traffic" exfiltration case — without a full protocol
re-assembler.

`capture.bin` is regenerated deterministically by `make_demo.py`:

- A real **libpcap** global header (magic `d4 c3 b2 a1`, LINKTYPE_ETHERNET).
- Payload bytes that reassemble into a minimal **JPEG** (SOI/JFIF/EOI).
- Payload bytes that reassemble into a small **PDF** (`%PDF` … `%%EOF`).

## Run it

```sh
# See the container + the files moved inside it
python -m filecarve scan demos/06-pcap-exfil/capture.bin

# Recover just the transferred documents (skip the pcap container itself)
python -m filecarve carve demos/06-pcap-exfil/capture.bin -o exfil --type jpg --type pdf

# Emit SARIF so the finding lands in your code-scanning / CI dashboard
python -m filecarve --format sarif scan demos/06-pcap-exfil/capture.bin > capture.sarif
```

## What to expect

Three carves: the **PCAP** container (`method=bounded`), and the recovered
**JPEG** and **PDF** (both `method=footer`, carved at their true byte offsets
inside the capture).

## How to act

Hash the recovered documents and compare against your DLP / known-sensitive
inventory. Pivot on the capture's byte offsets to the corresponding packets in
your full PCAP for the source/destination tuple behind the transfer.
