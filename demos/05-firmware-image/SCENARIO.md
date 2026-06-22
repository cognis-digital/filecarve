# Demo 05 — unpack an IoT / router firmware image

## Situation

You are reviewing the firmware blob (`firmware.bin`) of a device **you own**,
to inventory what ships inside it before deployment. Vendor firmware routinely
concatenates several regions into one flashable image with `0xFF` erase-padding
(NOR-flash convention) between them. You want a quick component inventory
without a full firmware-analysis framework.

`firmware.bin` is regenerated deterministically by `make_demo.py` and embeds:

1. A boot-logo **GIF** (resolved by its `0x3B` trailer → `method=length`).
2. A packed **GZIP** root filesystem placeholder.
3. An embedded **SQLite** settings database (real `SQLite format 3\x00` magic).
4. An inert **ELF** userland binary header (`\x7fELF`, severity **high**).

## Run it

```sh
# Inventory the firmware components
python -m filecarve scan demos/05-firmware-image/firmware.bin

# Machine-readable inventory for a build gate
python -m filecarve --format json scan demos/05-firmware-image/firmware.bin \
  | jq '[.findings[].ext] | group_by(.) | map({ext: .[0], n: length})'

# Pull out just the settings DB to inspect it
python -m filecarve carve demos/05-firmware-image/firmware.bin -o unpacked --type sqlite
```

## What to expect

Four carves (gif, gz, sqlite, elf). The GZIP, SQLite and ELF show
`method=bounded` because none carries a trailing end-marker — their byte ranges
extend to the next region or the size cap, so treat the lengths as upper bounds.

## How to act

Open the carved `.sqlite` with any SQLite browser to audit default settings /
credentials. Flag the **high**-severity ELF for binary review. Fail your
firmware CI build if an unexpected executable extension appears in the JSON
inventory.
