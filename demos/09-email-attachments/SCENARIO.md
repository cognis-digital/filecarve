# Demo 09 — pull attachments straight out of a mail spool

## Situation

You have a slice of a mailbox (`mailbox.bin`) from a mail store **you are
authorized to review** (e.g. an mbox region after its base64 attachment bodies
were decoded). Rather than write a full MIME parser, you want to recover the
decoded attachments directly from the spool bytes — a common DFIR shortcut for
triage.

`mailbox.bin` is regenerated deterministically by `make_demo.py` with mbox-style
framing around two decoded attachment byte runs:

1. An invoice **PDF** (contains an `INVOICE 0042 PAID` stream, `%%EOF` footer).
2. A photo **PNG** (proper `IEND` footer).

## Run it

```sh
python -m filecarve scan demos/09-email-attachments/mailbox.bin

# Recover the attachments
python -m filecarve carve demos/09-email-attachments/mailbox.bin -o attachments

# Documents only
python -m filecarve scan demos/09-email-attachments/mailbox.bin --type pdf
```

## What to expect

Two carves (pdf, png), both `method=footer`, recovered at their offsets inside
the spool. The PDF re-opens with its invoice text intact; the PNG opens as an
image.

## How to act

Hash the recovered attachments and check them against your malware/known-bad
inventory before opening. For the invoice, cross-reference the document number
against your finance system as part of a BEC / invoice-fraud review.
