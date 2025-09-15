# Design

Here are various design notes.

## Logging with JSONL

We now record logs in the JSONL format.

Rationale:

1. Fault tolerance: Crash during write? All previous entries still readable
2. Streaming: Can process logs while they're being written
3. Widely used: Used by ElasticSearch, many log processors.
4. Simple: No need to manage array brackets or commas
5. Performance: True append-only (no file rewrites)

We don't include timestamps because that made testing harder. We could add them back later if important.

For JSONL:

- Official spec: https://jsonlines.org/
- Also known as: JSON Lines, NDJSON (Newline Delimited JSON)
- MIME type: application/jsonl or application/x-jsonl

The usual file extension is `.jsonl` (so that is recommended).
