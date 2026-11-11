# Simulated live-monitoring fixtures

Every line in this directory is **simulated** for tests. None of it was collected from a real
server. Client addresses come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and RFC 3849 (2001:db8::/32), which are never routed on the
internet. Host names, users and paths are invented.

The files cover the formats in `packages/threatgraph/live/parsers.py`, including malformed and
hostile lines (garbage, terminal escapes, spoofed fields, prompt-injection text) that parsers
and the LLM investigator must handle safely.
