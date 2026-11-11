"""Live Monitoring Mode: telemetry from your own servers and websites.

Kept separate from Research Mode (historical LANL/synthetic data): live events, incidents and
notifications never mix with research results. Modules used by the collector agent
(`events`, `redact`, `parsers`, `agent`, `probe`) depend on the Python standard library only,
so the agent runs on a small VPS without the scientific stack.
"""
