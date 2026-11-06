"""Runtime environment facts recorded alongside every artifact."""

from __future__ import annotations

import platform
import resource
import sys
from importlib.metadata import PackageNotFoundError, version

TRACKED = ("numpy", "polars", "pyarrow", "duckdb", "scikit-learn", "fastapi", "pydantic")


def library_versions() -> dict[str, str]:
    out = {"python": platform.python_version()}
    for name in TRACKED:
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            out[name] = "not installed"
    return out


def peak_rss_mb() -> float:
    """Peak resident set size of this process (ru_maxrss is bytes on macOS, KiB on Linux)."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024, 1)
