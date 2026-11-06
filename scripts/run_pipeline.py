"""Wrapper for `threatgraph all`. Usage: python scripts/run_pipeline.py --help"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    main(["all", *sys.argv[1:]])
