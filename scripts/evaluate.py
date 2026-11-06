"""Wrapper for `threatgraph evaluate`. Usage: python scripts/evaluate.py --help"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    main(["evaluate", *sys.argv[1:]])
