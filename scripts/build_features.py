"""Wrapper for `threatgraph features`. Usage: python scripts/build_features.py --help"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    main(["features", *sys.argv[1:]])
