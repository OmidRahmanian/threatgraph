"""Wrapper for `threatgraph graph`. Usage: python scripts/build_graph.py --help"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    main(["graph", *sys.argv[1:]])
