"""Wrapper for `threatgraph export`. Usage: python scripts/export_demo.py --help"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    main(["export", *sys.argv[1:]])
