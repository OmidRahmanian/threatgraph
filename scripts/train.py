"""Wrapper for `threatgraph train`. Usage: python scripts/train.py --help"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    main(["train", *sys.argv[1:]])
