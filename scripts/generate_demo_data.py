"""Wrapper for `threatgraph generate`. Usage: python scripts/generate_demo_data.py --help"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    main(["generate", *sys.argv[1:]])
