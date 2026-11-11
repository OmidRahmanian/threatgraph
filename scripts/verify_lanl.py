"""Check the downloaded LANL files before ingesting them.

python scripts/verify_lanl.py                  # quick: first 10,000 rows of each file
python scripts/verify_lanl.py --full --sha256  # stream everything, hash, compare with last run
"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    args = sys.argv[1:]
    if not any(a == "--dataset" or a.startswith("--dataset=") for a in args):
        args = ["--dataset", "lanl", *args]
    main(["verify-raw", *args])
