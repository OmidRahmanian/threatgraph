"""Ingest LANL-format auth + red-team files (defaults to the real LANL dataset config).

python scripts/ingest_lanl.py                    # real data in data/raw/lanl/
python scripts/ingest_lanl.py --inspect-redteam  # red-team records per day, to pick splits
python scripts/ingest_lanl.py --dataset demo     # the synthetic fixture
"""

import sys

from threatgraph.cli import main

if __name__ == "__main__":
    args = sys.argv[1:]
    if not any(a == "--dataset" or a.startswith("--dataset=") for a in args):
        args = ["--dataset", "lanl", *args]
    main(["ingest", *args])
