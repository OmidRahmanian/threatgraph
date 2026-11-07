"""Scale rehearsal: replicate the synthetic fixture K times and measure each stage.

python scripts/scale_rehearsal.py --out /tmp/tg-scale --copies 200 --days 4

Accounts and computers are renamed per copy (U12@DOM1 -> U12k7@DOM1), so the result has K
times the entities and events per day of the first `--days` days of the demo. Each stage runs
in its own process so peak RSS is per stage. This measures the pipeline's resource use, not
detection quality, and it is still synthetic data. Output: <out>/scale_report.json.
"""

from __future__ import annotations

import argparse
import gzip
import json
import platform
import subprocess
import sys
from pathlib import Path

STAGE_CODE = """
import json, resource, sys, time
from pathlib import Path
from threatgraph import pipeline
from threatgraph.config import DatasetConfig, load_dataset_config, load_models_config
root, stage, chunk = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
base = load_dataset_config("demo").model_dump()
base.update(name="scale", raw_dir=str(root / "raw"), processed_dir=str(root / "processed"),
            artifacts_dir=str(root / "artifacts"))
base["features"]["chunk_seconds"] = chunk
base["ingest"].update(hash_source_files=False, block_size_bytes=64 * 1024 * 1024)
base["splits"] = {"warmup_end_day": 1, "train_end_day": 2, "validation_end_day": 3, "test_end_day": 4}
cfg = DatasetConfig(**base)
t = time.perf_counter()
info = {}
if stage == "ingest":
    r = pipeline.run_ingest(cfg)["auth"]
    info = {"events": r["rows_accepted"], "rows_per_second": r["rows_per_second"]}
elif stage == "features":
    info = {"windows": pipeline.run_features(cfg)["n_rows"]}
elif stage == "graph":
    info = {"edge_rows": pipeline.run_graph(cfg)["edge_rows"]}
elif stage in ("train", "evaluate"):
    getattr(pipeline, "run_" + stage)(cfg, load_models_config())
elif stage == "export":
    from threatgraph.serving.export import export_bundle
    from threatgraph.serving.payloads import ServingContext
    info = {"bundle_bytes": export_bundle(ServingContext(cfg, load_models_config(), public_ids=True),
                                          root / "export")["total_bytes"]}
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
rss_mb = rss / 1024 / 1024 if sys.platform == "darwin" else rss / 1024
print(json.dumps({"stage": stage, "chunk_seconds": chunk, "seconds": round(time.perf_counter() - t, 1),
                  "peak_rss_mb": round(rss_mb), **info}))
"""


def make_fixture(src: Path, out: Path, copies: int, days: int) -> int:
    import polars as pl

    cols = ["time", "sp", "dp", "sc", "dc", "at", "lt", "ao", "oc"]
    df = pl.read_csv(
        src,
        has_header=False,
        new_columns=cols,
        schema_overrides=dict.fromkeys(cols, pl.String),
        truncate_ragged_lines=True,
        quote_char=None,
    )
    df = df.with_columns(pl.col("time").cast(pl.Int64, strict=False)).filter(
        pl.col("time").is_not_null() & (pl.col("time") < days * 86_400)
    )
    parts = [
        df.with_columns(
            pl.col(c).str.replace(r"^([UC]\d+)", "${1}" + f"k{k}") for c in ("sp", "dp", "sc", "dc")
        )
        for k in range(copies)
    ]
    big = pl.concat(parts).sort("time", maintain_order=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wb", compresslevel=1) as fh:
        big.write_csv(fh, include_header=False, quote_style="never")
    return big.height


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--copies", type=int, default=200)
    ap.add_argument("--days", type=int, default=4)
    ap.add_argument("--chunks", default="86400,3600", help="feature chunk sizes to compare")
    args = ap.parse_args()
    repo = Path(__file__).resolve().parents[1]
    demo_raw = repo / "data" / "demo" / "raw"
    if not (demo_raw / "auth.txt.gz").exists():
        sys.exit("run `python scripts/generate_demo_data.py --seed 42` first")
    raw = args.out / "raw"
    n = make_fixture(demo_raw / "auth.txt.gz", raw / "auth.txt.gz", args.copies, args.days)
    (raw / "redteam.txt.gz").write_bytes((demo_raw / "redteam.txt.gz").read_bytes())
    chunks = [int(c) for c in args.chunks.split(",")]
    runs = []

    def run(stage: str, chunk: int) -> None:
        cmd = [sys.executable, "-c", STAGE_CODE, str(args.out), stage, str(chunk)]
        line = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()
        runs.append(json.loads(line.splitlines()[-1]))
        print(runs[-1], flush=True)

    run("ingest", chunks[-1])
    for c in chunks:
        run("features", c)
    for stage in ("graph", "train", "evaluate", "export"):
        run(stage, chunks[-1])
    report = {
        "fixture": {
            "kind": "synthetic demo replicated with renamed entities (not real data)",
            "copies": args.copies,
            "days": args.days,
            "events": n,
            "events_per_day": round(n / args.days),
        },
        "machine": {"platform": platform.platform(), "python": platform.python_version()},
        "runs": runs,
    }
    (args.out / "scale_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"wrote {args.out / 'scale_report.json'}")


if __name__ == "__main__":
    main()
