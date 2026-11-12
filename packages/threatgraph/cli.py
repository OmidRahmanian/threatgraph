"""Command-line entry points. `scripts/*.py` are thin wrappers around these commands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threatgraph import pipeline
from threatgraph.config import REPO_ROOT, DatasetConfig, load_dataset_config, load_models_config

DEFAULT_EXPORT_ROOT = REPO_ROOT / "apps" / "web" / "public" / "threatgraph-data"

LANL_MISSING_HELP = """\
LANL source files not found: {missing}

ThreatGraph never downloads the LANL data for you. To use real data:
  1. Visit https://csr.lanl.gov/data/cyber1/ and complete LANL's data-use form.
  2. Download auth.txt.gz and redteam.txt.gz (auth is ~7 GB compressed), and proc.txt.gz
     if `proc` is enabled for this dataset in configs/datasets.yaml (optional).
  3. Place them in {raw_dir}/ (this directory is git-ignored; never commit them).
  4. Run: python scripts/ingest_lanl.py --inspect-redteam
     then choose time_window / splits in configs/datasets.yaml so each evaluated split
     contains red-team records.
Until then, the synthetic demo keeps working:  python scripts/run_pipeline.py --dataset demo
"""


def _dataset(name: str) -> DatasetConfig:
    return load_dataset_config(name)


def _print(obj: object) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_generate(args: argparse.Namespace) -> None:
    from threatgraph.data.synthetic import SyntheticSpec, generate_fixture

    cfg = _dataset("demo")
    res = generate_fixture(cfg.raw_path, SyntheticSpec(seed=args.seed))
    _print(
        {
            "auth": str(res.auth_path),
            "redteam": str(res.redteam_path),
            "files": res.manifest["files"],
        }
    )


def _check_raw(cfg: DatasetConfig) -> None:
    missing = [k for k in cfg.files if not cfg.raw_file(k).exists()]
    if not missing:
        return
    if cfg.mode == "lanl":
        names = ", ".join(cfg.files[k] for k in missing)
        sys.exit(LANL_MISSING_HELP.format(missing=names, raw_dir=cfg.raw_dir))
    sys.exit(
        f"missing {missing} in {cfg.raw_dir}; run: python scripts/generate_demo_data.py --seed 42"
    )


def cmd_ingest(args: argparse.Namespace) -> None:
    cfg = _dataset(args.dataset)
    _check_raw(cfg)
    if args.inspect_redteam:
        from threatgraph.data.ingest import ingest_redteam

        unbounded = cfg.model_copy(
            update={
                "time_window": cfg.time_window.model_copy(
                    update={"end_seconds": None, "start_seconds": 0}
                )
            }
        )
        from threatgraph.data.splits import suggest_splits, yaml_snippet

        _, report = ingest_redteam(unbounded, cfg.processed_path / "inspect")
        by_day = {int(k): v for k, v in report["records_by_day"].items()}
        s = cfg.splits
        suggestion = suggest_splits(
            by_day,
            warmup_days=round(s.warmup_end_day),
            train_days=round(s.train_end_day - s.warmup_end_day),
            validation_days=round(s.validation_end_day - s.train_end_day),
            test_days=round(s.test_end_day - s.validation_end_day),
        )
        _print(
            {
                "records_total": report["records_total"],
                "records_by_day": report["records_by_day"],
                "split_suggestion": suggestion,
            }
        )
        if suggestion["ok"]:
            print(
                f"\nTo use it, set these two lines under `{cfg.name}:` in configs/datasets.yaml:\n"
                + yaml_snippet(suggestion["suggestion"])
            )
        return
    report = pipeline.run_ingest(cfg)
    auth = report["auth"]
    _print(
        {
            "rows_accepted": auth["rows_accepted"],
            "rows_rejected": auth["rows_rejected"],
            "rows_per_second": auth["rows_per_second"],
            "label_join": {
                k: v for k, v in report["label_join"].items() if k != "unmatched_examples"
            },
            "report": str(pipeline.quality_report_path(cfg)),
        }
    )


def cmd_features(args: argparse.Namespace) -> None:
    cfg = _dataset(args.dataset)
    if not pipeline.labels_path(cfg).exists():
        print(f"no ingested data for '{cfg.name}' yet; running ingest first", file=sys.stderr)
        cmd_ingest(argparse.Namespace(dataset=args.dataset, inspect_redteam=False))
    manifest = pipeline.run_features(cfg)
    _print({"n_rows": manifest["n_rows"], "splits": manifest["splits"]})


def cmd_graph(args: argparse.Namespace) -> None:
    m = pipeline.run_graph(_dataset(args.dataset))
    _print({k: m[k] for k in ("edge_rows", "events_in_graph", "principals", "computers")})


def cmd_train(args: argparse.Namespace) -> None:
    summaries = pipeline.run_train(_dataset(args.dataset), load_models_config())
    _print({m: {"threshold": s["threshold"], **s["train_info"]} for m, s in summaries.items()})


def cmd_evaluate(args: argparse.Namespace) -> None:
    cfg = _dataset(args.dataset)
    pipeline.run_evaluate(cfg, load_models_config())
    print((cfg.artifacts_path / "reports" / "evaluation.md").read_text())


def cmd_export(args: argparse.Namespace) -> None:
    from threatgraph.serving.export import export_bundle
    from threatgraph.serving.payloads import ServingContext

    cfg = _dataset(args.dataset)
    ctx = ServingContext(cfg, load_models_config(), public_ids=True)
    out = Path(args.out) if args.out else DEFAULT_EXPORT_ROOT / cfg.name / "v1"
    res = export_bundle(ctx, out)
    _print(
        {"out_dir": res["out_dir"], "total_bytes": res["total_bytes"], "n_files": len(res["files"])}
    )


def cmd_verify_raw(args: argparse.Namespace) -> None:
    from threatgraph.data.integrity import integrity_report_path, verify_raw

    cfg = _dataset(args.dataset)
    _check_raw(cfg)
    report = verify_raw(cfg, full=args.full, sha256=args.sha256)
    _print(report)
    print(f"\nwritten to {integrity_report_path(cfg)}", file=sys.stderr)
    if not report["ok"]:
        sys.exit(1)


def cmd_status(_: argparse.Namespace) -> None:
    from threatgraph.serving.datasets import dataset_status_list

    for d in dataset_status_list(load_models_config()).datasets:
        print(f"{d.dataset:<12} {d.mode_label:<34} {d.status:<14} {d.status_detail}")


def cmd_all(args: argparse.Namespace) -> None:
    if args.dataset == "demo" and not _dataset("demo").raw_file("auth").exists():
        cmd_generate(argparse.Namespace(seed=args.seed))
    for fn in (cmd_ingest, cmd_features, cmd_graph, cmd_train, cmd_evaluate, cmd_export):
        fn(argparse.Namespace(dataset=args.dataset, inspect_redteam=False, out=None))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threatgraph")
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate", help="write the deterministic synthetic fixture")
    g.add_argument("--seed", type=int, default=42)
    g.set_defaults(fn=cmd_generate)
    st = sub.add_parser("status", help="show which datasets are pending, stale or evaluated")
    st.set_defaults(fn=cmd_status)
    v = sub.add_parser("verify-raw", help="check raw source files before ingesting them")
    v.add_argument("--dataset", default="lanl")
    v.add_argument("--full", action="store_true", help="stream the whole file (slow on LANL)")
    v.add_argument("--sha256", action="store_true", help="hash and compare with last run")
    v.set_defaults(fn=cmd_verify_raw)
    for name, fn, help_ in (
        ("ingest", cmd_ingest, "parse raw files into Parquet + data-quality report"),
        ("features", cmd_features, "build causal window features"),
        ("graph", cmd_graph, "build the entity graph tables"),
        ("train", cmd_train, "fit models and persist scores"),
        ("evaluate", cmd_evaluate, "compute held-out metrics"),
        ("export", cmd_export, "write the static website bundle"),
        ("all", cmd_all, "run every stage"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--dataset", default="demo")
        sp.set_defaults(fn=fn)
        if name == "ingest":
            sp.add_argument(
                "--inspect-redteam", action="store_true", help="only summarise red-team days"
            )
        if name == "export":
            sp.add_argument("--out", default=None)
        if name == "all":
            sp.add_argument("--seed", type=int, default=42)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except pipeline.MissingInputError as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
