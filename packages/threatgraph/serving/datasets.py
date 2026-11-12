"""Status of every configured research dataset (synthetic demo, real LANL, ...).

The Experiment Lab uses this to say plainly whether real-data results exist. A dataset is
reported as `evaluated` only when a metrics.json built for the *current* configuration exists;
otherwise it is pending, and no number is shown for it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatgraph.config import (
    CONFIG_DIR,
    DatasetConfig,
    ModelsConfig,
    _read_yaml,
    load_dataset_config,
)
from threatgraph.pipeline import (
    StaleInputError,
    load_run_records,
    metrics_path,
    quality_report_path,
    require_fresh,
)
from threatgraph.provenance import mode_label
from threatgraph.serving import schemas as S

STATUS_SEMANTICS = (
    "files_missing: the raw files are not on this machine (real LANL data must be requested "
    "through LANL's form). not_processed: files are present but the pipeline has not run. "
    "ingested: parsed, not yet evaluated. stale: outputs exist but were built under a different "
    "configuration. evaluated: held-out metrics exist for the current configuration. Results "
    "are shown only for evaluated datasets."
)


def dataset_names(path: Path | None = None) -> list[str]:
    return list(_read_yaml(path or CONFIG_DIR / "datasets.yaml")["datasets"])


def _model_results(metrics: dict[str, Any]) -> list[S.DatasetModelResult]:
    out = []
    for model_id, m in metrics.get("models", {}).items():
        test = m.get("splits", {}).get("test", {})
        op = test.get("operating_point") or {}
        out.append(
            S.DatasetModelResult(
                model_id=model_id,
                display_name=m.get("display_name", model_id),
                test_average_precision=test.get("average_precision")
                if test.get("average_precision_estimable")
                else None,
                test_known_positive_windows=int(test.get("n_positive_windows", 0)),
                test_alerts=op.get("alerts"),
            )
        )
    return out


def dataset_status(cfg: DatasetConfig, mcfg: ModelsConfig) -> S.DatasetStatus:
    present = {k: cfg.raw_file(k).exists() for k in cfg.files}
    runs = load_run_records(cfg) if cfg.artifacts_path.exists() else {}
    seconds = {k: float(v["seconds"]) for k, v in runs.items() if "seconds" in v}
    rss = {k: float(v["peak_rss_mb"]) for k, v in runs.items() if "peak_rss_mb" in v}
    rows_ok = rows_bad = None
    models: list[S.DatasetModelResult] = []
    qpath = quality_report_path(cfg)

    status: str
    if metrics_path(cfg).exists():
        try:
            require_fresh(metrics_path(cfg), cfg, "evaluate", mcfg)
            status, detail = "evaluated", "Held-out metrics exist for the current configuration."
            models = _model_results(json.loads(metrics_path(cfg).read_text()))
        except StaleInputError as exc:
            status, detail = "stale", str(exc).split(" (")[0] + " was built for another config."
    elif qpath.exists():
        try:
            require_fresh(qpath, cfg, "ingest")
            status, detail = "ingested", "Parsed; features, training or evaluation have not run."
        except StaleInputError:
            status, detail = "stale", "Processed data was built for another configuration."
    elif all(present.values()):
        status, detail = "not_processed", "Raw files are present; the pipeline has not run."
    else:
        missing = ", ".join(cfg.files[k] for k, ok in present.items() if not ok)
        status, detail = "files_missing", f"Not on this machine: {missing}."
    if qpath.exists():
        q = json.loads(qpath.read_text())
        rows_ok = q.get("auth", {}).get("rows_accepted")
        rows_bad = q.get("auth", {}).get("rows_rejected")
    return S.DatasetStatus(
        dataset=cfg.name,
        mode=cfg.mode,
        mode_label=mode_label(cfg.mode),
        status=status,  # type: ignore[arg-type]
        status_detail=detail,
        raw_files_present=present,
        time_window_seconds=[cfg.time_window.start_seconds, cfg.time_window.end_seconds],
        rows_accepted=rows_ok,
        rows_rejected=rows_bad,
        stage_seconds=seconds,
        stage_peak_rss_mb=rss,
        models=models,
    )


def dataset_status_list(
    mcfg: ModelsConfig, path: Path | None = None, provenance: S.Provenance | None = None
) -> S.DatasetStatusList:
    return S.DatasetStatusList(
        provenance=provenance,
        datasets=[dataset_status(load_dataset_config(n, path), mcfg) for n in dataset_names(path)],
        semantics=STATUS_SEMANTICS,
    )
