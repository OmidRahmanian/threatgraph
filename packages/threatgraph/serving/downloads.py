"""Plain-file downloads generated from the same payloads as the API: a model-comparison CSV,
one Markdown model card per model, and the incident write-ups. Each file states its dataset
mode in its first line, so a copied file cannot be mistaken for real-data results."""

from __future__ import annotations

import csv
import io
import json

from threatgraph.serving import schemas as S
from threatgraph.serving.incidents import rel_time, writeups_markdown
from threatgraph.serving.payloads import ServingContext

COMPARISON_COLUMNS = [
    "model_id",
    "display_name",
    "split",
    "n_windows",
    "n_known_positive_windows",
    "average_precision",
    "random_ranking_average_precision",
    "precision_at_10",
    "threshold",
    "alerts",
    "known_label_recall",
    "precision_lower_bound",
]


def _header(p: S.Provenance) -> str:
    return f"{p.mode_label} · dataset {p.dataset} · config {p.config_hash} · pipeline {p.pipeline_version}"


def comparison_csv(ctx: ServingContext) -> str:
    buf = io.StringIO()
    buf.write(f"# {_header(ctx.provenance)}. Unlabeled windows count as negatives.\n")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COMPARISON_COLUMNS)
    for m in ctx.model_list().models:
        for h in m.headline:
            sm = ctx.metrics["models"][m.model_id]["splits"][h.split]
            w.writerow(
                [
                    m.model_id,
                    m.display_name,
                    h.split,
                    sm["n_windows"],
                    sm["n_positive_windows"],
                    h.average_precision,
                    h.random_ranking_average_precision,
                    h.precision_at_10,
                    m.threshold,
                    h.alerts,
                    h.known_label_recall,
                    h.precision_lower_bound,
                ]
            )
    return buf.getvalue()


def model_card_md(ctx: ServingContext, m: S.ModelInfo) -> str:
    t = m.train_info
    bounds = ctx.metrics["split_boundaries_seconds"]
    fmt = lambda v: "n/e" if v is None else f"{v:.3f}"  # noqa: E731
    lines = [
        f"# Model card — {m.display_name}",
        "",
        f"_{_header(ctx.provenance)}. Generated from artifacts; do not edit by hand._",
        "",
        "| | |",
        "|---|---|",
        f"| Model id | `{m.model_id}` ({m.kind}) |",
        f"| What it does | {m.description} |",
        "| Intended use | Ranking account-hours for analyst triage in research and demonstration |",
        "| Not intended for | Automated blocking, attribution, or any claim that an alert is malicious |",
        f"| Training | {t.get('n_train_rows')} windows of the train split "
        f"({rel_time(bounds['train'][0])} → {rel_time(bounds['train'][1])}); labels used: "
        f"{'yes' if t.get('labels_used') else 'no'}; seed {t.get('seed')} |",
        f"| Threshold | {m.threshold:.6f}: {m.threshold_policy.get('type')} "
        f"(alert rate {m.threshold_policy.get('alert_rate')}) on "
        f"{m.threshold_policy.get('calibrated_on')} |",
        f"| Features | {', '.join(f'`{f}`' for f in m.features)} |",
        f"| Hyperparameters | `{json.dumps(m.hyperparameters, sort_keys=True)}` |",
        f"| Explanations | {m.explanation_method}. {m.explanation_caveat} |",
        f"| Artifact | sha256 `{m.artifact_sha256}` |",
        f"| Libraries | {', '.join(f'{k} {v}' for k, v in m.library_versions.items())} |",
        "",
        "## Held-out results",
        "",
        "| Split | AP | Random-ranking AP | P@10 | Alerts | Known-label recall | Precision (lower bound) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for h in m.headline:
        lines.append(
            f"| {h.split} | {fmt(h.average_precision)} | {fmt(h.random_ranking_average_precision)} | "
            f"{fmt(h.precision_at_10)} | {h.alerts} | {fmt(h.known_label_recall)} | "
            f"{fmt(h.precision_lower_bound)} |"
        )
    lines += [
        "",
        "n/e = not estimable. Unlabeled windows count as negatives, so precision is a lower "
        "bound; recall covers documented red-team activity only.",
    ]
    if ctx.provenance.is_synthetic:
        lines += [
            "",
            "These results come from a synthetic fixture designed by the author. They show the "
            "pipeline works; they do not estimate real-world performance.",
        ]
    return "\n".join(lines) + "\n"


def downloads(ctx: ServingContext) -> dict[str, str]:
    """Relative path -> file contents."""
    out = {"model_comparison.csv": comparison_csv(ctx)}
    for m in ctx.model_list().models:
        out[f"model_cards/{m.model_id}.md"] = model_card_md(ctx, m)
    out["incident_writeups.md"] = writeups_markdown(ctx.incident_builder, "evaluated")
    return out
