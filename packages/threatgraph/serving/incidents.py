"""Incidents: labeled red-team activity grouped per account, replayed against model scores.

An incident is a maximal run of red-team-matched events by one source account in which
consecutive events are at most `incidents.gap_seconds` apart. It is derived from labels only
(never from scores), so it is a reconstruction of *documented* activity, not a detection.
Detection markers come from the persisted window scores at each model's fixed threshold, and
an alert is placed at its window's end, when it would have been raised.

Write-ups are generated from these facts by fixed templates (no language model), so every
sentence can be traced to a number in the same payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, Literal

import polars as pl

from threatgraph.config import DAY_SECONDS
from threatgraph.data.features import scoped_events
from threatgraph.pipeline import labels_path, scan_auth
from threatgraph.serving import schemas as S

if TYPE_CHECKING:
    from threatgraph.serving.payloads import ServingContext

EVALUATED = ("validation", "test")
SCORED = ("train", "validation", "test")
DEFINITION = (
    "An incident is a run of authentication events by one account that were matched to the "
    "red-team file, with no gap longer than {gap}. Incidents come from labels only. A model "
    "detects an incident when it alerts on at least one window containing a labeled event; the "
    "alert is placed at that window's end, when it would have been raised."
)
CAVEATS = [
    "Unlabeled events in the same period are not confirmed benign: the red-team file documents "
    "some attacker activity, not all of it.",
    "Alerts mean an account-hour was unusual compared with the training period. They are not "
    "verdicts.",
]


def rel_time(seconds: int) -> str:
    day, rem = divmod(int(seconds), DAY_SECONDS)
    return f"Day {day} · +{rem:,}s"


def duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    return f"{seconds / 3600:.1f} h"


@dataclass(frozen=True)
class _Incident:
    principal: str
    start: int
    end: int
    event_ids: tuple[int, ...]


class IncidentBuilder:
    def __init__(self, ctx: ServingContext):
        self.ctx = ctx
        self.cfg = ctx.cfg.incidents

    @cached_property
    def labeled_events(self) -> pl.DataFrame:
        ids = pl.read_parquet(labels_path(self.ctx.cfg))["event_id"]
        return (
            scan_auth(self.ctx.cfg)
            .filter(pl.col("event_id").is_in(ids.implode()))
            .collect()
            .sort("src_principal", "event_time_seconds", "event_id")
        )

    @cached_property
    def incidents(self) -> dict[str, _Incident]:
        df = self.labeled_events.with_columns(
            (pl.col("event_time_seconds").diff().over("src_principal") > self.cfg.gap_seconds)
            .fill_null(True)
            .cum_sum()
            .over("src_principal")
            .alias("_run")
        )
        out: dict[str, _Incident] = {}
        for (p, _), part in df.group_by("src_principal", "_run", maintain_order=True):
            inc = _Incident(
                principal=str(p),
                start=int(part["event_time_seconds"].min()),  # type: ignore[arg-type]
                end=int(part["event_time_seconds"].max()),  # type: ignore[arg-type]
                event_ids=tuple(part["event_id"].to_list()),
            )
            out[self.incident_id(inc)] = inc
        return dict(sorted(out.items(), key=lambda kv: (kv[1].start, kv[1].principal)))

    def incident_id(self, inc: _Incident) -> str:
        return f"inc:{self.ctx.alias(inc.principal)}:{inc.start}"

    def _range(self, inc: _Incident) -> tuple[int, int]:
        w = self.ctx.cfg.features.window_seconds
        ctx_w = -(-self.cfg.context_seconds // w) * w  # ceil to whole windows
        return inc.start // w * w - ctx_w, (inc.end // w + 1) * w + ctx_w

    def _windows(self, inc: _Incident) -> pl.DataFrame:
        lo, hi = self._range(inc)
        return self.ctx.predictions.filter(
            (pl.col("src_principal") == inc.principal)
            & (pl.col("window_start") >= lo)
            & (pl.col("window_start") < hi)
        ).sort("window_start")

    def _split(self, inc: _Incident) -> str:
        w = self.ctx.cfg.features.window_seconds
        hit = self.ctx.features.filter(
            (pl.col("src_principal") == inc.principal)
            & (pl.col("window_start") == inc.start // w * w)
        )
        return str(hit["split"][0]) if hit.height else "unscored"

    def _detections(self, inc: _Incident, windows: pl.DataFrame) -> list[S.IncidentDetection]:
        labeled = windows.filter((pl.col("label") == 1) & pl.col("split").is_in(SCORED))
        out = []
        for m, model in self.ctx.models.items():
            assert model.threshold is not None
            col = f"score__{m}"
            alerted = labeled.filter(pl.col(col) >= model.threshold)
            first = int(alerted["window_end"].min()) if alerted.height else None  # type: ignore[arg-type]
            status: Literal["detected", "missed", "not_scored"] = (
                "not_scored" if labeled.is_empty() else ("detected" if first else "missed")
            )
            out.append(
                S.IncidentDetection(
                    model_id=m,
                    display_name=model.display_name,
                    status=status,
                    first_alert_seconds=first,
                    latency_seconds=None if first is None else first - inc.start,
                    labeled_windows=labeled.height,
                    alerted_labeled_windows=alerted.height,
                    alerted_windows_in_range=int((windows[col] >= model.threshold).sum()),
                    max_labeled_score=float(labeled[col].max()) if labeled.height else None,  # type: ignore[arg-type]
                    threshold=model.threshold,
                )
            )
        return out

    def _computers(self, inc: _Incident) -> list[str]:
        hops = self.labeled_events.filter(pl.col("event_id").is_in(list(inc.event_ids)))
        seen: list[str] = []
        for r in hops.iter_rows(named=True):
            for c in (r["src_computer"], r["dst_computer"]):
                if c is not None and c not in seen:
                    seen.append(c)
        return seen

    def summary(self, incident_id: str, inc: _Incident) -> S.IncidentSummary:
        return S.IncidentSummary(
            incident_id=incident_id,
            principal=self.ctx.alias(inc.principal) or "",
            principal_id=self.ctx.entity_id("principal", inc.principal),
            split=self._split(inc),
            start_seconds=inc.start,
            end_seconds=inc.end,
            n_labeled_events=len(inc.event_ids),
            n_computers=len(self._computers(inc)),
            detections=self._detections(inc, self._windows(inc)),
        )

    def definition(self) -> str:
        return DEFINITION.format(gap=duration(self.cfg.gap_seconds))

    def index(self, scope: str) -> S.IncidentIndex:
        items = [self.summary(i, inc) for i, inc in self.incidents.items()]
        if scope == "evaluated":
            items = [s for s in items if s.split in EVALUATED]
        return S.IncidentIndex(
            provenance=self.ctx.provenance,
            scope="incidents whose first labeled event is in the validation or test split"
            if scope == "evaluated"
            else "all incidents",
            definition=self.definition(),
            incidents=items,
        )

    def incident(self, incident_id: str) -> S.Incident:
        from threatgraph.serving.payloads import NotFoundError

        inc = self.incidents.get(incident_id)
        if inc is None:
            raise NotFoundError(incident_id)
        ctx = self.ctx
        lo, hi = self._range(inc)
        events = (
            scan_auth(ctx.cfg)
            .filter(
                pl.col("day").is_between(lo // DAY_SECONDS, (hi - 1) // DAY_SECONDS)
                & (pl.col("src_principal") == inc.principal)
                & (pl.col("event_time_seconds") >= lo)
                & (pl.col("event_time_seconds") < hi)
            )
            .collect()
        )
        labeled_ids = set(inc.event_ids)
        # Keep every labeled event; fill the rest of the budget with remote events first.
        ranked = events.with_columns(
            pl.col("event_id").is_in(list(labeled_ids)).alias("_lab"),
            (pl.col("src_computer") != pl.col("dst_computer")).fill_null(False).alias("_remote"),
        ).sort(
            ["_lab", "_remote", "event_time_seconds", "event_id"],
            descending=[True, True, False, False],
        )
        shown = (
            ranked.head(self.cfg.max_events)
            .sort("event_time_seconds", "event_id")
            .drop("_lab", "_remote")
        )
        used = set(scoped_events(shown.lazy(), ctx.cfg).collect()["event_id"].to_list())
        windows = self._windows(inc)
        summary = self.summary(incident_id, inc)
        hops = [
            S.IncidentHop(
                event_id=r["event_id"],
                event_time_seconds=r["event_time_seconds"],
                src_computer=ctx.alias(r["src_computer"]),
                dst_computer=ctx.alias(r["dst_computer"]),
                auth_type=r["auth_type"],
                outcome=r["outcome"],
            )
            for r in self.labeled_events.filter(pl.col("event_id").is_in(list(inc.event_ids)))
            .sort("event_time_seconds", "event_id")
            .iter_rows(named=True)
        ]
        win_rows = []
        for r in windows.iter_rows(named=True):
            scores = {}
            for m, model in ctx.models.items():
                assert model.threshold is not None
                sc = float(r[f"score__{m}"])
                scores[m] = S.IncidentScore(
                    score=sc, threshold=model.threshold, flagged=sc >= model.threshold
                )
            win_rows.append(
                S.IncidentWindow(
                    window_id=ctx.window_id(inc.principal, r["window_start"]),
                    window_start=r["window_start"],
                    window_end=r["window_end"],
                    split=r["split"],
                    label="known_redteam" if r["label"] else "unlabeled",
                    n_labeled_events=r["n_labeled_events"],
                    scores=scores,
                )
            )
        caveats = list(CAVEATS)
        if ctx.provenance.is_synthetic:
            caveats.append(
                "Synthetic demo: this activity was generated by scripts/generate_demo_data.py."
            )
        return S.Incident(
            provenance=ctx.provenance,
            summary=summary,
            definition=self.definition(),
            range_start_seconds=lo,
            range_end_seconds=hi,
            hops=hops,
            events=ctx._event_rows(shown, used),
            n_events_total=events.height,
            events_truncated=events.height > shown.height,
            windows=win_rows,
            writeup=self.writeup(summary, hops),
            caveats=caveats,
        )

    def writeup(self, s: S.IncidentSummary, hops: list[S.IncidentHop]) -> list[str]:
        n_src = len({h.src_computer for h in hops if h.src_computer})
        n_dst = len({h.dst_computer for h in hops if h.dst_computer})
        span = s.end_seconds - s.start_seconds
        lines = [
            f"{s.principal} has {s.n_labeled_events} authentication event"
            f"{'' if s.n_labeled_events == 1 else 's'} matched to the red-team file between "
            f"{rel_time(s.start_seconds)} and {rel_time(s.end_seconds)} ({duration(span)}), "
            f"from {n_src} source to {n_dst} destination computer{'' if n_dst == 1 else 's'}.",
            "Labeled hops in order: "
            + ", ".join(f"{h.src_computer} → {h.dst_computer}" for h in hops[:12])
            + (f", and {len(hops) - 12} more." if len(hops) > 12 else "."),
        ]
        split_note = {
            "train": "The first labeled event falls in the training period, so these scores are "
            "in-sample for the models (trained there without labels).",
            "validation": "The first labeled event falls in the validation period, where the "
            "alert thresholds were calibrated.",
            "test": "The first labeled event falls in the held-out test period.",
        }.get(s.split, "The first labeled event falls outside the scored periods.")
        lines.append(split_note)
        for d in s.detections:
            if d.status == "detected":
                assert d.first_alert_seconds is not None and d.latency_seconds is not None
                lines.append(
                    f"{d.display_name}: first alert at {rel_time(d.first_alert_seconds)}, "
                    f"{duration(d.latency_seconds)} after the first labeled event; it alerted on "
                    f"{d.alerted_labeled_windows} of {d.labeled_windows} labeled windows."
                )
            elif d.status == "missed":
                lines.append(
                    f"{d.display_name}: no alert on any of the {d.labeled_windows} labeled "
                    f"windows (highest score {d.max_labeled_score:.4f} vs threshold "
                    f"{d.threshold:.4f})."
                )
            else:
                lines.append(f"{d.display_name}: no labeled window was scored.")
        return lines


def writeups_markdown(builder: IncidentBuilder, scope: str = "evaluated") -> str:
    """All write-ups of `scope` as one Markdown document (static download and report)."""
    prov = builder.ctx.provenance
    out = [
        f"# Incident write-ups: {prov.dataset} ({prov.mode_label})",
        "",
        "Generated from pipeline outputs by threatgraph.serving.incidents; do not edit by hand.",
        "",
        builder.definition(),
        "",
    ]
    for s in builder.index(scope).incidents:
        inc = builder.incident(s.incident_id)
        out += [f"## {s.principal} · {rel_time(s.start_seconds)} ({s.split})", ""]
        out += [f"- {line}" for line in inc.writeup]
        out += ["", *[f"> {c}" for c in inc.caveats], ""]
    return "\n".join(out) + "\n"
