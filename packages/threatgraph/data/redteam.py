"""Join red-team annotations to authentication events.

LANL documents red-team records as `time,user@domain,source computer,destination computer`.
We match on that composite key against auth events. Consequences that the report makes
explicit:

* a key can match several auth events (repeated lines) -> all are labeled, flagged ambiguous;
* a key can match nothing (outside the window, or no corresponding auth row) -> unmatched;
* an auth event without a match is *unlabeled*, not confirmed benign.
"""

from __future__ import annotations

from typing import Any, Literal

import polars as pl

from threatgraph.data.schema import LABEL_SCHEMA

KEY = ["event_time_seconds", "principal", "src_computer", "dst_computer"]


def match_redteam(
    auth: pl.LazyFrame,
    redteam: pl.DataFrame,
    *,
    user_field: Literal["source", "destination"],
    label_source: str,
) -> tuple[pl.DataFrame, dict[str, Any]]:
    """Return (labels, report). `labels` has one row per labeled auth event."""
    principal_col = "src_principal" if user_field == "source" else "dst_principal"
    keys = (
        redteam.group_by(KEY, maintain_order=True)
        .agg(
            pl.col("redteam_record_id").min().alias("redteam_record_id"),
            pl.len().alias("n_records"),
        )
        .sort("redteam_record_id")
    )
    times = keys["event_time_seconds"].unique().to_list()
    candidates = (
        auth.filter(pl.col("event_time_seconds").is_in(times))
        .select("event_id", "event_time_seconds", principal_col, "src_computer", "dst_computer")
        .rename({principal_col: "principal"})
        .collect()
    )
    matched = keys.join(candidates, on=KEY, how="inner", nulls_equal=False)
    per_key = matched.group_by("redteam_record_id").agg(pl.len().alias("match_multiplicity"))
    labels = (
        matched.join(per_key, on="redteam_record_id")
        .select(
            "event_id",
            pl.lit(label_source).alias("label_source"),
            "redteam_record_id",
            "match_multiplicity",
        )
        .unique(subset="event_id", keep="first", maintain_order=True)
        .sort("event_id")
        .cast(LABEL_SCHEMA)  # type: ignore[arg-type]
    )
    unmatched = keys.join(per_key, on="redteam_record_id", how="anti")
    report = {
        "match_key": ["time", f"{user_field}_principal", "src_computer", "dst_computer"],
        "records_considered": redteam.height,
        "distinct_keys": keys.height,
        "duplicate_records": int(redteam.height - keys.height),
        "keys_matched": per_key.height,
        "keys_unmatched": unmatched.height,
        "keys_ambiguous": int(per_key.filter(pl.col("match_multiplicity") > 1).height),
        "auth_events_labeled": labels.height,
        "unmatched_examples": unmatched.head(10).drop("n_records").to_dicts(),
        "label_semantics": "unmatched auth events are unlabeled, not confirmed benign",
    }
    return labels, report
