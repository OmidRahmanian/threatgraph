"""Choose a bounded time window and chronological split days from red-team record counts.

Run after the user has downloaded LANL's files: `python scripts/ingest_lanl.py --inspect-redteam`.
The suggestion only looks at *where* red-team records fall in time (not at any model score),
so choosing splits this way does not leak test performance into the design.
"""

from __future__ import annotations

from typing import Any

from threatgraph.config import DAY_SECONDS


def suggest_splits(
    records_by_day: dict[int, int],
    *,
    warmup_days: int = 2,
    train_days: int = 6,
    validation_days: int = 3,
    test_days: int = 3,
    first_day: int = 0,
    last_day: int | None = None,
) -> dict[str, Any]:
    """Pick the start day whose validation and test periods both hold the most records.

    Candidates are ranked by (min(validation, test) records, validation + test records,
    earlier start). `last_day` is the last day with auth data (inclusive), if known.
    """
    n_days = warmup_days + train_days + validation_days + test_days
    days = sorted(d for d, n in records_by_day.items() if n > 0)
    if not days:
        return {"ok": False, "reason": "the red-team file has no records", "alternatives": []}
    lo = max(first_day, days[0] - n_days + 1)
    hi = days[-1] if last_day is None else min(days[-1], last_day - n_days + 1)

    def count(a: int, b: int) -> int:
        return sum(records_by_day.get(d, 0) for d in range(a, b))

    cands: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for d0 in range(lo, max(lo, hi) + 1):
        b = [d0, d0 + warmup_days]
        b.append(b[-1] + train_days)
        b.append(b[-1] + validation_days)
        b.append(b[-1] + test_days)
        recs = {
            "warmup": count(b[0], b[1]),
            "train": count(b[1], b[2]),
            "validation": count(b[2], b[3]),
            "test": count(b[3], b[4]),
        }
        cands.append(
            (
                (min(recs["validation"], recs["test"]), recs["validation"] + recs["test"], -d0),
                {
                    "start_day": d0,
                    "time_window": {
                        "start_seconds": d0 * DAY_SECONDS,
                        "end_seconds": b[4] * DAY_SECONDS - 1,
                    },
                    "splits": {
                        "warmup_end_day": b[1],
                        "train_end_day": b[2],
                        "validation_end_day": b[3],
                        "test_end_day": b[4],
                    },
                    "redteam_records": recs,
                },
            )
        )
    cands.sort(key=lambda c: c[0], reverse=True)
    best = cands[0][1]
    ok = best["redteam_records"]["validation"] > 0 and best["redteam_records"]["test"] > 0
    return {
        "ok": ok,
        "reason": None
        if ok
        else f"no {n_days}-day window has red-team records in both validation and test",
        "suggestion": best,
        "alternatives": [c[1] for c in cands[1:4]],
        "note": (
            "Records are red-team lines, not matched auth events; matching happens at ingest. "
            "Records in warm-up/train are fine for unsupervised models, which never see labels."
        ),
    }


def yaml_snippet(suggestion: dict[str, Any]) -> str:
    tw, sp = suggestion["time_window"], suggestion["splits"]
    return (
        f"    time_window: {{ start_seconds: {tw['start_seconds']}, end_seconds: {tw['end_seconds']} }}\n"
        f"    splits: {{ warmup_end_day: {sp['warmup_end_day']}, train_end_day: {sp['train_end_day']}, "
        f"validation_end_day: {sp['validation_end_day']}, test_end_day: {sp['test_end_day']} }}"
    )
