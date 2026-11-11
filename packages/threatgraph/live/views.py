"""Read models for the private live dashboard.

Every number is computed from stored events. Missing telemetry is explicit: a time bucket in
which no agent reported (no heartbeat or metrics sample nearby) is `null`, not `0`, and the UI
draws it as a gap. Simulated test data is excluded unless explicitly requested and is then
labeled.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from threatgraph.live.config import LiveConfig
from threatgraph.live.store import LiveStore

RANGES: dict[str, tuple[int, int]] = {  # name → (seconds, bucket seconds)
    "15m": (900, 60),
    "1h": (3600, 60),
    "24h": (86_400, 900),
    "7d": (7 * 86_400, 7200),
}
COVERAGE_SLACK = 90  # heartbeats arrive every ~60 s


def _buckets(now: float, rng: str) -> tuple[float, int, list[int]]:
    span, b = RANGES[rng]
    end = (int(now) // b + 1) * b
    start = end - span
    return start, b, list(range(int(start), int(end), b))


def coverage(store: LiveStore, start: float, end: float, b: int, simulated: bool) -> set[int]:
    """Buckets during which at least one host agent was reporting."""
    rows = store.query(
        "SELECT ts FROM events WHERE kind IN ('agent.heartbeat', 'system.metrics') "
        "AND ts >= ? AND ts < ? AND simulated = ?",
        (start - COVERAGE_SLACK, end + COVERAGE_SLACK, int(simulated)),
    )
    out: set[int] = set()
    for r in rows:
        lo = int((r["ts"] - COVERAGE_SLACK) // b) * b
        hi = int((r["ts"] + COVERAGE_SLACK) // b) * b
        out.update(range(lo, hi + b, b))
    return out


def agent_status(store: LiveStore, cfg: LiveConfig, now: float) -> list[dict[str, Any]]:
    out = []
    limit = cfg.detection.agent_offline_after_seconds
    for a in store.agents():
        hb = a.get("last_heartbeat") or {}
        if a["disabled"]:
            status = "disabled"
        elif a["last_seen"] is None:
            status = "never_connected"
        else:
            status = "online" if now - a["last_seen"] < limit else "offline"
        logs = hb.get("logs") or {}
        out.append(
            {
                "source_id": a["source_id"],
                "role": a["role"],
                "status": status,
                "last_seen": a["last_seen"],
                "seconds_since_seen": None
                if a["last_seen"] is None
                else round(now - a["last_seen"]),
                "version": hb.get("version"),
                "buffered": hb.get("buffered"),
                "dropped_samples": hb.get("dropped_samples"),
                "send_failures": hb.get("send_failures"),
                "last_error": hb.get("last_error"),
                "logs": [
                    {
                        "path": p,
                        **{
                            k: v
                            for k, v in d.items()
                            if k in ("type", "parsed", "unparsed", "readable")
                        },
                    }
                    for p, d in logs.items()
                ],
                "collectors": hb.get("collectors") or {},
            }
        )
    return out


def overview(
    store: LiveStore, cfg: LiveConfig, now: float, rng: str = "1h", simulated: bool = False
) -> dict[str, Any]:
    start, b, buckets = _buckets(now, rng)
    end = buckets[-1] + b
    sim = int(simulated)
    covered = coverage(store, start, end, b, simulated)

    def series(counts: dict[int, float]) -> list[float | None]:
        return [counts.get(t, 0) if t in covered else None for t in buckets]

    # ---- web traffic
    web = store.query(
        "SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, count(*) n, "
        "sum(CAST(json_extract(attrs, '$.status') AS INTEGER) BETWEEN 400 AND 499) e4, "
        "sum(CAST(json_extract(attrs, '$.status') AS INTEGER) >= 500) e5, "
        "avg(json_extract(attrs, '$.request_time_ms')) rt "
        "FROM events WHERE kind = 'http.access' AND ts >= ? AND ts < ? AND simulated = ? GROUP BY 1",
        (b, b, start, end, sim),
    )
    req = {r["bucket"]: r["n"] for r in web}
    e4 = {r["bucket"]: r["e4"] or 0 for r in web}
    e5 = {r["bucket"]: r["e5"] or 0 for r in web}
    total = sum(req.values())
    rt_rows = [r for r in web if r["rt"] is not None]

    # ---- SSH
    ssh = store.query(
        "SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, json_extract(attrs, '$.outcome') o, count(*) n "
        "FROM events WHERE kind = 'ssh.auth' AND ts >= ? AND ts < ? AND simulated = ? GROUP BY 1, 2",
        (b, b, start, end, sim),
    )
    fails: dict[int, float] = defaultdict(float)
    oks: dict[int, float] = defaultdict(float)
    for r in ssh:
        (fails if r["o"] == "failure" else oks if r["o"] == "success" else {})[r["bucket"]] += r[
            "n"
        ]
    top_ssh = store.query(
        "SELECT json_extract(attrs, '$.src_ip') ip, count(*) n FROM events WHERE kind = 'ssh.auth' "
        "AND json_extract(attrs, '$.outcome') = 'failure' AND ts >= ? AND ts < ? AND simulated = ? "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 5",
        (start, end, sim),
    )
    admin = store.scalar(
        "SELECT count(*) FROM events WHERE kind IN ('admin.sudo', 'admin.su', 'admin.account') "
        "AND ts >= ? AND ts < ? AND simulated = ?",
        (start, end, sim),
    )

    # ---- hosts
    hosts = []
    for src in [
        r["source_id"]
        for r in store.query(
            "SELECT DISTINCT source_id FROM events WHERE kind = 'system.metrics' AND ts >= ? AND simulated = ?",
            (now - 7 * 86_400, sim),
        )
    ]:
        latest = store.query(
            "SELECT ts, attrs FROM events WHERE kind = 'system.metrics' AND source_id = ? AND simulated = ? "
            "ORDER BY ts DESC LIMIT 1",
            (src, sim),
        )[0]
        rows = store.query(
            "SELECT CAST(ts / ? AS INTEGER) * ? bucket, avg(json_extract(attrs, '$.cpu_percent')) cpu, "
            "avg(json_extract(attrs, '$.mem_percent')) mem FROM events WHERE kind = 'system.metrics' "
            "AND source_id = ? AND ts >= ? AND ts < ? AND simulated = ? GROUP BY 1",
            (b, b, src, start, end, sim),
        )
        cpu = {r["bucket"]: r["cpu"] for r in rows}
        mem = {r["bucket"]: r["mem"] for r in rows}
        a = latest["attrs"]
        hosts.append(
            {
                "source_id": src,
                "sample_age_seconds": round(now - latest["ts"]),
                "cpu_percent": a.get("cpu_percent"),
                "mem_percent": a.get("mem_percent"),
                "load_1m": a.get("load_1m"),
                "cpu_count": a.get("cpu_count"),
                "uptime_seconds": a.get("uptime_seconds"),
                "disks": a.get("disks") or [],
                "cpu_series": [None if cpu.get(t) is None else round(cpu[t], 1) for t in buckets],
                "mem_series": [None if mem.get(t) is None else round(mem[t], 1) for t in buckets],
            }
        )

    # ---- availability
    probes = store.query(
        "SELECT source_id, ts, attrs FROM events WHERE kind = 'probe.http' AND ts >= ? AND ts < ? "
        "AND simulated = ? ORDER BY ts",
        (start, end, sim),
    )
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for p in probes:
        by_target[str(p["attrs"].get("target"))].append(p)
    availability = []
    for target, rs in sorted(by_target.items()):
        lat: dict[int, list[float]] = defaultdict(list)
        okb: dict[int, list[bool]] = defaultdict(list)
        for r in rs:
            bk = int(r["ts"] // b) * b
            okb[bk].append(bool(r["attrs"].get("ok")))
            if r["attrs"].get("latency_ms") is not None:
                lat[bk].append(r["attrs"]["latency_ms"])
        last = rs[-1]
        n_ok = sum(bool(r["attrs"].get("ok")) for r in rs)
        availability.append(
            {
                "target": target,
                "url": last["attrs"].get("url"),
                "up": bool(last["attrs"].get("ok")),
                "last_check_age_seconds": round(now - last["ts"]),
                "last_status": last["attrs"].get("status"),
                "last_error": last["attrs"].get("error"),
                "cert_days_left": last["attrs"].get("cert_days_left"),
                "checks": len(rs),
                "uptime_ratio": n_ok / len(rs),
                "locations": sorted({r["source_id"] for r in rs}),
                "latency_series": [
                    round(sum(lat[t]) / len(lat[t]), 1) if lat.get(t) else None for t in buckets
                ],
                "ok_series": [None if t not in okb else (1 if all(okb[t]) else 0) for t in buckets],
            }
        )

    # ---- incidents
    inc_open = store.query(
        "SELECT severity, count(*) n FROM incidents WHERE status != 'resolved' AND simulated = ? GROUP BY 1",
        (sim,),
    )
    recent = store.query(
        "SELECT id, title, severity, assessment, status, category, service, source_id, entity, "
        "detected_at, last_seen, occurrences, detector, rule_id, simulated FROM incidents "
        "WHERE simulated = ? AND (last_seen >= ? OR status != 'resolved') ORDER BY detected_at DESC LIMIT 20",
        (sim, start),
    )
    return {
        "generated_at": now,
        "range": rng,
        "bucket_seconds": b,
        "buckets": buckets,
        "covered_buckets": sum(t in covered for t in buckets),
        "simulated": simulated,
        "agents": agent_status(store, cfg, now),
        "web": {
            "requests": series(req),
            "status_4xx": series(e4),
            "status_5xx": series(e5),
            "total_requests": total,
            "error_rate_5xx": (sum(e5.values()) / total) if total else None,
            "mean_request_ms": (
                sum(r["rt"] * r["n"] for r in rt_rows) / sum(r["n"] for r in rt_rows)
                if rt_rows
                else None
            ),
        },
        "auth": {
            "ssh_failures": series(fails),
            "ssh_successes": series(oks),
            "total_failures": int(sum(fails.values())),
            "total_successes": int(sum(oks.values())),
            "top_failure_sources": [{"source": r["ip"], "failures": r["n"]} for r in top_ssh],
            "admin_events": admin,
        },
        "hosts": hosts,
        "availability": availability,
        "incidents": {
            "open_by_severity": {r["severity"]: r["n"] for r in inc_open},
            "recent": recent,
        },
        "worker": store.kv_get("worker_status"),
    }


def incident_detail(store: LiveStore, inc_id: str) -> dict[str, Any] | None:
    rows = store.query("SELECT * FROM incidents WHERE id = ?", (inc_id,))
    if not rows:
        return None
    ids = [
        r["event_rowid"]
        for r in store.query(
            "SELECT event_rowid FROM incident_events WHERE incident_id = ?", (inc_id,)
        )
    ]
    inv = store.query(
        "SELECT created_at, model, status, result, error FROM investigations WHERE incident_id = ? "
        "ORDER BY id DESC LIMIT 1",
        (inc_id,),
    )
    notes = store.query(
        "SELECT id, channel, kind, status, attempts, created_at, sent_at, next_attempt_at, last_error "
        "FROM notifications WHERE incident_id = ? ORDER BY id",
        (inc_id,),
    )
    return {
        "incident": rows[0],
        "evidence_events": store.events_by_rowid(ids),
        "notifications": notes,
        "investigation": inv[0] if inv else None,
    }


def incident_list(
    store: LiveStore, *, status: str | None, simulated: bool, limit: int = 200
) -> list[dict[str, Any]]:
    where: list[str] = ["simulated = ?"]
    params: list[Any] = [int(simulated)]
    if status == "active":
        where.append("status != 'resolved'")
    elif status:
        where.append("status = ?")
        params.append(status)
    return store.query(
        "SELECT id, title, severity, assessment, status, category, service, source_id, entity, "
        "detector, rule_id, detected_at, first_seen, last_seen, occurrences, verdict, simulated "
        f"FROM incidents WHERE {' AND '.join(where)} ORDER BY detected_at DESC LIMIT ?",
        [*params, limit],
    )


def jsonable(obj: Any) -> Any:
    return json.loads(json.dumps(obj, default=str))
