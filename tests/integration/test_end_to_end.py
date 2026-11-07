"""Fixture -> ingest -> features -> train -> evaluate -> export -> API, in a temp directory."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import numpy as np
import polars as pl
import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_cfg, write_datasets_yaml
from threatgraph import pipeline
from threatgraph.config import load_models_config
from threatgraph.data.synthetic import SyntheticSpec, generate_fixture
from threatgraph.ml.metrics import threshold_counts
from threatgraph.serving import payloads
from threatgraph.serving.export import MAX_BUNDLE_BYTES, export_bundle, static_slug
from threatgraph.serving.payloads import ServingContext
from threatgraph_api.main import Settings, create_app

M1 = "m1_isolation_forest"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("e2e")
    cfg = make_cfg(root)
    mcfg = load_models_config()
    generate_fixture(cfg.raw_path, SyntheticSpec(seed=42))
    pipeline.run_ingest(cfg)
    pipeline.run_features(cfg)
    pipeline.run_graph(cfg)
    pipeline.run_train(cfg, mcfg)
    pipeline.run_evaluate(cfg, mcfg)
    ctx = ServingContext(cfg, mcfg, public_ids=True)
    bundle = export_bundle(ctx, root / "export")
    settings = Settings()
    settings.datasets_config = str(write_datasets_yaml(root / "datasets.yaml", cfg))
    settings.dataset = cfg.name
    with TestClient(create_app(settings)) as client:
        yield cfg, mcfg, ctx, bundle, client


def test_quality_report_records_injected_issues(built) -> None:
    cfg, *_ = built
    q = json.loads(pipeline.quality_report_path(cfg).read_text())
    assert q["auth"]["rows_rejected"] == 5
    assert q["label_join"]["keys_unmatched"] == 1
    assert q["label_join"]["keys_ambiguous"] == 1
    assert q["redteam"]["duplicate_records_in_window"] == 1


def test_chronological_splits_and_no_test_leakage(built) -> None:
    cfg, mcfg, *_ = built
    preds = pl.read_parquet(pipeline.predictions_path(cfg))
    bounds = cfg.splits.boundaries_seconds()
    for split in ("train", "validation", "test"):
        part = preds.filter(pl.col("split") == split)
        lo, hi = bounds[split]
        assert part["window_start"].min() >= lo and part["window_start"].max() < hi
        assert part["label"].sum() > 0, f"{split} must contain known positives in the demo"
    for model_id in mcfg.models:
        meta = json.loads((pipeline.model_dir(cfg, model_id) / "metadata.json").read_text())
        assert meta["train_info"]["labels_used"] is False
        assert meta["train_info"]["n_train_rows"] == preds.filter(pl.col("split") == "train").height
        assert meta["threshold_policy"]["calibrated_on"] == "validation"


def test_score_table_reproduces_stored_operating_point(built) -> None:
    """What the browser slider does: recompute metrics from persisted scores."""
    _, mcfg, ctx, *_ = built
    for model_id in mcfg.models:
        table = ctx.score_table(model_id, "test")
        y = np.array([r[2] for r in table.rows])
        s = np.array([r[1] for r in table.rows])
        stored = ctx.model_metrics(model_id).splits["test"].operating_point
        recomputed = threshold_counts(y, s, table.calibrated_threshold)
        # Scores are rounded to 6 decimals in the table; counts must still agree.
        assert recomputed["alerts"] == stored.alerts
        assert recomputed["known_positive_alerts"] == stored.known_positive_alerts


def test_api_matches_static_export(built) -> None:
    *_, bundle, client = built
    out = Path(bundle["out_dir"])
    routes = {
        "metadata.json": "/api/v1/metadata",
        "summary.json": "/api/v1/summary",
        "models.json": "/api/v1/models",
        f"models/{M1}/metrics.json": f"/api/v1/models/{M1}/metrics",
        f"models/{M1}/scores/test.json": f"/api/v1/models/{M1}/scores?split=test",
        f"models/{M1}/predictions/test.json": f"/api/v1/models/{M1}/predictions?split=test&limit=100",
    }
    index = json.loads((out / "graph/windows/test/index.json").read_text())
    wid = index["windows"][0]["window_id"]
    graph = json.loads((out / f"graph/windows/{static_slug(wid)}.json").read_text())
    eid = graph["graph"]["nodes"][0]["node_id"]
    incidents = json.loads((out / "incidents/index.json").read_text())
    iid = incidents["incidents"][0]["incident_id"]
    routes |= {
        "incidents/index.json": "/api/v1/incidents",
        f"incidents/{static_slug(iid)}.json": f"/api/v1/incidents/{iid}",
        "graph/windows/test/index.json": "/api/v1/graph/windows?split=test",
        f"graph/windows/{static_slug(wid)}.json": f"/api/v1/graph/windows/{wid}",
        f"entities/{static_slug(eid)}.json": f"/api/v1/entities/{eid}",
    }
    for rel, url in routes.items():
        r = client.get(url)
        assert r.status_code == 200, url
        assert r.json() == json.loads((out / rel).read_text()), rel
    assert bundle["total_bytes"] < MAX_BUNDLE_BYTES


def test_every_payload_is_labeled_synthetic(built) -> None:
    *_, bundle, _ = built
    for rel in bundle["files"]:
        data = json.loads((Path(bundle["out_dir"]) / rel).read_text())
        assert data["provenance"]["mode_label"] == "Synthetic demo", rel
        assert data["provenance"]["is_synthetic"] is True


def test_explanations_are_grounded_in_window_events(built) -> None:
    _, _, ctx, bundle, client = built
    exp_bundle = json.loads(
        (Path(bundle["out_dir"]) / f"models/{M1}/explanations/test.json").read_text()
    )
    known = [e for e in exp_bundle["explanations"].values() if e["label"] == "known_redteam"]
    assert known, "export must include every known red-team test window"
    labeled_ids = ctx.labeled_event_ids
    for e in exp_bundle["explanations"].values():
        assert e["evidence_events"], e["window_id"]
        for ev in e["evidence_events"]:
            assert ev["src_principal"] == e["principal"]
            assert e["window_start"] <= ev["event_time_seconds"] < e["window_end"]
            assert ev["known_redteam"] == (ev["event_id"] in labeled_ids)
        if e["label"] == "known_redteam":
            assert any(ev["known_redteam"] for ev in e["evidence_events"])
    # API explanation for the same window is identical to the exported one.
    wid = known[0]["window_id"]
    assert (
        client.get(f"/api/v1/models/{M1}/explanations/{wid}").json()
        == exp_bundle["explanations"][wid]
    )


def test_api_validation_and_errors(built) -> None:
    *_, client = built
    assert client.get("/api/v1/health").json()["status"] == "ok"
    assert client.get("/api/v1/models/unknown_model/metrics").status_code == 404
    assert client.get(f"/api/v1/models/{M1}/predictions?limit=5000").status_code == 422
    assert client.get(f"/api/v1/models/{M1}/predictions?split=train").status_code == 422
    assert client.get(f"/api/v1/models/{M1}/explanations/w:U0@DOM1:3600").status_code == 404
    assert client.get("/api/v1/events?start=10&end=5").status_code == 422
    page1 = client.get("/api/v1/events?limit=3").json()
    page2 = client.get(f"/api/v1/events?limit=3&cursor={page1['next_cursor']}").json()
    ids = [r["event_id"] for r in page1["rows"] + page2["rows"]]
    assert ids == sorted(ids) and len(set(ids)) == 6
    r = client.get("/api/v1/summary")
    assert "max-age" in r.headers["cache-control"]
    assert client.post("/api/v1/summary").status_code == 405


def test_graph_edges_are_grounded_in_events(built) -> None:
    """Every exported edge's evidence events belong to that edge, direction and time range."""
    cfg, _, ctx, bundle, _ = built
    out = Path(bundle["out_dir"])
    index = json.loads((out / "graph/windows/test/index.json").read_text())
    auth = pipeline.scan_auth(cfg).collect()
    by_id = {r["event_id"]: r for r in auth.iter_rows(named=True)}
    labeled = ctx.labeled_event_ids
    known = [w for w in index["windows"] if w["label"] == "known_redteam"]
    assert known, "the index must include every known red-team test window"
    for w in index["windows"]:
        g = json.loads((out / f"graph/windows/{static_slug(w['window_id'])}.json").read_text())
        graph = g["graph"]
        assert graph["start_seconds"] == w["window_start"]
        assert graph["end_seconds"] == w["window_end"]
        assert len(graph["edges"]) <= graph["max_edges"]
        node_ids = {n["node_id"] for n in graph["nodes"]}
        for e in graph["edges"]:
            assert e["source"] in node_ids and e["target"] in node_ids
            assert (e["hop"] == 1) == (e["principal_id"] == w["principal_id"])
            assert e["sample_events"], e["edge_id"]
            for ev in e["sample_events"]:
                raw = by_id[ev["event_id"]]
                assert raw["src_principal"] == e["principal"]
                assert f"computer:{raw['src_computer']}" == e["source"]
                assert f"computer:{raw['dst_computer']}" == e["target"]
                assert graph["start_seconds"] <= raw["event_time_seconds"] < graph["end_seconds"]
                assert ev["known_redteam"] == (ev["event_id"] in labeled)
            if e["n_known_redteam"]:
                assert any(ev["known_redteam"] for ev in e["sample_events"])
        hop1_labeled = sum(e["n_known_redteam"] for e in graph["edges"] if e["hop"] == 1)
        if not graph["truncated"]:
            assert hop1_labeled == w["n_labeled_events"], w["window_id"]


def test_score_table_cap_keeps_exact_counts_above_cutoff(built, monkeypatch) -> None:
    _, _, ctx, *_ = built
    full = ctx.score_table(M1, "test")
    monkeypatch.setattr(payloads, "SCORE_TABLE_MAX_ROWS", 200)
    capped = ctx.score_table(M1, "test")
    assert capped.truncated and not full.truncated
    assert capped.n_rows_total == len(full.rows) and len(capped.rows) <= 200
    assert capped.n_known_positive_total == sum(r[2] for r in full.rows)
    assert capped.exact_above is not None
    assert all(r[1] > capped.exact_above for r in capped.rows)
    # Every row above the cutoff is present, so threshold counts there are exact.
    above = {r[0] for r in full.rows if r[1] > capped.exact_above}
    assert above == {r[0] for r in capped.rows}


def test_graph_api_bounds(built) -> None:
    *_, client = built
    index = client.get("/api/v1/graph/windows?split=test").json()
    w = index["windows"][0]
    ok = f"/api/v1/graph?entity={w['principal_id']}&start={w['window_start']}&end={w['window_end']}"
    assert client.get(ok).status_code == 200
    assert client.get(ok + "&hops=3").status_code == 422
    assert client.get(ok + "&max_edges=1000").status_code == 422
    too_long = f"/api/v1/graph?entity={w['principal_id']}&start=0&end={3 * 86_400}"
    assert client.get(too_long).status_code == 422
    assert client.get("/api/v1/graph?entity=principal:NOPE&start=0&end=10").status_code == 404
    assert client.get("/api/v1/entities/computer:NOPE").status_code == 404
    assert client.get("/api/v1/entities/badtype:C1").status_code == 422
    capped = client.get(ok + "&hops=2&max_edges=3").json()
    assert len(capped["edges"]) <= 3
    assert capped["n_edges_total"] >= len(capped["edges"])


def test_incidents_are_grounded_and_match_lab_latency(built) -> None:
    """Incidents come from labels; their detection numbers agree with metrics.json."""
    cfg, _, ctx, bundle, client = built
    out = Path(bundle["out_dir"])
    labels = set(ctx.labeled_event_ids)
    every = client.get("/api/v1/incidents?scope=all").json()["incidents"]
    # Every labeled in-scope event belongs to exactly one incident.
    covered: list[int] = []
    for s in every:
        inc = client.get(f"/api/v1/incidents/{s['incident_id']}").json()
        hop_ids = [h["event_id"] for h in inc["hops"]]
        assert set(hop_ids) <= labels and len(hop_ids) == s["n_labeled_events"]
        covered += hop_ids
        times = [h["event_time_seconds"] for h in inc["hops"]]
        assert times == sorted(times) and times[0] == s["start_seconds"]
        assert all(b - a <= cfg.incidents.gap_seconds for a, b in itertools.pairwise(times))
        shown = {e["event_id"] for e in inc["events"]}
        assert set(hop_ids) <= shown, "labeled events are never truncated away"
        for e in inc["events"]:
            assert e["src_principal"] == s["principal"]
            assert inc["range_start_seconds"] <= e["event_time_seconds"] < inc["range_end_seconds"]
            assert e["known_redteam"] == (e["event_id"] in labels)
        assert str(s["n_labeled_events"]) in inc["writeup"][0]
    assert sorted(covered) == sorted(labels)

    # Test-split incidents: same latency as the Lab's per-account detection latency.
    index = json.loads((out / "incidents/index.json").read_text())
    assert {s["split"] for s in index["incidents"]} <= {"validation", "test"}
    for model_id in ctx.mcfg.models:
        lab = {
            r["principal"]: r
            for r in ctx.model_metrics(model_id).model_dump()["splits"]["test"]["detection_latency"]
        }
        for s in (x for x in index["incidents"] if x["split"] == "test"):
            d = next(d for d in s["detections"] if d["model_id"] == model_id)
            row = lab[s["principal"]]
            assert d["latency_seconds"] == row["latency_seconds"], (model_id, s["principal"])
            assert d["alerted_labeled_windows"] == row["alerted_known_positive_windows"]
            assert d["labeled_windows"] == row["known_positive_windows"]


def test_downloads_match_metrics(built) -> None:
    _, mcfg, ctx, bundle, _ = built
    out = Path(bundle["out_dir"])
    lines = (out / "downloads/model_comparison.csv").read_text().splitlines()
    assert lines[0].startswith("# Synthetic demo")
    import csv

    rows = list(csv.DictReader(lines[1:]))
    assert len(rows) == 2 * len(mcfg.models)
    for r in rows:
        stored = ctx.metrics["models"][r["model_id"]]["splits"][r["split"]]
        assert int(r["alerts"]) == stored["operating_point"]["alerts"]
        assert float(r["average_precision"]) == stored["average_precision"]
    for m in mcfg.models:
        card = (out / f"downloads/model_cards/{m}.md").read_text()
        assert "Synthetic demo" in card and "labels used: no" in card
    assert "## " in (out / "downloads/incident_writeups.md").read_text()
