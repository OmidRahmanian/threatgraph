"""Real-data mode end to end on a LANL-format fixture.

No LANL data is used: the synthetic fixture is run with `mode: lanl` to check what changes
for real data. Public exports must replace every account and computer name with a salted
alias, and payloads must not be labeled synthetic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_cfg, write_datasets_yaml
from threatgraph import pipeline
from threatgraph.config import load_models_config
from threatgraph.data.synthetic import SyntheticSpec, generate_fixture
from threatgraph.serving.export import export_bundle
from threatgraph.serving.payloads import ServingContext
from threatgraph_api.main import Settings, create_app

RAW_ID = re.compile(r"\b(U\d+@DOM1|C\d+(\$@DOM1)?)\b")


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("lanl_mode")
    cfg = make_cfg(root, mode="lanl", name="lanl_fixture")
    mcfg = load_models_config()
    generate_fixture(cfg.raw_path, SyntheticSpec(seed=42))
    pipeline.run_ingest(cfg)
    pipeline.run_features(cfg)
    pipeline.run_graph(cfg)
    pipeline.run_train(cfg, mcfg)
    pipeline.run_evaluate(cfg, mcfg)
    bundle = export_bundle(ServingContext(cfg, mcfg, public_ids=True), root / "export")
    settings = Settings()
    settings.datasets_config = str(write_datasets_yaml(root / "datasets.yaml", cfg))
    settings.dataset = cfg.name
    with TestClient(create_app(settings)) as client:
        yield cfg, bundle, client


def test_export_contains_no_raw_identifiers(built) -> None:
    _, bundle, _ = built
    out = Path(bundle["out_dir"])
    for rel in bundle["files"]:
        text = (out / rel).read_text()
        hit = RAW_ID.search(text)
        assert hit is None, f"{rel} leaks {hit.group(0) if hit else ''}"
        prov = json.loads(text)["provenance"]
        assert prov["is_synthetic"] is False and prov["mode"] == "lanl"
        assert prov["label_source"] == "lanl_redteam"
    assert (Path(bundle["out_dir"]) / "graph/windows/test/index.json").exists()
    for rel in bundle["downloads"]:
        text = (out / rel).read_text()
        assert RAW_ID.search(text) is None, rel
        assert "LANL 2015" in text.splitlines()[0] or "LANL 2015" in text[:400], rel


def test_aliases_resolve_through_the_api(built) -> None:
    cfg, _, client = built
    index = client.get("/api/v1/graph/windows?split=test").json()
    w = next(x for x in index["windows"] if x["label"] == "known_redteam")
    assert w["principal"].startswith("X") and not RAW_ID.search(w["window_id"])
    g = client.get(f"/api/v1/graph/windows/{w['window_id']}").json()
    assert not RAW_ID.search(json.dumps(g))
    assert any(e["n_known_redteam"] for e in g["graph"]["edges"])
    node = g["graph"]["nodes"][0]["node_id"]
    assert client.get(f"/api/v1/entities/{node}").status_code == 200
    model = "m1_isolation_forest"
    exp = client.get(f"/api/v1/models/{model}/explanations/{w['window_id']}")
    assert exp.status_code == 200 and not RAW_ID.search(exp.text)
    # Raw identifiers are not accepted as a back door around the aliases.
    first = pipeline.scan_auth(cfg).head(1).collect().row(0, named=True)
    assert client.get(f"/api/v1/entities/computer:{first['dst_computer']}").status_code == 404
    raw_window = f"w:{first['src_principal']}:{w['window_start']}"
    assert client.get(f"/api/v1/graph/windows/{raw_window}").status_code == 404
