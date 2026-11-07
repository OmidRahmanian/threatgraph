from __future__ import annotations

import polars as pl
import pytest

from tests.conftest import auth_frame
from threatgraph.data.schema import LABEL_SCHEMA
from threatgraph.graph.build import build_edge_table, build_entity_tables, edges_glob
from threatgraph.graph.query import subgraph

H = 3600

ROWS = [
    (0, 1, "C1$@DOM1", "C1", "C2", "Success"),  # machine account: only dates the C1->C2 pair
    (1, 10, "U1@DOM1", "C1", "C2", "Fail"),
    (2, 20, "U1@DOM1", "C1", "C2", "Success"),
    (3, 30, "U1@DOM1", "C2", "C3", "Success", "NTLM"),  # labeled red-team below
    (4, 40, "U1@DOM1", "C1", "C1", "Success"),  # local logon
    (5, 50, "U2@DOM1", "C3", "C4", "Success"),  # another account on a hop-1 computer
    (6, 60, "U3@DOM1", "C5", "C2", "Success"),
    (7, 70, "U4@DOM1", "C6", "C2", "Success"),
    (8, 80, "U1@DOM1", "C2", "C3", "Success", None, "LogOff"),  # LogOff: out of scope
    (9, 2 * H + 5, "U1@DOM1", "C1", "C7", "Success"),  # outside a [0, H) query
]


@pytest.fixture
def graph(tmp_cfg, tmp_path):
    labels = pl.DataFrame(
        {
            "event_id": [3],
            "label_source": ["x"],
            "redteam_record_id": [0],
            "match_multiplicity": [1],
        }
    ).cast(LABEL_SCHEMA)
    out = tmp_path / "graph"
    report = build_edge_table(auth_frame(ROWS), labels, tmp_cfg, out)
    build_entity_tables(out)
    return tmp_cfg, out, report, pl.scan_parquet(edges_glob(out))


def q(edges, **kw):
    args = {"start": 0, "end": H, "window_seconds": H, "hops": 1, "max_edges": 50}
    args["hub_max_principals"] = 2
    return subgraph(edges, **(args | kw))


def test_edges_keep_direction_labels_and_evidence(graph) -> None:
    _, _, report, edges = graph
    table = edges.collect()
    assert report["events_in_graph"] == 8  # machine account and LogOff excluded
    pairs = set(table.select("src_principal", "src_computer", "dst_computer").iter_rows())
    assert ("U1@DOM1", "C1", "C2") in pairs and ("U1@DOM1", "C2", "C1") not in pairs
    e = table.filter((pl.col("src_principal") == "U1@DOM1") & (pl.col("src_computer") == "C1"))
    c1c2 = e.filter(pl.col("dst_computer") == "C2").row(0, named=True)
    assert (c1c2["n_events"], c1c2["n_fail"], c1c2["n_success"]) == (2, 1, 1)
    assert c1c2["edge_first_seen_seconds"] == 1  # first seen by the machine account
    assert c1c2["n_known_redteam"] == 0 and sorted(c1c2["sample_event_ids"]) == [1, 2]
    c2c3 = table.filter(pl.col("dst_computer") == "C3").row(0, named=True)
    assert c2c3["n_known_redteam"] == 1 and c2c3["sample_event_ids"] == [3]
    assert c2c3["auth_types"] == ["NTLM"]


def test_principal_subgraph_hops_hubs_and_time_range(graph) -> None:
    *_, edges = graph
    one = q(edges, focus_type="principal", focus_key="U1@DOM1")
    assert set(one.edges["hop"]) == {1}
    assert set(one.edges.select("src_computer", "dst_computer").iter_rows()) == {
        ("C1", "C2"),
        ("C2", "C3"),
        ("C1", "C1"),
    }  # C1->C7 is outside [0, H)
    assert one.edges.filter(pl.col("is_local")).height == 1
    two = q(edges, focus_type="principal", focus_key="U1@DOM1", hops=2)
    hop2 = set(
        two.edges.filter(pl.col("hop") == 2).select("src_principal", "src_computer").iter_rows()
    )
    # C2 is used by U1, U3 and U4 (3 > hub_max_principals=2), so it is not expanded;
    # C3 (U1, U2) is, which brings in U2's C3->C4 edge.
    assert hop2 == {("U2@DOM1", "C3")}
    nodes = {r["computer"]: r for r in two.nodes.iter_rows(named=True)}
    assert nodes["C2"]["is_hub"] and not nodes["C2"]["expanded"]
    assert nodes["C3"]["expanded"] and nodes["C4"]["hop"] == 2


def test_computer_subgraph_and_truncation(graph) -> None:
    *_, edges = graph
    res = q(edges, focus_type="computer", focus_key="C2")
    assert set(res.edges["src_principal"]) == {"U1@DOM1", "U3@DOM1", "U4@DOM1"}
    assert {r["computer"]: r["hop"] for r in res.nodes.iter_rows(named=True)}["C2"] == 0
    capped = q(edges, focus_type="computer", focus_key="C2", max_edges=2)
    assert capped.truncated and capped.edges.height == 2 and capped.n_edges_total == 4
    # Truncation never looks at labels: the order is hop, novelty, failures, event count.
    assert capped.edges["n_fail"][0] == 1


def test_entity_tables(graph) -> None:
    _, out, *_ = graph
    ent = pl.read_parquet(out / "entities.parquet")
    c1 = ent.filter(pl.col("entity_key") == "C1").row(0, named=True)
    assert c1["n_local_events"] == 1 and c1["out_degree"] == 2 and c1["in_degree"] == 0
    assert c1["n_events"] == 4  # 2 to C2 + 1 local + 1 to C7, the local logon counted once
    u1 = ent.filter(pl.col("entity_key") == "U1@DOM1").row(0, named=True)
    assert u1["n_known_redteam_events"] == 1 and u1["n_distinct_dst_computers"] == 4
    links = pl.read_parquet(out / "links.parquet")
    assert links.filter(pl.col("computer") == "C2")["src_principal"].sort().to_list() == [
        "U1@DOM1",
        "U3@DOM1",
        "U4@DOM1",
    ]
