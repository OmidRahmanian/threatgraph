# Entity graph, network explorer and incident replay

## Model

- **Nodes:** computers. Accounts are shown on edges and in the evidence panel.
- **Edges:** one account authenticating *from* a source computer *to* a destination computer.
  The direction is LANL's source and destination columns; edges are never symmetrised.
- **Scope:** the same scope as the features. LogOff events are excluded, as are machine accounts
  and anonymous logons (with `principals: users_only`) and events missing a computer.
- **Tables** (`data/processed/<ds>/graph/`, built by `scripts/build_graph.py`):
  - `edges/*.parquet`: one row per (window, account, source, destination), with event,
    success, failure and known red-team counts, first and last time, auth types, up to three
    sample event ids (labeled first) and `edge_first_seen_seconds`. That last field is the
    first time *any* event joined the two computers, the same definition as `n_novel_edge`.
    Sorted by window, so time-range queries read few row groups.
  - `entities.parquet`: per account and per computer totals, degrees and local logons.
  - `links.parquet`: (computer, account) totals for the entity panel.

## Queries

`GET /api/v1/graph?entity=&start=&end=&hops=&max_edges=` returns a bounded subgraph:

- hop 1 is the focus entity's own edges;
- hop 2 adds other accounts' edges on hop-1 computers, but never expands through a **hub**,
  a computer used by more than `graph.hub_max_principals` accounts in the range (domain
  controllers and file servers would otherwise connect everyone);
- the range is at most 48 hours and `max_edges` at most 300. Results are cut in a fixed order
  (hop, first-observed edges, failures, event count) and flagged `truncated`. **Red-team labels
  are not used to choose what is shown.**

`GET /api/v1/graph/windows?split=test` lists the windows the static site precomputes (each
model's top 40 plus every known red-team window). `GET /api/v1/graph/windows/{window_id}`
returns that window's 2-hop graph. `GET /api/v1/entities/{entity_id}` returns an entity's
evidence summary. The static export writes the same payloads.
`tests/integration/test_end_to_end.py` checks parity and that every edge's sample events
really have that account, source, destination and time range.

## Graph features

Two causal features join the model inputs (see `docs/data_dictionary.md`):

- `n_rare_dst`: destinations in the window that no other in-scope account had reached
  before the window started;
- `n_pivot_src`: source computers the account authenticated from after reaching them itself
  as a remote destination within the previous 24 h, i.e. a two-hop path A→B, B→C.

M3 is M1 plus these two features. The Lab and `evaluation.md` report the ablation.

## Caveat on the synthetic demo

The fixture's red-team campaigns hop from host to host by construction, and the pivot feature
was written knowing that. On the demo, nearly every known red-team window has a pivot and
almost no unlabeled window does; group `features/windows.parquet` by `label` to check. M3's
gain over M1 on the demo is therefore expected and is not evidence that the feature helps on
real data. Real admins also log on to one server and hop from it, so on LANL the feature may
mostly flag benign administration.

## Incidents and replay (Phase 4)

`packages/threatgraph/serving/incidents.py` groups red-team-matched events by source account
into incidents. A new incident starts after a gap longer than `incidents.gap_seconds` (24 h by
default). For each incident it builds:

- the account's events from one window before the first labeled event to one window after the
  last one. Every labeled event is kept; other events fill the `max_events` budget, remote ones
  first;
- every scored window in that range with each model's score and alert;
- per-model detection: `detected` if a window containing a labeled event was alerted, with
  latency = end of the first such window − first labeled event (the Lab's definition, and a
  test checks they agree); `missed`; or `not_scored`;
- a write-up filled in from those numbers by fixed templates.

`GET /api/v1/incidents?scope=evaluated|all` and `GET /api/v1/incidents/{incident_id}` serve
them. The static export includes validation and test incidents. The replay page steps through
the events and shows each alert only once its window has closed, which is when the score
would exist.
