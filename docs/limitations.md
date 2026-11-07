# Limitations

1. **Synthetic results are not real-world results.** The author designed the fixture's
   campaigns and benign look-alikes, so a detector built with knowledge of that design can
   score well on it. The synthetic numbers show that the pipeline, evaluation and UI work end
   to end, nothing more.
2. **Real LANL data has not been run yet.** The importer follows the published schema and is
   tested on LANL-format fixtures, and the whole pipeline is tested in real-data mode. Real
   files may hold surprises (encodings, unexpected tokens) that the data-quality report will
   surface. Memory use on LANL is extrapolated from a synthetic scale rehearsal, not measured
   (`docs/real_data.md`).
3. **Labels are incomplete.** Unlabeled ≠ benign. Precision is a lower bound and recall covers
   only documented activity. The LANL red-team file covers authentication events only.
4. **Red-team key choice.** Matching uses the *source* principal by default. This is a
   documented, configurable assumption.
5. **Small positive counts** make AP and recall noisy. The bootstrap intervals show how
   noisy: on the demo, test AP intervals span most of [0, 1].
6. **Window granularity.** Alerts arrive at window end (up to 1 hour of latency by
   construction). Attacks spread thinly across windows ("low and slow") are hard to detect at
   this unit.
7. **Explanations.** M0 explanations are exact. M1 explanations are proxy diagnostics, not
   attributions.
8. **Cold start.** New accounts and hosts look anomalous by construction (novelty features).
   The warm-up period and `log_prior_windows` mitigate this but do not remove it.
9. **No clock-time features.** LANL's epoch is unknown, so "off-hours" behavior is not
   modeled, deliberately.
10. **Single-process API** with in-memory rate limiting. That suits a portfolio demo, not a
    multi-replica deployment.
11. **Docker** is verified locally and in a CI job, but only with the synthetic demo.
12. **Graph scope.** Machine accounts and LogOff events are not in the graph, so it cannot show
    activity that only appears under machine accounts. Hub computers are not expanded at hop
    2, so activity hidden among a hub's many accounts is not drawn.
13. **Graph features on the demo** were designed knowing the fixture contains pivots, so the
    M1 vs M3 gain on synthetic data is expected by construction.
14. **Static explorer coverage.** The static site precomputes graphs only for each model's top
    40 test windows and every known red-team test window, and entity details only at hops 0–1.
    The live API serves any of them.
15. **Incidents are label-defined.** An incident groups red-team-matched events by account and
    time gap. It reconstructs documented activity; undocumented attacker activity forms no
    incident, and two campaigns by one account within the gap merge into one.
16. **Write-ups are templates.** They restate computed facts in fixed sentences. They do not
    interpret intent or impact, by design.
17. **History feature drifts by design.** The drift monitor shows the Isolation Forest score
    distributions shifting in later periods while every behavioral feature stays stable. The
    cause is `log_prior_windows`, which grows as history accumulates. Alert rates stay close to
    the budget on the demo, but on longer real data this could move alert volume. A fix would
    cap or rank-normalize the history feature; it is not applied, so as not to change models
    after seeing results.
18. **Faithfulness test baseline.** The deletion test resets features to training medians; a
    different baseline (for example a per-account median) could rank explanations differently.
