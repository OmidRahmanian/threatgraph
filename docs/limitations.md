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

29. **M2 learns from incomplete labels.** Unlabeled windows are negatives for fitting, so M2
    is pushed away from undocumented attacker activity. It trains only when labels permit,
    which the demo does not.
30. **Process features on the demo are not a win.** M4 scores below M3 on the synthetic test
    split; benign new programs (rollout, admin tools, new hires) look as unusual as attacker
    tools. Real LANL process data may behave differently and is untested.
31. **Graph embeddings are linear and daily.** M5 uses a truncated SVD refreshed per day, not
    a learned GNN; same-day structure is not in the embedding, and new accounts or computers
    have none.

## Live Monitoring Mode

19. **Not yet run on your VPS.** Every component is tested with simulated events and local
    stand-ins, and the stack was run locally with a real nginx container. Real SSH logs, your
    traffic, real Telegram/SMTP delivery and the GitHub Actions probe are unverified until you
    deploy them.
20. **Thresholds are starting values.** They are not fitted to your traffic. Expect to tune
    them; the false-alert rate is unknown until incidents are resolved with verdicts.
21. **Single host, single writer.** SQLite and in-process rate limits suit one VPS and a few
    agents. Several busy hosts need the storage interface backed by a server database.
22. **Detection depends on telemetry.** When an agent is offline, every rule for that host is
    blind (the `agent_offline` incident says so). Events that arrive later than the detection
    lookback are stored but not evaluated by event rules.
23. **Log-based security monitoring only.** No network traffic inspection, no process
    auditing (auditd/eBPF), no journald reader. An attacker with root can alter logs and stop
    the agent; the offline incident and the external probe are the only signals then.
24. **Rotation edge case.** If the agent is down across two log rotations and old logs are
    compressed, lines in between are not read.
25. **Privacy trade-offs.** IP truncation or hashing weakens per-source rules (all of a /24
    becomes one source). `sudo` command lines are kept (with secrets redacted) as evidence.
26. **The model is unsupervised** and new legitimate clients look unusual by construction;
    its findings are informational.
27. **The LLM note is advisory** and can be wrong even with citations enforced; it may also
    miss injection attempts that do not match the flagging patterns (they still cannot cause
    any action).
28. **Authentication is single-user**: one admin account, no multi-factor authentication. Put
    the dashboard behind your VPN as well if that is a concern.
