# Model card — ThreatGraph AI anomaly rankers (v0.1.0)

The live, generated model card for each trained model is in the **Experiment Lab** (from
`artifacts/<ds>/models/<id>/metadata.json` and `metrics.json`). This page covers what does
not change between runs.

| | |
|---|---|
| Models | M0 robust z-score baseline; M1 Isolation Forest (scikit-learn); M3 = M1 + two graph features |
| Task | Rank (account, hour) windows by how unusual their authentication behavior is, compared with the training period |
| Intended use | Research and portfolio demonstration of analyst triage ranking; a starting point for investigation |
| Not intended for | Automated blocking or account lockout, attribution, or any claim that an alert is malicious |
| Training data | The training split only (see `docs/evaluation.md`), with no labels |
| Inputs | 19 causal window features (`docs/data_dictionary.md`): M0 uses 5, M1 the 17 behavioral ones, M3 all 19 |
| Output | Unbounded anomaly score (higher = more unusual) and a binary alert at the validation-calibrated threshold |
| Evaluation | Chronological held-out test split; AP, precision@K, known-label recall, alert volume, latency; unlabeled treated as negative (precision is a lower bound) |
| Explanations | M0: exact (the score is the max feature z). M1/M3: proxy feature deviations, labeled approximate |
| Known failure modes | Benign high-novelty behavior (admin maintenance sweeps, new hires, workstation moves) ranks high; low-and-slow activity within normal fan-out ranks low |
| Ethical notes | Identifiers are pseudonyms (LANL) or invented (synthetic). Public real-data exports use salted aliases. Scores are not evidence of wrongdoing by any account holder |
