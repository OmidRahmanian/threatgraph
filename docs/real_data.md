# Running on real LANL data

Status: **the pipeline is ready for the real files, but has not been run on them.** LANL asks
users to complete a data-use form before downloading, so this project never downloads the
data. No real-data result exists until you run the steps below.

## Steps

1. Complete LANL's form at <https://csr.lanl.gov/data/cyber1/> and download `auth.txt.gz`
   (~7 GB compressed, ~1.05 billion events over 58 days) and `redteam.txt.gz`.
2. Put both in `data/raw/lanl/`. The path is git-ignored and excluded from Docker builds.
3. Choose the time window and split days:

   ```bash
   python scripts/ingest_lanl.py --inspect-redteam
   ```

   This reads only the red-team file. It prints red-team records per day and suggests a
   14-day window (2 warm-up, 6 train, 3 validation, 3 test) whose validation and test periods
   both contain records, ranked by `min(validation, test)` records. Paste the two printed
   lines into the `lanl:` entry of `configs/datasets.yaml`. The suggestion looks only at where
   labels fall in time, never at model scores, so choosing splits this way does not leak test
   performance.
4. Run everything:

   ```bash
   python scripts/run_pipeline.py --dataset lanl
   ```

   Ingest streams the file in 64 MB blocks and stops after the window end (the file is
   time-sorted). Features and graph tables are built in one-hour chunks.
5. Check `data/processed/lanl/reports/data_quality.json` (rejected rows, missing values,
   red-team keys matched, ambiguous and unmatched) before reading any metric.
6. Serve or export: `TG_DATASET=lanl make api`, or build the site with
   `NEXT_PUBLIC_TG_DATASET=lanl`. Exports replace every account and computer name with a salted
   alias; the salt stays in `data/processed/lanl/.export_salt`. Review the bundle before
   publishing it anywhere.

If the files are missing, every command prints these instructions and the demo keeps working.

## What changes in real-data mode

- Every payload says `LANL 2015 (real, de-identified)` and cites Kent (2015). Nothing is
  labeled synthetic.
- Public exports and API responses use aliases (`X` + 10 hex characters). The API also accepts
  only aliases, so raw names cannot be used to look entities up.
  `tests/integration/test_lanl_mode.py` runs the whole pipeline in this mode and checks that
  no exported file contains a raw identifier.
- Score tables over 10,000 rows are cut to the highest scores. The Lab keeps every count
  exact by moving the slider only above the cutoff and using the full split's totals.

## Scale rehearsal (synthetic, not LANL)

`python scripts/scale_rehearsal.py --out <dir> --copies 200 --days 4` replicates the demo's
first four days 200 times with renamed accounts and computers, then runs each stage in its own
process. One run on a MacBook with 8 GB RAM (macOS 26.5, Apple silicon, Python 3.12) gave the
numbers below; the raw report is [scale_report.json](scale_report.json).

| Stage | Seconds | Peak RSS (MB) | Output |
|---|---:|---:|---|
| ingest | 20.8 | 2,012 | 17,204,400 events, 1.45M rows/s |
| features, 1-day chunks | 19.2 | 2,248 | 1,359,800 windows |
| features, 1-hour chunks | 49.4 | 1,518 | identical table |
| graph (1-hour chunks) | 16.2 | 1,601 | 6,069,600 edge rows |
| train (3 models) | 18.4 | 1,665 | |
| evaluate | 425.4 | 973 | |
| export | 15.8 | 1,007 | 8.59 MB bundle, including both network maps |

Evaluate is dominated by the account cluster bootstrap (1,000 resamples for every model, split
and paired comparison). Its time grows with the number of windows, so on LANL expect it to be
the slowest stage; lower `uncertainty.n_boot` in `configs/models.yaml` for a first pass.

That is 4.3M events per day. LANL averages about 18M events per day, roughly four times more,
and its real entity counts and repetition differ. With 1-day chunks, feature memory grew with
daily volume during development runs, so the LANL config uses one-hour chunks.
That keeps each chunk smaller than a 6-hour chunk here, but **the peak memory of a LANL run is
an estimate, not a measurement.** If a stage runs out of memory, check
`artifacts/lanl/runs/<stage>.json` (each stage records its own peak RSS) and shorten the time
window first.
