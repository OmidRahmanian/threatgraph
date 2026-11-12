# Resource usage

## Measured

On a development VM (colima, 2 vCPU, 2 GB RAM, Docker 29.5) with the live profile running,
an almost empty database (under 100 events), idle:

| Container | Memory | Limit set in Compose |
|---|---:|---:|
| live-worker | 191 MiB | 512 MiB |
| live-dashboard | 153 MiB | 384 MiB |
| api (research, read-only) | 145 MiB | none |
| caddy | 53 MiB | 128 MiB |
| live-ingest | 46 MiB | 256 MiB |
| web (nginx, research static site) | 4 MiB | none |

CPU was under 2% for every container at idle. The live image is 1.19 GB (scientific Python
wheels; the worker needs scikit-learn for the model). The agent runs outside Docker with the
standard library only and is capped by systemd at 128 MB and 20% CPU.

**Not measured yet**: memory and CPU under sustained real traffic, database growth on your
VPS, and model training time on a week of real telemetry. The worker's training step is the
heaviest; expect it to grow with the number of (source, 5-minute) windows. Watch
`docker stats` after the first week and adjust `retention` and `ml.train_days`.

## Minimum requirements (estimate)

| Deployment | vCPU | RAM | Disk |
|---|---:|---:|---:|
| Agent only (monitored server) | any | 128 MB free | state file only |
| Live profile without LLM | 1 | 2 GB (1.5 GB usable for containers) | 5 GB + database |
| Live profile with Ollama (3B model) | 2 | 6 GB | 10 GB |

Database growth (an estimate, not yet measured on real traffic) depends on volume: roughly 300-500 bytes per stored event. A site with
50,000 requests a day stores about 20-25 MB a day, about 0.7 GB at the default 30-day
retention. Retention runs hourly; metrics and heartbeats are kept 14 days.

No GPU is needed for anything. The LLM is optional.

Raw LANL data is never deployed to the web server: Research Mode serves only processed,
aliased exports, and the live services never read research data.
