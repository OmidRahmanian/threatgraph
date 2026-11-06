# Synthetic demo fixture

`python scripts/generate_demo_data.py --seed 42` writes `raw/auth.txt.gz`, `raw/redteam.txt.gz`
and `raw/fixture_manifest.json` here. Everything is invented and deterministic (same seed →
byte-identical files); the manifest lists the injected campaigns, benign look-alike scenarios
and data-quality issues. The files are git-ignored because they regenerate from the seed.
