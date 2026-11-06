# Deployment

## Static site (recommended for a portfolio)

```bash
make demo                                    # produces the public bundle
cd apps/web
NEXT_PUBLIC_BASE_PATH=/projects \
NEXT_PUBLIC_REPO_URL=https://github.com/<you>/threatgraph-ai \
npm run build                                # → apps/web/out/
```

Copy `apps/web/out/` to `/projects/` on any static host (GitHub Pages, Netlify, S3+CloudFront,
or an existing site's `public/` folder). Pages are then served at `/projects/threatgraph/` and
`/projects/threatgraph/lab/`. `trailingSlash: true` emits `…/index.html`, so plain static
servers work.

### Integrating with an existing Next.js site

To avoid touching the existing site, deploy the export to a sub-path as above and link to it.
To merge it into the site instead, copy `src/app/threatgraph/`, `src/components/` and
`src/lib/` into the site, add Recharts, merge the CSS tokens from `src/app/globals.css`, and
copy `public/threatgraph-data/`. Everything is scoped to the `/threatgraph` route segment.

## Live API (optional)

```bash
TG_DATASET=demo TG_CORS_ORIGINS=https://your.site uvicorn threatgraph_api.main:app --port 8000
```

- Read-only GET endpoints, query bounds validated, generic 404/500 messages, a per-IP token
  bucket rate limit (`TG_RATE_LIMIT_PER_MINUTE`), and `Cache-Control: public, max-age=300` on
  200 responses.
- No upload or training endpoints exist.
- Put it behind a reverse proxy with TLS. The rate limiter is in-memory, per process.
- Build the website with `NEXT_PUBLIC_TG_API_BASE=https://api.your.site/api/v1`.

## Docker (optional, unverified)

`docker compose up --build` after `make demo`. The API image contains code and configs only;
`data/processed` and `artifacts` are mounted read-only. Nginx serves `apps/web/out`. These
files have not been built in CI or locally yet.

## Real data

Never deploy raw LANL files or `data/processed/lanl` publicly. Export with the default
`public_ids=True`, which replaces identifiers with salted aliases (the salt stays in
`data/processed/<ds>/.export_salt`), and review the bundle before publishing.
