# stigman-engine

A **standalone STIG compliance API + engine** on **Node + TypeScript + MySQL** —
independent of NUWCDIVNPT/stig-manager. It ingests scan results, computes
compliance metrics and findings, tracks remediation, and exposes a REST API for
collections / assets / reviews. Pairs with the `stigman-webui` Vue front-end.

## What it does

| Capability | Where |
|---|---|
| **Ingest & parse** CKL · CKLB · XCCDF into normalized reviews | `src/engine/parse/*`, `src/engine/ingest.ts` |
| **Compute metrics & findings** (pass/fail/NA, severity rollups, open findings = POA&M) | `src/engine/metrics.ts` |
| **Remediation tracking** (apply/verify run records) | `src/repositories/runs.ts`, routes |
| **CRUD** collections / assets / reviews | `src/repositories/*`, `src/routes/index.ts` |
| **Keycloak JWT auth** (JWKS verify, scope guards) | `src/auth/*` |

## Architecture

```
src/
  engine/          pure, testable core
    parse/         ckl.ts · cklb.ts · xccdf.ts · index.ts (detect+dispatch)
    metrics.ts     compliance scoring + open-findings rollup
    ingest.ts      parse -> persist
  repositories/    MySQL data access (collections, assets, reviews, runs)
  routes/          Fastify REST endpoints under /api
  auth/            jose JWKS verification + Fastify auth plugin
  db/              pool, schema.sql, migrate
  server.ts        Fastify app  ·  index.ts  bootstrap
test/engine/       vitest unit tests (parsers + metrics)
```

## API (under `/api`)

| Method | Path | Scope |
|---|---|---|
| GET | `/user` | (any authenticated) |
| GET/POST | `/collections`, `/collections/:id` | `stig-manager:collection` |
| GET/POST | `/collections/:id/assets` | `stig-manager:collection` |
| GET/PATCH | `/assets/:id/reviews` | `stig-manager:collection` |
| POST | `/collections/:id/ingest` | `:collection` + `:stig` |
| GET | `/collections/:id/metrics` · `/findings` | `stig-manager:collection` |
| GET/POST | `/assets/:id/remediation-runs` | `stig-manager:collection` |

`POST /collections/:id/ingest` body: `{ "content": "<raw CKL/CKLB/XCCDF>", "source"?: "ckl"|"cklb"|"xccdf" }` (format auto-detected if omitted).

## Run locally

```bash
cp .env.example .env          # adjust DB / OIDC if needed
npm install
npm run db:migrate            # create schema (needs a reachable MySQL)
npm run dev                   # http://localhost:54100  (GET /health)
npm test                      # engine unit tests (no DB needed)
```

## Run as a container (engine + its own MySQL)

```bash
docker compose up --build
# engine on http://localhost:54100, MySQL persisted to ./engine-mysql-data
```

## Auth notes

Tokens are validated against `OIDC_ISSUER`'s JWKS. For the local demo Keycloak
(which ships a publicly-known signing key) set `ALLOW_INSECURE_TOKENS=true` to
decode without signature verification — **DEV ONLY**. Get a token the same way
the demo does:

```bash
curl -sk -X POST https://localhost/kc/realms/stigman/protocol/openid-connect/token \
  -d client_id=stig-manager -d username=admin -d password=password -d grant_type=password \
  --data-urlencode 'scope=openid stig-manager:collection stig-manager:stig stig-manager:user stig-manager:op'
```

## Status

Engine (parsers + metrics) is unit-tested and the full project typechecks.
Repositories/routes require a MySQL instance to exercise end-to-end. Next:
review history/status workflow tables, STIG benchmark import, and POA&M export
endpoints.
