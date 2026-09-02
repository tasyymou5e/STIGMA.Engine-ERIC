# STIGMA.Engine

A from-scratch, open-source reimplementation of a STIG compliance platform —
the refactor of STIG Manager that **keeps Node.js + MySQL**, replaces the ExtJS
client with **Vue 3 + PrimeVue**, and stands up a **standalone API + engine** you
own (no dependency on NUWCDIVNPT/stig-manager).

## Layout

```
STIGMA.Engine/
  engine/   Backend — Node + TypeScript + Fastify + MySQL.
            Ingest/parse (CKL·CKLB·XCCDF) -> metrics/findings -> remediation tracking
            -> collections/assets/reviews CRUD. Keycloak JWT (JWKS) auth.
            Engine core is unit-tested (vitest); full project typechecks & builds.
  webui/    Front-end — Vite + TypeScript + Vue 3 + PrimeVue (DataTable grid).
            OIDC Authorization Code + PKCE against Keycloak, typed openapi-fetch
            client, packaged as an nginx appliance image with runtime config.
```

Each subproject has its own README with full run/build/deploy instructions.

## How the two fit together

```
 Browser ──► webui (Vue/PrimeVue, nginx)
                │  OIDC PKCE login ──────────► Keycloak
                │  REST (bearer token)
                ▼
            engine (Fastify API + engine) ──► MySQL
                ▲
   scan results (CKL/CKLB/XCCDF) POST /ingest
```

- The **webui** authenticates via Keycloak and calls the **engine** API with the
  bearer token. Point the webui's `apiBase` (in `public/config.js`) at the engine.
- The **engine** validates tokens against the same Keycloak realm, ingests scan
  results, computes metrics/findings, and persists everything to MySQL.

## Quick start (dev)

```bash
# Backend
cd engine && npm install && npm test        # engine unit tests (no DB)
docker compose up --build                   # engine + MySQL on :54100

# Frontend
cd ../webui && npm install && npm run dev    # http://localhost:5173
```

See `engine/README.md` and `webui/README.md` for auth setup (Keycloak redirect
URIs, demo tokens) and the appliance Docker builds.

## Status

- **engine:** parsers + metrics unit-tested (8/8), full typecheck + build clean.
  Repositories/routes need a live MySQL to exercise end-to-end (`docker compose up`).
- **webui:** typecheck + production build clean; OIDC login, whoami, and a
  Collections DataTable wired against the API.

### Next slices
- engine: review history + status-workflow tables, STIG benchmark import, POA&M/CKL export endpoints.
- webui: per-collection metrics dashboard (ECharts), assets grid, per-asset review grid, findings/POA&M views, full typed client via `npm run gen:api`.
