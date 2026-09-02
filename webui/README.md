# STIG Manager — Vue 3 + PrimeVue front-end (appliance build)

A modern, open-source replacement for the ExtJS web client. Talks to the
**existing STIG Manager Node API** (unchanged) and authenticates against the
**existing Keycloak** via OIDC Authorization Code + PKCE.

Stack: **Vite + TypeScript + Vue 3 + PrimeVue** (DataTable grid) ·
**openapi-fetch** typed client · **oidc-client-ts** auth · packaged as a
single **nginx Docker image** with runtime config.

---

## Project layout

```
src/
  api/        client.ts (openapi-fetch + bearer auth) · types.ts (minimal; regen full via gen:api)
  auth/       oidc.ts (Keycloak OIDC + PKCE)
  router/     routes + auth guard
  views/      HomeView (whoami) · CollectionsView (PrimeVue DataTable) · CallbackView
  config.ts   reads window.__APP_CONFIG__
public/config.js   runtime config (regenerated from env in the container)
deploy/     nginx.conf.template · 30-stigman-config.sh (writes config.js from env)
Dockerfile  multi-stage build -> nginx appliance image
```

---

## Run in dev (against your local stack)

Prereq: the STIG Manager stack is up at `https://localhost` (the
`stigman-orchestration` compose) and you've trusted the demo CA in your browser.

```bash
npm install
npm run dev      # http://localhost:5173
```

Vite proxies `/stigman` and `/kc` to `https://localhost` (self-signed cert
accepted), so there's no CORS to fight for API calls.

### One-time Keycloak step (dev only)

The dev SPA runs on `http://localhost:5173`, so the `stig-manager` client must
allow that origin. In Keycloak admin (`https://localhost/kc/admin`, `admin` /
`Pa55w0rd`) → realm **stigman** → Clients → **stig-manager**, add:

- **Valid redirect URIs:** `http://localhost:5173/callback`
- **Valid post logout redirect URIs:** `http://localhost:5173`
- **Web origins:** `http://localhost:5173`

> The demo Keycloak runs in dev mode (H2), so this resets if the container
> restarts. For the appliance build below this is a non-issue — the SPA is
> served from the same origin as the API/Keycloak, so the existing redirect
> URIs already match.

---

## Generate the full typed API client (recommended)

`src/api/types.ts` ships a *minimal* hand-authored slice so the skeleton
compiles. To get the complete typed surface from the live OpenAPI spec:

```bash
npm run gen:api          # writes src/api/schema.ts
```

Then point the client at it:

```ts
// src/api/client.ts
import type { paths } from './schema'   // was './types'
```

---

## Build the appliance image

```bash
docker build -t stigman-webui .
```

Run it next to the existing stack (same Docker network), serving the SPA and
proxying the API + Keycloak through itself:

```bash
docker run -d --name stigman-webui \
  --network stigman-orchestration_default \
  -p 8080:80 \
  -e OIDC_AUTHORITY=https://localhost/kc/realms/stigman \
  -e API_UPSTREAM=http://stigman:54000/ \
  -e KC_UPSTREAM=http://keycloak:8080/kc/ \
  stigman-webui
```

Browse `http://localhost:8080/`. Because the SPA, API, and Keycloak are all
behind this one nginx, everything is same-origin — no CORS, and OIDC redirect
URIs line up with the serving host.

### Configuration (all runtime env — no rebuild needed)

| Env var | Purpose | Default |
|---|---|---|
| `OIDC_AUTHORITY` | Keycloak realm issuer URL | `https://localhost/kc/realms/stigman` |
| `OIDC_CLIENT_ID` | OIDC client id | `stig-manager` |
| `OIDC_SCOPE` | requested scopes | `openid stig-manager:collection stig-manager:stig stig-manager:user stig-manager:op` |
| `API_BASE` | front-end API base path | `/stigman/api` |
| `API_UPSTREAM` | nginx proxy target for `/stigman/` | `http://stigman:54000/` |
| `KC_UPSTREAM` | nginx proxy target for `/kc/` | `http://keycloak:8080/kc/` |

---

## What's wired vs. what's next

**Wired:** OIDC-PKCE login/logout, auth guard, token-injecting API client,
`/user` (whoami) on the dashboard, `/collections` in a PrimeVue DataTable,
appliance Docker image with runtime config.

**Next screens to build** (against the same typed client): per-collection
metrics dashboard (ECharts), assets grid, per-asset review grid (the dense
ExtJS-style table), and findings/POA&M views.
