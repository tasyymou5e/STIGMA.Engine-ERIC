# STIG Manager → ERIC Port Plan

Dependency-ordered plan for porting NUWCDIVNPT/stig-manager onto the ERIC stack
(Fastify 5 + TypeScript + MySQL 8 backend; Vue 3 + PrimeVue frontend).

- **Backend root:** `engine/src/` (repositories, routes, auth, engine, db).
- **Target schema:** `docs/port/schema.target.sql` (this directory). Cut migrations
  from the diff between the live `engine/src/db/schema.sql` and the target.
- **Upstream reference:** `stig-manager-main-NAVY/api/source/` (service `*.js`,
  `specification/stig-manager.yaml`).

Each phase below is shippable on its own and unblocks the next. Verification
steps assume the existing test harness plus a seeded local MySQL 8.

---

## Phase ordering (dependency graph)

```
0 Foundation (schema split, lookups, users/identity, RBAC core)
        │
        ├──► 1 STIG library (catalog import + reads)
        │           │
        │           ▼
        ├──► 2 Reviews + workflow (depends on rule catalog + result/status lookups)
        │           │
        │           ├──► 3 Findings / POA&M  (depends on reviews + rule/cci catalog)
        │           └──► 4 Metrics           (depends on reviews + stig_asset_map + revision counts)
        │
        ├──► 5 Admin / RBAC surface (grants, ACL, labels, user-groups CRUD)
        └──► 6 Import / Export (CKL/CKLB/XCCDF, checklist export)
```

---

## Phase 0 — Foundation

Schema split + identity + RBAC core. Nothing else compiles cleanly without the
result/status lookups and `user_data`.

| Upstream endpoint group | ERIC files to create/change |
| --- | --- |
| (schema) result/status/severity_cat_map lookups | `engine/src/db/schema.sql` (apply target Sections 0); new `engine/src/db/seed.sql` (result/status/severity rows) |
| (schema) split `stig`→`stig`+`revision`; expand `collection`,`asset`,`review` | `engine/src/db/schema.sql` (target Sections 2,3,4,6); migration script under `engine/src/db/migrations/` |
| `GET/PATCH /user`, `GET/PATCH /user/web-preferences` | `engine/src/repositories/users.ts` (new); `engine/src/auth/plugin.ts` (lazy upsert preHandler); `engine/src/auth/jwt.ts` (retain claims); `engine/src/routes/index.ts` (extend `/user`, add web-preferences); `engine/src/engine/types.ts` (`UserProjected`) |
| RBAC enforcement layer (effective role on a collection) | `engine/src/auth/rbac.ts` (new — `requireCollectionRole(min)` preHandler resolving grant+group→roleId 1..4); replace bare `requireScope` on collection routes |

**Deliverables**
- Target schema applied: lookup tables seeded; `collection`/`asset`/`review`
  expanded; `stig` split into `stig`+`revision`; `user_data`/`user_group`/
  `user_group_user_map`/`collection_grant` created.
- Lazy `user_data` upsert in the `authenticate` preHandler: resolve username via
  configurable claim precedence, refresh `lastAccess`/`lastClaims`, block
  `status='unavailable'`.
- `requireCollectionRole` middleware: maps a requester to an effective roleId on
  a collection (user grant OR group grant), replacing pure scope checks.
- Configurable claim paths for username/privileges/scope (config plumbed).

**Verification**
- Unit: role resolution table (no grant→403; group grant→inherited role;
  Owner=4 > Manage=3 > Full=2 > Restricted=1).
- Integration: first authenticated request creates a `user_data` row; second
  request updates `lastAccess` only after throttle window.
- `GET /user` returns persisted `userId` (not raw `sub`) + privileges from claims.

---

## Phase 1 — STIG library

Benchmark catalog: import + read endpoints. Reviews and metrics depend on the
rule/revision catalog this phase populates.

| Upstream endpoint group | ERIC files to create/change |
| --- | --- |
| `POST /stigs` importBenchmark (XCCDF) | `engine/src/engine/importBenchmark.ts` (new — XCCDF parse, digest dedup into `check_content`/`fix_text`, `rev_group_rule_map`→`rule`, `rule_cci_map`, `current_rev` maintenance); `engine/src/repositories/stigs.ts` (new) |
| `GET /stigs`, `GET/DELETE /stigs/{benchmarkId}` | `engine/src/repositories/stigs.ts`; `engine/src/routes/stigs.ts` (new); `engine/src/engine/types.ts` (`StigProjected`,`RevisionProjected`,`RuleProjected`) |
| `GET /stigs/{id}/revisions[/{revisionStr}]` (+ delete) | `engine/src/repositories/stigs.ts`; `engine/src/routes/stigs.ts` (resolve `revisionStr` incl. `latest` via `current_rev`) |
| `GET .../revisions/{r}/groups[/{groupId}]`, `/rules[/{ruleId}]`, `/ccis` | `engine/src/repositories/stigs.ts`; `engine/src/routes/stigs.ts` |
| `GET /stigs/rules/{ruleId}`, `/stigs/ccis/{cci}`, `/stigs/scap-maps` | `engine/src/repositories/stigs.ts`, `engine/src/repositories/cci.ts` (new) |
| (seed) cci + cci_reference_map | `engine/src/db/seed.cci.ts` (new — load DISA U_CCI_List XML) |

**Deliverables**
- `importBenchmark` populating `stig`,`revision`,`current_rev`,`rule`,
  `rule_cci_map`,`check_content`,`fix_text`,`rule_version_check_digest`, with
  `?clobber` handling and per-revision count columns.
- 16 `/stigs` read/delete endpoints with `revisionStr` (`V{n}R{n}`/`latest`)
  resolution and projections (check, fix, cci).
- CCI reference data seeded.
- zod schemas for STIG/revision/rule/cci request+response shapes.

**Verification**
- Import a known STIG XCCDF → row counts match the benchmark's group/rule/CCI
  totals; re-import with `clobber` is idempotent.
- `GET /stigs/{id}/revisions/latest/rules?projection=cci` returns rules with CCIs;
  digest dedup confirmed (identical check text stored once).

---

## Phase 2 — Reviews + workflow

Re-platform reviews onto the lookup-FK model with full history and workflow.

| Upstream endpoint group | ERIC files to create/change |
| --- | --- |
| `GET/POST /collections/{id}/reviews` (+ batch, dry-run) | `engine/src/repositories/reviews.ts` (rewrite to resultId/statusId FK, version+checkDigest binding); `engine/src/routes/reviews.ts` (new, collection-scoped) |
| `GET/POST /collections/{id}/reviews/{assetId}` | `engine/src/repositories/reviews.ts`; `engine/src/routes/reviews.ts` |
| `GET/PATCH/PUT/DELETE /collections/{id}/reviews/{assetId}/{ruleId}` | `engine/src/repositories/reviews.ts`; `engine/src/routes/reviews.ts` |
| review metadata endpoints `/.../{ruleId}/metadata[/keys/{key}]` | `engine/src/repositories/reviews.ts`; `engine/src/routes/reviews.ts` |
| `GET/DELETE /collections/{id}/review-history`, `/stats` | `engine/src/repositories/reviewHistory.ts` (new); `engine/src/routes/reviews.ts` |
| (engine) result vocab + resultEngine normalization | `engine/src/engine/types.ts` (expand `ReviewResult`); `engine/src/engine/ingest.ts` (write resultEngine, autoResult) |
| (frontend) review grid + status actions | `web/src/views/Reviews*.vue` (status submit/accept/reject with text), review-history panel |

**Deliverables**
- `review` writes go through result/status lookups, set `version`+`checkDigest`
  from `rule_version_check_digest`, and append a `review_history` row on update.
- Status workflow with `statusText`/`statusUserId`/`statusTs`; submit/accept/reject
  actors recorded.
- `postReviewBatch` bulk create/update/delete with dry-run.
- Full result vocabulary (`unknown`,`error`,`notselected`,`fixed`) end to end.

**Verification**
- PATCH a review → prior state appears in `review_history`; `touchTs` reflects
  greatest(ts, statusTs).
- Batch dry-run reports counts without writing; real run writes + updates rollups.
- Accept/reject records the acting user.

---

## Phase 3 — Findings / POA&M

| Upstream endpoint group | ERIC files to create/change |
| --- | --- |
| `GET /collections/{id}/findings` (aggregator ruleId/groupId/cci, projections) | `engine/src/repositories/findings.ts` (new — join `rule`,`rule_cci_map`,`cci`,`cci_reference_map`,`rule_version_check_digest`; resultId=4); `engine/src/routes/findings.ts` (new); `engine/src/engine/metrics.ts` (replace flat `openFindings`) |
| `GET /collections/{id}/poam` (XLSX EMASS/MCCAST) | `engine/src/export/poam.ts` (new — exceljs; `poamObjectFromFindings`/`mccastPoamObjectFromFindings`/`xlsxFromPoamObject`); `engine/src/routes/findings.ts` (inline-file response) |

**Deliverables**
- Findings aggregated by `ruleId|groupId|cci` with `assetCount` and projections
  (assets, groups, rules, stigs, ccis).
- POA&M XLSX in EMASS and MCCAST formats with `apAcronym`/CCI definition/NIST
  `parentControl` columns and CAT levels from `severity_cat_map`.

**Verification**
- `GET /findings?aggregator=cci&projection=rules` returns CCI-grouped findings.
- POA&M XLSX opens in Excel; CAT column matches severity mapping; MCCAST variant
  includes package/auth-name fields.

---

## Phase 4 — Metrics

| Upstream endpoint group | ERIC files to create/change |
| --- | --- |
| `GET /collections/{id}/metrics/{detail\|summary}` (+ `/asset`,`/collection`,`/label`,`/stig`) | `engine/src/repositories/metrics.ts` (new — SQL GROUP BY over `review`+`stig_asset_map`+`revision`+`default_rev`); `engine/src/routes/metrics.ts` (new); `engine/src/engine/metrics.ts` (extend shape) |
| `GET /collections/meta/metrics/...` (cross-collection) | `engine/src/repositories/metrics.ts` (scope to readable collections via grants); `engine/src/routes/metrics.ts` |
| CSV output for every metrics endpoint | `engine/src/export/csv.ts` (new); routes honor `format=csv` |
| (rollup maintenance) `stig_asset_map` counters | `engine/src/repositories/stigAssetMap.ts` (new — maintain counts on review write & ingest) |

**Deliverables**
- Metrics object with `assessments`/`assessmentsBySeverity` (denominator from
  `revision.ruleCount` via `default_rev`), `statuses` rollup, `minTs`/`maxTs`/
  `maxTouchTs`, and per-result resultEngine sub-counts.
- Aggregation by asset / STIG / label / collection / meta.
- `stig_asset_map` maintained on every review write so metrics read counters.
- CSV serialization for all endpoints.

**Verification**
- Detail vs summary, each aggregation dimension, JSON and CSV.
- Counters in `stig_asset_map` match a fresh SQL recompute (consistency test).
- Meta metrics only include collections the requester can read.

---

## Phase 5 — Admin / RBAC surface

| Upstream endpoint group | ERIC files to create/change |
| --- | --- |
| `GET/POST/PUT/DELETE /collections/{id}/grants[/{grantId}]` | `engine/src/repositories/grants.ts` (new); `engine/src/routes/grants.ts` (new) |
| `GET/PUT /collections/{id}/grants/{grantId}/acl`, `GET .../users/{userId}/effective-acl` | `engine/src/repositories/acl.ts` (new — effective-ACL computation); `engine/src/routes/grants.ts` |
| `GET/POST/PATCH/DELETE /collections/{id}/labels[...]`, `/labels/{id}/assets` | `engine/src/repositories/labels.ts` (new); `engine/src/routes/labels.ts` (new) |
| `GET/POST/PATCH/PUT/DELETE /users[/{userId}]` (filters, elevate, projections) | `engine/src/repositories/users.ts`; `engine/src/routes/users.ts` (new) |
| `GET/POST/PATCH/PUT/DELETE /user-groups[/{id}]` | `engine/src/repositories/userGroups.ts` (new); `engine/src/routes/users.ts` |
| PATCH/PUT/DELETE/clone `/collections/{id}` (lifecycle) | `engine/src/repositories/collections.ts` (state/clone); `engine/src/routes/index.ts` |
| (frontend) admin views | `web/src/views/Admin/Grants.vue`, `Labels.vue`, `Users.vue`, `UserGroups.vue` (new) |

**Deliverables**
- Full grants CRUD (user + group), per-grant ACL rules (none/r/rw by asset/
  benchmark/label), and effective-ACL resolution endpoint.
- Collection labels CRUD + label↔asset membership.
- Users + user-groups CRUD with `?elevate=true` admin gate and projections.
- Collection lifecycle: PATCH/PUT, soft-delete (state), and clone (Owner grant on clone).

**Verification**
- Restricted (roleId=1) grant + ACL → user sees only permitted assets/benchmarks.
- effective-acl matches grant ⊕ group ⊕ ACL ⊕ label resolution.
- `elevate` denied without admin privilege (InvalidElevationError → 403).

---

## Phase 6 — Import / Export

| Upstream endpoint group | ERIC files to create/change |
| --- | --- |
| Asset CRUD + metadata + `/stigs` assignment | `engine/src/repositories/assets.ts` (top-level CRUD, soft-delete, stig_asset_map maintenance); `engine/src/routes/assets.ts` (new — move off `/collections/:id/assets`) |
| `GET /assets/{id}/checklists[...]` (CKL/CKLB/XCCDF) | `engine/src/export/checklist.ts` (new); `engine/src/routes/assets.ts` |
| CKL / CKLB / XCCDF ingest correctness | `engine/src/engine/ingest.ts` (parser fixes — see below) |
| (frontend) asset views + import dialog | `web/src/views/Assets*.vue`, import/upload component |

**Deliverables**
- Top-level `/assets` resource: list (with label/benchmark filters), get-one,
  POST, PATCH (merge incl. stigs[]/labelNames[]), PUT, DELETE (soft), bulk PATCH
  delete; asset metadata endpoints; `/stigs` assignment endpoints.
- `AssetProjected` with `stigs[]`, `labels[]`, and `statusStats` rollup.
- Checklist export (CKL/CKLB/XCCDF/JSON) for an asset and per asset+STIG.

**Verification**
- Round-trip: import a CKL, export it, re-import → equal review set.
- Soft-deleted asset frees its name for reuse; bulk delete works.

---

## Known correctness fixes still needed (carry across phases)

These are defects/limitations in ERIC's current engine that must be fixed as the
parser and metrics are re-platformed; they are not new features:

1. **Full result vocabulary** — ERIC's parser, metrics, and `review.result` ENUM
   only handle `pass/fail/notapplicable/notchecked/informational`. Add
   `unknown`, `error`, `notselected`, `fixed` in the parser
   (`engine/src/engine/ingest.ts`), the metrics counters
   (`engine/src/engine/metrics.ts`), and the schema (handled by the `result`
   lookup table in the target schema). Map CKL/CKLB status strings ↔ resultId.
2. **CKL multi-iSTIG** — a single `.ckl` can contain multiple `<iSTIG>` blocks
   (multiple benchmarks per asset). The current ingest assumes one; iterate every
   `iSTIG` and key reviews by its benchmark.
3. **CKLB multi-stig** — `.cklb` (JSON) `stigs[]` array likewise carries multiple
   STIGs; iterate all entries rather than the first.
4. **XCCDF rule-id prefix stripping** — XCCDF `idref`/`Rule id` values are
   often prefixed (e.g. `xccdf_mil.disa.stig_rule_SV-...`); strip the prefix to
   the canonical `SV-#####r#####_rule` form before matching the rule catalog and
   before writing `review.ruleId`. Apply the same normalization on import and on
   review write so they join.
5. **version + checkDigest binding on review write** — populate
   `review.version`/`review.checkDigest` from `rule_version_check_digest` so
   reviews survive rule-revision changes (currently absent in ERIC).
6. **touchTs / status timestamps** — ensure status changes set `statusTs` so the
   generated `touchTs` and the time-based metrics are correct.

---

## Cross-cutting notes / open questions

- **Id widths:** target keeps ERIC's `BIGINT UNSIGNED` (upstream uses `INT`).
  Confirm no upstream code path assumes a 32-bit id before reusing query text.
- **username vs userId:** target keeps the denormalized free-text `username`
  columns on `review`/`ingest_run`/`remediation_run` for transitional reads while
  adding `userId` FKs. Decide a cut-over point to drop the string columns.
- **result/status as lookup tables vs ENUM:** chose lookup tables (matches
  upstream and carries CKL/CKLB/abbr mappings the parser needs). If a pure-ENUM
  variant is preferred, the parser still needs the mapping data somewhere.
- **Generated `touchTs`:** modeled `GREATEST(ts, COALESCE(statusTs, ts))` STORED;
  upstream uses `greatest(ts, statusTs)` — verify NULL `statusTs` handling on your
  MySQL 8 minor version.
- **review_aging_rule** (auto-aging) is intentionally out of scope for parity.
