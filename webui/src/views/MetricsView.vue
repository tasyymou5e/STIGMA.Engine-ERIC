<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Card from 'primevue/card'
import ProgressBar from 'primevue/progressbar'
import Button from 'primevue/button'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import { api } from '../api/client'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'
import type { Collection, Asset, Review, OpenFinding, Metrics } from '../api/types'

const props = defineProps<{ id: string }>()
const router = useRouter()
const cid = Number(props.id)

// ── State ─────────────────────────────────────────────────────────────────────
const collection  = ref<Collection | null>(null)
const metrics     = ref<Metrics | null>(null)
const assets      = ref<Asset[]>([])
const findings    = ref<OpenFinding[]>([])
const loading     = ref(true)
const error       = ref('')

/** ruleId → reviews across all assets (loaded per-asset, keyed by assetId) */
const reviewsByAsset = ref<Map<number, Review[]>>(new Map())
const reviewsLoading = ref(false)

// ── Data fetch ────────────────────────────────────────────────────────────────
onMounted(async () => {
  const [c, m, a, f] = await Promise.all([
    api.GET('/collections/{id}',         { params: { path: { id: cid } } }),
    api.GET('/collections/{id}/metrics', { params: { path: { id: cid } } }),
    api.GET('/collections/{id}/assets',  { params: { path: { id: cid } } }),
    api.GET('/collections/{id}/findings',{ params: { path: { id: cid } } })
  ])

  if (c.error) { error.value = 'Failed to load collection'; loading.value = false; return }
  collection.value = c.data ?? null
  metrics.value    = m.data ?? null
  assets.value     = a.data ?? []
  findings.value   = f.data ?? []
  loading.value    = false

  // Load all asset reviews in parallel (needed for By Asset & By STIG tabs)
  reviewsLoading.value = true
  const reviewResults = await Promise.all(
    assets.value.map(asset =>
      api.GET('/assets/{id}/reviews', { params: { path: { id: asset.assetId } } })
        .then(res => ({ assetId: asset.assetId, reviews: res.data ?? [] }))
    )
  )
  const map = new Map<number, Review[]>()
  for (const { assetId, reviews } of reviewResults) map.set(assetId, reviews)
  reviewsByAsset.value = map
  reviewsLoading.value = false
})

// ── Top-level metric helpers ──────────────────────────────────────────────────
const compliance = computed(() => metrics.value?.compliancePct ?? 0)
const openCount  = computed(() =>
  metrics.value
    ? metrics.value.findings.high + metrics.value.findings.medium + metrics.value.findings.low
    : 0
)
const totalResults = computed(() =>
  metrics.value
    ? metrics.value.results.pass + metrics.value.results.fail +
      metrics.value.results.notapplicable + metrics.value.results.notchecked +
      metrics.value.results.informational
    : 0
)

// ── By Asset rows ─────────────────────────────────────────────────────────────
interface AssetRow {
  assetId: number
  name: string
  fqdn: string
  ip: string
  total: number
  assessed: number
  pass: number
  fail: number
  notapplicable: number
  notchecked: number
  catI: number
  catII: number
  catIII: number
  compliancePct: number
}

const assetRows = computed<AssetRow[]>(() => {
  return assets.value.map(asset => {
    const reviews = reviewsByAsset.value.get(asset.assetId) ?? []
    const total         = reviews.length
    const pass          = reviews.filter(r => r.result === 'pass').length
    const fail          = reviews.filter(r => r.result === 'fail').length
    const notapplicable = reviews.filter(r => r.result === 'notapplicable').length
    const notchecked    = reviews.filter(r => r.result === 'notchecked').length
    const catI          = reviews.filter(r => r.result === 'fail' && r.severity === 'high').length
    const catII         = reviews.filter(r => r.result === 'fail' && r.severity === 'medium').length
    const catIII        = reviews.filter(r => r.result === 'fail' && r.severity === 'low').length
    const assessed      = pass + fail + notapplicable
    const compliancePct = assessed > 0 ? Math.round((pass / assessed) * 100) : 0
    return {
      assetId: asset.assetId,
      name: asset.name,
      fqdn: asset.fqdn ?? '',
      ip:   asset.ip   ?? '',
      total, assessed, pass, fail, notapplicable, notchecked,
      catI, catII, catIII, compliancePct
    }
  })
})

// ── By STIG rows ──────────────────────────────────────────────────────────────
interface StigRow {
  benchmarkKey: string   // derived from ruleVersion prefix (STIG-BENCH-VxRy) or full ruleId
  ruleVersion: string    // representative sample
  title: string
  total: number
  pass: number
  fail: number
  notapplicable: number
  notchecked: number
  catI: number
  catII: number
  catIII: number
  compliancePct: number
}

const stigRows = computed<StigRow[]>(() => {
  // Aggregate all reviews across all assets, grouping by benchmarkId (derived from ruleVersion)
  const allReviews: Review[] = []
  for (const reviews of reviewsByAsset.value.values()) allReviews.push(...reviews)

  // Derive a benchmark key: e.g. "V-12345" ruleVersion → strip trailing digits or use ruleVersion prefix
  // Group by ruleVersion prefix up to the last dot-separated segment (or just by ruleVersion)
  const benchmarkMap = new Map<string, { reviews: Review[] }>()

  for (const review of allReviews) {
    // Group by everything before the last "_" or by groupId prefix (STIG usually shares groupId prefix)
    // Best effort: group on ruleVersion stripped of trailing rule suffix
    const key = deriveBenchmarkKey(review.ruleVersion)
    if (!benchmarkMap.has(key)) benchmarkMap.set(key, { reviews: [] })
    benchmarkMap.get(key)!.reviews.push(review)
  }

  return Array.from(benchmarkMap.entries()).map(([key, { reviews }]) => {
    const sample        = reviews[0]
    const total         = reviews.length
    const pass          = reviews.filter(r => r.result === 'pass').length
    const fail          = reviews.filter(r => r.result === 'fail').length
    const notapplicable = reviews.filter(r => r.result === 'notapplicable').length
    const notchecked    = reviews.filter(r => r.result === 'notchecked').length
    const catI          = reviews.filter(r => r.result === 'fail' && r.severity === 'high').length
    const catII         = reviews.filter(r => r.result === 'fail' && r.severity === 'medium').length
    const catIII        = reviews.filter(r => r.result === 'fail' && r.severity === 'low').length
    const assessed      = pass + fail + notapplicable
    const compliancePct = assessed > 0 ? Math.round((pass / assessed) * 100) : 0
    return {
      benchmarkKey: key,
      ruleVersion: sample?.ruleVersion ?? key,
      title: sample?.title ?? key,
      total, pass, fail, notapplicable, notchecked,
      catI, catII, catIII, compliancePct
    }
  })
})

/**
 * Derive a grouping key from a ruleVersion string.
 * STIG rule versions look like "SV-12345r1_rule" or "RHEL-08-010000".
 * We strip trailing "_rule" / trailing version suffixes to get a benchmark-level key.
 */
function deriveBenchmarkKey(ruleVersion: string): string {
  // Strip trailing _rule suffix
  let k = ruleVersion.replace(/_rule$/i, '')
  // Strip trailing numeric revision (r1, r2, …)
  k = k.replace(/r\d+$/i, '')
  // If the result still has a digit-only suffix separated by dash/dot, strip that too
  // leaving a prefix that roughly identifies the STIG benchmark
  return k.replace(/[-.]?\d{5,}$/, '')
}

// ── CSV export ────────────────────────────────────────────────────────────────
const exportingCsv = ref(false)
const exportCsvError = ref('')

async function exportMetricsCsv() {
  exportingCsv.value = true
  exportCsvError.value = ''
  try {
    const token = await getAccessToken()
    const url = `${config.apiBase}/collections/${cid}/metrics?format=csv`
    const resp = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const blob = await resp.blob()
    const anchor = document.createElement('a')
    anchor.href = URL.createObjectURL(blob)
    anchor.download = `collection-${cid}-metrics.csv`
    anchor.click()
    URL.revokeObjectURL(anchor.href)
  } catch (e) {
    exportCsvError.value = `CSV export failed: ${(e as Error).message}`
  } finally {
    exportingCsv.value = false
  }
}

// ── Results breakdown (donut-like) ────────────────────────────────────────────
const resultBreakdown = computed(() => {
  if (!metrics.value) return []
  const r = metrics.value.results
  const total = totalResults.value || 1
  return [
    { label: 'Not a Finding', count: r.pass,           pct: Math.round((r.pass           / total) * 100), severity: 'success'   as const },
    { label: 'Open',          count: r.fail,           pct: Math.round((r.fail           / total) * 100), severity: 'danger'    as const },
    { label: 'Not Applicable',count: r.notapplicable,  pct: Math.round((r.notapplicable  / total) * 100), severity: 'secondary' as const },
    { label: 'Not Reviewed',  count: r.notchecked,     pct: Math.round((r.notchecked     / total) * 100), severity: 'warn'      as const },
    { label: 'Informational', count: r.informational,  pct: Math.round((r.informational  / total) * 100), severity: 'info'      as const },
  ]
})
</script>

<template>
  <section>
    <!-- Breadcrumb -->
    <p>
      <router-link to="/collections">&larr; Collections</router-link>
      &nbsp;/&nbsp;
      <router-link :to="`/collections/${id}`">{{ collection?.name ?? `Collection ${id}` }}</router-link>
    </p>

    <p v-if="error" style="color: #f85149">{{ error }}</p>

    <template v-if="!loading">
      <div class="page-header">
        <div>
          <h2>Metrics &mdash; {{ collection?.name ?? `Collection ${id}` }}</h2>
          <p v-if="collection?.description" class="muted">{{ collection.description }}</p>
        </div>
        <div style="display: flex; gap: 0.5rem">
          <Button
            label="Export CSV"
            icon="pi pi-file-export"
            severity="secondary"
            size="small"
            :loading="exportingCsv"
            @click="exportMetricsCsv"
          />
          <Button
            label="Back to Collection"
            icon="pi pi-arrow-left"
            severity="secondary"
            size="small"
            @click="router.push({ name: 'collection', params: { id } })"
          />
        </div>
        <p v-if="exportCsvError" style="color: #f85149; margin: 0; font-size: 0.875rem">{{ exportCsvError }}</p>
      </div>

      <!-- ── Summary cards ── -->
      <div class="cards" v-if="metrics">
        <Card class="metric">
          <template #title>Compliance</template>
          <template #content>
            <div class="big" :class="{ success: compliance >= 80, danger: compliance < 50 }">
              {{ compliance }}%
            </div>
            <ProgressBar :value="compliance" :showValue="false" style="height: 0.5rem; margin-top: 0.5rem" />
            <div class="muted" style="margin-top: 0.35rem">
              {{ metrics.assessed }} of {{ metrics.total }} assessed
            </div>
          </template>
        </Card>

        <Card class="metric">
          <template #title>Open Findings</template>
          <template #content>
            <div class="big" :class="{ danger: openCount > 0 }">{{ openCount }}</div>
            <div class="sev-row" style="margin-top: 0.5rem">
              <Tag :value="`CAT I: ${metrics.findings.high}`"   severity="danger" />
              <Tag :value="`CAT II: ${metrics.findings.medium}`" severity="warn" />
              <Tag :value="`CAT III: ${metrics.findings.low}`"  severity="info" />
            </div>
          </template>
        </Card>

        <Card class="metric">
          <template #title>Results</template>
          <template #content>
            <div class="sev-row wrap">
              <Tag :value="`Pass: ${metrics.results.pass}`"                  severity="success" />
              <Tag :value="`Open: ${metrics.results.fail}`"                  severity="danger" />
              <Tag :value="`N/A: ${metrics.results.notapplicable}`"          severity="secondary" />
              <Tag :value="`Not Reviewed: ${metrics.results.notchecked}`"    severity="warn" />
              <Tag :value="`Info: ${metrics.results.informational}`"         severity="info" />
            </div>
          </template>
        </Card>

        <Card class="metric">
          <template #title>Assets</template>
          <template #content>
            <div class="big">{{ assets.length }}</div>
            <div class="muted">systems in collection</div>
          </template>
        </Card>
      </div>

      <!-- ── Tabs ── -->
      <TabView class="tabs-block">
        <!-- By Asset -->
        <TabPanel value="byAsset" header="By Asset">
          <DataTable
            :value="assetRows"
            :loading="reviewsLoading"
            dataKey="assetId"
            paginator
            :rows="20"
            :rowsPerPageOptions="[10, 20, 50]"
            stripedRows
            responsiveLayout="scroll"
            sortField="compliancePct"
            :sortOrder="1"
          >
            <template #empty>
              <span class="muted">No assets loaded yet.</span>
            </template>

            <Column field="name" header="Asset" sortable style="min-width: 10rem" />
            <Column field="fqdn" header="FQDN" />
            <Column field="ip"   header="IP" style="width: 10rem" />

            <Column header="Compliance" field="compliancePct" sortable style="width: 12rem">
              <template #body="{ data }">
                <div class="compliance-cell">
                  <span class="compliance-pct" :class="complianceClass(data.compliancePct)">
                    {{ data.compliancePct }}%
                  </span>
                  <ProgressBar
                    :value="data.compliancePct"
                    :showValue="false"
                    style="height: 0.4rem; flex: 1"
                  />
                </div>
              </template>
            </Column>

            <Column header="Assessed" field="assessed" sortable style="width: 7rem; text-align: right">
              <template #body="{ data }">
                <span>{{ data.assessed }} / {{ data.total }}</span>
              </template>
            </Column>

            <Column header="Pass" field="pass" sortable style="width: 5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.pass > 0" :value="String(data.pass)" severity="success" rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="Open" field="fail" sortable style="width: 5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.fail > 0" :value="String(data.fail)" severity="danger" rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="CAT I" field="catI" sortable style="width: 5.5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.catI > 0"   :value="String(data.catI)"   severity="danger"    rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="CAT II" field="catII" sortable style="width: 5.5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.catII > 0"  :value="String(data.catII)"  severity="warn"      rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="CAT III" field="catIII" sortable style="width: 6rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.catIII > 0" :value="String(data.catIII)" severity="info"      rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="Not Reviewed" field="notchecked" sortable style="width: 8rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.notchecked > 0" :value="String(data.notchecked)" severity="warn" rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>
          </DataTable>
        </TabPanel>

        <!-- By STIG -->
        <TabPanel value="byStig" header="By STIG">
          <DataTable
            :value="stigRows"
            :loading="reviewsLoading"
            dataKey="benchmarkKey"
            paginator
            :rows="20"
            :rowsPerPageOptions="[10, 20, 50]"
            stripedRows
            responsiveLayout="scroll"
            sortField="compliancePct"
            :sortOrder="1"
          >
            <template #empty>
              <span class="muted">No STIG data loaded yet.</span>
            </template>

            <Column field="benchmarkKey" header="Benchmark" sortable style="min-width: 10rem" />

            <Column header="Compliance" field="compliancePct" sortable style="width: 12rem">
              <template #body="{ data }">
                <div class="compliance-cell">
                  <span class="compliance-pct" :class="complianceClass(data.compliancePct)">
                    {{ data.compliancePct }}%
                  </span>
                  <ProgressBar
                    :value="data.compliancePct"
                    :showValue="false"
                    style="height: 0.4rem; flex: 1"
                  />
                </div>
              </template>
            </Column>

            <Column header="Rules" field="total" sortable style="width: 6rem; text-align: right" />

            <Column header="Pass" field="pass" sortable style="width: 5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.pass > 0" :value="String(data.pass)" severity="success" rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="Open" field="fail" sortable style="width: 5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.fail > 0" :value="String(data.fail)" severity="danger" rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="CAT I" field="catI" sortable style="width: 5.5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.catI > 0"   :value="String(data.catI)"   severity="danger" rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="CAT II" field="catII" sortable style="width: 5.5rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.catII > 0"  :value="String(data.catII)"  severity="warn"   rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="CAT III" field="catIII" sortable style="width: 6rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.catIII > 0" :value="String(data.catIII)" severity="info"   rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>

            <Column header="Not Reviewed" field="notchecked" sortable style="width: 8rem; text-align: right">
              <template #body="{ data }">
                <Tag v-if="data.notchecked > 0" :value="String(data.notchecked)" severity="warn" rounded />
                <span v-else class="muted">0</span>
              </template>
            </Column>
          </DataTable>
        </TabPanel>

        <!-- Results breakdown -->
        <TabPanel value="results" header="Results">
          <div v-if="metrics" class="results-breakdown">
            <div class="results-total">
              <span class="big">{{ totalResults }}</span>
              <span class="muted" style="margin-left: 0.5rem">total review results</span>
            </div>

            <div class="result-bars">
              <div v-for="item in resultBreakdown" :key="item.label" class="result-bar-row">
                <div class="result-label">
                  <Tag :value="item.label" :severity="item.severity" style="min-width: 9rem" />
                </div>
                <div class="result-progress">
                  <ProgressBar :value="item.pct" :showValue="false" style="height: 1rem" />
                </div>
                <div class="result-count">
                  <span class="count-num">{{ item.count }}</span>
                  <span class="muted count-pct">({{ item.pct }}%)</span>
                </div>
              </div>
            </div>

            <!-- Donut-like proportional block -->
            <div class="proportion-bar" v-if="totalResults > 0">
              <div
                v-for="item in resultBreakdown.filter(r => r.count > 0)"
                :key="item.label"
                class="proportion-segment"
                :class="`seg-${item.severity}`"
                :style="{ flexGrow: item.count }"
                :title="`${item.label}: ${item.count} (${item.pct}%)`"
              />
            </div>
            <div class="proportion-legend">
              <div v-for="item in resultBreakdown.filter(r => r.count > 0)" :key="item.label" class="legend-item">
                <span class="legend-swatch" :class="`seg-${item.severity}`" />
                <span>{{ item.label }}: {{ item.count }}</span>
              </div>
            </div>
          </div>

          <p v-else class="muted">Metrics not available.</p>
        </TabPanel>
      </TabView>
    </template>

    <p v-else class="muted">Loading metrics…</p>
  </section>
</template>

<script lang="ts">
// Non-setup helpers (accessible in template via function call)
function complianceClass(pct: number): string {
  if (pct >= 80) return 'pct-success'
  if (pct >= 50) return 'pct-warn'
  return 'pct-danger'
}
</script>

<style scoped>
/* Layout */
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}
.page-header h2 { margin: 0; }

/* Summary cards */
.cards  { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
.metric { flex: 1 1 200px; min-width: 200px; }
.big    { font-size: 2rem; font-weight: 700; line-height: 1.1; }
.big.success { color: #3fb950; }
.big.danger  { color: #f85149; }
.sev-row     { display: flex; gap: 0.4rem; align-items: center; }
.sev-row.wrap { flex-wrap: wrap; }

/* Tabs */
.tabs-block { margin-top: 1.25rem; }

/* Compliance cell in DataTable */
.compliance-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.compliance-pct {
  font-weight: 600;
  width: 3rem;
  text-align: right;
  flex-shrink: 0;
}
.pct-success { color: #3fb950; }
.pct-warn    { color: #d29922; }
.pct-danger  { color: #f85149; }

/* Results tab */
.results-breakdown { max-width: 700px; padding: 0.5rem 0; }
.results-total     { margin-bottom: 1.25rem; display: flex; align-items: baseline; }
.result-bars       { display: flex; flex-direction: column; gap: 0.75rem; }

.result-bar-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.result-label    { flex: 0 0 9.5rem; }
.result-progress { flex: 1; }
.result-count    { flex: 0 0 7rem; text-align: right; display: flex; gap: 0.35rem; justify-content: flex-end; align-items: baseline; }
.count-num       { font-weight: 600; }
.count-pct       { font-size: 0.8rem; }

/* Proportional bar */
.proportion-bar {
  display: flex;
  height: 2rem;
  border-radius: 4px;
  overflow: hidden;
  margin-top: 1.5rem;
  gap: 2px;
}
.proportion-segment { min-width: 2px; transition: flex-grow 0.3s; }

.proportion-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 0.75rem;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.85rem;
}
.legend-swatch {
  display: inline-block;
  width: 0.9rem;
  height: 0.9rem;
  border-radius: 2px;
}

/* Severity/result segment & swatch colours (mirror PrimeVue Tag palette) */
.seg-success   { background: #3fb950; }
.seg-danger    { background: #f85149; }
.seg-warn      { background: #d29922; }
.seg-secondary { background: #6e7681; }
.seg-info      { background: #58a6ff; }

.muted { color: var(--text-color-secondary, #888); font-size: 0.875rem; }
</style>
