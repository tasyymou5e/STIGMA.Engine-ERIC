<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Card from 'primevue/card'
import ProgressBar from 'primevue/progressbar'
import Button from 'primevue/button'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import Chart from "primevue/chart"
import { api } from '../api/client'
import type { CollectionMetaRow } from '../api/types'

// ── Local types ────────────────────────────────────────────────────────────────
interface StigMetaRow {
  benchmarkId:    string
  title:          string | null
  collectionCount: number
  assetCount:     number
  passCount:      number
  failCount:      number
  catI:           number
  catII:          number
  catIII:         number
  compliancePct:  number
}

const router = useRouter()

// ── State ─────────────────────────────────────────────────────────────────────
const rows       = ref<CollectionMetaRow[]>([])
const stigRows   = ref<StigMetaRow[]>([])
const loading    = ref(true)
const stigLoading = ref(false)
const error      = ref('')

// ── Fetch — collections ────────────────────────────────────────────────────────
async function load() {
  loading.value = true
  error.value   = ''
  const { data, error: err } = await api.GET('/collections/meta/metrics')
  if (err || !data) {
    error.value   = 'Failed to load application overview data.'
    loading.value = false
    return
  }
  rows.value    = data
  loading.value = false
}

// ── Tab-change handler ─────────────────────────────────────────────────────────
function onTabChange(e: { index: number; value?: string }) {
  if (e.value === 'by-stig' || e.index === 1) loadStigs()
}

// ── Fetch — by STIG ────────────────────────────────────────────────────────────
async function loadStigs() {
  if (stigRows.value.length > 0) return   // already loaded
  stigLoading.value = true
  try {
    const token = await (await import('../auth/oidc')).getAccessToken()
    const { config } = await import('../config')
    const res = await fetch(`${config.apiBase}/metrics/summary/agg-stig`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (res.ok) {
      stigRows.value = await res.json() as StigMetaRow[]
    }
  } finally {
    stigLoading.value = false
  }
}

onMounted(load)

// ── Summary totals ─────────────────────────────────────────────────────────────
const totalCollections = computed(() => rows.value.length)
const totalAssets      = computed(() => rows.value.reduce((s, r) => s + r.assetCount, 0))
const totalReviews     = computed(() => rows.value.reduce((s, r) => s + r.passCount + r.failCount, 0))
const overallCompliance = computed(() => {
  const pass = rows.value.reduce((s, r) => s + r.passCount, 0)
  const fail = rows.value.reduce((s, r) => s + r.failCount, 0)
  const denom = pass + fail
  return denom > 0 ? Math.round((pass / denom) * 1000) / 10 : 0
})

// ── System-wide POA&M totals ───────────────────────────────────────────────────
const totalCatI   = computed(() => rows.value.reduce((s, r) => s + r.catI,   0))
const totalCatII  = computed(() => rows.value.reduce((s, r) => s + r.catII,  0))
const totalCatIII = computed(() => rows.value.reduce((s, r) => s + r.catIII, 0))

// Chart: compliance by collection (horizontal bar)
const complianceChartData = computed(() => ({
  labels: rows.value.map(r => r.name.length > 20 ? r.name.slice(0, 20) + "…" : r.name),
  datasets: [
    { label: "Pass %", data: rows.value.map(r => r.compliancePct), backgroundColor: "#3fb950", borderRadius: 4 },
    { label: "Open %", data: rows.value.map(r => r.failCount > 0 ? Math.round((r.failCount/(r.passCount+r.failCount))*100) : 0), backgroundColor: "#f85149", borderRadius: 4 }
  ]
}))
const complianceChartOpts = { responsive: true, maintainAspectRatio: false, indexAxis: "y", plugins: { legend: { position: "top" as const }, tooltip: { callbacks: { label: (ctx: any) => ctx.dataset.label + ": " + ctx.parsed.x + "%" } } }, scales: { x: { min: 0, max: 100, ticks: { callback: (v: any) => v + "%" } } } }

// Chart: CAT distribution across all collections (doughnut)
const catChartData = computed(() => ({
  labels: ["CAT I (High)", "CAT II (Medium)", "CAT III (Low)"],
  datasets: [{ data: [totalCatI.value, totalCatII.value, totalCatIII.value], backgroundColor: ["#f85149", "#d29922", "#58a6ff"], hoverOffset: 4 }]
}))
const catChartOpts = { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom" as const } } }

function openGrafana() { window.open("/grafana/d/eric-overview/stigma-engine-overview", "_blank", "noopener") }

const exportingMetaPoam = ref(false)
async function downloadMetaPoam() {
  exportingMetaPoam.value = true
  try {
    const token = await (await import('../auth/oidc')).getAccessToken()
    const { config } = await import('../config')
    const res = await fetch(`${config.apiBase}/collections/meta/poam/emass.xlsx`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `POAM-eMASS-all-collections-${new Date().toISOString().slice(0, 10)}.xlsx`
    a.click()
    URL.revokeObjectURL(a.href)
  } catch (e) { console.error(e) }
  finally { exportingMetaPoam.value = false }
}

// ── CSV export (collections) ────────────────────────────────────────────────────
function exportCsv() {
  const headers = [
    'Collection Name', 'Collection ID',
    'Assets', 'STIGs',
    'Pass', 'Open',
    'CAT I', 'CAT II', 'CAT III',
    'Compliance %'
  ]
  const lines: string[] = [headers.join(',')]
  for (const r of rows.value) {
    lines.push([
      `"${r.name.replace(/"/g, '""')}"`,
      r.collectionId,
      r.assetCount,
      r.stigCount,
      r.passCount,
      r.failCount,
      r.catI,
      r.catII,
      r.catIII,
      r.compliancePct
    ].join(','))
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' })
  const url  = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href     = url
  link.download = `application-overview-${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

// ── CSV export (by STIG) ───────────────────────────────────────────────────────
function exportStigCsv() {
  const headers = ['Benchmark ID', 'STIG Title', 'Collections', 'Assets', 'Pass', 'Open', 'CAT I', 'CAT II', 'CAT III', 'Compliance %']
  const lines: string[] = [headers.join(',')]
  for (const r of stigRows.value) {
    lines.push([
      `"${r.benchmarkId}"`,
      `"${(r.title ?? '').replace(/"/g, '""')}"`,
      r.collectionCount,
      r.assetCount,
      r.passCount,
      r.failCount,
      r.catI,
      r.catII,
      r.catIII,
      r.compliancePct
    ].join(','))
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' })
  const url  = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href     = url
  link.download = `stig-overview-${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function complianceClass(pct: number): string {
  if (pct >= 80) return 'pct-success'
  if (pct >= 50) return 'pct-warn'
  return 'pct-danger'
}
</script>

<template>
  <section>
    <div class="page-header">
      <h2>Application Overview</h2>
      <div class="toolbar">
        <Button
          label="Refresh"
          icon="pi pi-refresh"
          severity="secondary"
          size="small"
          :loading="loading"
          @click="load"
        />
      </div>
    </div>

    <p v-if="error" style="color: #f85149">{{ error }}</p>

    <!-- ── Summary totals bar ── -->
    <div v-if="!loading" class="summary-bar">
      <Card class="summary-card">
        <template #title>Collections</template>
        <template #content>
          <span class="big">{{ totalCollections }}</span>
        </template>
      </Card>
      <Card class="summary-card">
        <template #title>Assets</template>
        <template #content>
          <span class="big">{{ totalAssets }}</span>
        </template>
      </Card>
      <Card class="summary-card">
        <template #title>Total Reviews</template>
        <template #content>
          <span class="big">{{ totalReviews.toLocaleString() }}</span>
        </template>
      </Card>
      <Card class="summary-card">
        <template #title>Overall Compliance</template>
        <template #content>
          <span class="big" :class="complianceClass(overallCompliance)">
            {{ overallCompliance }}%
          </span>
          <ProgressBar
            :value="overallCompliance"
            :showValue="false"
            style="height: 0.5rem; margin-top: 0.5rem"
          />
        </template>
      </Card>
    </div>

    <!-- ── System POA&M totals row ── -->
    <div v-if="!loading" class="meta-poam-row">
      <span class="meta-poam-label">System POA&amp;M:</span>
      <Tag :value="'CAT I: ' + totalCatI" severity="danger" />
      <Tag :value="'CAT II: ' + totalCatII" severity="warn" />
      <Tag :value="'CAT III: ' + totalCatIII" severity="info" />
      <span class="meta-poam-total muted">{{ totalCatI + totalCatII + totalCatIII }} total items</span>
      <Button label="Export All POA&M" icon="pi pi-shield" size="small" severity="secondary" outlined @click="downloadMetaPoam" :loading="exportingMetaPoam" />
    </div>

    <!-- ── Charts + Grafana section ── -->
    <div v-if="!loading && rows.length > 0" class="charts-section">
      <h3 class="charts-title">Compliance Overview</h3>
      <div class="charts-row">

        <!-- Compliance by collection bar chart -->
        <Card class="chart-card chart-card-wide">
          <template #title>Compliance % by Collection</template>
          <template #content>
            <Chart type="bar" :data="complianceChartData" :options="complianceChartOpts" style="height:220px" />
          </template>
        </Card>

        <!-- CAT distribution doughnut -->
        <Card class="chart-card">
          <template #title>Open Findings by CAT</template>
          <template #content>
            <div class="chart-center">
              <Chart type="doughnut" :data="catChartData" :options="catChartOpts" style="height:220px" />
            </div>
            <div class="cat-totals">
              <span class="cat-total-item danger">CAT I: {{ totalCatI }}</span>
              <span class="cat-total-item warn">CAT II: {{ totalCatII }}</span>
              <span class="cat-total-item info">CAT III: {{ totalCatIII }}</span>
            </div>
          </template>
        </Card>
      </div>

      <!-- Grafana embedded panels -->
      <h3 class="charts-title" style="margin-top:1.5rem">System Monitoring</h3>
      <div class="grafana-panels">
        <Card class="chart-card">
          <template #title>Review Count</template>
          <template #content>
            <iframe
              src="/grafana/d/eric-overview/stigma-engine-overview?orgId=1&panelId=1&theme=dark&kiosk=tv"
              class="grafana-iframe"
              frameborder="0"
              title="Review Count"
            />
          </template>
        </Card>
        <Card class="chart-card">
          <template #title>HTTP Request Rate</template>
          <template #content>
            <iframe
              src="/grafana/d/eric-overview/stigma-engine-overview?orgId=1&panelId=3&theme=dark&kiosk=tv"
              class="grafana-iframe"
              frameborder="0"
              title="HTTP Request Rate"
            />
          </template>
        </Card>
        <Card class="chart-card">
          <template #title>Node.js Memory</template>
          <template #content>
            <iframe
              src="/grafana/d/eric-overview/stigma-engine-overview?orgId=1&panelId=5&theme=dark&kiosk=tv"
              class="grafana-iframe"
              frameborder="0"
              title="Node.js Memory"
            />
          </template>
        </Card>
        <div class="grafana-full-link">
          <Button label="Open Full Monitoring Dashboard" icon="pi pi-chart-line" severity="secondary" outlined @click="openGrafana" />
        </div>
      </div>
    </div>

    <!-- ── Tabs ── -->
    <Tabs value="by-collection" style="margin-top: 1.25rem" @update:value="(v) => onTabChange({ value: String(v), index: v === 'by-stig' ? 1 : 0 })">
      <TabList>
        <Tab value="by-collection">By Collection</Tab>
        <Tab value="by-stig">By STIG</Tab>
      </TabList>
      <TabPanels>

      <!-- By Collection -->
      <TabPanel value="by-collection">
        <div class="tab-toolbar">
          <Button
            label="Export CSV"
            icon="pi pi-download"
            severity="secondary"
            size="small"
            :disabled="rows.length === 0"
            @click="exportCsv"
          />
        </div>
        <DataTable
          :value="rows"
          :loading="loading"
          dataKey="collectionId"
          paginator
          :rows="25"
          :rowsPerPageOptions="[10, 25, 50, 100]"
          stripedRows
          responsiveLayout="scroll"
          sortField="name"
          :sortOrder="1"
        >
          <template #empty>
            <span class="muted">No collections visible to your account.</span>
          </template>

          <Column field="name" header="Collection Name" sortable style="min-width: 12rem">
            <template #body="{ data }">
              <a
                class="col-link"
                href="#"
                @click.prevent="router.push(`/collections/${data.collectionId}`)"
              >{{ data.name }}</a>
            </template>
          </Column>
          <Column field="assetCount" header="Assets" sortable style="width: 6rem; text-align: right">
            <template #body="{ data }"><span>{{ data.assetCount }}</span></template>
          </Column>
          <Column field="stigCount" header="STIGs" sortable style="width: 5.5rem; text-align: right">
            <template #body="{ data }"><span>{{ data.stigCount }}</span></template>
          </Column>
          <Column field="passCount" header="Pass" sortable style="width: 5.5rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.passCount > 0" :value="String(data.passCount)" severity="success" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
          <Column field="failCount" header="Open" sortable style="width: 5.5rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.failCount > 0" :value="String(data.failCount)" severity="danger" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
          <Column field="catI" header="CAT I" sortable style="width: 5.5rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.catI > 0" :value="String(data.catI)" severity="danger" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
          <Column field="catII" header="CAT II" sortable style="width: 5.5rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.catII > 0" :value="String(data.catII)" severity="warn" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
          <Column field="catIII" header="CAT III" sortable style="width: 6rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.catIII > 0" :value="String(data.catIII)" severity="info" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
          <Column field="compliancePct" header="Compliance %" sortable style="min-width: 12rem">
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
        </DataTable>
      </TabPanel>

      <!-- By STIG -->
      <TabPanel value="by-stig">
        <div class="tab-toolbar">
          <Button
            label="Export CSV"
            icon="pi pi-download"
            severity="secondary"
            size="small"
            :disabled="stigRows.length === 0"
            @click="exportStigCsv"
          />
        </div>
        <DataTable
          :value="stigRows"
          :loading="stigLoading"
          dataKey="benchmarkId"
          paginator
          :rows="25"
          :rowsPerPageOptions="[10, 25, 50, 100]"
          stripedRows
          responsiveLayout="scroll"
          sortField="benchmarkId"
          :sortOrder="1"
        >
          <template #empty>
            <span class="muted">No STIG data available.</span>
          </template>

          <Column field="benchmarkId" header="Benchmark ID" sortable style="min-width: 14rem">
            <template #body="{ data }">
              <span class="benchmark-id">{{ data.benchmarkId }}</span>
            </template>
          </Column>
          <Column field="title" header="STIG Name" sortable style="min-width: 18rem">
            <template #body="{ data }">
              <span>{{ data.title ?? data.benchmarkId }}</span>
            </template>
          </Column>
          <Column field="collectionCount" header="Collections" sortable style="width: 7rem; text-align: right">
            <template #body="{ data }"><span>{{ data.collectionCount }}</span></template>
          </Column>
          <Column field="assetCount" header="Assets" sortable style="width: 6rem; text-align: right">
            <template #body="{ data }"><span>{{ data.assetCount }}</span></template>
          </Column>
          <Column field="compliancePct" header="Compliance %" sortable style="min-width: 12rem">
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
          <Column field="catI" header="CAT I" sortable style="width: 5.5rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.catI > 0" :value="String(data.catI)" severity="danger" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
          <Column field="catII" header="CAT II" sortable style="width: 5.5rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.catII > 0" :value="String(data.catII)" severity="warn" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
          <Column field="catIII" header="CAT III" sortable style="width: 6rem; text-align: right">
            <template #body="{ data }">
              <Tag v-if="data.catIII > 0" :value="String(data.catIII)" severity="info" rounded />
              <span v-else class="muted">0</span>
            </template>
          </Column>
        </DataTable>
      </TabPanel>

      </TabPanels>
    </Tabs>
  </section>
</template>

<style scoped>
/* Page header */
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 1rem;
}
.page-header h2 { margin: 0; }
.toolbar { display: flex; gap: 0.5rem; }

/* Tab toolbar (inside each TabPanel) */
.tab-toolbar {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}

/* Summary totals bar */
.summary-bar {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 0.5rem;
}
.summary-card {
  flex: 1 1 180px;
  min-width: 160px;
}

.big { font-size: 1.75rem; font-weight: 700; line-height: 1.15; }

/* Compliance pct colours */
.pct-success { color: #3fb950; }
.pct-warn    { color: #d29922; }
.pct-danger  { color: #f85149; }

/* Compliance cell with bar */
.compliance-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.compliance-pct {
  font-weight: 600;
  width: 3.5rem;
  text-align: right;
  flex-shrink: 0;
}

/* Clickable collection name */
.col-link {
  color: var(--primary-color, #58a6ff);
  text-decoration: none;
  font-weight: 500;
}
.col-link:hover { text-decoration: underline; }

.benchmark-id {
  font-family: monospace;
  font-size: 0.82rem;
}

.muted { color: var(--text-color-secondary, #888); font-size: 0.875rem; }

/* System POA&M totals row */
.meta-poam-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
  padding: 0.5rem 0 0.25rem;
  margin-bottom: 0.25rem;
}
.meta-poam-label {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-color-secondary, #888);
  white-space: nowrap;
}
.meta-poam-total {
  font-size: 0.85rem;
  white-space: nowrap;
}

/* Charts + Grafana section */
.charts-section { margin: 1.25rem 0; }
.charts-title { font-size: 1rem; font-weight: 600; margin: 0 0 0.75rem; }
.charts-row { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; }
.chart-card { flex: 1 1 300px; min-width: 280px; }
.chart-card-wide { flex: 2 1 500px; }
.chart-center { display: flex; justify-content: center; }
.cat-totals { display: flex; justify-content: center; gap: 1.5rem; margin-top: 0.75rem; font-size: 0.85rem; font-weight: 600; }
.cat-total-item.danger { color: #f85149; }
.cat-total-item.warn   { color: #d29922; }
.cat-total-item.info   { color: #58a6ff; }
.grafana-panels { display: flex; gap: 1rem; flex-wrap: wrap; }
.grafana-iframe { width: 100%; height: 200px; border-radius: 4px; background: #111; }
.grafana-full-link { display: flex; align-items: center; justify-content: center; width: 100%; padding: 0.5rem 0; }
</style>
