<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import Toast from 'primevue/toast'
import DataTable, { type DataTableRowClickEvent, type DataTableRowExpandEvent } from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Card from 'primevue/card'
import ProgressBar from 'primevue/progressbar'
import Button from 'primevue/button'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import Dialog from 'primevue/dialog'
import Dropdown from 'primevue/dropdown'
import MultiSelect from 'primevue/multiselect'
import { api } from '../api/client'
import type {
  Collection, Metrics, LabelRecord, StigAggRow, AssetAggRow,
  CollectionStigRow, CollectionStigAsset, UnreviewedAsset, UnreviewedRule, Stig,
  StigAssetMetricsRow, LabelMetrics
} from '../api/types'
import { coraScore, coraRisk, coraColor } from '../util/cora'
import Chart from "primevue/chart"
import ImportDialog from '../components/ImportDialog.vue'
import ExportPanel from '../components/ExportPanel.vue'

const props = defineProps<{ id: string }>()
const router = useRouter()
let cid = Number(props.id)

// core state
const importDialogVisible = ref(false)
const collection = ref<Collection | null>(null)
const metrics = ref<Metrics | null>(null)
const loading = ref(true)
const error = ref('')

// Label filter
const labelFilter = ref<LabelMetrics | null>(null)

// STIG tab
const stigRows = ref<CollectionStigRow[]>([])
const stigRowsLoading = ref(false)
const selectedCollectionStig = ref<CollectionStigRow | null>(null)
const stigAssetRows = ref<CollectionStigAsset[]>([])
const stigAssetRowsLoading = ref(false)
const stigExpandedRows = ref<Record<string, boolean>>({})
const stigExpandedData = ref<Record<string, StigAssetMetricsRow[]>>({})
const stigExpandedLoading = ref<Record<string, boolean>>({})

// Assign-STIG dialog
const assignStigDialogVisible = ref(false)
const allStigs = ref<Stig[]>([])
const assignBenchmarkId = ref<string | null>(null)
const assignAssetIds = ref<number[]>([])
const allCollectionAssets = ref<{ assetId: number; name: string }[]>([])
const assignStigSaving = ref(false)

// Asset tab
const assetRows = ref<AssetAggRow[]>([])
const assetRowsLoading = ref(false)
const selectedAsset = ref<AssetAggRow | null>(null)
const assetStigRows = ref<StigAggRow[]>([])
const assetStigRowsLoading = ref(false)
const assetExpandedRows = ref<Record<string, boolean>>({})
const assetExpandedData = ref<Record<number, StigAggRow[]>>({})
const assetExpandedLoading = ref<Record<number, boolean>>({})

// Labels tab
const labels = ref<LabelRecord[]>([])
const labelsLoading = ref(false)
const labelMetrics = ref<LabelMetrics[]>([])
const labelMetricsLoading = ref(false)

// Unreviewed tab
const unreviewedTabLoaded = ref(false)
const unreviewedAssetsRows = ref<UnreviewedAsset[]>([])
const unreviewedRulesRows = ref<UnreviewedRule[]>([])
const unreviewedLoading = ref(false)

// derived stats
const compliance = computed(() => metrics.value?.compliancePct ?? 0)
const stigCount = computed(() => stigRows.value.length)
const cora = computed(() => {
  const m = metrics.value
  if (!m) return 100
  return coraScore(m.findings.high, m.findings.medium, m.findings.low, m.total)
})
const filteredAssetRows = computed(() => assetRows.value)
const complianceMiniData = computed(() => {
  const m = metrics.value
  if (!m) return null
  return {
    labels: ['Pass', 'Fail', 'N/A', 'Not Reviewed'],
    datasets: [{
      data: [m.results.pass, m.results.fail, m.results.notapplicable, m.results.notchecked],
      backgroundColor: ['#3fb950', '#f85149', '#6b7280', '#d29922'],
      hoverOffset: 2
    }]
  }
})
const complianceMiniOpts = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { callbacks: { label: (ctx: any) => ctx.label + ': ' + ctx.raw } } } }

// bootstrap
async function loadCollection(id: number) {
  loading.value = true
  error.value = ''
  collection.value = null
  metrics.value = null
  stigRows.value = []
  selectedCollectionStig.value = null
  stigAssetRows.value = []
  stigExpandedRows.value = {}
  stigExpandedData.value = {}
  stigExpandedLoading.value = {}
  assetRows.value = []
  selectedAsset.value = null
  assetStigRows.value = []
  assetExpandedRows.value = {}
  assetExpandedData.value = {}
  assetExpandedLoading.value = {}
  labels.value = []
  labelMetrics.value = []
  labelFilter.value = null
  unreviewedTabLoaded.value = false
  unreviewedAssetsRows.value = []
  unreviewedRulesRows.value = []
  const [c, m] = await Promise.all([
    api.GET('/collections/{id}', { params: { path: { id } } }),
    api.GET('/collections/{id}/metrics', { params: { path: { id } } })
  ])
  loading.value = false
  if (c.error) { error.value = 'Failed to load collection'; return }
  collection.value = c.data ?? null
  metrics.value = m.data ?? null
  loadStigTab()
  loadAssetTab()
  loadLabelsTab()
}
onMounted(() => loadCollection(cid))
watch(() => props.id, (newId) => { cid = Number(newId); loadCollection(cid) })

// STIG tab loaders
async function loadStigTab() {
  stigRowsLoading.value = true
  const { data } = await api.GET('/collections/{id}/stigs', { params: { path: { id: cid } } })
  stigRows.value = (data ?? []) as CollectionStigRow[]
  stigRowsLoading.value = false
}
async function onCollectionStigRowClick(e: DataTableRowClickEvent) {
  const row = e.data as CollectionStigRow
  selectedCollectionStig.value = row
  stigAssetRows.value = []
  stigAssetRowsLoading.value = true
  const { data } = await api.GET('/collections/{id}/stigs/{benchmarkId}/assets', {
    params: { path: { id: cid, benchmarkId: row.benchmarkId } }
  })
  stigAssetRows.value = (data ?? []) as CollectionStigAsset[]
  stigAssetRowsLoading.value = false
}
function onStigAssetRowDblClick(e: DataTableRowClickEvent) {
  const row = e.data as CollectionStigAsset
  if (!selectedCollectionStig.value) return
  router.push({ name: 'checklist', params: { id: String(cid), benchmarkId: selectedCollectionStig.value.benchmarkId, assetId: String(row.assetId) } })
}
async function onStigRowExpand(e: DataTableRowExpandEvent) {
  const row = e.data as CollectionStigRow
  const key = row.benchmarkId
  if (stigExpandedData.value[key]) return
  stigExpandedLoading.value[key] = true
  try {
    const { data } = await (api as any).GET('/collections/{id}/metrics/stigs/{benchmarkId}/assets', {
      params: { path: { id: cid, benchmarkId: key } }
    })
    stigExpandedData.value[key] = (data ?? []) as StigAssetMetricsRow[]
  } catch { stigExpandedData.value[key] = [] }
  finally { stigExpandedLoading.value[key] = false }
}
function onStigRowCollapse(_e: any) {}

async function openAssignStigDialog() {
  const [stigsRes, assetsRes] = await Promise.all([
    api.GET('/stigs', {}),
    api.GET('/assets', { params: { query: { collectionId: cid } } })
  ])
  allStigs.value = (stigsRes.data ?? []) as Stig[]
  allCollectionAssets.value = (assetsRes.data ?? []).map(a => ({ assetId: a.assetId, name: a.name }))
  assignBenchmarkId.value = null
  assignAssetIds.value = []
  assignStigDialogVisible.value = true
}
async function saveAssignStig() {
  if (!assignBenchmarkId.value) return
  assignStigSaving.value = true
  await api.PUT('/collections/{id}/stigs/{benchmarkId}/assets', {
    params: { path: { id: cid, benchmarkId: assignBenchmarkId.value } },
    body: { assetIds: assignAssetIds.value }
  })
  assignStigSaving.value = false
  assignStigDialogVisible.value = false
  loadStigTab()
}
async function removeCollectionStig(benchmarkId: string) {
  await api.DELETE('/collections/{id}/stigs/{benchmarkId}', { params: { path: { id: cid, benchmarkId } } })
  selectedCollectionStig.value = null
  stigAssetRows.value = []
  loadStigTab()
}

// Asset tab loaders
async function loadAssetTab() {
  assetRowsLoading.value = true
  const { data } = await api.GET('/collections/{id}/metrics/assets-agg', { params: { path: { id: cid } } })
  assetRows.value = data ?? []
  assetRowsLoading.value = false
}
async function onAssetRowClick(e: DataTableRowClickEvent) {
  const row = e.data as AssetAggRow
  selectedAsset.value = row
  assetStigRows.value = []
  assetStigRowsLoading.value = true
  const { data } = await api.GET('/collections/{id}/metrics/assets-agg/{assetId}', {
    params: { path: { id: cid, assetId: row.assetId } }
  })
  assetStigRows.value = data ?? []
  assetStigRowsLoading.value = false
}
function onAssetStigRowDblClick(e: DataTableRowClickEvent) {
  const row = e.data as StigAggRow
  if (!selectedAsset.value) return
  router.push({ name: 'checklist', params: { id: String(cid), benchmarkId: row.benchmarkId, assetId: String(selectedAsset.value.assetId) } })
}
async function onAssetRowExpand(e: DataTableRowExpandEvent) {
  const row = e.data as AssetAggRow
  const key = row.assetId
  if (assetExpandedData.value[key]) return
  assetExpandedLoading.value[key] = true
  try {
    const { data } = await (api as any).GET('/collections/{id}/metrics/assets/{assetId}/stigs', {
      params: { path: { id: cid, assetId: key } }
    })
    assetExpandedData.value[key] = (data ?? []) as StigAggRow[]
  } catch { assetExpandedData.value[key] = [] }
  finally { assetExpandedLoading.value[key] = false }
}
function onAssetRowCollapse(_e: any) {}

// Labels tab loader
async function loadLabelsTab() {
  labelsLoading.value = true
  labelMetricsLoading.value = true
  const [labelsRes, metricsRes] = await Promise.all([
    api.GET('/collections/{id}/labels', { params: { path: { id: cid } } }),
    (api as any).GET('/collections/{id}/metrics/labels', { params: { path: { id: cid } } })
  ])
  labels.value = labelsRes.data ?? []
  labelMetrics.value = (metricsRes.data ?? []) as LabelMetrics[]
  labelsLoading.value = false
  labelMetricsLoading.value = false
}
function onLabelClick(lm: LabelMetrics) {
  labelFilter.value = labelFilter.value?.clId === lm.clId ? null : lm
}
function clearLabelFilter() { labelFilter.value = null }

// Tab change
function onTabChange(e: { index: number; value?: string }) {
  if (e.value === 'unreviewed' || e.index === 3) loadUnreviewedTab()
}
async function loadUnreviewedTab() {
  if (unreviewedTabLoaded.value) return
  unreviewedLoading.value = true
  const [assetsRes, rulesRes] = await Promise.all([
    api.GET('/collections/{id}/unreviewed/assets', { params: { path: { id: cid } } }),
    api.GET('/collections/{id}/unreviewed/rules',  { params: { path: { id: cid } } })
  ])
  unreviewedAssetsRows.value = (assetsRes.data ?? []) as UnreviewedAsset[]
  unreviewedRulesRows.value  = (rulesRes.data  ?? []) as UnreviewedRule[]
  unreviewedLoading.value = false
  unreviewedTabLoaded.value = true
}
async function reloadAfterImport() {
  const { data } = await api.GET('/collections/{id}/metrics', { params: { path: { id: cid } } })
  metrics.value = data ?? null
  loadStigTab()
  loadAssetTab()
  unreviewedTabLoaded.value = false
}

// POA&M export
const exportingPoam = ref(false)
async function downloadPoam(includeNA: boolean) {
  exportingPoam.value = true
  try {
    const { getAccessToken } = await import('../auth/oidc')
    const { config } = await import('../config')
    const token = await getAccessToken()
    const url = config.apiBase + '/collections/' + cid + '/poam/emass.xlsx' + (includeNA ? '?includeNA=true' : '')
    const res = await fetch(url, { headers: token ? { Authorization: 'Bearer ' + token } : {} })
    if (!res.ok) throw new Error('HTTP ' + res.status)
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'POAM-eMASS-' + (collection.value?.name ?? 'collection') + '.xlsx'
    a.click()
    URL.revokeObjectURL(a.href)
  } catch (e) { console.error(e) }
  finally { exportingPoam.value = false }
}

function pct(val: number) { return Math.min(100, Math.max(0, Math.round(val))) }
function passPctSeverity(p: number): 'success' | 'warn' | 'danger' {
  if (p >= 80) return 'success'
  if (p >= 40) return 'warn'
  return 'danger'
}
function labelStyle(color: string | null) {
  return color
    ? { backgroundColor: color, color: '#fff', borderRadius: '4px', padding: '2px 8px', fontSize: '0.78rem' }
    : { backgroundColor: 'var(--p-surface-border, #30363d)', color: 'inherit', borderRadius: '4px', padding: '2px 8px', fontSize: '0.78rem' }
}
</script>

<template>
  <Toast />
  <section class="cv-root">
    <p class="breadcrumb"><router-link to="/collections">&larr; Collections</router-link></p>
    <p v-if="error" class="err">{{ error }}</p>
    <p v-if="loading" class="muted">Loading...</p>
    <template v-if="collection">
      <h2 class="cv-title">{{ collection.name }}</h2>
      <p v-if="collection.description" class="muted cv-desc">{{ collection.description }}</p>
      <ImportDialog v-model:visible="importDialogVisible" :collectionId="String(cid)" @imported="reloadAfterImport" />
      <div class="workspace">

        <!-- LEFT SIDEBAR -->
        <aside class="sidebar">
          <Card class="stat-card">
            <template #title>Compliance</template>
            <template #content>
              <div class="big-pct" v-if="metrics">{{ metrics.compliancePct }}%</div>
              <div class="big-pct muted" v-else>-</div>
              <ProgressBar :value="pct(compliance)" :showValue="false" class="stat-bar" />
              <div class="muted stat-sub" v-if="metrics">{{ metrics.assessed }} of {{ metrics.total }} assessed</div>
            </template>
          </Card>
          <Card class="stat-card">
            <template #title>Findings</template>
            <template #content>
              <div v-if="metrics" class="tag-stack">
                <div class="tag-row"><Tag :value="`CAT I - ${metrics.findings.high}`" severity="danger" /></div>
                <div class="tag-row"><Tag :value="`CAT II - ${metrics.findings.medium}`" severity="warn" /></div>
                <div class="tag-row"><Tag :value="`CAT III - ${metrics.findings.low}`" severity="info" /></div>
              </div>
              <span v-else class="muted">-</span>
            </template>
          </Card>
          <Card class="stat-card">
            <template #title>POA&amp;M Items</template>
            <template #content>
              <div v-if="metrics" class="poam-rows">
                <div class="poam-row"><span class="poam-label">Open Items:</span><span class="poam-count">{{ metrics.findings.high + metrics.findings.medium + metrics.findings.low }}</span></div>
                <div class="poam-row"><Tag value="CAT I" severity="danger" /><span class="poam-count danger">{{ metrics.findings.high }}</span></div>
                <div class="poam-row"><Tag value="CAT II" severity="warn" /><span class="poam-count warn">{{ metrics.findings.medium }}</span></div>
                <div class="poam-row"><Tag value="CAT III" severity="info" /><span class="poam-count">{{ metrics.findings.low }}</span></div>
                <div class="poam-buttons">
                  <Button label="Export eMASS POA&M" icon="pi pi-shield" size="small" severity="secondary" outlined class="w-full" @click="downloadPoam(false)" :loading="exportingPoam" />
                  <Button label="Include N/A items" icon="pi pi-file-excel" size="small" severity="secondary" text class="w-full" @click="downloadPoam(true)" :loading="exportingPoam" />
                </div>
              </div>
              <span v-else class="muted">-</span>
            </template>
          </Card>
          <Card class="stat-card">
            <template #title>CORA Risk Score</template>
            <template #content>
              <div v-if="metrics">
                <div class="big-pct" :style="{ color: coraColor(cora) }">{{ cora }}%</div>
                <div class="cora-tag-row">
                  <Tag :value="coraRisk(cora).charAt(0).toUpperCase() + coraRisk(cora).slice(1) + ' Risk'" :severity="coraRisk(cora) === 'low' ? 'success' : coraRisk(cora) === 'medium' ? 'warn' : 'danger'" />
                </div>
              </div>
              <div class="big-pct muted" v-else>-</div>
            </template>
          </Card>
          <Card class="stat-card">
            <template #title>Results</template>
            <template #content>
              <div v-if="metrics" class="tag-wrap">
                <Tag :value="`Pass ${metrics.results.pass}`" severity="success" />
                <Tag :value="`Open ${metrics.results.fail}`" severity="danger" />
                <Tag :value="`N/A ${metrics.results.notapplicable}`" severity="secondary" />
                <Tag :value="`Not Reviewed ${metrics.results.notchecked}`" severity="warn" />
              </div>
              <Chart v-if="complianceMiniData" type="doughnut" :data="complianceMiniData" :options="complianceMiniOpts" style="height:100px;margin-top:0.5rem" />
              <span v-else class="muted">-</span>
            </template>
          </Card>
          <Card class="stat-card">
            <template #title>Inventory</template>
            <template #content>
              <div class="inv-row"><span class="inv-label muted">Assets</span><Tag :value="String(assetRows.length)" severity="secondary" /></div>
              <div class="inv-row"><span class="inv-label muted">STIGs</span><Tag :value="String(stigCount)" severity="secondary" /></div>
            </template>
          </Card>
          <Card class="stat-card">
            <template #title>Export</template>
            <template #content>
              <ExportPanel :collectionId="cid" :collectionName="collection.name" />
            </template>
          </Card>
          <div class="sidebar-actions">
            <Button label="Import Checklist" icon="pi pi-upload" severity="secondary" size="small" class="w-full" @click="importDialogVisible = true" />
            <Button label="Manage Assets" icon="pi pi-server" severity="secondary" size="small" class="w-full" @click="router.push({ name: 'collection-assets', params: { collectionId: String(cid) } })" />
            <Button label="Collection Settings" icon="pi pi-cog" severity="secondary" size="small" class="w-full" @click="router.push({ name: 'collection-settings', params: { id: String(cid) } })" />
          </div>
        </aside>

        <!-- Assign-STIG dialog -->
        <Dialog v-model:visible="assignStigDialogVisible" header="Assign STIG to Collection" :modal="true" :style="{ width: '480px' }">
          <div class="assign-stig-form">
            <label class="assign-label">STIG</label>
            <Dropdown v-model="assignBenchmarkId" :options="allStigs" optionLabel="benchmarkId" optionValue="benchmarkId" placeholder="Select a STIG..." filter filterPlaceholder="Search benchmarks..." class="w-full" />
            <label class="assign-label" style="margin-top:1rem">Assets</label>
            <MultiSelect v-model="assignAssetIds" :options="allCollectionAssets" optionLabel="name" optionValue="assetId" placeholder="Select assets..." filter filterPlaceholder="Search assets..." class="w-full" />
          </div>
          <template #footer>
            <Button label="Cancel" severity="secondary" @click="assignStigDialogVisible = false" />
            <Button label="Assign" :disabled="!assignBenchmarkId || assignAssetIds.length === 0" :loading="assignStigSaving" @click="saveAssignStig" />
          </template>
        </Dialog>

        <!-- CENTER: TabView -->
        <div class="center">
          <TabView @tab-change="onTabChange">

            <!-- TAB 1: STIGs -->
            <TabPanel value="stigs" header="STIGs">
              <div class="split-panes">
                <div class="pane-upper">
                  <div class="pane-toolbar">
                    <Button label="Assign STIG" icon="pi pi-plus" size="small" severity="secondary" @click="openAssignStigDialog" />
                    <Button v-if="selectedCollectionStig" label="Remove from Collection" icon="pi pi-trash" size="small" severity="danger" @click="removeCollectionStig(selectedCollectionStig!.benchmarkId)" />
                    <div v-if="labelFilter" class="label-filter-chip">
                      <span class="lfc-label">Filtered by label:</span>
                      <span class="lfc-color-dot" :style="{ background: labelFilter.color ?? '#6b7280' }"></span>
                      <span class="lfc-name">{{ labelFilter.name }}</span>
                      <button class="lfc-dismiss" @click="clearLabelFilter" title="Clear filter">x</button>
                    </div>
                  </div>
                  <DataTable
                    :value="stigRows" :loading="stigRowsLoading" dataKey="benchmarkId"
                    selectionMode="single" :selection="selectedCollectionStig"
                    v-model:expandedRows="stigExpandedRows"
                    stripedRows scrollable scrollHeight="flex"
                    :pt="{ bodyRow: { style: 'cursor: pointer' } }"
                    @row-click="onCollectionStigRowClick"
                    @row-expand="onStigRowExpand"
                    @row-collapse="onStigRowCollapse"
                  >
                    <template #empty><span class="muted">No STIGs assigned to this collection. Use "Assign STIG" to add one.</span></template>
                    <Column expander style="width: 3rem" />
                    <Column field="benchmarkId" header="Benchmark ID" sortable style="min-width: 18rem" />
                    <Column field="title" header="Title" />
                    <Column header="Version" style="width: 7rem">
                      <template #body="{ data }">
                        <span v-if="data.version && data.release">V{{ data.version }}R{{ data.release }}</span>
                        <span v-else class="muted">-</span>
                      </template>
                    </Column>
                    <Column header="Rules" style="width: 5rem; text-align: right">
                      <template #body="{ data }"><span>{{ data.ruleCount ?? '-' }}</span></template>
                    </Column>
                    <Column header="CAT I" style="width: 5rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.highCount" :value="String(data.highCount)" severity="danger" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <Column header="CAT II" style="width: 5rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.mediumCount" :value="String(data.mediumCount)" severity="warn" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <Column header="CAT III" style="width: 5rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.lowCount" :value="String(data.lowCount)" severity="info" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <Column field="assetCount" header="Assets" style="width: 5rem; text-align: right" sortable />
                    <template #expansion="{ data: stigRow }">
                      <div class="expand-pane">
                        <div class="expand-head">
                          <span class="expand-title">Assets -- {{ stigRow.benchmarkId }}</span>
                          <span class="muted expand-hint">double-click a row to open checklist</span>
                        </div>
                        <DataTable
                          :value="stigExpandedData[stigRow.benchmarkId] ?? []"
                          :loading="stigExpandedLoading[stigRow.benchmarkId]"
                          dataKey="assetId" size="small" stripedRows
                          :pt="{ bodyRow: { style: 'cursor: pointer' } }"
                          @row-dblclick="(e: DataTableRowClickEvent) => router.push({ name: 'checklist', params: { id: String(cid), benchmarkId: stigRow.benchmarkId, assetId: String(e.data.assetId) } })"
                        >
                          <template #empty><span class="muted">{{ stigExpandedLoading[stigRow.benchmarkId] ? 'Loading...' : 'No asset data available.' }}</span></template>
                          <Column field="assetName" header="Asset Name" sortable style="min-width: 12rem" />
                          <Column header="Pass %" style="width: 8rem">
                            <template #body="{ data: ar }">
                              <Tag :value="`${ar.compliancePct}%`" :severity="passPctSeverity(ar.compliancePct)" />
                            </template>
                          </Column>
                          <Column header="Pass" style="width: 5rem; text-align: right">
                            <template #body="{ data: ar }"><span class="result-pass">{{ ar.results?.pass ?? '-' }}</span></template>
                          </Column>
                          <Column header="Fail" style="width: 5rem; text-align: right">
                            <template #body="{ data: ar }"><span :class="ar.results?.fail ? 'result-fail' : 'muted'">{{ ar.results?.fail ?? '-' }}</span></template>
                          </Column>
                          <Column header="N/A" style="width: 5rem; text-align: right">
                            <template #body="{ data: ar }"><span class="muted">{{ ar.results?.notapplicable ?? '-' }}</span></template>
                          </Column>
                          <Column header="Not Rev." style="width: 5.5rem; text-align: right">
                            <template #body="{ data: ar }"><span :class="ar.results?.notchecked ? 'result-nr' : 'muted'">{{ ar.results?.notchecked ?? '-' }}</span></template>
                          </Column>
                          <Column header="Submitted" style="width: 6.5rem; text-align: right">
                            <template #body="{ data: ar }"><span class="muted">{{ ar.results?.submitted ?? '-' }}</span></template>
                          </Column>
                          <Column header="Accepted" style="width: 6.5rem; text-align: right">
                            <template #body="{ data: ar }"><span :class="ar.results?.accepted ? 'result-accepted' : 'muted'">{{ ar.results?.accepted ?? '-' }}</span></template>
                          </Column>
                        </DataTable>
                      </div>
                    </template>
                  </DataTable>
                </div>
                <div class="pane-lower">
                  <div class="pane-lower-head">
                    <span v-if="selectedCollectionStig" class="muted pane-lower-label">Assets -- {{ selectedCollectionStig.benchmarkId }}</span>
                    <span v-else class="muted pane-lower-label">Select a STIG to see assigned assets</span>
                  </div>
                  <DataTable :value="stigAssetRows" :loading="stigAssetRowsLoading" dataKey="assetId" stripedRows scrollable scrollHeight="flex" :pt="{ bodyRow: { style: 'cursor: pointer' } }" @row-dblclick="onStigAssetRowDblClick">
                    <template #empty><span class="muted">No data - click a STIG row above.</span></template>
                    <Column field="name" header="Asset Name" sortable style="min-width: 12rem" />
                    <Column field="fqdn" header="FQDN">
                      <template #body="{ data }"><span v-if="data.fqdn">{{ data.fqdn }}</span><span v-else class="muted">-</span></template>
                    </Column>
                    <Column field="ip" header="IP">
                      <template #body="{ data }"><span v-if="data.ip">{{ data.ip }}</span><span v-else class="muted">-</span></template>
                    </Column>
                  </DataTable>
                </div>
              </div>
            </TabPanel>

            <!-- TAB 2: Assets -->
            <TabPanel value="assets" header="Assets">
              <div class="split-panes">
                <div class="pane-upper">
                  <div class="pane-toolbar">
                    <Button label="Import Checklist" icon="pi pi-upload" size="small" severity="primary" @click="importDialogVisible = true" />
                    <Button label="Manage Assets" icon="pi pi-server" size="small" severity="secondary" @click="router.push({ name: 'collection-assets', params: { collectionId: String(cid) } })" />
                    <Button label="Import Assets (CSV)" icon="pi pi-file-import" size="small" severity="secondary" outlined @click="router.push({ name: 'collection-assets', params: { collectionId: String(cid) } })" />
                    <div v-if="labelFilter" class="label-filter-chip">
                      <span class="lfc-label">Filtered by label:</span>
                      <span class="lfc-color-dot" :style="{ background: labelFilter.color ?? '#6b7280' }"></span>
                      <span class="lfc-name">{{ labelFilter.name }}</span>
                      <button class="lfc-dismiss" @click="clearLabelFilter" title="Clear filter">x</button>
                    </div>
                    <span class="muted" style="font-size:0.8rem;margin-left:auto">{{ assetRows.length }} asset{{ assetRows.length !== 1 ? 's' : '' }} - double-click a row to open checklist</span>
                  </div>
                  <DataTable
                    :value="filteredAssetRows" :loading="assetRowsLoading" dataKey="assetId"
                    selectionMode="single" :selection="selectedAsset"
                    v-model:expandedRows="assetExpandedRows"
                    stripedRows scrollable scrollHeight="flex"
                    :pt="{ bodyRow: { style: 'cursor: pointer' } }"
                    @row-click="onAssetRowClick"
                    @row-expand="onAssetRowExpand"
                    @row-collapse="onAssetRowCollapse"
                  >
                    <template #empty>
                      <div class="empty-assets">
                        <i class="pi pi-server" style="font-size:2rem;opacity:0.35" />
                        <p>No assets in this collection.</p>
                        <div style="display:flex;gap:0.5rem;justify-content:center;flex-wrap:wrap">
                          <Button label="Import a Checklist (CKL/CKLB)" icon="pi pi-upload" size="small" @click="importDialogVisible = true" />
                          <Button label="Manage Assets" icon="pi pi-server" size="small" severity="secondary" @click="router.push({ name: 'collection-assets', params: { collectionId: String(cid) } })" />
                        </div>
                      </div>
                    </template>
                    <Column expander style="width: 3rem" />
                    <Column field="assetName" header="Asset Name" sortable style="min-width: 14rem" />
                    <Column field="stigCount" header="STIGs" style="width: 6rem; text-align: right" sortable />
                    <Column header="Assessed %" style="width: 12rem">
                      <template #body="{ data }">
                        <div class="pct-cell">
                          <ProgressBar :value="pct(data.compliancePct)" :showValue="false" class="inline-bar" />
                          <span class="pct-label">{{ data.compliancePct }}%</span>
                        </div>
                      </template>
                    </Column>
                    <Column header="CAT I" style="width: 6rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.findings.high" :value="String(data.findings.high)" severity="danger" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <Column header="CAT II" style="width: 6rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.findings.medium" :value="String(data.findings.medium)" severity="warn" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <Column header="CAT III" style="width: 6rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.findings.low" :value="String(data.findings.low)" severity="info" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <template #expansion="{ data: assetRow }">
                      <div class="expand-pane">
                        <div class="expand-head">
                          <span class="expand-title">STIGs -- {{ assetRow.assetName }}</span>
                          <span class="muted expand-hint">double-click a row to open checklist</span>
                        </div>
                        <DataTable
                          :value="assetExpandedData[assetRow.assetId] ?? []"
                          :loading="assetExpandedLoading[assetRow.assetId]"
                          dataKey="benchmarkId" size="small" stripedRows
                          :pt="{ bodyRow: { style: 'cursor: pointer' } }"
                          @row-dblclick="(e: DataTableRowClickEvent) => router.push({ name: 'checklist', params: { id: String(cid), benchmarkId: e.data.benchmarkId, assetId: String(assetRow.assetId) } })"
                        >
                          <template #empty><span class="muted">{{ assetExpandedLoading[assetRow.assetId] ? 'Loading...' : 'No STIG data available.' }}</span></template>
                          <Column field="benchmarkId" header="Benchmark ID" sortable style="min-width: 18rem" />
                          <Column field="title" header="Title" />
                          <Column header="Assessed %" style="width: 12rem">
                            <template #body="{ data: sr }">
                              <div class="pct-cell">
                                <ProgressBar :value="pct(sr.compliancePct)" :showValue="false" class="inline-bar" />
                                <span class="pct-label">{{ sr.compliancePct }}%</span>
                              </div>
                            </template>
                          </Column>
                          <Column header="CAT I" style="width: 6rem; text-align: right">
                            <template #body="{ data: sr }">
                              <Tag v-if="sr.findings?.high" :value="String(sr.findings.high)" severity="danger" />
                              <span v-else class="muted">0</span>
                            </template>
                          </Column>
                          <Column header="CAT II" style="width: 6rem; text-align: right">
                            <template #body="{ data: sr }">
                              <Tag v-if="sr.findings?.medium" :value="String(sr.findings.medium)" severity="warn" />
                              <span v-else class="muted">0</span>
                            </template>
                          </Column>
                          <Column header="CAT III" style="width: 6rem; text-align: right">
                            <template #body="{ data: sr }">
                              <Tag v-if="sr.findings?.low" :value="String(sr.findings.low)" severity="info" />
                              <span v-else class="muted">0</span>
                            </template>
                          </Column>
                        </DataTable>
                      </div>
                    </template>
                  </DataTable>
                </div>
                <div class="pane-lower">
                  <div class="pane-lower-head">
                    <span v-if="selectedAsset" class="muted pane-lower-label">STIGs -- {{ selectedAsset.assetName }}</span>
                    <span v-else class="muted pane-lower-label">Select an asset to see per-STIG results</span>
                  </div>
                  <DataTable :value="assetStigRows" :loading="assetStigRowsLoading" dataKey="benchmarkId" stripedRows scrollable scrollHeight="flex" :pt="{ bodyRow: { style: 'cursor: pointer' } }" @row-dblclick="onAssetStigRowDblClick">
                    <template #empty><span class="muted">No data - click an asset row above.</span></template>
                    <Column field="benchmarkId" header="Benchmark ID" sortable style="min-width: 18rem" />
                    <Column field="title" header="Title" />
                    <Column header="Assessed %" style="width: 12rem">
                      <template #body="{ data }">
                        <div class="pct-cell">
                          <ProgressBar :value="pct(data.compliancePct)" :showValue="false" class="inline-bar" />
                          <span class="pct-label">{{ data.compliancePct }}%</span>
                        </div>
                      </template>
                    </Column>
                    <Column header="CAT I" style="width: 6rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.findings.high" :value="String(data.findings.high)" severity="danger" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <Column header="CAT II" style="width: 6rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.findings.medium" :value="String(data.findings.medium)" severity="warn" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                    <Column header="CAT III" style="width: 6rem; text-align: right">
                      <template #body="{ data }">
                        <Tag v-if="data.findings.low" :value="String(data.findings.low)" severity="info" />
                        <span v-else class="muted">0</span>
                      </template>
                    </Column>
                  </DataTable>
                </div>
              </div>
            </TabPanel>

            <!-- TAB 3: Labels -->
            <TabPanel value="labels" header="Labels">
              <div class="labels-header">
                <span class="muted" style="font-size:0.82rem;margin-right:auto">Click a row to set a label filter on the STIGs and Assets tabs.</span>
                <Button label="Manage Labels" icon="pi pi-tag" severity="secondary" size="small" @click="router.push({ name: 'collection-labels', params: { collectionId: String(cid) } })" />
              </div>
              <div v-if="labelFilter" class="label-filter-banner">
                <span>Active filter:</span>
                <span class="lfc-color-dot" :style="{ background: labelFilter.color ?? '#6b7280' }"></span>
                <strong>{{ labelFilter.name }}</strong>
                <Button icon="pi pi-times" size="small" severity="secondary" text @click="clearLabelFilter" style="margin-left:0.25rem" />
              </div>
              <DataTable
                :value="labelMetrics.length ? labelMetrics : labels.map(l => ({ ...l, assetCount: 0, assessed: 0, total: 0, compliancePct: 0, findings: { high: 0, medium: 0, low: 0 } }))"
                :loading="labelsLoading || labelMetricsLoading"
                dataKey="clId" stripedRows scrollable scrollHeight="flex"
                :pt="{ bodyRow: { style: 'cursor: pointer' } }"
                @row-click="(e: DataTableRowClickEvent) => onLabelClick(e.data as LabelMetrics)"
              >
                <template #empty><span class="muted">No labels defined. Use Manage Labels to create some.</span></template>
                <Column header="Label" style="width: 11rem">
                  <template #body="{ data }">
                    <span :style="labelStyle(data.color)">{{ data.name }}</span>
                    <span v-if="labelFilter?.clId === data.clId" class="lfc-active-dot" title="Active filter"> &#9679;</span>
                  </template>
                </Column>
                <Column field="name" header="Name" sortable />
                <Column header="Assets" style="width: 6rem; text-align: right">
                  <template #body="{ data }"><Tag :value="String(data.assetCount ?? 0)" severity="secondary" /></template>
                </Column>
                <Column header="Pass %" style="width: 11rem">
                  <template #body="{ data }">
                    <div v-if="data.total" class="pct-cell">
                      <ProgressBar :value="pct(data.compliancePct)" :showValue="false" class="inline-bar" />
                      <span class="pct-label">{{ data.compliancePct }}%</span>
                    </div>
                    <span v-else class="muted">-</span>
                  </template>
                </Column>
                <Column header="CAT I" style="width: 6rem; text-align: right">
                  <template #body="{ data }">
                    <Tag v-if="data.findings?.high" :value="String(data.findings.high)" severity="danger" />
                    <span v-else class="muted">0</span>
                  </template>
                </Column>
                <Column header="CAT II" style="width: 6rem; text-align: right">
                  <template #body="{ data }">
                    <Tag v-if="data.findings?.medium" :value="String(data.findings.medium)" severity="warn" />
                    <span v-else class="muted">0</span>
                  </template>
                </Column>
                <Column header="CAT III" style="width: 6rem; text-align: right">
                  <template #body="{ data }">
                    <Tag v-if="data.findings?.low" :value="String(data.findings.low)" severity="info" />
                    <span v-else class="muted">0</span>
                  </template>
                </Column>
                <Column field="description" header="Description">
                  <template #body="{ data }">
                    <span v-if="data.description">{{ data.description }}</span>
                    <span v-else class="muted">-</span>
                  </template>
                </Column>
              </DataTable>
            </TabPanel>

            <!-- TAB 4: Unreviewed -->
            <TabPanel value="unreviewed" header="Unreviewed">
              <div class="unreviewed-tab">
                <div v-if="!unreviewedLoading && unreviewedAssetsRows.length === 0 && unreviewedRulesRows.length === 0 && unreviewedTabLoaded" class="unreviewed-success">
                  <i class="pi pi-check-circle" style="font-size: 2rem; color: #3fb950" />
                  <p>All assigned STIGs have been reviewed!</p>
                </div>
                <template v-else>
                  <div class="unreviewed-section">
                    <div class="unreviewed-section-head">
                      <span class="unreviewed-section-title">Assets with no reviews</span>
                      <Tag v-if="!unreviewedLoading" :value="String(unreviewedAssetsRows.length)" :severity="unreviewedAssetsRows.length > 0 ? 'warn' : 'success'" />
                    </div>
                    <DataTable :value="unreviewedAssetsRows" :loading="unreviewedLoading" dataKey="assetId" stripedRows scrollable scrollHeight="200px">
                      <template #empty><span class="muted">{{ unreviewedTabLoaded ? 'No unreviewed assets.' : 'Click the Unreviewed tab to load.' }}</span></template>
                      <Column field="name" header="Asset Name" sortable style="min-width: 12rem" />
                      <Column field="benchmarkId" header="STIG" sortable style="min-width: 14rem" />
                      <Column field="stigTitle" header="STIG Title">
                        <template #body="{ data }"><span v-if="data.stigTitle">{{ data.stigTitle }}</span><span v-else class="muted">-</span></template>
                      </Column>
                      <Column header="Actions" style="width: 8rem">
                        <template #body="{ data }">
                          <Button label="Checklist" icon="pi pi-external-link" size="small" severity="secondary" @click="router.push({ name: 'checklist', params: { id: String(cid), benchmarkId: data.benchmarkId, assetId: String(data.assetId) } })" />
                        </template>
                      </Column>
                    </DataTable>
                  </div>
                  <div class="unreviewed-section" style="margin-top: 1rem">
                    <div class="unreviewed-section-head">
                      <span class="unreviewed-section-title">Rules not yet reviewed</span>
                      <Tag v-if="!unreviewedLoading" :value="String(unreviewedRulesRows.length)" :severity="unreviewedRulesRows.length > 0 ? 'warn' : 'success'" />
                    </div>
                    <DataTable :value="unreviewedRulesRows" :loading="unreviewedLoading" dataKey="ruleId" stripedRows scrollable scrollHeight="flex">
                      <template #empty><span class="muted">{{ unreviewedTabLoaded ? 'No unreviewed rules.' : 'Click the Unreviewed tab to load.' }}</span></template>
                      <Column header="CAT" style="width: 5rem">
                        <template #body="{ data }">
                          <Tag :value="data.severity === 'high' ? 'I' : data.severity === 'medium' ? 'II' : 'III'" :severity="data.severity === 'high' ? 'danger' : data.severity === 'medium' ? 'warn' : 'info'" />
                        </template>
                      </Column>
                      <Column field="groupId" header="Group" sortable style="width: 7rem" />
                      <Column field="ruleVersion" header="STIG ID" sortable style="min-width: 10rem" />
                      <Column field="title" header="Title" style="min-width: 18rem" />
                      <Column field="benchmarkId" header="STIG Name" sortable style="min-width: 14rem" />
                      <Column field="assetCount" header="Assets" style="width: 5rem; text-align: right" sortable />
                    </DataTable>
                  </div>
                </template>
              </div>
            </TabPanel>

          </TabView>
        </div>

      </div>
    </template>
  </section>
</template>

<style scoped>
.cv-root { padding: 0.5rem 1rem 2rem; }
.breadcrumb { margin: 0 0 0.5rem; }
.cv-title { margin: 0 0 0.25rem; }
.cv-desc  { margin: 0 0 1rem; }
.err  { color: #f85149; }

.workspace { display: flex; gap: 1rem; height: calc(100vh - 160px); min-height: 500px; }

.sidebar { width: 280px; min-width: 280px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.75rem; }
.stat-card { flex-shrink: 0; }
.big-pct { font-size: 2rem; font-weight: 700; line-height: 1.2; }
.stat-bar { height: 0.45rem; margin-top: 0.35rem; }
.stat-sub { font-size: 0.8rem; margin-top: 0.3rem; }
.cora-tag-row { margin-top: 0.5rem; }
.tag-stack { display: flex; flex-direction: column; gap: 0.4rem; }
.tag-row { display: flex; }
.tag-wrap { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.inv-row { display: flex; align-items: center; justify-content: space-between; padding: 0.2rem 0; }
.inv-label { font-size: 0.85rem; }
.w-full { width: 100%; }
.sidebar-actions { display: flex; flex-direction: column; gap: 0.5rem; padding: 0.25rem 0; }

.center { flex: 1; display: flex; flex-direction: column; min-width: 0; overflow: hidden; }
.center :deep(.p-tabview) { display: flex; flex-direction: column; height: 100%; }
.center :deep(.p-tabview-panels) { flex: 1; overflow: hidden; padding: 0; }
.center :deep(.p-tabview-panel) { height: 100%; display: flex; flex-direction: column; }

.split-panes { display: flex; flex-direction: column; gap: 0; height: 100%; overflow: hidden; }
.pane-upper { flex: 1 1 0; min-height: 0; overflow: hidden; display: flex; flex-direction: column; }
.pane-lower { flex: 0 0 220px; min-height: 0; overflow: hidden; display: flex; flex-direction: column; border-top: 1px solid var(--p-surface-border, #30363d); }
.pane-lower-head { padding: 0.35rem 0.5rem; background: var(--p-surface-section, transparent); flex-shrink: 0; }
.pane-lower-label { font-size: 0.82rem; }

.pane-upper :deep(.p-datatable),
.pane-lower :deep(.p-datatable) { display: flex; flex-direction: column; height: 100%; }
.pane-upper :deep(.p-datatable-wrapper),
.pane-lower :deep(.p-datatable-wrapper) { flex: 1; overflow-y: auto; }

.pct-cell { display: flex; align-items: center; gap: 0.5rem; }
.inline-bar { flex: 1; height: 0.4rem; }
.pct-label { font-size: 0.78rem; min-width: 2.5rem; text-align: right; }

.labels-header { display: flex; align-items: center; justify-content: flex-end; padding: 0.5rem 0 0.75rem; gap: 0.5rem; }

.label-filter-chip {
  display: inline-flex; align-items: center; gap: 0.3rem;
  background: var(--p-surface-section, #161b22);
  border: 1px solid var(--p-surface-border, #30363d);
  border-radius: 20px; padding: 0.15rem 0.4rem 0.15rem 0.6rem; font-size: 0.8rem;
}
.lfc-label { color: var(--p-text-muted-color, #8b949e); }
.lfc-color-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.lfc-name { font-weight: 600; }
.lfc-dismiss {
  background: none; border: none; cursor: pointer;
  color: var(--p-text-muted-color, #8b949e);
  font-size: 1rem; line-height: 1; padding: 0 0.15rem;
  display: flex; align-items: center;
}
.lfc-dismiss:hover { color: var(--p-text-color, #e6edf3); }
.label-filter-banner { display: flex; align-items: center; gap: 0.4rem; padding: 0.3rem 0.5rem 0.5rem; font-size: 0.82rem; color: var(--p-text-muted-color, #8b949e); }
.lfc-active-dot { color: #3b82f6; font-size: 0.65rem; vertical-align: middle; margin-left: 2px; }

.expand-pane { padding: 0.5rem 1rem 0.75rem; background: var(--p-surface-section, #0d1117); border-top: 1px solid var(--p-surface-border, #30363d); }
.expand-head { display: flex; align-items: baseline; gap: 0.75rem; margin-bottom: 0.4rem; }
.expand-title { font-size: 0.82rem; font-weight: 600; color: var(--p-text-muted-color, #8b949e); text-transform: uppercase; letter-spacing: 0.04em; }
.expand-hint { font-size: 0.75rem; }

.result-pass    { color: #3fb950; font-weight: 600; }
.result-fail    { color: #f85149; font-weight: 600; }
.result-nr      { color: #d29922; font-weight: 600; }
.result-accepted{ color: #58a6ff; font-weight: 600; }

.empty-assets { display: flex; flex-direction: column; align-items: center; gap: 0.75rem; padding: 2rem 1rem; color: var(--p-text-muted-color, #6b7280); }

.pane-toolbar { display: flex; gap: 0.5rem; padding: 0.4rem 0 0.4rem; align-items: center; flex-shrink: 0; flex-wrap: wrap; }

.unreviewed-tab { height: 100%; display: flex; flex-direction: column; overflow: hidden; padding: 0.5rem 0; }
.unreviewed-success { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; padding: 3rem 1rem; color: #3fb950; }
.unreviewed-section { display: flex; flex-direction: column; min-height: 0; }
.unreviewed-section-head { display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0 0.4rem; flex-shrink: 0; }
.unreviewed-section-title { font-size: 0.82rem; font-weight: 600; color: var(--p-text-muted-color, #8b949e); text-transform: uppercase; letter-spacing: 0.04em; }

.poam-rows { display: flex; flex-direction: column; gap: 0.35rem; }
.poam-row { display: flex; justify-content: space-between; align-items: center; }
.poam-label { font-size: 0.85rem; color: var(--p-text-muted-color, #6b7280); }
.poam-count { font-size: 1.1rem; font-weight: 700; }
.poam-count.danger { color: #ef4444; }
.poam-count.warn { color: #f59e0b; }
.poam-buttons { display: flex; flex-direction: column; gap: 0.4rem; margin-top: 0.5rem; }

.assign-stig-form { display: flex; flex-direction: column; gap: 0.5rem; padding: 0.5rem 0; }
.assign-label { font-size: 0.85rem; font-weight: 600; color: var(--p-text-muted-color, #8b949e); }

.muted { color: var(--p-text-muted-color, #6b7280); }
</style>
