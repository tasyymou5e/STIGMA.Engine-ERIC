<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import SelectButton from 'primevue/selectbutton'
import Select from 'primevue/select'
import { api } from '../api/client'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'
import type { OpenFinding, Metrics, LabelRecord } from '../api/types'
import { severityTag } from '../util/chips'

const props = defineProps<{ id: string }>()
const cid = Number(props.id)

// ── State ────────────────────────────────────────────────────────────────────
const findings = ref<OpenFinding[]>([])
const metrics = ref<Metrics | null>(null)
const labels = ref<LabelRecord[]>([])
const loading = ref(true)
const loadingFindings = ref(false)
const error = ref('')
const exporting = ref(false)
const exportingCsv = ref(false)
const exportingEmass = ref(false)
const exportingEmassNA = ref(false)

// ── Toolbar controls ─────────────────────────────────────────────────────────
type Aggregator = 'rule' | 'cci'
const aggregator = ref<Aggregator>('rule')
const aggregatorOptions = [
  { label: 'By Rule', value: 'rule' },
  { label: 'By CCI',  value: 'cci'  }
]

type SevFilter = 'all' | 'high' | 'medium' | 'low'
const sevFilter = ref<SevFilter>('all')
const sevFilterOptions = [
  { label: 'All',     value: 'all'    },
  { label: 'CAT I',   value: 'high'   },
  { label: 'CAT II',  value: 'medium' },
  { label: 'CAT III', value: 'low'    }
]

// ── Label filter ──────────────────────────────────────────────────────────────
// null = "All Labels" (no filter); number = clId of selected label
const selectedLabelId = ref<number | null>(null)

const labelOptions = computed(() => [
  { clId: null, name: 'All Labels', color: null },
  ...labels.value
])

const selectedLabel = computed(() =>
  selectedLabelId.value !== null
    ? labels.value.find(l => l.clId === selectedLabelId.value) ?? null
    : null
)

function clearLabelFilter() {
  selectedLabelId.value = null
}

// ── Data fetch ───────────────────────────────────────────────────────────────
async function fetchFindings(labelId: number | null = null) {
  loadingFindings.value = true
  try {
    // Build query params. The typed api client uses path+query params;
    // labelId is passed as a query param when set.
    const params: Record<string, unknown> = { path: { id: cid } }
    if (labelId !== null) {
      params.query = { labelId }
    }
    const f = await api.GET('/collections/{id}/findings', { params: params as any })
    if (f.error) {
      error.value = 'Failed to load findings'
      return
    }
    findings.value = f.data ?? []
  } finally {
    loadingFindings.value = false
  }
}

onMounted(async () => {
  const [f, m, l] = await Promise.all([
    api.GET('/collections/{id}/findings', { params: { path: { id: cid } } }),
    api.GET('/collections/{id}/metrics',  { params: { path: { id: cid } } }),
    api.GET('/collections/{id}/labels',   { params: { path: { id: cid } } })
  ])
  loading.value = false
  if (f.error) { error.value = 'Failed to load findings'; return }
  findings.value = f.data ?? []
  metrics.value = m.data ?? null
  labels.value = l.error ? [] : (l.data ?? [])
})

// Re-fetch findings when label filter changes
watch(selectedLabelId, (newVal) => {
  fetchFindings(newVal)
})

// ── Derived / filtered rows ───────────────────────────────────────────────────
const filteredFindings = computed(() => {
  let rows = findings.value
  if (sevFilter.value !== 'all') rows = rows.filter(r => r.severity === sevFilter.value)

  if (aggregator.value === 'cci') {
    // Explode by CCI: one row per unique CCI across all findings, grouped by CCI.
    const map = new Map<string, OpenFinding & { _aggKey: string }>()
    for (const f of rows) {
      const ccis: string[] = (f as any).ccis ?? []
      if (ccis.length === 0) {
        // Finding with no CCIs — group under sentinel
        const key = `NO_CCI__${f.ruleId}`
        if (!map.has(key)) map.set(key, { ...f, ccis: [], _aggKey: key })
      } else {
        for (const cci of ccis) {
          if (!map.has(cci)) {
            map.set(cci, { ...f, ccis: [cci], _aggKey: cci })
          } else {
            // Merge: keep highest severity, accumulate asset count
            const existing = map.get(cci)!
            const existingSev = severityRank(existing.severity)
            const newSev = severityRank(f.severity)
            if (newSev > existingSev) {
              map.set(cci, { ...f, ccis: [cci], _aggKey: cci,
                assetCount: (existing.assetCount ?? 0) + (f.assetCount ?? 0) })
            } else {
              existing.assetCount = (existing.assetCount ?? 0) + (f.assetCount ?? 0)
            }
          }
        }
      }
    }
    return [...map.values()]
  }

  return rows
})

function severityRank(s: string): number {
  return s === 'high' ? 3 : s === 'medium' ? 2 : s === 'low' ? 1 : 0
}

// ── Summary counts ────────────────────────────────────────────────────────────
const totalCount  = computed(() => findings.value.length)
const catICount   = computed(() => findings.value.filter(f => f.severity === 'high').length)
const catIICount  = computed(() => findings.value.filter(f => f.severity === 'medium').length)
const catIIICount = computed(() => findings.value.filter(f => f.severity === 'low').length)

// ── CSV export ────────────────────────────────────────────────────────────────
async function exportCsv() {
  exportingCsv.value = true
  try {
    const token = await getAccessToken()
    let url = `${config.apiBase}/collections/${cid}/findings?format=csv&aggregator=${aggregator.value}${sevFilter.value !== 'all' ? `&severity=${sevFilter.value}` : ''}`
    if (selectedLabelId.value !== null) {
      url += `&labelId=${selectedLabelId.value}`
    }
    const resp = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const blob = await resp.blob()
    const anchor = document.createElement('a')
    anchor.href = URL.createObjectURL(blob)
    anchor.download = `collection-${cid}-findings.csv`
    anchor.click()
    URL.revokeObjectURL(anchor.href)
  } catch (e) {
    error.value = `CSV export failed: ${(e as Error).message}`
  } finally {
    exportingCsv.value = false
  }
}

// ── POA&M XLSX export (legacy format) ────────────────────────────────────────
async function exportPoam() {
  exporting.value = true
  try {
    const token = await getAccessToken()
    const url = `${config.apiBase}/collections/${cid}/poam.xlsx`
    const resp = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const blob = await resp.blob()
    const anchor = document.createElement('a')
    anchor.href = URL.createObjectURL(blob)
    anchor.download = `collection-${cid}-poam.xlsx`
    anchor.click()
    URL.revokeObjectURL(anchor.href)
  } catch (e) {
    error.value = `POA&M export failed: ${(e as Error).message}`
  } finally {
    exporting.value = false
  }
}

// ── eMASS POA&M XLSX export ───────────────────────────────────────────────────
async function exportEmassPoam() {
  exportingEmass.value = true
  try {
    const token = await getAccessToken()
    const url = `${config.apiBase}/collections/${cid}/poam/emass.xlsx`
    const resp = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const blob = await resp.blob()
    const anchor = document.createElement('a')
    anchor.href = URL.createObjectURL(blob)
    anchor.download = `POAM-eMASS-collection-${cid}.xlsx`
    anchor.click()
    URL.revokeObjectURL(anchor.href)
  } catch (e) {
    error.value = `eMASS POA&M export failed: ${(e as Error).message}`
  } finally {
    exportingEmass.value = false
  }
}

// ── eMASS POA&M XLSX export (include N/A) ────────────────────────────────────
async function exportEmassPoamNA() {
  exportingEmassNA.value = true
  try {
    const token = await getAccessToken()
    const url = `${config.apiBase}/collections/${cid}/poam/emass.xlsx?includeNA=true`
    const resp = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const blob = await resp.blob()
    const anchor = document.createElement('a')
    anchor.href = URL.createObjectURL(blob)
    anchor.download = `POAM-eMASS-collection-${cid}-with-NA.xlsx`
    anchor.click()
    URL.revokeObjectURL(anchor.href)
  } catch (e) {
    error.value = `eMASS POA&M (+N/A) export failed: ${(e as Error).message}`
  } finally {
    exportingEmassNA.value = false
  }
}
</script>

<template>
  <section>
    <!-- Breadcrumb -->
    <p>
      <router-link to="/collections">&larr; Collections</router-link>
      &nbsp;/&nbsp;
      <router-link :to="`/collections/${id}`">Collection {{ id }}</router-link>
    </p>

    <p v-if="error" style="color: #f85149">{{ error }}</p>

    <!-- Summary chips -->
    <div class="summary-row" v-if="!loading">
      <Tag :value="`Total: ${totalCount}`" severity="secondary" class="summary-chip" />
      <Tag :value="`CAT I: ${catICount}`" severity="danger" class="summary-chip" />
      <Tag :value="`CAT II: ${catIICount}`" severity="warn" class="summary-chip" />
      <Tag :value="`CAT III: ${catIIICount}`" severity="info" class="summary-chip" />
    </div>

    <h2>Open Findings (POA&amp;M)</h2>

    <!-- Toolbar -->
    <div class="toolbar">
      <div class="toolbar-left">
        <span class="toolbar-label">Group:</span>
        <SelectButton
          v-model="aggregator"
          :options="aggregatorOptions"
          optionLabel="label"
          optionValue="value"
          :allowEmpty="false"
        />
        <span class="toolbar-label ml">Severity:</span>
        <SelectButton
          v-model="sevFilter"
          :options="sevFilterOptions"
          optionLabel="label"
          optionValue="value"
          :allowEmpty="false"
        />
        <span class="toolbar-label ml">Label:</span>
        <Select
          v-model="selectedLabelId"
          :options="labelOptions"
          optionLabel="name"
          optionValue="clId"
          placeholder="All Labels"
          :disabled="labels.length === 0"
          class="label-select"
        >
          <template #value="{ value }">
            <span v-if="value !== null && selectedLabel">
              <span
                v-if="selectedLabel.color"
                class="label-dot"
                :style="{ background: selectedLabel.color }"
              />
              {{ selectedLabel.name }}
            </span>
            <span v-else class="muted">All Labels</span>
          </template>
          <template #option="{ option }">
            <span class="label-option">
              <span
                v-if="option.color"
                class="label-dot"
                :style="{ background: option.color }"
              />
              <span :class="{ muted: option.clId === null }">{{ option.name }}</span>
            </span>
          </template>
        </Select>
      </div>
      <div style="display: flex; gap: 0.5rem">
        <Button
          label="Export CSV"
          icon="pi pi-file-export"
          severity="secondary"
          :loading="exportingCsv"
          @click="exportCsv"
        />
        <Button
          label="Export POA&M (XLSX)"
          icon="pi pi-file-excel"
          severity="success"
          :loading="exporting"
          @click="exportPoam"
        />
        <Button
          label="eMASS POA&M (Open)"
          icon="pi pi-shield"
          severity="info"
          size="small"
          :loading="exportingEmass"
          @click="exportEmassPoam"
        />
        <Button
          label="eMASS POA&M (+N/A)"
          icon="pi pi-file-excel"
          severity="secondary"
          size="small"
          outlined
          :loading="exportingEmassNA"
          @click="exportEmassPoamNA"
        />
      </div>
    </div>

    <!-- Active label filter chip -->
    <div v-if="selectedLabel" class="active-filter-row">
      <span class="active-filter-label">Filtered by label:</span>
      <span class="active-filter-chip">
        <span
          v-if="selectedLabel.color"
          class="label-dot"
          :style="{ background: selectedLabel.color }"
        />
        {{ selectedLabel.name }}
        <button class="dismiss-btn" @click="clearLabelFilter" title="Remove label filter">
          <i class="pi pi-times" />
        </button>
      </span>
    </div>

    <!-- Findings DataTable -->
    <DataTable
      :value="filteredFindings"
      :dataKey="aggregator === 'cci' ? '_aggKey' : 'ruleId'"
      :loading="loading || loadingFindings"
      paginator
      :rows="20"
      :rowsPerPageOptions="[10, 20, 50, 100]"
      stripedRows
      responsiveLayout="scroll"
      sortField="severity"
      :sortOrder="1"
    >
      <template #empty>
        <span class="muted">No open findings match the current filter.</span>
      </template>

      <!-- Severity chip -->
      <Column header="Severity" field="severity" sortable style="width: 7rem">
        <template #body="{ data }">
          <Tag
            :value="severityTag(data.severity).label"
            :severity="severityTag(data.severity).severity"
          />
        </template>
      </Column>

      <!-- STIG ID -->
      <Column field="ruleVersion" header="STIG ID" sortable style="width: 13rem" />

      <!-- Group ID -->
      <Column field="groupId" header="Group" sortable style="width: 8rem" />

      <!-- Title -->
      <Column field="title" header="Rule Title" sortable />

      <!-- Asset count badge -->
      <Column header="Assets" style="width: 6rem; text-align: center">
        <template #body="{ data }">
          <Tag
            v-if="data.assetCount != null"
            :value="String(data.assetCount)"
            severity="secondary"
            rounded
          />
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <!-- CCIs (shown in By CCI mode or when present) -->
      <Column header="CCIs" style="min-width: 12rem">
        <template #body="{ data }">
          <span v-if="data.ccis && data.ccis.length" class="cci-list">
            {{ data.ccis.join(', ') }}
          </span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
    </DataTable>

    <p v-if="loading" class="muted">Loading findings…</p>
  </section>
</template>

<style scoped>
.summary-row {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-bottom: 0.75rem;
}
.summary-chip {
  font-size: 0.85rem;
}
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin: 0.75rem 0 1rem;
}
.toolbar-left {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.toolbar-label {
  font-size: 0.875rem;
  color: var(--text-color-secondary, #888);
  white-space: nowrap;
}
.toolbar-label.ml {
  margin-left: 0.75rem;
}
.label-select {
  min-width: 10rem;
}
.label-option {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}
.label-dot {
  display: inline-block;
  width: 0.65rem;
  height: 0.65rem;
  border-radius: 50%;
  flex-shrink: 0;
}
/* Active label filter chip row */
.active-filter-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}
.active-filter-label {
  font-size: 0.8rem;
  color: var(--text-color-secondary, #888);
}
.active-filter-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  background: var(--surface-100, #f3f4f6);
  border: 1px solid var(--surface-300, #d1d5db);
  border-radius: 1rem;
  padding: 0.15rem 0.55rem 0.15rem 0.45rem;
  font-size: 0.8rem;
  font-weight: 500;
}
.dismiss-btn {
  display: inline-flex;
  align-items: center;
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  margin-left: 0.15rem;
  color: var(--text-color-secondary, #888);
  font-size: 0.65rem;
  line-height: 1;
}
.dismiss-btn:hover {
  color: var(--text-color, #222);
}
.cci-list {
  font-size: 0.8rem;
  font-family: monospace;
}
.muted {
  color: var(--text-color-secondary, #888);
  font-size: 0.875rem;
}
</style>
