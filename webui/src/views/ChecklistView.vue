<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import Toast from 'primevue/toast'
import DataTable, { type DataTableCellEditCompleteEvent, type DataTableRowClickEvent } from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import Splitter from 'primevue/splitter'
import SplitterPanel from 'primevue/splitterpanel'
import Textarea from 'primevue/textarea'
import { api } from '../api/client'
import type { Asset, ChecklistRule, ChecklistReview, ReviewResult } from '../api/types'
import { severityTag, resultTag } from '../util/chips'
import BatchReviewDialog from '../components/BatchReviewDialog.vue'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------
const props = defineProps<{
  id: string          // collectionId
  benchmarkId: string
  assetId?: string    // optional — from route or query
}>()

const toast = useToast()
const cid = Number(props.id)

// ---------------------------------------------------------------------------
// Asset selector state
// ---------------------------------------------------------------------------
interface AssetOption { label: string; value: number | null }

const assets = ref<Asset[]>([])
const assetOptions = ref<AssetOption[]>([])
const selectedAssetId = ref<number | null>(props.assetId ? Number(props.assetId) : null)
const collectionName = ref('')

// ---------------------------------------------------------------------------
// Top grid state (rules)
// ---------------------------------------------------------------------------
const rules = ref<ChecklistRule[]>([])
const rulesLoading = ref(false)
const selectedRule = ref<ChecklistRule | null>(null)

// ---------------------------------------------------------------------------
// Multi-select state for batch edit
// ---------------------------------------------------------------------------
const selectedRules = ref<ChecklistRule[]>([])
const batchDialogVisible = ref(false)

const canBatchEdit = computed(() => selectedRules.value.length >= 2)
const selectedBatchRuleIds = computed(() => selectedRules.value.map(r => r.ruleId))

// ---------------------------------------------------------------------------
// Bottom grid state (reviews)
// ---------------------------------------------------------------------------
const reviews = ref<ChecklistReview[]>([])
const reviewsLoading = ref(false)
const selectedReviews = ref<ChecklistReview[]>([])

// ---------------------------------------------------------------------------
// Inline edit — track expanded detail/comment cells
// ---------------------------------------------------------------------------
const expandedDetailRow = ref<number | null>(null)
const expandedCommentRow = ref<number | null>(null)

// ---------------------------------------------------------------------------
// Result options for inline SelectButton / Dropdown
// ---------------------------------------------------------------------------
const resultOptions: { label: string; value: ReviewResult }[] = [
  { label: 'NF', value: 'pass' },
  { label: 'Open', value: 'fail' },
  { label: 'N/A', value: 'notapplicable' },
  { label: 'NR', value: 'notchecked' }
]

// ---------------------------------------------------------------------------
// Stats derived from rule totals
// ---------------------------------------------------------------------------
const totals = computed(() => {
  let open = 0, nf = 0, na = 0, nr = 0, total = 0
  for (const r of rules.value) {
    open += r.failCount
    nf   += r.passCount
    na   += r.naCount
    nr   += r.nrCount
    total++
  }
  return { total, open, nf, na, nr }
})

// ---------------------------------------------------------------------------
// Submit / Accept enablement
// ---------------------------------------------------------------------------
const canSubmit = computed(() =>
  selectedReviews.value.length > 0 &&
  selectedReviews.value.every(r =>
    r.result === 'pass' || r.result === 'fail' || r.result === 'notapplicable'
  )
)

const canAccept = computed(() => selectedReviews.value.length > 0)

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
onMounted(async () => {
  // Load collection name + assets in parallel
  const [colRes, assetsRes] = await Promise.all([
    api.GET('/collections/{id}', { params: { path: { id: cid } } }),
    api.GET('/collections/{id}/assets', { params: { path: { id: cid } } })
  ])
  collectionName.value = colRes.data?.name ?? String(cid)
  assets.value = assetsRes.data ?? []
  assetOptions.value = [
    { label: 'All Assets', value: null },
    ...(assetsRes.data ?? []).map(a => ({ label: a.name, value: a.assetId }))
  ]

  await loadRules()
})

// ---------------------------------------------------------------------------
// Watch asset selector — reload rules on change
// ---------------------------------------------------------------------------
watch(selectedAssetId, async () => {
  selectedRule.value = null
  reviews.value = []
  selectedReviews.value = []
  await loadRules()
})

// ---------------------------------------------------------------------------
// Load rules
// ---------------------------------------------------------------------------
async function loadRules() {
  rulesLoading.value = true
  const query: Record<string, string> = {}
  if (selectedAssetId.value !== null) {
    query.assetId = String(selectedAssetId.value)
  }
  const { data, error } = await api.GET(
    '/collections/{id}/checklist/{benchmarkId}/rules' as any,
    { params: { path: { id: cid, benchmarkId: props.benchmarkId }, query } }
  )
  rulesLoading.value = false
  if (error) {
    toast.add({ severity: 'error', summary: 'Load failed', detail: 'Could not load checklist rules.', life: 4000 })
    return
  }
  rules.value = (data as ChecklistRule[]) ?? []
}

// ---------------------------------------------------------------------------
// Row click → load reviews
// ---------------------------------------------------------------------------
async function onRuleRowClick(e: DataTableRowClickEvent) {
  const rule = e.data as ChecklistRule
  if (selectedRule.value?.ruleId === rule.ruleId) return
  selectedRule.value = rule
  reviews.value = []
  selectedReviews.value = []
  await loadReviews(rule.ruleId)
}

async function loadReviews(ruleId: string) {
  reviewsLoading.value = true
  const query: Record<string, string> = {}
  if (selectedAssetId.value !== null) {
    query.assetId = String(selectedAssetId.value)
  }
  const { data, error } = await api.GET(
    '/collections/{id}/checklist/{benchmarkId}/rules/{ruleId}/reviews' as any,
    { params: { path: { id: cid, benchmarkId: props.benchmarkId, ruleId }, query } }
  )
  reviewsLoading.value = false
  if (error) {
    toast.add({ severity: 'error', summary: 'Load failed', detail: 'Could not load reviews.', life: 4000 })
    return
  }
  reviews.value = (data as ChecklistReview[]) ?? []
}

// ---------------------------------------------------------------------------
// Inline cell edit complete
// ---------------------------------------------------------------------------
async function onCellEditComplete(event: DataTableCellEditCompleteEvent) {
  const { data, newValue, field } = event
  const review = data as ChecklistReview
  if (newValue === review[field as keyof ChecklistReview]) return

  const patch: Partial<ChecklistReview> = { [field]: newValue }
  const { error } = await api.PATCH(
    '/collections/{id}/checklist/{benchmarkId}/rules/{ruleId}/reviews/{assetId}' as any,
    {
      params: { path: { id: cid, benchmarkId: props.benchmarkId, ruleId: review.ruleId, assetId: review.assetId } },
      body: patch as any
    }
  )
  if (error) {
    toast.add({ severity: 'error', summary: 'Save failed', detail: 'Could not save review change.', life: 4000 })
    return
  }
  // Apply locally
  ;(review as any)[field] = newValue
  // Refresh rule row counts
  await refreshRuleRow(review.ruleId)
}

// ---------------------------------------------------------------------------
// Refresh single rule row counts after edit
// ---------------------------------------------------------------------------
async function refreshRuleRow(ruleId: string) {
  const query: Record<string, string> = {}
  if (selectedAssetId.value !== null) query.assetId = String(selectedAssetId.value)
  const { data } = await api.GET(
    '/collections/{id}/checklist/{benchmarkId}/rules' as any,
    { params: { path: { id: cid, benchmarkId: props.benchmarkId }, query } }
  )
  if (!data) return
  const fresh = (data as ChecklistRule[]).find(r => r.ruleId === ruleId)
  if (!fresh) return
  const idx = rules.value.findIndex(r => r.ruleId === ruleId)
  if (idx >= 0) rules.value[idx] = fresh
}

// ---------------------------------------------------------------------------
// Submit selected
// ---------------------------------------------------------------------------
async function submitSelected() {
  const targets = selectedReviews.value.slice()
  let ok = 0
  for (const rev of targets) {
    const { error } = await api.PATCH(
      '/collections/{id}/checklist/{benchmarkId}/rules/{ruleId}/reviews/{assetId}/status' as any,
      {
        params: { path: { id: cid, benchmarkId: props.benchmarkId, ruleId: rev.ruleId, assetId: rev.assetId } },
        body: { status: 'submitted' } as any
      }
    )
    if (!error) {
      rev.status = 'submitted'
      ok++
    }
  }
  toast.add({ severity: ok > 0 ? 'success' : 'error', summary: ok > 0 ? 'Submitted' : 'Submit failed', detail: `${ok} of ${targets.length} submitted.`, life: 3000 })
  if (ok > 0 && selectedRule.value) await refreshRuleRow(selectedRule.value.ruleId)
}

// ---------------------------------------------------------------------------
// Accept selected
// ---------------------------------------------------------------------------
async function acceptSelected() {
  const targets = selectedReviews.value.slice()
  let ok = 0
  for (const rev of targets) {
    const { error } = await api.PATCH(
      '/collections/{id}/checklist/{benchmarkId}/rules/{ruleId}/reviews/{assetId}/status' as any,
      {
        params: { path: { id: cid, benchmarkId: props.benchmarkId, ruleId: rev.ruleId, assetId: rev.assetId } },
        body: { status: 'accepted' } as any
      }
    )
    if (!error) {
      rev.status = 'accepted'
      ok++
    }
  }
  toast.add({ severity: ok > 0 ? 'success' : 'error', summary: ok > 0 ? 'Accepted' : 'Accept failed', detail: `${ok} of ${targets.length} accepted.`, life: 3000 })
  if (ok > 0 && selectedRule.value) await refreshRuleRow(selectedRule.value.ruleId)
}

// ---------------------------------------------------------------------------
// Batch edit callback — refresh all affected rule rows then reload reviews
// ---------------------------------------------------------------------------
async function onBatchUpdated() {
  batchDialogVisible.value = false
  toast.add({ severity: 'success', summary: 'Batch applied', detail: `${selectedRules.value.length} rules updated across selected assets.`, life: 3000 })
  // Reload rules to get fresh counts
  await loadRules()
  // Re-load reviews for currently selected rule, if any
  if (selectedRule.value) await loadReviews(selectedRule.value.ruleId)
}

// ---------------------------------------------------------------------------
// Status badge severity
// ---------------------------------------------------------------------------
function statusSeverity(status: string): 'secondary' | 'info' | 'success' | 'danger' | 'warn' {
  switch (status) {
    case 'saved':      return 'secondary'
    case 'submitted':  return 'info'
    case 'accepted':   return 'success'
    case 'rejected':   return 'danger'
    default:           return 'secondary'
  }
}

// ---------------------------------------------------------------------------
// Truncation helpers
// ---------------------------------------------------------------------------
function truncate(s: string | null | undefined, len = 60): string {
  if (!s) return ''
  return s.length > len ? s.slice(0, len) + '…' : s
}
</script>

<template>
  <Toast />

  <!-- ── Batch Review Dialog ──────────────────────────────────────────────── -->
  <BatchReviewDialog
    v-model:visible="batchDialogVisible"
    :collection-id="cid"
    :selected-rule-ids="selectedBatchRuleIds"
    :available-assets="assets"
    @updated="onBatchUpdated"
  />

  <div class="cl-root">

    <!-- ── HEADER BAR ──────────────────────────────────────────────────────── -->
    <div class="cl-header">
      <div class="cl-breadcrumb">
        <router-link :to="`/collections/${id}`">&larr; {{ collectionName || id }}</router-link>
        <span class="sep">&rsaquo;</span>
        <span class="mono bench-id">{{ benchmarkId }}</span>
      </div>

      <div class="cl-controls">
        <Dropdown
          v-model="selectedAssetId"
          :options="assetOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="All Assets"
          class="asset-dd"
          :showClear="selectedAssetId !== null"
        />
      </div>

      <div class="cl-stats" v-if="!rulesLoading">
        <span class="stat-item">
          <span class="stat-label">Total</span>
          <Tag :value="String(totals.total)" severity="secondary" />
        </span>
        <span class="stat-item">
          <span class="stat-label">O:</span>
          <Tag :value="String(totals.open)" severity="danger" />
        </span>
        <span class="stat-item">
          <span class="stat-label">NF:</span>
          <Tag :value="String(totals.nf)" severity="success" />
        </span>
        <span class="stat-item">
          <span class="stat-label">NA:</span>
          <Tag :value="String(totals.na)" severity="secondary" />
        </span>
        <span class="stat-item">
          <span class="stat-label">NR:</span>
          <Tag :value="String(totals.nr)" severity="warn" />
        </span>
      </div>
    </div>

    <!-- ── SPLITTER: Rules (top) / Reviews (bottom) ────────────────────────── -->
    <Splitter layout="vertical" class="cl-splitter">

      <!-- ── TOP PANEL: Rules ───────────────────────────────────────────────── -->
      <SplitterPanel :size="60" :minSize="20" class="cl-panel">

        <!-- Rules toolbar — only visible when 2+ rules selected -->
        <div v-if="canBatchEdit" class="rules-toolbar">
          <span class="muted small">
            {{ selectedRules.length }} rule{{ selectedRules.length !== 1 ? 's' : '' }} selected
          </span>
          <Button
            label="Batch Edit"
            icon="pi pi-pencil"
            severity="warn"
            size="small"
            @click="batchDialogVisible = true"
          />
        </div>

        <DataTable
          :value="rules"
          :loading="rulesLoading"
          dataKey="ruleId"
          selectionMode="multiple"
          v-model:selection="selectedRules"
          stripedRows
          scrollable
          scrollHeight="flex"
          :defaultSortField="'severityOrder'"
          :defaultSortOrder="1"
          :pt="{ bodyRow: { style: 'cursor: pointer' } }"
          @row-click="onRuleRowClick"
          class="cl-rules-table"
        >
          <template #empty>
            <span class="muted">No rules found. Ensure the STIG is assigned to assets in this collection.</span>
          </template>

          <!-- Checkbox selection column -->
          <Column selectionMode="multiple" style="width: 42px; flex-shrink: 0" />

          <!-- Severity -->
          <Column header="Sev" style="width: 70px" field="severityOrder" :sortable="true">
            <template #body="{ data }">
              <Tag
                :value="severityTag(data.severity).label"
                :severity="severityTag(data.severity).severity"
                style="font-size: 0.72rem; padding: 2px 5px"
              />
            </template>
          </Column>

          <!-- Group -->
          <Column field="groupId" header="Group" style="width: 90px" :sortable="true">
            <template #body="{ data }">
              <span class="mono small">{{ data.groupId }}</span>
            </template>
          </Column>

          <!-- Rule version (STIG ID) -->
          <Column field="ruleVersion" header="Rule" style="width: 130px" :sortable="true">
            <template #body="{ data }">
              <span class="mono small">{{ data.ruleVersion }}</span>
            </template>
          </Column>

          <!-- Title -->
          <Column field="title" header="Title" style="min-width: 0; flex: 1">
            <template #body="{ data }">
              <span class="rule-title-cell" :title="data.title">{{ truncate(data.title, 80) }}</span>
            </template>
          </Column>

          <!-- Open (O) -->
          <Column header="O" style="width: 44px; text-align: center" field="failCount" :sortable="true">
            <template #body="{ data }">
              <Tag v-if="data.failCount" :value="String(data.failCount)" severity="danger" class="count-badge" />
              <span v-else class="muted zero">0</span>
            </template>
          </Column>

          <!-- Not a Finding (NF) -->
          <Column header="NF" style="width: 44px; text-align: center" field="passCount" :sortable="true">
            <template #body="{ data }">
              <Tag v-if="data.passCount" :value="String(data.passCount)" severity="success" class="count-badge" />
              <span v-else class="muted zero">0</span>
            </template>
          </Column>

          <!-- Not Applicable (NA) -->
          <Column header="NA" style="width: 44px; text-align: center" field="naCount" :sortable="true">
            <template #body="{ data }">
              <Tag v-if="data.naCount" :value="String(data.naCount)" severity="secondary" class="count-badge" />
              <span v-else class="muted zero">0</span>
            </template>
          </Column>

          <!-- Not Reviewed (NR) -->
          <Column header="NR" style="width: 44px; text-align: center" field="nrCount" :sortable="true">
            <template #body="{ data }">
              <Tag v-if="data.nrCount" :value="String(data.nrCount)" severity="warn" class="count-badge" />
              <span v-else class="muted zero">0</span>
            </template>
          </Column>

          <!-- Submitted (Sub) -->
          <Column header="Sub" style="width: 44px; text-align: center" field="submittedCount" :sortable="true">
            <template #body="{ data }">
              <Tag v-if="data.submittedCount" :value="String(data.submittedCount)" severity="info" class="count-badge" />
              <span v-else class="zero muted">—</span>
            </template>
          </Column>

          <!-- Accepted (Acc) -->
          <Column header="Acc" style="width: 44px; text-align: center" field="acceptedCount" :sortable="true">
            <template #body="{ data }">
              <span v-if="data.acceptedCount" class="acc-badge">
                <i class="pi pi-star-fill" style="color: #22c55e; font-size: 0.7rem"></i>
                {{ data.acceptedCount }}
              </span>
              <span v-else class="zero muted">—</span>
            </template>
          </Column>

        </DataTable>
      </SplitterPanel>

      <!-- ── BOTTOM PANEL: Reviews ──────────────────────────────────────────── -->
      <SplitterPanel :size="40" :minSize="15" class="cl-panel">

        <!-- Toolbar -->
        <div class="reviews-toolbar">
          <span class="toolbar-label muted">
            <template v-if="selectedRule">
              {{ selectedRule.ruleId }} — {{ truncate(selectedRule.title, 50) }}
            </template>
            <template v-else>Select a rule above to view reviews</template>
          </span>
          <div class="toolbar-actions">
            <span class="muted small" v-if="reviews.length">{{ reviews.length }} review{{ reviews.length !== 1 ? 's' : '' }}</span>
            <Button
              label="Submit Selected"
              icon="pi pi-send"
              severity="info"
              size="small"
              :disabled="!canSubmit"
              @click="submitSelected"
            />
            <Button
              label="Accept Selected"
              icon="pi pi-check"
              severity="success"
              size="small"
              :disabled="!canAccept"
              @click="acceptSelected"
            />
          </div>
        </div>

        <!-- Reviews DataTable — inline cell editing -->
        <DataTable
          :value="reviews"
          :loading="reviewsLoading"
          dataKey="assetId"
          selectionMode="multiple"
          v-model:selection="selectedReviews"
          stripedRows
          scrollable
          scrollHeight="flex"
          editMode="cell"
          @cell-edit-complete="onCellEditComplete"
          class="cl-reviews-table"
        >
          <template #empty>
            <span class="muted">
              {{ selectedRule ? 'No reviews found for this rule.' : 'Click a rule row above.' }}
            </span>
          </template>

          <!-- Status -->
          <Column field="status" header="Status" style="width: 90px">
            <template #body="{ data }">
              <Tag
                :value="data.status ?? 'saved'"
                :severity="statusSeverity(data.status ?? 'saved')"
                style="font-size: 0.72rem"
              />
            </template>
          </Column>

          <!-- Asset name -->
          <Column field="assetName" header="Asset" style="width: 120px" :sortable="true">
            <template #body="{ data }">
              <span class="small">{{ data.assetName }}</span>
            </template>
          </Column>

          <!-- Result — editable -->
          <Column field="result" header="Result" style="width: 130px">
            <template #body="{ data }">
              <Tag
                :value="resultTag(data.result).label"
                :severity="resultTag(data.result).severity"
                style="font-size: 0.72rem; cursor: pointer"
              />
            </template>
            <template #editor="{ data, field }">
              <Dropdown
                v-model="data[field]"
                :options="resultOptions"
                optionLabel="label"
                optionValue="value"
                style="width: 120px; font-size: 0.82rem"
                autofocus
              />
            </template>
          </Column>

          <!-- Detail — truncated, expand on click -->
          <Column field="detail" header="Detail" style="min-width: 0; flex: 1">
            <template #body="{ data }">
              <div
                v-if="expandedDetailRow !== data.assetId"
                class="truncated-cell"
                @click="expandedDetailRow = data.assetId; expandedCommentRow = null"
                :title="data.detail"
              >
                {{ truncate(data.detail, 80) || '—' }}
              </div>
              <span v-else class="muted small" @click="expandedDetailRow = null" style="cursor: pointer">Click to collapse</span>
            </template>
            <template #editor="{ data, field }">
              <Textarea
                v-model="data[field]"
                rows="3"
                autoResize
                style="width: 100%; font-family: monospace; font-size: 0.8rem"
              />
            </template>
          </Column>

          <!-- Comment -->
          <Column field="comment" header="Comment" style="width: 120px">
            <template #body="{ data }">
              <div
                class="truncated-cell"
                :title="data.comment"
              >
                {{ truncate(data.comment, 30) || '—' }}
              </div>
            </template>
            <template #editor="{ data, field }">
              <Textarea
                v-model="data[field]"
                rows="2"
                autoResize
                style="width: 100%; font-size: 0.8rem"
              />
            </template>
          </Column>

          <!-- User -->
          <Column field="username" header="User" style="width: 90px" :sortable="true">
            <template #body="{ data }">
              <span class="small muted">{{ data.username ?? '—' }}</span>
            </template>
          </Column>

        </DataTable>
      </SplitterPanel>

    </Splitter>
  </div>
</template>

<style scoped>
/* ── Root ─────────────────────────────────────────────────────────────────── */
.cl-root {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 60px);
  overflow: hidden;
  padding: 0;
}

/* ── Header ───────────────────────────────────────────────────────────────── */
.cl-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.5rem 1rem;
  background: var(--p-surface-section, transparent);
  border-bottom: 1px solid var(--p-surface-border, #30363d);
  flex-shrink: 0;
  flex-wrap: wrap;
}
.cl-breadcrumb {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.9rem;
}
.sep { color: var(--p-text-muted-color); }
.bench-id { font-size: 0.9rem; }

.cl-controls { display: flex; align-items: center; gap: 0.5rem; }
.asset-dd { min-width: 200px; font-size: 0.85rem; }

.cl-stats { display: flex; align-items: center; gap: 0.6rem; margin-left: auto; flex-wrap: wrap; }
.stat-item { display: flex; align-items: center; gap: 0.25rem; }
.stat-label { font-size: 0.78rem; color: var(--p-text-muted-color); }

/* ── Splitter ─────────────────────────────────────────────────────────────── */
.cl-splitter {
  flex: 1;
  min-height: 0;
  border: none !important;
}

.cl-panel {
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-height: 0;
}

/* ── Tables ───────────────────────────────────────────────────────────────── */
.cl-rules-table,
.cl-reviews-table {
  flex: 1;
  min-height: 0;
  height: 100%;
}

.cl-rules-table :deep(.p-datatable),
.cl-reviews-table :deep(.p-datatable) {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.cl-rules-table :deep(.p-datatable-wrapper),
.cl-reviews-table :deep(.p-datatable-wrapper) {
  flex: 1;
  overflow-y: auto;
}

/* ── Rule title cell ─────────────────────────────────────────────────────── */
.rule-title-cell {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.85rem;
  cursor: pointer;
}

/* ── Count badges ────────────────────────────────────────────────────────── */
.count-badge { font-size: 0.72rem; padding: 2px 5px; }
.zero { font-size: 0.78rem; }
.acc-badge { display: inline-flex; align-items: center; gap: 3px; font-size: 0.78rem; color: #22c55e; }

/* ── Rules toolbar (batch edit) ──────────────────────────────────────────── */
.rules-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.35rem 0.75rem;
  background: var(--p-orange-950, rgba(251,146,60,0.08));
  border-bottom: 1px solid var(--p-orange-500, #f97316);
  flex-shrink: 0;
}

/* ── Reviews toolbar ─────────────────────────────────────────────────────── */
.reviews-toolbar {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.4rem 0.75rem;
  background: var(--p-surface-section, transparent);
  border-bottom: 1px solid var(--p-surface-border, #30363d);
  flex-shrink: 0;
  flex-wrap: wrap;
}
.toolbar-label { font-size: 0.82rem; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.toolbar-actions { display: flex; align-items: center; gap: 0.5rem; flex-shrink: 0; }

/* ── Inline edit cell ────────────────────────────────────────────────────── */
.truncated-cell {
  font-size: 0.82rem;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 100%;
}

/* ── Misc ─────────────────────────────────────────────────────────────────── */
.mono { font-family: monospace; }
.small { font-size: 0.82rem; }
.muted { color: var(--p-text-muted-color, #8b949e); }
</style>
