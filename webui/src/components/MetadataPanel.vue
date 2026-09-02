<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------
const props = withDefaults(defineProps<{
  entityType: 'collection' | 'asset' | 'review'
  entityId: number
  readonly?: boolean
}>(), {
  readonly: false
})

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface MetaRow {
  _rowId: number   // internal key for Vue list rendering
  key: string
  value: string
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const toast = useToast()
const loading = ref(false)
const saving = ref(false)
const error = ref('')
const editing = ref(false)
let nextRowId = 0

/** Committed (server) state — plain object */
const committed = ref<Record<string, string>>({})

/** Working copy shown in the table */
const rows = ref<MetaRow[]>([])

// ---------------------------------------------------------------------------
// URL helper
// ---------------------------------------------------------------------------
function metaUrl(): string {
  const entityPath: Record<string, string> = {
    collection: 'collections',
    asset: 'assets',
    review: 'reviews'
  }
  return `${config.apiBase}/${entityPath[props.entityType]}/${props.entityId}/metadata`
}

async function bearerHeaders(json = true): Promise<HeadersInit> {
  const token = await getAccessToken()
  const base: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}
  if (json) base['Content-Type'] = 'application/json'
  return base
}

// ---------------------------------------------------------------------------
// Convert between object and row array
// ---------------------------------------------------------------------------
function objectToRows(obj: Record<string, string>): MetaRow[] {
  return Object.entries(obj).map(([key, value]) => ({ _rowId: nextRowId++, key, value }))
}

function rowsToObject(arr: MetaRow[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const r of arr) {
    const k = r.key.trim()
    if (k) out[k] = r.value
  }
  return out
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------
async function load() {
  if (!props.entityId) return
  loading.value = true
  error.value = ''
  try {
    const headers = await bearerHeaders(false)
    const res = await fetch(metaUrl(), { headers })
    if (res.status === 404) {
      // No metadata yet — treat as empty
      committed.value = {}
      rows.value = []
      return
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data: Record<string, string> = await res.json()
    committed.value = data ?? {}
    rows.value = objectToRows(committed.value)
  } catch (e) {
    error.value = `Failed to load metadata: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

onMounted(load)

// Reload if entityId changes (e.g. panel reused for different records)
watch(() => props.entityId, load)

// ---------------------------------------------------------------------------
// Edit helpers
// ---------------------------------------------------------------------------
function beginEdit() {
  // Clone committed state into working rows
  rows.value = objectToRows(committed.value)
  editing.value = true
}

function cancelEdit() {
  rows.value = objectToRows(committed.value)
  editing.value = false
}

function addRow() {
  rows.value.push({ _rowId: nextRowId++, key: '', value: '' })
}

function deleteRow(rowId: number) {
  rows.value = rows.value.filter(r => r._rowId !== rowId)
}

// ---------------------------------------------------------------------------
// Save (PUT)
// ---------------------------------------------------------------------------
async function save() {
  // Validate — no duplicate keys, no blank keys
  const payload = rowsToObject(rows.value)
  const rawKeys = rows.value.map(r => r.key.trim()).filter(k => k !== '')
  const uniqKeys = new Set(rawKeys)
  if (rawKeys.length !== uniqKeys.size) {
    toast.add({ severity: 'warn', summary: 'Duplicate keys', detail: 'Each metadata key must be unique.', life: 4000 })
    return
  }

  saving.value = true
  error.value = ''
  try {
    const headers = await bearerHeaders()
    const res = await fetch(metaUrl(), {
      method: 'PUT',
      headers,
      body: JSON.stringify(payload)
    })
    if (!res.ok) {
      const msg = await res.text()
      throw new Error(msg || `HTTP ${res.status}`)
    }
    const updated: Record<string, string> = await res.json().catch(() => payload)
    committed.value = updated
    rows.value = objectToRows(committed.value)
    editing.value = false
    toast.add({ severity: 'success', summary: 'Saved', detail: 'Metadata updated.', life: 3000 })
  } catch (e) {
    error.value = `Save failed: ${(e as Error).message}`
    toast.add({ severity: 'error', summary: 'Save failed', detail: (e as Error).message, life: 5000 })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="mp-root">
    <p v-if="loading" class="muted mp-msg">Loading metadata…</p>
    <p v-else-if="error" class="mp-error">{{ error }}</p>

    <template v-else>
      <!-- Read-only: simple key-value table -->
      <template v-if="!editing">
        <p v-if="rows.length === 0" class="muted mp-msg">No metadata entries.</p>
        <DataTable
          v-else
          :value="rows"
          dataKey="_rowId"
          size="small"
          class="mp-table"
        >
          <Column field="key"   header="Key"   style="width: 40%" />
          <Column field="value" header="Value" />
        </DataTable>

        <div v-if="!readonly" class="mp-toolbar">
          <Button
            label="Edit Metadata"
            icon="pi pi-pencil"
            size="small"
            severity="secondary"
            @click="beginEdit"
          />
        </div>
      </template>

      <!-- Edit mode -->
      <template v-else>
        <DataTable
          :value="rows"
          dataKey="_rowId"
          size="small"
          class="mp-table"
        >
          <Column header="Key" style="width: 40%">
            <template #body="{ data }">
              <InputText
                v-model="data.key"
                placeholder="key"
                size="small"
                class="mp-input"
              />
            </template>
          </Column>
          <Column header="Value">
            <template #body="{ data }">
              <InputText
                v-model="data.value"
                placeholder="value"
                size="small"
                class="mp-input"
              />
            </template>
          </Column>
          <Column header="" style="width: 3rem; text-align: center">
            <template #body="{ data }">
              <Button
                icon="pi pi-trash"
                severity="danger"
                size="small"
                text
                rounded
                v-tooltip.top="'Remove row'"
                @click="deleteRow(data._rowId)"
              />
            </template>
          </Column>
        </DataTable>

        <div class="mp-toolbar">
          <Button
            label="Add Row"
            icon="pi pi-plus"
            size="small"
            severity="secondary"
            outlined
            @click="addRow"
          />
          <div class="mp-spacer" />
          <Button
            label="Cancel"
            icon="pi pi-times"
            size="small"
            severity="secondary"
            text
            :disabled="saving"
            @click="cancelEdit"
          />
          <Button
            label="Save"
            icon="pi pi-check"
            size="small"
            :loading="saving"
            @click="save"
          />
        </div>
      </template>
    </template>
  </div>
</template>

<style scoped>
.mp-root { }

.mp-msg   { font-size: 0.875rem; margin: 0.25rem 0; }
.mp-error { color: #f85149; font-size: 0.875rem; margin: 0.25rem 0; }

.mp-table { width: 100%; }

/* Make inputs fill their cells */
.mp-input { width: 100%; }

.mp-toolbar {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.6rem;
  flex-wrap: wrap;
}

.mp-spacer { flex: 1; }
</style>
