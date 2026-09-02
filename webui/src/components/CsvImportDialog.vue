<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import Textarea from 'primevue/textarea'
import Checkbox from 'primevue/checkbox'
import Select from 'primevue/select'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'

// ---------------------------------------------------------------------------
// Props / emits
// ---------------------------------------------------------------------------
const props = defineProps<{
  visible: boolean
  collectionId: number
}>()

const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
  (e: 'imported'): void
}>()

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Step = 'input' | 'configure'

interface FieldFlags {
  name: boolean
  fqdn: boolean
  ip: boolean
  mac: boolean
  description: boolean
  stigs: boolean
}

interface DelimiterOption {
  label: string
  value: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const DELIMITER_OPTIONS: DelimiterOption[] = [
  { label: 'Comma  ( , )', value: ',' },
  { label: 'Tab    ( \\t )', value: '\t' },
  { label: 'Semicolon  ( ; )', value: ';' }
]

const ALL_FIELDS: Array<{ key: keyof FieldFlags; label: string; required: boolean }> = [
  { key: 'name',        label: 'Name',        required: true  },
  { key: 'fqdn',        label: 'FQDN',        required: false },
  { key: 'ip',          label: 'IP Address',  required: false },
  { key: 'mac',         label: 'MAC Address', required: false },
  { key: 'description', label: 'Description', required: false },
  { key: 'stigs',       label: 'STIGs',       required: false },
]

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const step = ref<Step>('input')

// Step 1
const csvText  = ref('')
const fileRef  = ref<HTMLInputElement | null>(null)

// Step 2
const delimiter = ref<DelimiterOption>(DELIMITER_OPTIONS[0])
const fields = ref<FieldFlags>({
  name: true,
  fqdn: false,
  ip: false,
  mac: false,
  description: false,
  stigs: false
})

// Import state
const importing  = ref(false)
const importDone = ref(false)
const importedCount = ref(0)
const importErrors  = ref<string[]>([])

// ---------------------------------------------------------------------------
// Computed — parse CSV for preview
// ---------------------------------------------------------------------------

/** Split raw CSV into rows/cells using the selected delimiter. */
function parseCsvPreview(text: string, delim: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let inQuote = false
  const chars = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')

  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i]
    if (inQuote) {
      if (ch === '"') {
        if (chars[i + 1] === '"') { cell += '"'; i++ }
        else inQuote = false
      } else {
        cell += ch
      }
    } else if (ch === '"') {
      inQuote = true
    } else if (ch === delim) {
      row.push(cell); cell = ''
    } else if (ch === '\n') {
      row.push(cell); cell = ''
      if (row.some(c => c !== '')) rows.push(row)
      row = []
    } else {
      cell += ch
    }
  }
  row.push(cell)
  if (row.some(c => c !== '')) rows.push(row)
  return rows
}

const parsedRows = computed(() => parseCsvPreview(csvText.value, delimiter.value.value))

/** Column headers from row 0. */
const csvHeaders = computed(() => parsedRows.value[0] ?? [])

/** Data rows — up to 5 for the preview table. */
const previewRows = computed(() => {
  const data = parsedRows.value.slice(1, 6)
  return data.map((row, i) => {
    const obj: Record<string, string> = { _idx: String(i) }
    csvHeaders.value.forEach((h, ci) => { obj[h] = row[ci] ?? '' })
    return obj
  })
})

/** Auto-detect which fields have a matching header and enable their checkboxes. */
function autoDetectFields() {
  const lower = csvHeaders.value.map(h => h.trim().toLowerCase())
  for (const f of ALL_FIELDS) {
    fields.value[f.key] = f.required || lower.includes(f.key)
  }
}

// ---------------------------------------------------------------------------
// Step navigation
// ---------------------------------------------------------------------------
function goToConfigure() {
  autoDetectFields()
  step.value = 'configure'
}

function goBack() {
  step.value = 'input'
  importDone.value = false
  importedCount.value = 0
  importErrors.value = []
}

// ---------------------------------------------------------------------------
// File upload
// ---------------------------------------------------------------------------
function triggerFileOpen() {
  fileRef.value?.click()
}

async function onFileChange(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  csvText.value = await file.text()
  // Reset the input so the same file can be re-selected
  input.value = ''
  if (csvText.value.trim()) goToConfigure()
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------
async function bearerHeaders(): Promise<HeadersInit> {
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

async function runImport() {
  importing.value = true
  importDone.value = false
  importErrors.value = []
  importedCount.value = 0

  try {
    const headers = await bearerHeaders()
    const res = await fetch(
      `${config.apiBase}/collections/${props.collectionId}/assets/import`,
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          csv: csvText.value,
          fields: { ...fields.value },
          delimiter: delimiter.value.value
        })
      }
    )
    if (!res.ok) {
      const text = await res.text()
      importErrors.value = [`HTTP ${res.status}: ${text}`]
    } else {
      const data = await res.json() as { imported: number; errors: string[] }
      importedCount.value = data.imported
      importErrors.value = data.errors ?? []
      importDone.value = true
      if (data.imported > 0) emit('imported')
    }
  } catch (e) {
    importErrors.value = [(e as Error).message]
  } finally {
    importing.value = false
  }
}

// ---------------------------------------------------------------------------
// Reset / close
// ---------------------------------------------------------------------------
function reset() {
  step.value = 'input'
  csvText.value = ''
  delimiter.value = DELIMITER_OPTIONS[0]
  fields.value = { name: true, fqdn: false, ip: false, mac: false, description: false, stigs: false }
  importing.value = false
  importDone.value = false
  importedCount.value = 0
  importErrors.value = []
}

function close() {
  if (importing.value) return
  reset()
  emit('update:visible', false)
}

// Reset internal state whenever the dialog is re-opened
watch(() => props.visible, (v) => { if (v) reset() })
</script>

<template>
  <Dialog
    :visible="visible"
    header="Import Assets from CSV"
    modal
    :style="{ width: '52rem', maxWidth: '95vw' }"
    :closable="!importing"
    @update:visible="(_v) => { if (!importing) close() }"
  >
    <!-- ------------------------------------------------------------------ -->
    <!-- Step 1 — Paste or upload CSV                                        -->
    <!-- ------------------------------------------------------------------ -->
    <div v-if="step === 'input'" class="step-body">
      <p class="hint">
        Paste CSV text below or upload a <code>.csv</code> file.
        The first row must be a header row with column names matching:
        <code>name</code>, <code>fqdn</code>, <code>ip</code>,
        <code>mac</code>, <code>description</code>, <code>stigs</code>.
        STIGs column should contain pipe-delimited benchmark IDs
        (e.g. <code>MS_Windows_10_STIG|Ubuntu_20-04_LTS_STIG</code>).
      </p>

      <div class="upload-row">
        <input
          ref="fileRef"
          type="file"
          accept=".csv,text/csv"
          style="display:none"
          @change="onFileChange"
        />
        <Button
          label="Upload .csv File"
          icon="pi pi-upload"
          severity="secondary"
          size="small"
          @click="triggerFileOpen"
        />
      </div>

      <Textarea
        v-model="csvText"
        placeholder="name,fqdn,ip,mac,stigs&#10;web-server-01,web01.corp.local,10.0.0.1,,MS_Windows_Server_2019_STIG"
        :rows="10"
        style="width: 100%; font-family: monospace; font-size: 0.82rem"
        autoResize
      />
    </div>

    <!-- ------------------------------------------------------------------ -->
    <!-- Step 2 — Configure fields + preview                                 -->
    <!-- ------------------------------------------------------------------ -->
    <div v-else class="step-body">

      <!-- Field checkboxes + delimiter selector -->
      <div class="config-row">
        <div class="field-checks">
          <span class="config-label">Import columns:</span>
          <div
            v-for="f in ALL_FIELDS"
            :key="f.key"
            class="check-item"
          >
            <Checkbox
              v-model="fields[f.key]"
              :inputId="`csv-field-${f.key}`"
              :binary="true"
              :disabled="f.required"
            />
            <label :for="`csv-field-${f.key}`" :class="{ 'req-label': f.required }">
              {{ f.label }}<span v-if="f.required" class="req"> *</span>
            </label>
          </div>
        </div>

        <div class="delimiter-group">
          <span class="config-label">Delimiter:</span>
          <Select
            v-model="delimiter"
            :options="DELIMITER_OPTIONS"
            optionLabel="label"
            style="min-width: 13rem"
          />
        </div>
      </div>

      <!-- Preview table (first 5 data rows) -->
      <div v-if="previewRows.length" class="preview-section">
        <p class="config-label" style="margin-bottom: 0.4rem">
          Preview — first {{ previewRows.length }} of
          {{ parsedRows.length - 1 }} data row(s):
        </p>
        <DataTable
          :value="previewRows"
          class="p-datatable-sm"
          responsiveLayout="scroll"
          style="font-size: 0.82rem"
        >
          <Column
            v-for="h in csvHeaders"
            :key="h"
            :field="h"
            :header="h"
            style="min-width: 8rem; max-width: 14rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap"
          />
        </DataTable>
      </div>
      <p v-else class="muted">No data rows detected. Check your delimiter selection.</p>

      <!-- Import result -->
      <div v-if="importDone" class="result-box" :class="importErrors.length ? 'result-warn' : 'result-ok'">
        <span class="result-summary">
          {{ importedCount }} asset{{ importedCount !== 1 ? 's' : '' }} imported
          <span v-if="importErrors.length">, {{ importErrors.length }} error{{ importErrors.length !== 1 ? 's' : '' }}</span>
        </span>
        <ul v-if="importErrors.length" class="error-list">
          <li v-for="(err, i) in importErrors" :key="i">{{ err }}</li>
        </ul>
      </div>
      <div v-else-if="importErrors.length" class="result-box result-err">
        <ul class="error-list">
          <li v-for="(err, i) in importErrors" :key="i">{{ err }}</li>
        </ul>
      </div>
    </div>

    <!-- ------------------------------------------------------------------ -->
    <!-- Footer                                                               -->
    <!-- ------------------------------------------------------------------ -->
    <template #footer>
      <template v-if="step === 'input'">
        <Button label="Cancel" severity="secondary" text :disabled="importing" @click="close" />
        <Button
          label="Next"
          icon="pi pi-arrow-right"
          iconPos="right"
          :disabled="!csvText.trim()"
          @click="goToConfigure"
        />
      </template>
      <template v-else>
        <Button label="Cancel" severity="secondary" text :disabled="importing" @click="close" />
        <Button label="Back" icon="pi pi-arrow-left" severity="secondary" text :disabled="importing" @click="goBack" />
        <Button
          :label="importDone ? 'Import Again' : 'Import'"
          icon="pi pi-check"
          :loading="importing"
          :disabled="importing || parsedRows.length < 2"
          @click="runImport"
        />
      </template>
    </template>
  </Dialog>
</template>

<style scoped>
.step-body {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
  padding: 0.25rem 0;
}

.hint {
  font-size: 0.85rem;
  color: var(--p-text-muted-color, #8b949e);
  margin: 0;
  line-height: 1.5;
}

.upload-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

/* Config row — checkboxes left, delimiter right */
.config-row {
  display: flex;
  align-items: flex-start;
  gap: 2rem;
  flex-wrap: wrap;
}

.config-label {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--p-text-muted-color, #8b949e);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 0.4rem;
  display: block;
}

.field-checks {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.check-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
}

.req { color: #f85149; }
.req-label { font-weight: 500; }

.delimiter-group {
  display: flex;
  flex-direction: column;
}

.preview-section {
  overflow-x: auto;
}

/* Result boxes */
.result-box {
  border-radius: 4px;
  padding: 0.65rem 0.9rem;
  font-size: 0.88rem;
}
.result-ok   { background: rgba(63, 185, 80, 0.12); border-left: 3px solid #3fb950; }
.result-warn { background: rgba(210, 153, 34, 0.12); border-left: 3px solid #d29922; }
.result-err  { background: rgba(248, 81, 73, 0.10); border-left: 3px solid #f85149; }

.result-summary { font-weight: 600; }

.error-list {
  margin: 0.4rem 0 0 1rem;
  padding: 0;
  font-family: monospace;
  font-size: 0.8rem;
  color: #f85149;
  max-height: 8rem;
  overflow-y: auto;
}
</style>
