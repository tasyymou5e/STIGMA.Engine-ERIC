<script setup lang="ts">
import { ref } from 'vue'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import FileUpload, { type FileUploadSelectEvent } from 'primevue/fileupload'
import ProgressBar from 'primevue/progressbar'
import Tag from 'primevue/tag'
import Select from 'primevue/select'
import Checkbox from 'primevue/checkbox'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'

// ---------------------------------------------------------------------------
// Props / emits
// ---------------------------------------------------------------------------
const props = defineProps<{ collectionId: string; visible: boolean }>()
const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
  (e: 'imported'): void
}>()

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type IngestSource = 'ckl' | 'cklb' | 'xccdf'

interface FileResult {
  name: string
  status: 'pending' | 'processing' | 'success' | 'error'
  message?: string
}

interface ImportOptions {
  autoStatus:   boolean
  unreviewed:   'always' | 'never' | 'preserve'
  emptyDetail:  'ignore' | 'replace'
  emptyComment: 'ignore' | 'replace'
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const fileResults = ref<FileResult[]>([])
const importing = ref(false)
const overallProgress = ref(0)
const selectedFiles = ref<File[]>([])
const optionsExpanded = ref(false)

// Import options (defaults match "no special handling")
const importOptions = ref<ImportOptions>({
  autoStatus:   false,
  unreviewed:   'always',
  emptyDetail:  'replace',
  emptyComment: 'replace'
})

// Select option lists
const unreviewedOptions = [
  { label: 'Always import', value: 'always' },
  { label: 'Never import',  value: 'never'  },
  { label: 'Preserve existing', value: 'preserve' }
]

const emptyFieldOptions = [
  { label: 'Replace existing', value: 'replace' },
  { label: 'Ignore blank',     value: 'ignore'  }
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function detectSource(filename: string): IngestSource {
  const lower = filename.toLowerCase()
  if (lower.endsWith('.cklb')) return 'cklb'
  if (lower.endsWith('.ckl'))  return 'ckl'
  return 'xccdf'
}

async function bearerHeaders(): Promise<HeadersInit> {
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

/** Build endpoint URL based on detected source format. */
function importUrl(source: IngestSource): string {
  return `${config.apiBase}/collections/${props.collectionId}/import/${source}`
}

// ---------------------------------------------------------------------------
// File selection
// ---------------------------------------------------------------------------
function onFilesSelect(e: FileUploadSelectEvent) {
  selectedFiles.value = Array.from(e.files as File[])
  fileResults.value = selectedFiles.value.map(f => ({
    name: f.name,
    status: 'pending'
  }))
  overallProgress.value = 0
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------
async function runImport() {
  if (!selectedFiles.value.length) return
  importing.value = true
  overallProgress.value = 0

  const total = selectedFiles.value.length
  let completed = 0

  for (let i = 0; i < selectedFiles.value.length; i++) {
    const file = selectedFiles.value[i]
    const result = fileResults.value[i]
    result.status = 'processing'

    try {
      const content = await file.text()
      const source = detectSource(file.name)
      const headers = await bearerHeaders()
      const res = await fetch(
        importUrl(source),
        {
          method: 'POST',
          headers,
          body: JSON.stringify({ content, options: importOptions.value })
        }
      )
      if (!res.ok) {
        const text = await res.text()
        result.status = 'error'
        result.message = text || `HTTP ${res.status}`
      } else {
        result.status = 'success'
      }
    } catch (e) {
      result.status = 'error'
      result.message = (e as Error).message
    }

    completed++
    overallProgress.value = Math.round((completed / total) * 100)
  }

  importing.value = false
  const anySuccess = fileResults.value.some(r => r.status === 'success')
  if (anySuccess) emit('imported')
}

// ---------------------------------------------------------------------------
// Reset & close
// ---------------------------------------------------------------------------
function close() {
  if (importing.value) return
  selectedFiles.value = []
  fileResults.value = []
  overallProgress.value = 0
  emit('update:visible', false)
}

function reset() {
  selectedFiles.value = []
  fileResults.value = []
  overallProgress.value = 0
}

// ---------------------------------------------------------------------------
// Computed helpers
// ---------------------------------------------------------------------------
function resultSeverity(status: FileResult['status']): 'success' | 'danger' | 'warn' | 'secondary' {
  switch (status) {
    case 'success':    return 'success'
    case 'error':      return 'danger'
    case 'processing': return 'warn'
    default:           return 'secondary'
  }
}

function resultLabel(status: FileResult['status']): string {
  switch (status) {
    case 'success':    return 'Imported'
    case 'error':      return 'Failed'
    case 'processing': return 'Processing…'
    default:           return 'Pending'
  }
}
</script>

<template>
  <Dialog
    :visible="visible"
    header="Import Checklists"
    modal
    :style="{ width: '42rem' }"
    :closable="!importing"
    @update:visible="(v) => { if (!importing) emit('update:visible', v) }"
  >
    <div class="import-body">
      <!-- File picker -->
      <FileUpload
        mode="advanced"
        :multiple="true"
        accept=".ckl,.cklb,.xml"
        :auto="false"
        :disabled="importing"
        :showUploadButton="false"
        :showCancelButton="false"
        chooseLabel="Choose Files"
        @select="onFilesSelect"
      >
        <template #empty>
          <div class="drop-hint">
            <i class="pi pi-cloud-upload" style="font-size: 2rem; color: var(--p-primary-color, #58a6ff)" />
            <p>Drag &amp; drop <code>.ckl</code>, <code>.cklb</code>, or <code>.xml</code> files here, or click <em>Choose Files</em>.</p>
          </div>
        </template>
      </FileUpload>

      <!-- Import Options (collapsible) -->
      <div class="options-section">
        <button
          type="button"
          class="options-toggle"
          :disabled="importing"
          @click="optionsExpanded = !optionsExpanded"
          :aria-expanded="optionsExpanded"
        >
          <i :class="optionsExpanded ? 'pi pi-chevron-down' : 'pi pi-chevron-right'" class="toggle-icon" />
          Import Options
        </button>

        <div v-if="optionsExpanded" class="options-grid">
          <!-- autoStatus -->
          <div class="option-row">
            <Checkbox
              v-model="importOptions.autoStatus"
              inputId="opt-auto-status"
              :binary="true"
              :disabled="importing"
            />
            <label for="opt-auto-status" class="option-label">
              Auto-submit reviews
              <span class="option-hint">Set status to Submitted for pass / fail / N/A results</span>
            </label>
          </div>

          <!-- unreviewed -->
          <div class="option-row option-row--select">
            <label class="option-label">
              Not-checked results
              <span class="option-hint">How to handle rules with no result recorded</span>
            </label>
            <Select
              v-model="importOptions.unreviewed"
              :options="unreviewedOptions"
              optionLabel="label"
              optionValue="value"
              :disabled="importing"
              class="option-select"
            />
          </div>

          <!-- emptyDetail -->
          <div class="option-row option-row--select">
            <label class="option-label">
              Blank detail
              <span class="option-hint">What to do when imported finding detail is empty</span>
            </label>
            <Select
              v-model="importOptions.emptyDetail"
              :options="emptyFieldOptions"
              optionLabel="label"
              optionValue="value"
              :disabled="importing"
              class="option-select"
            />
          </div>

          <!-- emptyComment -->
          <div class="option-row option-row--select">
            <label class="option-label">
              Blank comment
              <span class="option-hint">What to do when imported comment is empty</span>
            </label>
            <Select
              v-model="importOptions.emptyComment"
              :options="emptyFieldOptions"
              optionLabel="label"
              optionValue="value"
              :disabled="importing"
              class="option-select"
            />
          </div>
        </div>
      </div>

      <!-- Progress bar (shown while importing) -->
      <div v-if="importing" class="progress-section">
        <ProgressBar :value="overallProgress" style="height: 0.6rem; margin-top: 0.75rem" />
        <p class="muted progress-label">{{ overallProgress }}% — processing {{ selectedFiles.length }} file(s)…</p>
      </div>

      <!-- Per-file results -->
      <div v-if="fileResults.length" class="results-list">
        <div
          v-for="r in fileResults"
          :key="r.name"
          class="result-row"
        >
          <Tag
            :value="resultLabel(r.status)"
            :severity="resultSeverity(r.status)"
            class="result-tag"
          />
          <span class="file-name" :title="r.name">{{ r.name }}</span>
          <span v-if="r.message" class="err-msg muted" :title="r.message">{{ r.message }}</span>
        </div>
      </div>
    </div>

    <template #footer>
      <Button
        label="Reset"
        icon="pi pi-refresh"
        severity="secondary"
        text
        :disabled="importing || !fileResults.length"
        @click="reset"
      />
      <Button
        label="Cancel"
        severity="secondary"
        text
        :disabled="importing"
        @click="close"
      />
      <Button
        label="Import"
        icon="pi pi-upload"
        :loading="importing"
        :disabled="!selectedFiles.length || importing"
        @click="runImport"
      />
    </template>
  </Dialog>
</template>

<style scoped>
.import-body { display: flex; flex-direction: column; gap: 0.75rem; }

.drop-hint {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.4rem;
  padding: 1.25rem 0;
  text-align: center;
  color: var(--p-text-muted-color, #8b949e);
}
.drop-hint p { margin: 0; font-size: 0.875rem; }

/* Options section */
.options-section {
  border: 1px solid var(--p-surface-border, #30363d);
  border-radius: 6px;
  overflow: hidden;
}

.options-toggle {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  width: 100%;
  padding: 0.5rem 0.75rem;
  background: var(--p-surface-100, #161b22);
  border: none;
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--p-text-color, #e6edf3);
  text-align: left;
}
.options-toggle:disabled { opacity: 0.5; cursor: default; }
.options-toggle:not(:disabled):hover { background: var(--p-surface-200, #1c2128); }

.toggle-icon { font-size: 0.7rem; }

.options-grid {
  display: flex;
  flex-direction: column;
  gap: 0;
  padding: 0.5rem 0.75rem 0.75rem;
  background: var(--p-surface-0, #0d1117);
}

.option-row {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.45rem 0;
  border-bottom: 1px solid var(--p-surface-border, #21262d);
}
.option-row:last-child { border-bottom: none; }

.option-row--select {
  justify-content: space-between;
  align-items: center;
}

.option-label {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  font-size: 0.85rem;
  color: var(--p-text-color, #e6edf3);
  cursor: pointer;
  flex: 1;
}

.option-hint {
  font-size: 0.75rem;
  color: var(--p-text-muted-color, #8b949e);
  font-weight: 400;
  cursor: default;
}

.option-select { width: 14rem; flex-shrink: 0; font-size: 0.85rem; }

.progress-section { margin-top: 0.25rem; }
.progress-label { margin: 0.35rem 0 0; font-size: 0.8rem; }

.results-list {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  max-height: 14rem;
  overflow-y: auto;
  padding: 0.25rem 0;
}

.result-row {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  min-height: 1.75rem;
}

.result-tag { flex-shrink: 0; min-width: 6.5rem; text-align: center; }

.file-name {
  flex: 1;
  font-family: monospace;
  font-size: 0.85rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.err-msg {
  font-size: 0.78rem;
  max-width: 14rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #f85149;
}
</style>
