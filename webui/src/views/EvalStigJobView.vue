<script setup lang="ts">
import { onMounted, onUnmounted, ref, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Card from 'primevue/card'
import Message from 'primevue/message'
import Toast from 'primevue/toast'
import type { EvalStigJob } from '../api/types'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'

// ── Props ─────────────────────────────────────────────────────────────────────
const props = defineProps<{ jobId: string }>()

// ── State ─────────────────────────────────────────────────────────────────────
const router = useRouter()

const job = ref<EvalStigJob | null>(null)
const loading = ref(true)
const error = ref('')
const logLines = ref<string[]>([])
const logContainer = ref<HTMLDivElement | null>(null)
let eventSource: EventSource | null = null

// ── Auth helper ───────────────────────────────────────────────────────────────
async function authHeaders(): Promise<HeadersInit> {
  const token = await getAccessToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

// ── Scroll to bottom ──────────────────────────────────────────────────────────
async function scrollLog() {
  await nextTick()
  if (logContainer.value) {
    logContainer.value.scrollTop = logContainer.value.scrollHeight
  }
}

// ── Load job ──────────────────────────────────────────────────────────────────
async function loadJob() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch(`${config.apiBase}/eval-stig/jobs/${props.jobId}`, {
      headers: await authHeaders()
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    job.value = await res.json()
  } catch (e) {
    error.value = `Failed to load job: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

// ── SSE streaming ─────────────────────────────────────────────────────────────
async function connectStream() {
  const token = await getAccessToken()
  // EventSource doesn't support custom headers; pass token as query param if needed
  const url = new URL(`${config.apiBase}/eval-stig/jobs/${props.jobId}/stream`)
  if (token) url.searchParams.set('token', token)

  eventSource = new EventSource(url.toString())

  eventSource.addEventListener('log', (e: MessageEvent) => {
    logLines.value.push(e.data)
    scrollLog()
  })

  eventSource.addEventListener('status', (e: MessageEvent) => {
    if (job.value) {
      try {
        const update = JSON.parse(e.data)
        job.value = { ...job.value, ...update }
        // If terminal state reached, close stream
        if (update.status === 'completed' || update.status === 'failed' || update.status === 'cancelled') {
          eventSource?.close()
          eventSource = null
        }
      } catch { /* ignore parse errors */ }
    }
  })

  eventSource.onerror = () => {
    // Connection lost or closed — close cleanly
    eventSource?.close()
    eventSource = null
  }
}

// ── Load historic log (completed/failed) ─────────────────────────────────────
async function loadHistoricLog() {
  try {
    const res = await fetch(`${config.apiBase}/eval-stig/jobs/${props.jobId}/log?limit=500`, {
      headers: await authHeaders()
    })
    if (res.ok) {
      const text = await res.text()
      logLines.value = text.split('\n').filter(l => l.length > 0)
      scrollLog()
    }
  } catch { /* ignore */ }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
onMounted(async () => {
  await loadJob()
  if (!job.value) return

  if (job.value.status === 'pending' || job.value.status === 'running') {
    await connectStream()
  } else {
    await loadHistoricLog()
  }
})

onUnmounted(() => {
  eventSource?.close()
  eventSource = null
})

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  try {
    return new Intl.DateTimeFormat(undefined, {
      month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(new Date(iso))
  } catch { return iso }
}

function statusSeverity(s: string): 'warn' | 'info' | 'success' | 'danger' | 'secondary' {
  switch (s) {
    case 'pending':   return 'warn'
    case 'running':   return 'info'
    case 'completed': return 'success'
    case 'failed':    return 'danger'
    default:          return 'secondary'
  }
}
</script>

<template>
  <Toast />

  <section class="job-root">
    <!-- Breadcrumb -->
    <div class="breadcrumb">
      <Button
        icon="pi pi-arrow-left"
        label="Eval STIG Jobs"
        text
        size="small"
        @click="router.push('/eval-stig')"
      />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <div v-if="loading && !job" class="loading-msg">
      <i class="pi pi-spin pi-spinner" /> Loading job...
    </div>

    <template v-if="job">
      <!-- Header Card -->
      <Card class="header-card">
        <template #content>
          <div class="job-header">
            <div class="job-title-row">
              <h2 class="job-title">Job #{{ job.jobId }}</h2>
              <Tag
                :value="job.status"
                :severity="statusSeverity(job.status)"
                :class="{ 'status-running': job.status === 'running' }"
                style="font-size: 0.85rem"
              />
            </div>
            <div class="job-meta">
              <span class="meta-item">
                <span class="meta-label">Collection:</span>
                <span class="meta-value">{{ job.collectionId }}</span>
              </span>
              <span class="meta-item">
                <span class="meta-label">Started:</span>
                <span class="meta-value mono-date">{{ fmtDate(job.startedAt) }}</span>
              </span>
              <span class="meta-item">
                <span class="meta-label">Completed:</span>
                <span class="meta-value mono-date">{{ fmtDate(job.completedAt) }}</span>
              </span>
              <span class="meta-item">
                <span class="meta-label">Submitted by:</span>
                <span class="meta-value">{{ job.createdBy }}</span>
              </span>
            </div>
          </div>
        </template>
      </Card>

      <!-- Details Row -->
      <Card class="details-card">
        <template #content>
          <div class="details-grid">
            <div class="detail-section">
              <div class="detail-label">Target Hosts</div>
              <div class="tag-wrap">
                <Tag
                  v-for="h in job.targetHosts"
                  :key="h"
                  :value="h"
                  severity="secondary"
                  class="host-tag"
                />
              </div>
            </div>

            <div class="detail-section">
              <div class="detail-label">STIGs</div>
              <div v-if="!job.selectedStigs" class="muted">All applicable STIGs</div>
              <div v-else class="tag-wrap">
                <Tag
                  v-for="s in job.selectedStigs"
                  :key="s"
                  :value="s"
                  severity="info"
                  class="stig-tag"
                />
              </div>
            </div>

            <div class="detail-section">
              <div class="detail-label">Output Path</div>
              <code class="output-path">{{ job.outputPath }}</code>
            </div>
          </div>
        </template>
      </Card>

      <!-- Import success banner -->
      <Message
        v-if="job.importedCount > 0"
        severity="success"
        :closable="false"
        class="import-banner"
      >
        <i class="pi pi-check-circle" style="margin-right: 0.4rem" />
        {{ job.importedCount }} checklist{{ job.importedCount !== 1 ? 's' : '' }} imported into collection
        <Button
          :label="`View Collection ${job.collectionId}`"
          text
          size="small"
          style="margin-left: 0.5rem"
          @click="router.push(`/collections/${job.collectionId}`)"
        />
      </Message>

      <!-- Error banner -->
      <Message
        v-if="job.status === 'failed' && job.errorMsg"
        severity="error"
        :closable="false"
        class="import-banner"
      >
        <i class="pi pi-times-circle" style="margin-right: 0.4rem" />
        {{ job.errorMsg }}
      </Message>

      <!-- Log Viewer -->
      <div class="log-section">
        <div class="log-toolbar">
          <span class="log-title">Scan Log</span>
          <span v-if="job.status === 'running'" class="live-indicator">
            <span class="live-dot" />
            Live — streaming
          </span>
          <span v-else-if="job.status === 'completed'" class="done-indicator success">
            <i class="pi pi-check" /> Scan completed
          </span>
          <span v-else-if="job.status === 'failed'" class="done-indicator danger">
            <i class="pi pi-times" /> Scan failed
          </span>
        </div>

        <div ref="logContainer" class="log-viewer">
          <pre class="log-pre">{{ logLines.join('\n') || (job.status === 'pending' ? 'Waiting for agent to pick up job...' : '') }}</pre>
        </div>
      </div>
    </template>
  </section>
</template>

<style scoped>
.job-root    { padding: 0.5rem 1rem 3rem; max-width: 1100px; }

.breadcrumb  { margin-bottom: 0.75rem; }

.err         { color: #f85149; margin-bottom: 0.75rem; }
.muted       { color: var(--p-text-muted-color, #6b7280); }
.mono-date   { font-variant-numeric: tabular-nums; }

.loading-msg {
  color: var(--p-text-muted-color, #6b7280);
  padding: 2rem;
  text-align: center;
}

/* Header card */
.header-card  { margin-bottom: 1rem; }

.job-header       { display: flex; flex-direction: column; gap: 0.5rem; }
.job-title-row    { display: flex; align-items: center; gap: 0.75rem; }
.job-title        { margin: 0; font-size: 1.25rem; }
.job-meta         { display: flex; flex-wrap: wrap; gap: 1.25rem; font-size: 0.875rem; }
.meta-item        { display: flex; gap: 0.35rem; align-items: center; }
.meta-label       { color: var(--p-text-muted-color, #6b7280); }
.meta-value       { font-weight: 500; }

/* Details card */
.details-card { margin-bottom: 1rem; }
.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.25rem;
}
.detail-section { display: flex; flex-direction: column; gap: 0.4rem; }
.detail-label   { font-size: 0.78rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--p-text-muted-color, #6b7280); }

.tag-wrap  { display: flex; flex-wrap: wrap; gap: 0.25rem; }
.host-tag  { font-size: 0.75rem; }
.stig-tag  { font-size: 0.72rem; max-width: 18ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.output-path {
  font-size: 0.82rem;
  font-family: monospace;
  background: var(--p-surface-100, #f3f4f6);
  padding: 0.2rem 0.45rem;
  border-radius: 4px;
  word-break: break-all;
}

.import-banner { margin-bottom: 1rem; }

/* Log viewer */
.log-section { margin-top: 0.5rem; }

.log-toolbar {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.4rem 0.75rem;
  background: var(--p-surface-800, #1e293b);
  border-radius: 6px 6px 0 0;
  border-bottom: 1px solid var(--p-surface-600, #334155);
}

.log-title {
  font-size: 0.82rem;
  font-weight: 600;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.live-indicator {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.78rem;
  color: #f87171;
}

.live-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: #f87171;
  animation: pulse-dot 1.2s ease-in-out infinite;
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.4; transform: scale(0.8); }
}

.done-indicator {
  font-size: 0.78rem;
  display: flex;
  align-items: center;
  gap: 0.3rem;
}
.done-indicator.success { color: #4ade80; }
.done-indicator.danger  { color: #f87171; }

.log-viewer {
  height: 500px;
  overflow-y: auto;
  background: var(--p-surface-900, #0f172a);
  border-radius: 0 0 6px 6px;
  padding: 0.75rem 1rem;
}

.log-pre {
  margin: 0;
  font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
  font-size: 0.82rem;
  line-height: 1.55;
  color: #e2e8f0;
  white-space: pre-wrap;
  word-break: break-all;
}

/* Pulse for running status tag */
.status-running { animation: pulse 1.5s infinite; }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.5; }
}
</style>
