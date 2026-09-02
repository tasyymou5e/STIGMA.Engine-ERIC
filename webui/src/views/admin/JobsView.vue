<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'
import Toast from 'primevue/toast'

// ── Types ─────────────────────────────────────────────────────────────────────
interface ServiceJob {
  jobId:        string
  name:         string
  description?: string
  tasks?:       string[]
  status:       string
  lastRun:      string | null
  nextRun:      string | null
  enabled?:     boolean
  collectionId?: number
  config?:      Record<string, unknown>
}

interface RunResult {
  jobId:   string
  jobName: string
  ts:      string
  data:    Record<string, unknown>
}

// ── State ─────────────────────────────────────────────────────────────────────
// Use Record<string,boolean> instead of Set — Vue tracks property changes reliably.
const running      = ref<Record<string, boolean>>({})
// Client-side last-run timestamps updated immediately on success (backend doesn't persist).
const lastRunAt    = ref<Record<string, string>>({})
const jobs         = ref<ServiceJob[]>([])
const loading      = ref(true)
const error        = ref('')
const lastResults  = ref<RunResult[]>([])
const toast        = useToast()

// ── Auth helper ───────────────────────────────────────────────────────────────
async function getToken(): Promise<string | null> {
  const { getAccessToken } = await import('../../auth/oidc')
  return getAccessToken()
}

// ── Load jobs ─────────────────────────────────────────────────────────────────
async function loadJobs() {
  loading.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const token = await getToken()
    // GET — no Content-Type header (no body, avoids Fastify JSON body-parser issues)
    const res = await fetch(`${config.apiBase}/jobs`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
    jobs.value = await res.json()
  } catch (e) {
    error.value = `Failed to load jobs: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

onMounted(loadJobs)

// ── Run a job ─────────────────────────────────────────────────────────────────
async function runNow(job: ServiceJob) {
  if (running.value[job.jobId]) return
  // Spread-assign to guarantee Vue picks up the change (reactive property addition)
  running.value = { ...running.value, [job.jobId]: true }

  try {
    const { config } = await import('../../config')
    const token = await getToken()
    const res = await fetch(
      `${config.apiBase}/jobs/${encodeURIComponent(job.jobId)}/run`,
      {
        method: 'POST',
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          'Content-Type': 'application/json'  // required — Fastify body parser
        },
        body: '{}'   // empty JSON object — avoids FST_ERR_CTP_EMPTY_JSON_BODY
      }
    )
    const data = await res.json().catch(() => ({})) as Record<string, unknown>
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${String(data.error ?? JSON.stringify(data))}`)

    // Record the server-side Date header as the last-run timestamp
    const ts = res.headers.get('date') ?? ''
    lastRunAt.value = { ...lastRunAt.value, [job.jobId]: ts }
    lastResults.value = [
      { jobId: job.jobId, jobName: job.name, ts, data },
      ...lastResults.value.slice(0, 9)
    ]
    toast.add({
      severity: 'success',
      summary:  'Job complete',
      detail:   `${job.name}: ${formatSummary(data)}`,
      life:     5000
    })
    setTimeout(loadJobs, 1200)
  } catch (e) {
    toast.add({
      severity: 'error',
      summary:  'Run failed',
      detail:   (e as Error).message,
      life:     6000
    })
  } finally {
    const next = { ...running.value }
    delete next[job.jobId]
    running.value = next
  }
}

// ── Formatting helpers ────────────────────────────────────────────────────────
function formatSummary(d: Record<string, unknown>): string {
  const parts: string[] = []
  if (typeof d.deletedCollections === 'number') parts.push(`${d.deletedCollections} collections removed`)
  if (typeof d.deletedAssets      === 'number') parts.push(`${d.deletedAssets} assets removed`)
  if (typeof d.deletedReviews     === 'number') parts.push(`${d.deletedReviews} reviews removed`)
  if (typeof d.deleted            === 'number') parts.push(`${d.deleted} records deleted`)
  if (typeof d.affected           === 'number') parts.push(`${d.affected} rows affected`)
  if (d.message && parts.length === 0) return String(d.message)
  return parts.length ? parts.join(', ') : 'Done.'
}

function formatResultJson(d: Record<string, unknown>): string {
  const { message, ...rest } = d
  const lines: string[] = []
  if (message) lines.push(String(message))
  for (const [k, v] of Object.entries(rest)) lines.push(`  ${k}: ${JSON.stringify(v)}`)
  return lines.join('\n')
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  try {
    return new Intl.DateTimeFormat(undefined, {
      month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(new Date(iso))
  } catch { return iso }
}

function statusSev(s: string): 'success' | 'warn' | 'danger' | 'secondary' {
  if (s === 'running')  return 'warn'
  if (s === 'error')    return 'danger'
  if (s === 'disabled') return 'secondary'
  return 'success'   // idle
}

function statusLabel(s: string): string {
  if (s === 'running')  return 'Running'
  if (s === 'error')    return 'Error'
  if (s === 'disabled') return 'Disabled'
  return 'Idle'
}
</script>

<template>
  <Toast />

  <section class="jobs-root">
    <!-- Header -->
    <div class="jobs-header">
      <div>
        <h2 class="jobs-title">Service Jobs</h2>
        <p class="jobs-subtitle muted">
          System maintenance tasks — clean up orphaned data, enforce review aging rules,
          and optimize database performance. Requires admin role.
        </p>
      </div>
      <Button
        label="Refresh"
        icon="pi pi-refresh"
        severity="secondary"
        outlined
        size="small"
        :loading="loading"
        @click="loadJobs"
      />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <!-- Jobs table -->
    <DataTable
      :value="jobs"
      :loading="loading"
      dataKey="jobId"
      stripedRows
      responsiveLayout="scroll"
    >
      <template #empty>
        <div class="empty-msg">
          <i class="pi pi-cog empty-icon" />
          <p>No service jobs found.</p>
        </div>
      </template>

      <!-- Name + description -->
      <Column field="name" header="Job" sortable style="min-width: 16rem">
        <template #body="{ data }">
          <div>
            <span class="job-name">{{ data.name }}</span>
            <p v-if="data.description" class="job-desc muted">{{ data.description }}</p>
          </div>
        </template>
      </Column>

      <!-- Task chips -->
      <Column header="Tasks" style="min-width: 20rem">
        <template #body="{ data }">
          <div v-if="data.tasks && data.tasks.length" class="task-chips">
            <span v-for="t in data.tasks" :key="t" class="task-chip">{{ t }}</span>
          </div>
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <!-- Status -->
      <Column header="Status" style="width: 8rem; text-align: center">
        <template #body="{ data }">
          <Tag
            :value="running[data.jobId] ? 'Running' : statusLabel(data.status)"
            :severity="running[data.jobId] ? 'warn' : statusSev(data.status)"
          />
        </template>
      </Column>

      <!-- Last run — uses local timestamp updated on success -->
      <Column header="Last Run" style="width: 13rem">
        <template #body="{ data }">
          <span class="mono-date">{{ fmtDate(lastRunAt[data.jobId] ?? data.lastRun) }}</span>
        </template>
      </Column>

      <!-- Run Now -->
      <Column header="" style="width: 9rem; text-align: right">
        <template #body="{ data }">
          <Button
            label="Run Now"
            icon="pi pi-play"
            size="small"
            severity="secondary"
            outlined
            :loading="running[data.jobId] === true"
            :disabled="running[data.jobId] === true || data.status === 'disabled' || data.enabled === false"
            @click="runNow(data)"
          />
        </template>
      </Column>
    </DataTable>

    <!-- Recent run results -->
    <section v-if="lastResults.length" class="results-section">
      <h3 class="results-title">Recent Run Results</h3>
      <div
        v-for="r in lastResults"
        :key="r.ts + r.jobId"
        class="result-card"
      >
        <div class="result-header">
          <span class="result-job">{{ r.jobName }}</span>
          <span class="result-ts muted">{{ fmtDate(r.ts) }}</span>
        </div>
        <pre class="result-body">{{ formatResultJson(r.data) }}</pre>
      </div>
    </section>
  </section>
</template>

<style scoped>
.jobs-root     { padding: 0.5rem 1rem 3rem; max-width: 1100px; }
.jobs-header   { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1.25rem; }
.jobs-title    { margin: 0 0 0.25rem; }
.jobs-subtitle { margin: 0; font-size: 0.875rem; }

.err   { color: #f85149; margin-bottom: 0.75rem; }
.muted { color: var(--p-text-muted-color, #6b7280); }

.job-name  { font-weight: 600; }
.job-desc  { margin: 0.2rem 0 0; font-size: 0.8rem; }

.task-chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
.task-chip  {
  background: var(--p-surface-100, #f3f4f6);
  color: var(--p-text-color, #111827);
  border-radius: 4px;
  padding: 0.1rem 0.5rem;
  font-size: 0.75rem;
  font-family: monospace;
  white-space: nowrap;
}

.mono-date { font-size: 0.85rem; font-variant-numeric: tabular-nums; }

.empty-msg  { display: flex; flex-direction: column; align-items: center; gap: 0.5rem; padding: 2.5rem 1rem; color: var(--p-text-muted-color, #6b7280); }
.empty-icon { font-size: 2.5rem; opacity: 0.35; }

/* Results section */
.results-section { margin-top: 2rem; }
.results-title   { margin: 0 0 0.75rem; font-size: 1rem; font-weight: 600; }

.result-card {
  border: 1px solid var(--p-surface-200, #e5e7eb);
  border-radius: 6px;
  margin-bottom: 0.75rem;
  overflow: hidden;
}

.result-header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 0.45rem 0.75rem;
  background: var(--p-surface-50, #f9fafb);
  border-bottom: 1px solid var(--p-surface-200, #e5e7eb);
  gap: 1rem;
}

.result-job { font-weight: 600; font-size: 0.875rem; }
.result-ts  { font-size: 0.8rem; font-variant-numeric: tabular-nums; }

.result-body {
  margin: 0; padding: 0.6rem 0.75rem;
  font-size: 0.82rem; font-family: monospace;
  white-space: pre-wrap; word-break: break-all;
  background: var(--p-surface-0, #fff);
  color: var(--p-text-color, #111);
  line-height: 1.5;
}
</style>
