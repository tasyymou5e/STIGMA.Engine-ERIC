<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import Button from 'primevue/button'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'
import Tag from 'primevue/tag'
import ToggleButton from 'primevue/togglebutton'
import { useToast } from 'primevue/usetoast'
import Toast from 'primevue/toast'
import { config } from '../../config'
import { getAccessToken } from '../../auth/oidc'

// ── Types ──────────────────────────────────────────────────────────────────────
interface LogEntry {
  ts:       string
  level:    'debug' | 'info' | 'warn' | 'error'
  category: string
  msg:      string
  data?:    Record<string, unknown>
  err?:     string
  ms?:      number
  userId?:  string
}

// ── State ──────────────────────────────────────────────────────────────────────
const toast        = useToast()
const entries      = ref<LogEntry[]>([])
const streaming    = ref(true)
const paused       = ref(false)
const filterLevel  = ref<string>('')
const filterCat    = ref<string>('')
const filterSearch = ref<string>('')
const logContainer = ref<HTMLElement | null>(null)
const autoScroll   = ref(true)
const loading      = ref(false)

let evtSource: EventSource | null = null

// ── Options ────────────────────────────────────────────────────────────────────
const levelOptions = [
  { label: 'All Levels', value: '' },
  { label: 'Info',       value: 'info'  },
  { label: 'Warn',       value: 'warn'  },
  { label: 'Error',      value: 'error' },
  { label: 'Debug',      value: 'debug' },
]

const catOptions = [
  { label: 'All Categories', value: '' },
  { label: 'API',        value: 'api'       },
  { label: 'Auth',       value: 'auth'      },
  { label: 'System',     value: 'system'    },
  { label: 'Import',     value: 'import'    },
  { label: 'Review',     value: 'review'    },
  { label: 'Export',     value: 'export'    },
  { label: 'Eval-STIG',  value: 'eval-stig' },
  { label: 'Metrics',    value: 'metrics'   },
  { label: 'DB',         value: 'db'        },
  { label: 'Job',        value: 'job'       },
  { label: 'STIG',       value: 'stig'      },
]

// ── Filtered view ──────────────────────────────────────────────────────────────
const visible = computed(() => {
  let list = entries.value
  if (filterLevel.value)  list = list.filter(e => e.level    === filterLevel.value)
  if (filterCat.value)    list = list.filter(e => e.category === filterCat.value)
  if (filterSearch.value) {
    const q = filterSearch.value.toLowerCase()
    list = list.filter(e => JSON.stringify(e).toLowerCase().includes(q))
  }
  return list
})

const errorCount = computed(() => entries.value.filter(e => e.level === 'error').length)
const warnCount  = computed(() => entries.value.filter(e => e.level === 'warn').length)

// ── Helpers ────────────────────────────────────────────────────────────────────
async function authHeader(): Promise<Record<string, string>> {
  const tok = await getAccessToken()
  return tok ? { Authorization: `Bearer ${tok}` } : {}
}

function levelSeverity(level: string) {
  return level === 'error' ? 'danger' : level === 'warn' ? 'warn' : level === 'debug' ? 'secondary' : 'info'
}

function fmtTime(ts: string) {
  return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })
}

function fmtDate(ts: string) {
  return new Date(ts).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit' })
}

function catColor(cat: string) {
  const map: Record<string, string> = {
    api: '#3b82f6', auth: '#8b5cf6', system: '#6b7280', import: '#10b981',
    review: '#f59e0b', export: '#06b6d4', 'eval-stig': '#ef4444',
    metrics: '#84cc16', db: '#f97316', job: '#ec4899', stig: '#14b8a6',
  }
  return map[cat] ?? '#9ca3af'
}

async function scrollBottom() {
  if (!autoScroll.value) return
  await nextTick()
  if (logContainer.value) {
    logContainer.value.scrollTop = logContainer.value.scrollHeight
  }
}

// ── SSE stream ─────────────────────────────────────────────────────────────────
async function startStream() {
  stopStream()
  streaming.value = true
  const tok = await getAccessToken()
  const params = new URLSearchParams()
  if (tok) params.set('token', tok)   // fallback — nginx may strip Auth header on SSE

  const url = `${config.apiBase}/op/logs/stream?${params}`
  evtSource = new EventSource(url)

  evtSource.onmessage = (e) => {
    if (paused.value) return
    try {
      const entry: LogEntry = JSON.parse(e.data)
      entries.value.push(entry)
      if (entries.value.length > 5000) entries.value.splice(0, entries.value.length - 5000)
      scrollBottom()
    } catch { /* skip */ }
  }
  evtSource.onerror = () => {
    streaming.value = false
    // Auto-retry after 5s if the connection drops
    setTimeout(() => { if (!evtSource || evtSource.readyState === EventSource.CLOSED) startStream() }, 5000)
  }
}

function stopStream() {
  evtSource?.close()
  evtSource = null
  streaming.value = false
}

// ── Load historical logs (no SSE) ─────────────────────────────────────────────
async function loadHistory() {
  loading.value = true
  try {
    const hdr  = await authHeader()
    const params = new URLSearchParams()
    if (filterLevel.value) params.set('level',    filterLevel.value)
    if (filterCat.value)   params.set('category', filterCat.value)
    if (filterSearch.value) params.set('search',  filterSearch.value)
    params.set('limit', '1000')

    const res = await fetch(`${config.apiBase}/op/logs?${params}`, { headers: hdr })
    if (res.ok) {
      entries.value = await res.json()
      scrollBottom()
    }
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Load failed', detail: String(e), life: 4000 })
  } finally {
    loading.value = false
  }
}

// ── Download ───────────────────────────────────────────────────────────────────
async function downloadLog() {
  const hdr  = await authHeader()
  const date = new Date().toISOString().slice(0, 10)
  const res  = await fetch(`${config.apiBase}/op/logs/download?date=${date}`, { headers: hdr })
  if (!res.ok) { toast.add({ severity: 'error', summary: 'Download failed', life: 3000 }); return }
  const blob = await res.blob()
  const a    = document.createElement('a')
  a.href     = URL.createObjectURL(blob)
  a.download = `stigma-engine-${date}.log`
  a.click()
}

function clearDisplay() { entries.value = [] }

// ── Lifecycle ──────────────────────────────────────────────────────────────────
onMounted(() => startStream())
onUnmounted(() => stopStream())
</script>

<template>
  <Toast />
  <div class="logs-root">

    <!-- Header bar -->
    <div class="logs-header">
      <div class="logs-title">
        <h2><i class="pi pi-list" style="margin-right:0.4rem;color:#58a6ff" /> System Logs</h2>
        <div class="logs-badges">
          <Tag v-if="errorCount" severity="danger"  :value="`${errorCount} errors`" style="margin-right:0.3rem" />
          <Tag v-if="warnCount"  severity="warn"    :value="`${warnCount} warnings`" />
        </div>
      </div>

      <div class="logs-toolbar">
        <!-- Level filter -->
        <Select
          v-model="filterLevel"
          :options="levelOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="Level"
          style="width:140px"
        />

        <!-- Category filter -->
        <Select
          v-model="filterCat"
          :options="catOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="Category"
          style="width:150px"
        />

        <!-- Search -->
        <span class="p-input-icon-left" style="flex:1;min-width:180px;max-width:320px">
          <i class="pi pi-search" />
          <InputText v-model="filterSearch" placeholder="Search logs…" class="full-width" />
        </span>

        <!-- Live toggle -->
        <ToggleButton
          v-model="streaming"
          onLabel="Live"
          offLabel="Paused"
          onIcon="pi pi-circle-fill"
          offIcon="pi pi-circle"
          style="min-width:100px"
          @change="streaming ? startStream() : stopStream()"
        />

        <!-- Auto-scroll -->
        <Button
          :icon="autoScroll ? 'pi pi-lock' : 'pi pi-lock-open'"
          :severity="autoScroll ? 'success' : 'secondary'"
          v-tooltip="autoScroll ? 'Auto-scroll on' : 'Auto-scroll off'"
          outlined
          @click="autoScroll = !autoScroll"
        />

        <!-- Load history -->
        <Button icon="pi pi-history" label="History" severity="secondary" outlined :loading="loading" @click="loadHistory" />

        <!-- Download -->
        <Button icon="pi pi-download" label="Download" severity="secondary" outlined @click="downloadLog" />

        <!-- Clear -->
        <Button icon="pi pi-trash" severity="danger" outlined @click="clearDisplay" v-tooltip="'Clear display'" />
      </div>
    </div>

    <!-- Stats bar -->
    <div class="logs-stats">
      <span class="stat"><strong>{{ visible.length }}</strong> entries shown</span>
      <span class="stat" v-if="entries.length !== visible.length">of {{ entries.length }} loaded</span>
      <span class="stat streaming-dot" :class="streaming ? 'live' : 'off'">
        <span class="dot" /> {{ streaming ? 'Live' : 'Offline' }}
      </span>
    </div>

    <!-- Log entries -->
    <div class="log-container" ref="logContainer">
      <div v-if="visible.length === 0" class="log-empty">
        <i class="pi pi-inbox" style="font-size:2rem;color:#4b5563" /><br/>
        No log entries match the current filters
      </div>

      <div
        v-for="(entry, i) in visible"
        :key="i"
        class="log-row"
        :class="`level-${entry.level}`"
      >
        <!-- Timestamp -->
        <span class="log-date muted">{{ fmtDate(entry.ts) }}</span>
        <span class="log-time">{{ fmtTime(entry.ts) }}</span>

        <!-- Level badge -->
        <Tag
          :severity="levelSeverity(entry.level)"
          :value="entry.level.toUpperCase()"
          class="log-level-tag"
        />

        <!-- Category chip -->
        <span class="log-cat" :style="{ color: catColor(entry.category) }">
          {{ entry.category }}
        </span>

        <!-- Message -->
        <span class="log-msg">{{ entry.msg }}</span>

        <!-- Duration -->
        <span v-if="entry.ms !== undefined" class="log-ms muted">{{ entry.ms }}ms</span>

        <!-- Error details (expandable) -->
        <details v-if="entry.err" class="log-err-detail">
          <summary>Stack trace</summary>
          <pre class="log-err-pre">{{ entry.err }}</pre>
        </details>

        <!-- Data payload -->
        <details v-if="entry.data && Object.keys(entry.data).length" class="log-data-detail">
          <summary>Data</summary>
          <pre class="log-err-pre">{{ JSON.stringify(entry.data, null, 2) }}</pre>
        </details>
      </div>
    </div>
  </div>
</template>

<style scoped>
.logs-root  { display: flex; flex-direction: column; height: calc(100vh - 60px); padding: 0.5rem 1rem; gap: 0.5rem; }

.logs-header { display: flex; flex-direction: column; gap: 0.5rem; }
.logs-title  { display: flex; align-items: center; gap: 0.75rem; }
.logs-title h2 { margin: 0; font-size: 1.1rem; }

.logs-toolbar {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
}
.full-width { width: 100%; }

.logs-stats {
  display: flex;
  align-items: center;
  gap: 1rem;
  font-size: 0.8rem;
  color: var(--p-text-muted-color, #6b7280);
  padding: 0.2rem 0;
  border-bottom: 1px solid var(--p-surface-200, #2d2d3d);
}
.stat { display: flex; align-items: center; gap: 0.3rem; }
.streaming-dot { font-weight: 600; }
.streaming-dot .dot {
  width: 8px; height: 8px; border-radius: 50%;
  display: inline-block; margin-right: 4px;
}
.streaming-dot.live  .dot { background: #22c55e; animation: pulse-dot 1.5s infinite; }
.streaming-dot.off   .dot { background: #6b7280; }
.streaming-dot.live  { color: #22c55e; }

.log-container {
  flex: 1;
  overflow-y: auto;
  font-family: 'Consolas', 'Fira Mono', monospace;
  font-size: 0.78rem;
  background: var(--p-surface-900, #0d1117);
  border: 1px solid var(--p-surface-700, #21262d);
  border-radius: 6px;
  padding: 0.4rem;
}

.log-empty {
  text-align: center;
  padding: 3rem;
  color: var(--p-text-muted-color, #6b7280);
}

.log-row {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 0.35rem;
  padding: 0.18rem 0.3rem;
  border-radius: 3px;
  line-height: 1.4;
  border-left: 3px solid transparent;
}
.log-row:hover         { background: var(--p-surface-800, #161b22); }
.log-row.level-error   { border-left-color: #ef4444; background: rgba(239,68,68,0.06); }
.log-row.level-warn    { border-left-color: #f59e0b; background: rgba(245,158,11,0.05); }
.log-row.level-info    { border-left-color: transparent; }
.log-row.level-debug   { opacity: 0.65; }

.log-date    { color: var(--p-text-muted-color, #555); min-width: 36px; }
.log-time    { color: #8b949e; min-width: 90px; }
.log-level-tag { font-size: 0.65rem !important; padding: 0.1rem 0.3rem !important; min-width: 44px; text-align: center; }
.log-cat     { font-weight: 600; min-width: 72px; font-size: 0.75rem; }
.log-msg     { flex: 1; color: var(--p-text-color, #e6edf3); word-break: break-word; }
.log-ms      { font-size: 0.72rem; min-width: 48px; text-align: right; }
.muted       { color: var(--p-text-muted-color, #6b7280); }

.log-err-detail,
.log-data-detail {
  width: 100%;
  font-size: 0.72rem;
  margin-top: 0.1rem;
}
.log-err-detail summary,
.log-data-detail summary {
  cursor: pointer;
  color: var(--p-text-muted-color, #6b7280);
  user-select: none;
}
.log-err-pre {
  background: var(--p-surface-800, #161b22);
  border-radius: 4px;
  padding: 0.4rem 0.6rem;
  margin: 0.2rem 0 0;
  white-space: pre-wrap;
  word-break: break-all;
  color: #f87171;
  max-height: 200px;
  overflow-y: auto;
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.4; }
}
</style>
