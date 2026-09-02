<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { config } from '../config'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Card from 'primevue/card'

interface AppInfo {
  version: string
  node: string
  db: string
  commit: string
}

interface TableStat {
  name: string
  rowCount: number
}

interface SystemState {
  collectionCount: number
  assetCount: number
  reviewCount: number
  userCount: number
  stigCount: number
  dbVersion: string
  ts: string
}

const appInfo = ref<AppInfo | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)

// Table stats state
const tableStats = ref<TableStat[]>([])
const tableStatsLoading = ref(false)
const tableStatsError = ref<string | null>(null)
const tableStatsLoaded = ref(false)

// System state
const systemState = ref<SystemState | null>(null)
const stateLoading = ref(false)
const stateError = ref<string | null>(null)
const stateLoaded = ref(false)

// Export state
const exportLoading = ref(false)

// ── Watchdog state ────────────────────────────────────────────────────────────
interface WatchdogStatus {
  taskName: string
  installed: boolean
  running: boolean
  lastWritten: string | null
  lastLogLine: string
  scriptPath: string
  installCommand: string
  setupCommand: string
  manualInstall: string
}
const watchdog = ref<WatchdogStatus | null>(null)
const watchdogLoading = ref(false)
const copied = ref(false)

async function loadWatchdog() {
  watchdogLoading.value = true
  try {
    const res = await fetch(`${config.apiBase}/op/watchdog`)
    if (res.ok) watchdog.value = await res.json()
  } finally {
    watchdogLoading.value = false
  }
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(() => {
    copied.value = true
    setTimeout(() => { copied.value = false }, 2500)
  })
}

function fmtRelative(iso: string | null): string {
  if (!iso) return 'Never'
  const diff = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.round(diff/60)}m ago`
  return `${Math.round(diff/3600)}h ago`
}

onMounted(async () => {
  try {
    const res = await fetch(`${config.apiBase}/op/appinfo`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    appInfo.value = await res.json()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Unknown error'
  } finally {
    loading.value = false
  }
  loadWatchdog()
})

async function loadTableStats() {
  tableStatsLoading.value = true
  tableStatsError.value = null
  try {
    const res = await fetch(`${config.apiBase}/op/appdata/tables`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    tableStats.value = await res.json()
    tableStatsLoaded.value = true
  } catch (e) {
    tableStatsError.value = e instanceof Error ? e.message : 'Unknown error'
  } finally {
    tableStatsLoading.value = false
  }
}

async function loadSystemState() {
  stateLoading.value = true
  stateError.value = null
  try {
    const res = await fetch(`${config.apiBase}/op/state`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    systemState.value = await res.json()
    stateLoaded.value = true
  } catch (e) {
    stateError.value = e instanceof Error ? e.message : 'Unknown error'
  } finally {
    stateLoading.value = false
  }
}

async function exportAppData() {
  exportLoading.value = true
  try {
    const date = new Date().toISOString().slice(0, 10)
    const res = await fetch(`${config.apiBase}/op/appdata`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `stigman-backup-${date}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  } catch (e) {
    // Surface the error visually if needed — silently log for now
    console.error('Export failed:', e)
  } finally {
    exportLoading.value = false
  }
}

const changelog = [
  {
    icon: 'pi-server',
    title: 'Fastify 5 + TypeScript backend replacing Express',
    detail: 'Full type-safe HTTP layer with schema validation via Zod, ESM modules, and structured logging.'
  },
  {
    icon: 'pi-desktop',
    title: 'Vue 3 + PrimeVue 4 UI replacing Ext JS',
    detail: 'Reactive Composition API frontend with PrimeVue component library, dark mode, and Vue Router.'
  },
  {
    icon: 'pi-database',
    title: 'Full 28-table schema with RBAC, review history, STIG library',
    detail: 'MySQL 8 schema covering collections, assets, rules, reviews, review history, users, roles, grants, labels, user groups, STIG benchmarks, and more.'
  },
  {
    icon: 'pi-file-import',
    title: 'CKL / CKLB / XCCDF import and export',
    detail: 'Ingest engine parses all three checklist formats, maps findings to the DB schema, and supports round-trip export.'
  },
  {
    icon: 'pi-file-export',
    title: 'Batch review, POA&M export, CORA scoring',
    detail: 'Bulk-patch review status across assets, generate POA&M spreadsheets (XLSX), and compute CORA compliance scores per collection.'
  },
  {
    icon: 'pi-lock',
    title: 'Keycloak OIDC with RS256 signature verification',
    detail: 'JWT access tokens verified against Keycloak JWKS endpoint; scope- and role-based access control enforced on every protected route.'
  }
]

const links = [
  { label: 'STIG Manager (upstream, Navy)', href: 'https://github.com/NUWCDIVNPT/stig-manager', icon: 'pi-github' },
  { label: 'DISA STIG Downloads', href: 'https://public.cyber.mil/stigs/downloads/', icon: 'pi-shield' },
  { label: 'Fastify Documentation', href: 'https://fastify.dev/', icon: 'pi-external-link' },
  { label: 'PrimeVue 4 Documentation', href: 'https://primevue.org/', icon: 'pi-external-link' }
]
</script>

<template>
  <div class="appinfo-page">
    <!-- Header -->
    <div class="appinfo-header">
      <div class="appinfo-title-row">
        <h1 class="appinfo-title">STIG Manager <span class="appinfo-edition">MEO Edition</span></h1>
        <span v-if="appInfo" class="appinfo-version-badge">v{{ appInfo.version }}</span>
        <span v-else-if="loading" class="appinfo-version-badge muted">loading…</span>
      </div>
      <p class="appinfo-subtitle">STIG Manager rewrite on the Tech stack — Fastify 5, Vue 3, MySQL 8, Keycloak OIDC</p>
    </div>

    <!-- Info table -->
    <section class="appinfo-section">
      <h2 class="section-title">Build Information</h2>
      <div v-if="loading" class="appinfo-loading">
        <i class="pi pi-spin pi-spinner" /> Fetching build info…
      </div>
      <div v-else-if="error" class="appinfo-error">
        <i class="pi pi-exclamation-triangle" /> Could not load app info: {{ error }}
      </div>
      <table v-else-if="appInfo" class="appinfo-table">
        <tbody>
          <tr>
            <th>Version</th>
            <td><code>{{ appInfo.version }}</code></td>
          </tr>
          <tr>
            <th>Node.js</th>
            <td><code>{{ appInfo.node }}</code></td>
          </tr>
          <tr>
            <th>Database</th>
            <td>{{ appInfo.db }}</td>
          </tr>
          <tr>
            <th>Build</th>
            <td>{{ appInfo.commit }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- Watchdog Management -->
    <section class="appinfo-section">
      <h2 class="section-title">
        <i class="pi pi-shield" style="margin-right:0.5rem;color:var(--p-primary-color,#58a6ff)" />
        Stack Watchdog
      </h2>

      <div v-if="watchdogLoading" class="appdata-desc muted">Checking watchdog status…</div>

      <div v-else-if="watchdog" class="watchdog-panel">
        <!-- Status row -->
        <div class="watchdog-status-row">
          <div class="watchdog-indicator" :class="watchdog.running ? 'wd-running' : watchdog.installed ? 'wd-stopped' : 'wd-missing'">
            <i :class="watchdog.running ? 'pi pi-check-circle' : 'pi pi-exclamation-circle'" />
            <span>{{ watchdog.running ? 'Running' : watchdog.installed ? 'Not Running' : 'Not Installed' }}</span>
          </div>
          <span v-if="watchdog.lastWritten" class="muted wd-meta">
            Last heartbeat: {{ fmtRelative(watchdog.lastWritten) }}
          </span>
          <Button icon="pi pi-refresh" size="small" severity="secondary" text @click="loadWatchdog" :loading="watchdogLoading" title="Refresh" />
        </div>

        <!-- Last log line -->
        <div v-if="watchdog.lastLogLine" class="wd-log-line">
          <span class="muted">Last log:</span> {{ watchdog.lastLogLine }}
        </div>

        <!-- What the watchdog does -->
        <div class="wd-description">
          <p>The watchdog monitors all stack containers and automatically heals:</p>
          <ul>
            <li><strong>502 Bad Gateway</strong> — restarts nginx when engine gets a new IP after restart</li>
            <li><strong>Stopped containers</strong> — restarts any container that has stopped unexpectedly</li>
            <li><strong>Sustained failures</strong> — runs <code>docker compose up -d</code> after 5+ consecutive failures</li>
          </ul>
          <p>Also auto-starts on Windows login. Log: <code>scripts\watchdog.log</code></p>
        </div>

        <!-- Install commands -->
        <div class="wd-commands">
          <h4 class="wd-cmd-title">Install / Start Commands</h4>
          <p class="muted" style="font-size:0.8rem;margin:0 0 0.5rem">Run one of these in a <strong>PowerShell terminal on this Windows machine</strong>:</p>

          <div class="wd-cmd-block">
            <div class="wd-cmd-label">Start watchdog immediately (runs until terminal closes)</div>
            <div class="wd-cmd-row">
              <code class="wd-code">{{ watchdog.installCommand }}</code>
              <Button icon="pi pi-copy" size="small" severity="secondary" text :label="copied ? 'Copied!' : 'Copy'" @click="copyToClipboard(watchdog!.installCommand)" />
            </div>
          </div>

          <div class="wd-cmd-block">
            <div class="wd-cmd-label">Install as scheduled task (auto-runs at every login) — recommended</div>
            <div class="wd-cmd-row">
              <code class="wd-code">{{ watchdog.setupCommand }}</code>
              <Button icon="pi pi-copy" size="small" severity="secondary" text @click="copyToClipboard(watchdog!.setupCommand)" />
            </div>
          </div>

          <div class="wd-cmd-block">
            <div class="wd-cmd-label">Check if scheduled task is installed</div>
            <div class="wd-cmd-row">
              <code class="wd-code">schtasks.exe /Query /TN "STIGMA-Engine-Watchdog" /FO LIST</code>
              <Button icon="pi pi-copy" size="small" severity="secondary" text @click='copyToClipboard(`schtasks.exe /Query /TN "STIGMA-Engine-Watchdog" /FO LIST`)' />
            </div>
          </div>

          <div class="wd-cmd-block">
            <div class="wd-cmd-label">Stop and remove scheduled task</div>
            <div class="wd-cmd-row">
              <code class="wd-code">schtasks.exe /Delete /TN "STIGMA-Engine-Watchdog" /F</code>
              <Button icon="pi pi-copy" size="small" severity="secondary" text @click='copyToClipboard(`schtasks.exe /Delete /TN "STIGMA-Engine-Watchdog" /F`)' />
            </div>
          </div>
        </div>
      </div>

      <div v-else class="appdata-desc muted">Watchdog status unavailable — scripts directory may not be mounted.</div>
    </section>

    <!-- App Data Export -->
    <section class="appinfo-section">
      <h2 class="section-title">App Data</h2>
      <div class="appdata-actions">
        <Button
          label="Export App Data"
          icon="pi pi-download"
          :loading="exportLoading"
          @click="exportAppData"
        />
        <p class="appdata-desc">Downloads all application data as a JSON backup file.</p>
      </div>
    </section>

    <!-- Table Stats -->
    <section class="appinfo-section">
      <h2 class="section-title">Table Statistics</h2>
      <div v-if="!tableStatsLoaded" class="appdata-actions">
        <Button
          label="View Table Stats"
          icon="pi pi-table"
          severity="secondary"
          :loading="tableStatsLoading"
          @click="loadTableStats"
        />
      </div>
      <div v-if="tableStatsError" class="appinfo-error">
        <i class="pi pi-exclamation-triangle" /> {{ tableStatsError }}
      </div>
      <DataTable
        v-if="tableStatsLoaded"
        :value="tableStats"
        size="small"
        striped-rows
        class="appdata-table-stats"
      >
        <Column field="name" header="Table Name" sortable />
        <Column field="rowCount" header="Row Count" sortable style="text-align: right; width: 140px" />
      </DataTable>
    </section>

    <!-- System State -->
    <section class="appinfo-section">
      <h2 class="section-title">System State</h2>
      <div v-if="!stateLoaded" class="appdata-actions">
        <Button
          label="Load System State"
          icon="pi pi-chart-bar"
          severity="secondary"
          :loading="stateLoading"
          @click="loadSystemState"
        />
      </div>
      <div v-if="stateError" class="appinfo-error">
        <i class="pi pi-exclamation-triangle" /> {{ stateError }}
      </div>
      <div v-if="stateLoaded && systemState" class="state-cards">
        <Card class="state-card">
          <template #title>Collections</template>
          <template #content><span class="state-count">{{ systemState.collectionCount.toLocaleString() }}</span></template>
        </Card>
        <Card class="state-card">
          <template #title>Assets</template>
          <template #content><span class="state-count">{{ systemState.assetCount.toLocaleString() }}</span></template>
        </Card>
        <Card class="state-card">
          <template #title>Reviews</template>
          <template #content><span class="state-count">{{ systemState.reviewCount.toLocaleString() }}</span></template>
        </Card>
        <Card class="state-card">
          <template #title>Users</template>
          <template #content><span class="state-count">{{ systemState.userCount.toLocaleString() }}</span></template>
        </Card>
        <Card class="state-card">
          <template #title>STIGs</template>
          <template #content><span class="state-count">{{ systemState.stigCount.toLocaleString() }}</span></template>
        </Card>
        <Card class="state-card state-card--db">
          <template #title>DB Version</template>
          <template #content><span class="state-db">{{ systemState.dbVersion }}</span></template>
        </Card>
      </div>
      <div v-if="stateLoaded && systemState" class="state-ts">
        Snapshot at {{ new Date(systemState.ts).toLocaleString() }}
        <Button label="Refresh" icon="pi pi-refresh" text size="small" @click="loadSystemState" style="margin-left: 0.5rem" />
      </div>
    </section>

    <!-- What's New -->
    <section class="appinfo-section">
      <h2 class="section-title">What's New — MEO Edition</h2>
      <ul class="changelog-list">
        <li v-for="item in changelog" :key="item.title" class="changelog-item">
          <span class="changelog-icon"><i :class="`pi ${item.icon}`" /></span>
          <div class="changelog-body">
            <div class="changelog-title">{{ item.title }}</div>
            <div class="changelog-detail">{{ item.detail }}</div>
          </div>
        </li>
      </ul>
    </section>

    <!-- Links -->
    <section class="appinfo-section">
      <h2 class="section-title">Links</h2>
      <ul class="links-list">
        <li v-for="link in links" :key="link.href">
          <a :href="link.href" target="_blank" rel="noopener noreferrer" class="appinfo-link">
            <i :class="`pi ${link.icon}`" />
            {{ link.label }}
          </a>
        </li>
      </ul>
    </section>
  </div>
</template>

<style scoped>
.appinfo-page {
  max-width: 820px;
  margin: 0 auto;
  padding: 2rem 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

/* Header */
.appinfo-header {
  border-bottom: 2px solid var(--p-primary-color, #6366f1);
  padding-bottom: 1rem;
}

.appinfo-title-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.appinfo-title {
  font-size: 1.6rem;
  font-weight: 700;
  margin: 0;
  line-height: 1.2;
}

.appinfo-edition {
  color: var(--p-primary-color, #6366f1);
}

.appinfo-version-badge {
  display: inline-flex;
  align-items: center;
  background: var(--p-primary-color, #6366f1);
  color: #fff;
  font-size: 0.8rem;
  font-weight: 600;
  padding: 0.2rem 0.55rem;
  border-radius: 999px;
  letter-spacing: 0.03em;
}

.appinfo-version-badge.muted {
  background: var(--p-surface-300, #dee2e6);
  color: var(--p-text-muted-color, #6c757d);
}

.appinfo-subtitle {
  margin: 0.5rem 0 0;
  font-size: 0.9rem;
  color: var(--p-text-muted-color, #6c757d);
}

/* Sections */
.appinfo-section {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.section-title {
  font-size: 1rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--p-primary-color, #6366f1);
  margin: 0;
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--p-surface-200, #e9ecef);
}

/* Info table */
.appinfo-table {
  border-collapse: collapse;
  font-size: 0.9rem;
  width: 100%;
}

.appinfo-table th,
.appinfo-table td {
  padding: 0.45rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--p-surface-200, #e9ecef);
}

.appinfo-table th {
  width: 140px;
  font-weight: 600;
  color: var(--p-text-muted-color, #6c757d);
  background: var(--p-surface-50, #f8f9fa);
}

.appinfo-table code {
  font-family: 'Fira Mono', 'Consolas', monospace;
  font-size: 0.875em;
  background: var(--p-surface-100, #f1f3f5);
  padding: 0.1em 0.35em;
  border-radius: 3px;
}

.appinfo-loading,
.appinfo-error {
  font-size: 0.9rem;
  color: var(--p-text-muted-color, #6c757d);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.appinfo-error {
  color: var(--p-red-500, #ef4444);
}

/* Changelog */
.changelog-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.changelog-item {
  display: flex;
  gap: 0.85rem;
  align-items: flex-start;
  padding: 0.75rem 1rem;
  background: var(--p-surface-50, #f8f9fa);
  border: 1px solid var(--p-surface-200, #e9ecef);
  border-radius: 6px;
}

.changelog-icon {
  flex-shrink: 0;
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--p-primary-color, #6366f1);
  color: #fff;
  border-radius: 6px;
  font-size: 0.85rem;
}

.changelog-body {
  flex: 1;
}

.changelog-title {
  font-weight: 600;
  font-size: 0.9rem;
  margin-bottom: 0.2rem;
}

.changelog-detail {
  font-size: 0.825rem;
  color: var(--p-text-muted-color, #6c757d);
  line-height: 1.5;
}

/* Links */
.links-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.appinfo-link {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.9rem;
  color: var(--p-primary-color, #6366f1);
  text-decoration: none;
  padding: 0.2rem 0;
}

.appinfo-link:hover {
  text-decoration: underline;
}

/* ── Watchdog panel ── */
.watchdog-panel { display: flex; flex-direction: column; gap: 1rem; }
.watchdog-status-row { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.watchdog-indicator { display: flex; align-items: center; gap: 0.4rem; font-weight: 600; font-size: 0.95rem; padding: 0.3rem 0.75rem; border-radius: 6px; }
.wd-running  { background: rgba(63,185,80,0.12);  color: #3fb950; }
.wd-stopped  { background: rgba(248,81,73,0.12);  color: #f85149; }
.wd-missing  { background: rgba(107,114,128,0.12); color: #6b7280; }
.wd-meta { font-size: 0.85rem; }
.wd-log-line { font-size: 0.8rem; font-family: monospace; background: var(--p-surface-100, #f3f4f6); border-radius: 4px; padding: 0.35rem 0.6rem; color: var(--p-text-muted-color, #6b7280); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wd-description { font-size: 0.875rem; }
.wd-description p { margin: 0 0 0.3rem; }
.wd-description ul { margin: 0.3rem 0 0.5rem 1.2rem; }
.wd-description li { margin: 0.15rem 0; }
.wd-description code { font-family: monospace; font-size: 0.82rem; background: var(--p-surface-100, #f3f4f6); padding: 0.1rem 0.3rem; border-radius: 3px; }
.wd-commands { display: flex; flex-direction: column; gap: 0.75rem; }
.wd-cmd-title { margin: 0 0 0.25rem; font-size: 0.9rem; font-weight: 600; }
.wd-cmd-block { display: flex; flex-direction: column; gap: 0.25rem; }
.wd-cmd-label { font-size: 0.78rem; color: var(--p-text-muted-color, #6b7280); }
.wd-cmd-row { display: flex; align-items: center; gap: 0.5rem; }
.wd-code { font-family: monospace; font-size: 0.8rem; background: var(--p-surface-100, #f3f4f6); padding: 0.3rem 0.6rem; border-radius: 4px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* App data / export */
.appdata-actions {
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.appdata-desc {
  margin: 0;
  font-size: 0.85rem;
  color: var(--p-text-muted-color, #6c757d);
}

.appdata-table-stats {
  font-size: 0.875rem;
}

/* System state cards */
.state-cards {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.state-card {
  min-width: 120px;
  flex: 1 1 120px;
}

:deep(.state-card .p-card-title) {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--p-text-muted-color, #6c757d);
  margin-bottom: 0.25rem;
}

:deep(.state-card .p-card-content) {
  padding-top: 0;
}

.state-count {
  font-size: 1.6rem;
  font-weight: 700;
  color: var(--p-primary-color, #6366f1);
  line-height: 1;
}

.state-db {
  font-size: 0.9rem;
  font-weight: 600;
  font-family: 'Fira Mono', 'Consolas', monospace;
}

.state-ts {
  font-size: 0.8rem;
  color: var(--p-text-muted-color, #6c757d);
  display: flex;
  align-items: center;
  margin-top: 0.25rem;
}

/* Dark mode */
:root.p-dark .appinfo-table th,
body.p-dark .appinfo-table th {
  background: var(--p-surface-800, #1e1e2e);
}

:root.p-dark .appinfo-table code,
body.p-dark .appinfo-table code {
  background: var(--p-surface-700, #374151);
}

:root.p-dark .changelog-item,
body.p-dark .changelog-item {
  background: var(--p-surface-800, #1e1e2e);
  border-color: var(--p-surface-700, #374151);
}

:root.p-dark .section-title,
body.p-dark .section-title {
  border-bottom-color: var(--p-surface-700, #374151);
}

:root.p-dark .appinfo-table th,
:root.p-dark .appinfo-table td,
body.p-dark .appinfo-table th,
body.p-dark .appinfo-table td {
  border-bottom-color: var(--p-surface-700, #374151);
}
</style>
