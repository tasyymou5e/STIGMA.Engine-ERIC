<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api/client'
import { logout } from '../auth/oidc'
import type { Collection } from '../api/types'
import Button from 'primevue/button'
import Accordion from 'primevue/accordion'
import AccordionPanel from 'primevue/accordionpanel'
import AccordionHeader from 'primevue/accordionheader'
import AccordionContent from 'primevue/accordioncontent'

const props = defineProps<{
  username: string
  darkMode?: boolean
}>()

const emit = defineEmits<{
  (e: 'dark-mode-change', value: boolean): void
}>()

const router = useRouter()
const collections = ref<Collection[]>([])

// Expanded accordion values: 'collections' open by default, others closed
const expandedPanels = ref<string[]>(['collections'])

// ── SSE live indicator ─────────────────────────────────────────────────────────
const sseConnected = ref(false)
const sseStats = ref<{ reviewCount: number; assetCount: number; collectionCount: number } | null>(null)
let sseSource: EventSource | null = null

function connectSse() {
  const url = '/stigman/api/op/state/sse'
  sseSource = new EventSource(url)

  sseSource.addEventListener('state', (e: MessageEvent) => {
    sseConnected.value = true
    try {
      const data = JSON.parse(e.data as string) as Record<string, unknown>
      sseStats.value = {
        reviewCount:     Number(data.reviewCount     ?? 0),
        assetCount:      Number(data.assetCount      ?? 0),
        collectionCount: Number(data.collectionCount ?? 0)
      }
    } catch {
      // ignore malformed events
    }
  })

  sseSource.onerror = () => {
    sseConnected.value = false
  }

  sseSource.onopen = () => {
    sseConnected.value = true
  }
}

onMounted(async () => {
  const { data } = await api.GET('/collections')
  collections.value = data ?? []
  connectSse()
})

onUnmounted(() => {
  sseSource?.close()
  sseSource = null
})

function toggleDarkMode() {
  // Delegate to parent — the useDarkMode composable owns the state and localStorage
  emit('dark-mode-change', !props.darkMode)
}

function goToCollection(collectionId: string | number) {
  router.push(`/collections/${collectionId}`)
}

function goToCollectionSettings(collectionId: string | number, event: Event) {
  event.stopPropagation()
  router.push(`/collections/${collectionId}/settings`)
}

function goToNewCollection() {
  router.push('/collections?create=true')
}

function goTo(path: string) {
  router.push(path)
}

function openGrafana() {
  window.open('http://localhost:3000', '_blank', 'noopener')
}

async function downloadAllPoam() {
  try {
    const { getAccessToken } = await import('../auth/oidc')
    const { config } = await import('../config')
    const token = await getAccessToken()
    const res = await fetch(`${config.apiBase}/collections/meta/poam/emass.xlsx`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'POAM-eMASS-all-collections.xlsx'
    a.click()
    URL.revokeObjectURL(a.href)
  } catch (e) { console.error('POA&M export failed', e) }
}

// STIG import: open hidden file input
const stigFileInput = ref<HTMLInputElement | null>(null)

function triggerStigImport() {
  stigFileInput.value?.click()
}

async function handleStigFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  if (!input.files?.length) return
  const file = input.files[0]
  const formData = new FormData()
  formData.append('importFile', file)
  // POST /stigs with multipart — use raw fetch to avoid typed client limitations
  const { getAccessToken } = await import('../auth/oidc')
  const { config } = await import('../config')
  const token = await getAccessToken()
  await fetch(`${config.apiBase}/stigs`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: formData
  })
  input.value = ''
  router.push('/stigs')
}
</script>

<template>
  <aside class="nav-sidebar">
    <!-- User section -->
    <div class="sidebar-user">
      <span class="sidebar-avatar">
        <i class="pi pi-user" />
      </span>
      <span class="sidebar-username" :title="username">{{ username || 'Loading…' }}</span>
      <Button
        icon="pi pi-sign-out"
        size="small"
        severity="secondary"
        text
        rounded
        aria-label="Sign out"
        title="Sign out"
        @click="logout"
      />
    </div>

    <!-- Top-level shortcuts -->
    <ul class="sidebar-list sidebar-top-nav">
      <li class="sidebar-list-item" @click="goTo('/dashboard')">
        <i class="pi pi-th-large sidebar-item-icon" />
        <span>Application Overview</span>
      </li>
      <li class="sidebar-list-item" @click="openGrafana">
        <i class="pi pi-chart-line sidebar-item-icon" />
        <span>Monitoring (Grafana)</span>
        <i class="pi pi-external-link sidebar-item-ext" />
      </li>
    </ul>

    <!-- Nav panels -->
    <Accordion v-model:value="expandedPanels" multiple class="sidebar-accordion">
      <!-- Collections panel -->
      <AccordionPanel value="collections">
        <AccordionHeader>
          <span class="panel-header-label">Collections</span>
          <Button
            icon="pi pi-plus"
            size="small"
            severity="secondary"
            text
            rounded
            aria-label="New Collection"
            title="New Collection"
            class="panel-header-action"
            @click.stop="goToNewCollection"
          />
        </AccordionHeader>
        <AccordionContent>
          <ul class="sidebar-list">
            <li
              v-for="col in collections"
              :key="col.collectionId"
              class="sidebar-list-item"
              @click="goToCollection(col.collectionId)"
            >
              <span class="sidebar-list-name" :title="col.name">{{ col.name }}</span>
              <Button
                icon="pi pi-cog"
                size="small"
                severity="secondary"
                text
                rounded
                aria-label="Collection settings"
                title="Collection settings"
                class="sidebar-list-action"
                @click="goToCollectionSettings(col.collectionId, $event)"
              />
            </li>
            <li v-if="collections.length === 0" class="sidebar-list-empty">
              No collections
            </li>
          </ul>
        </AccordionContent>
      </AccordionPanel>

      <!-- Eval STIG panel -->
      <AccordionPanel value="eval-stig">
        <AccordionHeader>
          <span class="panel-header-label">
            <i class="pi pi-bolt" style="margin-right:0.4rem;color:#58a6ff" />
            Eval STIG
          </span>
        </AccordionHeader>
        <AccordionContent>
          <ul class="sidebar-list">
            <li class="sidebar-list-item" @click="goTo('/eval-stig')">
              <i class="pi pi-list sidebar-item-icon" />
              <span>Evaluation Jobs</span>
            </li>
            <li class="sidebar-list-item sidebar-action-item" @click="goTo('/eval-stig/new')">
              <i class="pi pi-play sidebar-item-icon" />
              <span>Launch Evaluation</span>
            </li>
            <li class="sidebar-list-item sidebar-action-item" @click="goTo('/eval-stig?startAgent=1')">
              <i class="pi pi-desktop sidebar-item-icon" />
              <span>Start Agent Remotely</span>
            </li>
          </ul>
        </AccordionContent>
      </AccordionPanel>

      <!-- STIG Library panel -->
      <AccordionPanel value="stigs">
        <AccordionHeader>
          <span class="panel-header-label">STIG Library</span>
        </AccordionHeader>
        <AccordionContent>
          <ul class="sidebar-list">
            <li class="sidebar-list-item" @click="goTo('/stigs')">
              <i class="pi pi-book sidebar-item-icon" />
              <span>Browse STIGs</span>
            </li>
            <li class="sidebar-list-item" @click="triggerStigImport">
              <i class="pi pi-upload sidebar-item-icon" />
              <span>Import STIG</span>
            </li>
          </ul>
          <input
            ref="stigFileInput"
            type="file"
            accept=".zip,.xml"
            style="display: none"
            @change="handleStigFileChange"
          />
        </AccordionContent>
      </AccordionPanel>

      <!-- Administration panel -->
      <AccordionPanel value="admin">
        <AccordionHeader>
          <span class="panel-header-label">Administration</span>
        </AccordionHeader>
        <AccordionContent>
          <ul class="sidebar-list">
            <li class="sidebar-list-item" @click="goTo('/admin/collections')">
              <i class="pi pi-folder sidebar-item-icon" />
              <span>Collections</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/admin/users')">
              <i class="pi pi-users sidebar-item-icon" />
              <span>Users</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/admin/user-groups')">
              <i class="pi pi-sitemap sidebar-item-icon" />
              <span>User Groups</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/stigs')">
              <i class="pi pi-shield sidebar-item-icon" />
              <span>STIG Benchmarks</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/admin/jobs')">
              <i class="pi pi-cog sidebar-item-icon" />
              <span>Service Jobs</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/admin/logs')">
              <i class="pi pi-list sidebar-item-icon" style="color:#58a6ff" />
              <span>System Logs</span>
            </li>
            <li class="sidebar-list-item sidebar-section-divider" @click="downloadAllPoam">
              <i class="pi pi-shield sidebar-item-icon" />
              <span>Export All eMASS POA&amp;M</span>
            </li>
            <li class="sidebar-list-item" @click="openGrafana">
              <i class="pi pi-chart-line sidebar-item-icon" />
              <span>Monitoring (Grafana)</span>
              <i class="pi pi-external-link sidebar-item-ext" />
            </li>
            <li class="sidebar-list-item" @click="goTo('/info')">
              <i class="pi pi-info-circle sidebar-item-icon" />
              <span>App Info</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/info')">
              <i class="pi pi-database sidebar-item-icon" />
              <span>App Data</span>
            </li>
            <li class="sidebar-list-item sidebar-section-divider" @click="goTo('/docs')">
              <i class="pi pi-book sidebar-item-icon" style="color:#58a6ff" />
              <span>Documentation</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/docs/docker')">
              <i class="pi pi-box sidebar-item-icon" />
              <span>Docker Install</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/docs/winrm')">
              <i class="pi pi-lock sidebar-item-icon" />
              <span>WinRM Setup</span>
            </li>
            <li class="sidebar-list-item" @click="goTo('/docs/eval-stig')">
              <i class="pi pi-bolt sidebar-item-icon" />
              <span>Eval-STIG Agent</span>
            </li>
          </ul>
        </AccordionContent>
      </AccordionPanel>
    </Accordion>

    <!-- ── Quick-access Log Viewer button — always visible ── -->
    <div class="sidebar-log-btn-wrap">
      <button class="sidebar-log-btn" @click="goTo('/admin/logs')">
        <i class="pi pi-list" />
        <span>System Logs</span>
        <i class="pi pi-arrow-right sidebar-log-arrow" />
      </button>
    </div>

    <!-- Bottom: live indicator + dark mode toggle -->
    <div class="sidebar-footer">
      <!-- SSE live indicator -->
      <div class="live-indicator" :title="sseConnected ? `Live — ${sseStats?.reviewCount?.toLocaleString() ?? 0} reviews` : 'Disconnected from server'">
        <span class="live-dot" :class="sseConnected ? 'live-dot--on' : 'live-dot--off'" />
        <span class="live-label">{{ sseConnected ? 'Live' : 'Offline' }}</span>
        <span v-if="sseConnected && sseStats" class="live-stats">
          {{ sseStats.collectionCount }}c / {{ sseStats.assetCount }}a / {{ sseStats.reviewCount.toLocaleString() }}r
        </span>
      </div>

      <label class="dark-mode-toggle">
        <input
          type="checkbox"
          :checked="darkMode ?? false"
          @change="toggleDarkMode"
        />
        <span>Dark mode</span>
      </label>
    </div>
  </aside>
</template>

<style scoped>
.nav-sidebar {
  width: 240px;
  min-width: 240px;
  max-width: 240px;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: var(--p-surface-100, #f8f9fa);
  border-right: 1px solid var(--p-surface-200, #e9ecef);
  overflow-y: auto;
  overflow-x: hidden;
}

/* User section */
.sidebar-user {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 0.75rem 0.5rem;
  border-bottom: 1px solid var(--p-surface-200, #e9ecef);
  min-height: 52px;
}

.sidebar-avatar {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: var(--p-primary-color, #6366f1);
  color: #fff;
  font-size: 0.8rem;
  flex-shrink: 0;
}

.sidebar-username {
  flex: 1;
  font-size: 0.85rem;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Top-level nav (above accordion) */
.sidebar-top-nav {
  border-bottom: 1px solid var(--p-surface-200, #e9ecef);
  padding: 0.25rem 0;
}

/* Accordion */
.sidebar-accordion {
  flex: 1;
  border: none;
}

/* Panel header layout: label fills space, action button on right */
:deep(.p-accordion-header-link) {
  padding: 0.5rem 0.75rem !important;
  font-size: 0.8rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

:deep(.p-accordion-content) {
  padding: 0 !important;
}

.panel-header-label {
  flex: 1;
}

.panel-header-action {
  margin-left: auto;
  opacity: 0.7;
}
.panel-header-action:hover {
  opacity: 1;
}

/* List items */
.sidebar-list {
  list-style: none;
  margin: 0;
  padding: 0.25rem 0;
}

.sidebar-list-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.35rem 0.75rem 0.35rem 1rem;
  font-size: 0.875rem;
  cursor: pointer;
  border-radius: 0;
  transition: background 0.15s;
}

.sidebar-list-item:hover {
  background: var(--p-surface-200, #e9ecef);
}

.sidebar-list-name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sidebar-list-action {
  opacity: 0;
  flex-shrink: 0;
}

.sidebar-list-item:hover .sidebar-list-action {
  opacity: 0.7;
}

.sidebar-list-action:hover {
  opacity: 1 !important;
}

.sidebar-list-empty {
  padding: 0.35rem 1rem;
  font-size: 0.8rem;
  color: var(--p-text-muted-color, #6c757d);
  font-style: italic;
}

.sidebar-item-ext {
  font-size: 0.65rem;
  opacity: 0.5;
  margin-left: auto;
  flex-shrink: 0;
}
.sidebar-section-divider {
  border-top: 1px solid var(--p-surface-200, rgba(255,255,255,0.1));
  margin-top: 0.25rem;
  padding-top: 0.4rem;
}
.sidebar-item-icon {
  font-size: 0.8rem;
  opacity: 0.7;
  flex-shrink: 0;
}

/* Log Viewer quick-access button */
.sidebar-log-btn-wrap {
  padding: 0.5rem 0.75rem 0.25rem;
}
.sidebar-log-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.55rem 0.75rem;
  background: var(--p-surface-800, #161b22);
  border: 1px solid var(--p-primary-color, #58a6ff);
  border-radius: 6px;
  color: var(--p-primary-color, #58a6ff);
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.15s, box-shadow 0.15s;
  text-align: left;
}
.sidebar-log-btn:hover {
  background: rgba(88,166,255,0.12);
  box-shadow: 0 0 0 1px var(--p-primary-color, #58a6ff);
}
.sidebar-log-btn .pi-list { font-size: 0.9rem; }
.sidebar-log-arrow { margin-left: auto; font-size: 0.75rem; opacity: 0.6; }

/* Footer */
.sidebar-footer {
  padding: 0.75rem;
  border-top: 1px solid var(--p-surface-200, #e9ecef);
  margin-top: auto;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

/* Live indicator */
.live-indicator {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.78rem;
  cursor: default;
  user-select: none;
}

.live-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  transition: background-color 0.4s;
}

.live-dot--on {
  background: #3fb950;
  box-shadow: 0 0 4px #3fb950aa;
}

.live-dot--off {
  background: #6c757d;
}

.live-label {
  font-weight: 600;
  color: var(--p-text-color, inherit);
}

.live-stats {
  color: var(--p-text-muted-color, #888);
  font-size: 0.72rem;
  margin-left: 0.1rem;
}

.dark-mode-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
  cursor: pointer;
  user-select: none;
}

.dark-mode-toggle input {
  cursor: pointer;
}

/* Dark mode overrides for the sidebar itself */
:root.p-dark .nav-sidebar,
body.p-dark .nav-sidebar {
  background: var(--p-surface-900, #1a1a2e);
  border-right-color: var(--p-surface-700, #374151);
}

:root.p-dark .sidebar-user,
body.p-dark .sidebar-user {
  border-bottom-color: var(--p-surface-700, #374151);
}

:root.p-dark .sidebar-list-item:hover,
body.p-dark .sidebar-list-item:hover {
  background: var(--p-surface-700, #374151);
}

:root.p-dark .sidebar-footer,
body.p-dark .sidebar-footer {
  border-top-color: var(--p-surface-700, #374151);
}
</style>
