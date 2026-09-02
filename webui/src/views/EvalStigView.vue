<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Toast from 'primevue/toast'
import ConfirmDialog from 'primevue/confirmdialog'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Password from 'primevue/password'
import Checkbox from 'primevue/checkbox'
import Select from 'primevue/select'
import Message from 'primevue/message'
import Divider from 'primevue/divider'
import EvalStigRunDialog from '../components/EvalStigRunDialog.vue'
import type { EvalStigJob, EvalStigStatus } from '../api/types'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'

// ── Props ─────────────────────────────────────────────────────────────────────
const props = defineProps<{ openNew?: boolean }>()

// ── State ─────────────────────────────────────────────────────────────────────
const router = useRouter()
const route  = useRoute()
const toast = useToast()
const confirm = useConfirm()

const jobs = ref<EvalStigJob[]>([])
const agentStatus = ref<EvalStigStatus | null>(null)
const loading = ref(true)
const error = ref('')
const showRunDialog = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

// ── Auth helper ───────────────────────────────────────────────────────────────
async function authHeaders(): Promise<HeadersInit> {
  const token = await getAccessToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

// ── Data fetchers ─────────────────────────────────────────────────────────────
async function loadStatus() {
  try {
    const res = await fetch(`${config.apiBase}/eval-stig/status`, {
      headers: await authHeaders()
    })
    if (res.ok) agentStatus.value = await res.json()
  } catch {
    // silently ignore status fetch errors
  }
}

async function loadJobs() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch(`${config.apiBase}/eval-stig/jobs`, {
      headers: await authHeaders()
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    jobs.value = await res.json()
  } catch (e) {
    error.value = `Failed to load jobs: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

function hasActiveJobs(): boolean {
  return jobs.value.some(j => j.status === 'pending' || j.status === 'running')
}

function startPolling() {
  if (pollTimer) return
  pollTimer = setInterval(async () => {
    if (hasActiveJobs()) {
      await loadJobs()
    } else {
      stopPolling()
    }
  }, 10_000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
onMounted(async () => {
  await Promise.all([loadStatus(), loadJobs()])
  if (hasActiveJobs()) startPolling()
  if (props.openNew) showRunDialog.value = true
  if (route.query.startAgent === '1') openStartAgentDialog()
})

onUnmounted(() => stopPolling())

// ── Cancel job ────────────────────────────────────────────────────────────────
function confirmCancel(job: EvalStigJob) {
  confirm.require({
    message: `Cancel job #${job.jobId}? The scan will be stopped.`,
    header: 'Cancel Evaluation',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    acceptLabel: 'Cancel Scan',
    rejectLabel: 'Keep Running',
    accept: () => doCancel(job)
  })
}

async function doCancel(job: EvalStigJob) {
  try {
    const res = await fetch(`${config.apiBase}/eval-stig/jobs/${job.jobId}`, {
      method: 'DELETE',
      headers: await authHeaders()
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    toast.add({ severity: 'info', summary: 'Job cancelled', detail: `Job #${job.jobId} cancelled`, life: 3000 })
    await loadJobs()
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Cancel failed', detail: (e as Error).message, life: 4000 })
  }
}

// ── After launch ──────────────────────────────────────────────────────────────
async function onLaunched(jobId: number) {
  showRunDialog.value = false
  await loadJobs()
  startPolling()
  router.push(`/eval-stig/${jobId}`)
}

// ── Formatting helpers ────────────────────────────────────────────────────────
function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  try {
    return new Intl.DateTimeFormat(undefined, {
      month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
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

const agentScriptCmd = 'pwsh -File "C:\\Temp\\Evaulate.STIG\\eval-stig-agent.ps1"'

async function copyAgentCmd() {
  try {
    await navigator.clipboard.writeText(agentScriptCmd)
    toast.add({ severity: 'success', summary: 'Copied', detail: 'Command copied to clipboard', life: 2500 })
  } catch {
    toast.add({ severity: 'warn', summary: 'Copy failed', detail: 'Use manual copy', life: 3000 })
  }
}

// ── Remote Start Agent dialog ─────────────────────────────────────────────────
const showStartAgent   = ref(false)
const startAgentBusy   = ref(false)
const startAgentResult = ref<{ started: boolean; pid?: number; stdout?: string; stderr?: string; error?: string; hint?: string } | null>(null)

const winrmHost        = ref('host.docker.internal')
const winrmPort        = ref(5985)
const winrmUseSSL      = ref(false)
const winrmUsername    = ref('')
const winrmPassword    = ref('')
const winrmSkipCert    = ref(true)
const winrmAgentScript = ref('C:\\Temp\\Evaulate.STIG\\eval-stig-agent.ps1')

const winrmProtocols   = [
  { label: 'HTTP (5985) — default', value: false },
  { label: 'HTTPS (5986)',          value: true  },
]

function openStartAgentDialog() {
  startAgentResult.value = null
  winrmPort.value = winrmUseSSL.value ? 5986 : 5985
  showStartAgent.value = true
}

async function remoteStartAgent() {
  if (!winrmUsername.value || !winrmPassword.value) {
    toast.add({ severity: 'warn', summary: 'Credentials required', detail: 'Enter WinRM username and password', life: 3000 })
    return
  }
  startAgentBusy.value   = true
  startAgentResult.value = null
  try {
    const res = await fetch(`${config.apiBase}/eval-stig/agent/start`, {
      method:  'POST',
      headers: { ...(await authHeaders()), 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        host:          winrmHost.value,
        port:          winrmPort.value,
        useSSL:        winrmUseSSL.value,
        username:      winrmUsername.value,
        password:      winrmPassword.value,
        skipCertCheck: winrmSkipCert.value,
        agentScript:   winrmAgentScript.value,
      }),
    })
    const data = await res.json()
    startAgentResult.value = data
    if (res.ok && data.started) {
      toast.add({ severity: 'success', summary: 'Agent started', detail: `PID ${data.pid} on ${winrmHost.value}`, life: 4000 })
      setTimeout(loadStatus, 5000)   // re-check status after 5s
    } else {
      toast.add({ severity: 'error', summary: 'Failed to start', detail: data.error ?? 'Unknown error', life: 5000 })
    }
  } catch (e) {
    startAgentResult.value = { started: false, error: String(e) }
    toast.add({ severity: 'error', summary: 'Network error', detail: String(e), life: 5000 })
  } finally {
    startAgentBusy.value = false
  }
}
</script>

<template>
  <Toast />
  <ConfirmDialog />

  <!-- Remote Start Agent Dialog -->
  <Dialog v-model:visible="showStartAgent" header="Start Eval-STIG Agent Remotely" modal :style="{ width: '480px' }">
    <div class="start-agent-form">
      <p class="muted" style="font-size:0.85rem;margin-bottom:1rem">
        Connects to the Windows host via WinRM and launches the agent process in the background.
      </p>

      <label class="field-label">Target Host</label>
      <InputText v-model="winrmHost" class="full-width" placeholder="host.docker.internal" />

      <label class="field-label" style="margin-top:0.75rem">Protocol</label>
      <Select
        v-model="winrmUseSSL"
        :options="winrmProtocols"
        optionLabel="label"
        optionValue="value"
        class="full-width"
        @change="winrmPort = winrmUseSSL ? 5986 : 5985"
      />

      <label class="field-label" style="margin-top:0.75rem">WinRM Port</label>
      <InputNumber v-model="winrmPort" :min="1" :max="65535" style="width:120px" />

      <Divider />

      <label class="field-label">Windows Username</label>
      <InputText v-model="winrmUsername" class="full-width" placeholder="DOMAIN\user or .\localuser" autocomplete="off" />

      <label class="field-label" style="margin-top:0.75rem">Windows Password</label>
      <Password v-model="winrmPassword" class="full-width" :feedback="false" toggleMask />

      <div class="check-row" style="margin-top:0.75rem">
        <Checkbox v-model="winrmSkipCert" :binary="true" inputId="startSkipCert" />
        <label for="startSkipCert" class="check-label">Skip certificate validation</label>
      </div>

      <Divider />

      <label class="field-label">Agent Script Path (on Windows host)</label>
      <InputText v-model="winrmAgentScript" class="full-width" />

      <!-- Result display -->
      <div v-if="startAgentResult" class="start-result" :class="startAgentResult.started ? 'result-ok' : 'result-err'">
        <div v-if="startAgentResult.started">
          <i class="pi pi-check-circle" /> Agent started — PID {{ startAgentResult.pid }}
          <pre v-if="startAgentResult.stdout" class="result-pre">{{ startAgentResult.stdout }}</pre>
        </div>
        <div v-else>
          <i class="pi pi-times-circle" /> {{ startAgentResult.error }}
          <div v-if="startAgentResult.hint" class="result-hint">{{ startAgentResult.hint }}</div>
          <pre v-if="startAgentResult.stderr" class="result-pre">{{ startAgentResult.stderr }}</pre>
        </div>
      </div>
    </div>

    <template #footer>
      <Button label="Cancel" severity="secondary" outlined @click="showStartAgent = false" :disabled="startAgentBusy" />
      <Button
        label="Start Agent"
        icon="pi pi-play"
        :loading="startAgentBusy"
        @click="remoteStartAgent"
      />
    </template>
  </Dialog>

  <section class="evalst-root">
    <!-- Agent Status Banner -->
    <div v-if="agentStatus" class="banner-row">
      <!-- Available + running -->
      <Message
        v-if="agentStatus.available && agentStatus.agentRunning"
        severity="success"
        :closable="false"
        class="banner-msg"
      >
        <i class="pi pi-check-circle" style="margin-right: 0.4rem" />
        Agent Ready — eval-stig agent is running and accepting jobs.
      </Message>

      <!-- Available but not running -->
      <Message
        v-else-if="agentStatus.available && !agentStatus.agentRunning"
        severity="warn"
        :closable="false"
        class="banner-msg"
      >
        <span style="flex:1">
          <i class="pi pi-exclamation-triangle" style="margin-right: 0.4rem" />
          Agent not running — eval-stig scans will queue until agent starts.
        </span>
        <Button
          label="Start Agent Remotely"
          icon="pi pi-play"
          size="small"
          severity="warn"
          style="margin-left: 1rem"
          @click="openStartAgentDialog"
        />
        <Button
          label="Copy Command"
          icon="pi pi-copy"
          size="small"
          severity="secondary"
          outlined
          style="margin-left: 0.5rem"
          @click="copyAgentCmd"
        />
        <code class="agent-cmd">{{ agentScriptCmd }}</code>
      </Message>

      <!-- Not available -->
      <Message
        v-else
        severity="error"
        :closable="false"
        class="banner-msg"
      >
        <i class="pi pi-times-circle" style="margin-right: 0.4rem" />
        Evaluate-STIG not found — place the Evaluate-STIG folder at
        <code>C:\Temp\Evaulate.STIG</code> on the Windows host, then run
        <code>pwsh -File scripts\setup-eval-stig-agent.ps1</code> to register the agent.
      </Message>
    </div>

    <!-- Page Header -->
    <div class="page-header">
      <h2>Evaluate-STIG Jobs</h2>
      <Button
        label="Launch New Evaluation"
        icon="pi pi-play"
        size="small"
        @click="showRunDialog = true"
      />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <!-- Jobs Table -->
    <DataTable
      :value="jobs"
      :loading="loading"
      dataKey="jobId"
      stripedRows
      responsiveLayout="scroll"
    >
      <template #empty>
        <div class="empty-msg">
          <i class="pi pi-shield empty-icon" />
          <p>No evaluation jobs yet. Launch an evaluation to get started.</p>
        </div>
      </template>

      <Column field="jobId" header="Job ID" sortable style="width: 6rem" />

      <Column header="Collection" style="min-width: 10rem">
        <template #body="{ data }">
          <span>{{ data.collectionId }}</span>
        </template>
      </Column>

      <Column header="Target Hosts" style="min-width: 12rem">
        <template #body="{ data }">
          <div class="tag-wrap">
            <Tag
              v-for="h in (data.targetHosts ?? []).slice(0, 3)"
              :key="h"
              :value="h"
              severity="secondary"
              class="host-tag"
            />
            <Tag
              v-if="(data.targetHosts ?? []).length > 3"
              :value="`+${data.targetHosts.length - 3} more`"
              severity="secondary"
              class="host-tag"
            />
          </div>
        </template>
      </Column>

      <Column header="STIGs" style="width: 8rem">
        <template #body="{ data }">
          <span v-if="!data.selectedStigs" class="muted">All</span>
          <span v-else>{{ data.selectedStigs.length }} selected</span>
        </template>
      </Column>

      <Column header="Status" style="width: 8rem">
        <template #body="{ data }">
          <Tag
            :value="data.status"
            :severity="statusSeverity(data.status)"
            :class="{ 'status-running': data.status === 'running' }"
          />
        </template>
      </Column>

      <Column header="Started" style="width: 11rem">
        <template #body="{ data }">
          <span class="mono-date">{{ fmtDate(data.startedAt) }}</span>
        </template>
      </Column>

      <Column header="Completed" style="width: 11rem">
        <template #body="{ data }">
          <span class="mono-date">{{ fmtDate(data.completedAt) }}</span>
        </template>
      </Column>

      <Column header="Imported" style="width: 7rem; text-align: center">
        <template #body="{ data }">
          <span v-if="data.importedCount > 0" class="import-count">{{ data.importedCount }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <Column header="" style="width: 10rem; text-align: right">
        <template #body="{ data }">
          <span class="row-action">
            <Button
              icon="pi pi-eye"
              size="small"
              severity="secondary"
              text
              rounded
              title="View job detail"
              @click="router.push(`/eval-stig/${data.jobId}`)"
            />
            <Button
              v-if="data.status === 'pending' || data.status === 'running'"
              icon="pi pi-times"
              size="small"
              severity="danger"
              text
              rounded
              title="Cancel job"
              @click="confirmCancel(data)"
            />
          </span>
        </template>
      </Column>
    </DataTable>

    <!-- Run Dialog -->
    <EvalStigRunDialog
      v-model:visible="showRunDialog"
      @launched="onLaunched"
    />
  </section>
</template>

<style scoped>
.evalst-root  { padding: 0.5rem 1rem 3rem; max-width: 1200px; }

.banner-row   { margin-bottom: 1rem; }
.banner-msg   { width: 100%; }
.agent-cmd    {
  display: inline-block;
  font-size: 0.78rem;
  font-family: monospace;
  background: var(--p-surface-100, #f3f4f6);
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  margin-left: 0.75rem;
  word-break: break-all;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}
.page-header h2 { margin: 0; }

.err   { color: #f85149; margin-bottom: 0.75rem; }
.muted { color: var(--p-text-muted-color, #6b7280); }

.tag-wrap  { display: flex; flex-wrap: wrap; gap: 0.25rem; }
.host-tag  { font-size: 0.75rem; }

.mono-date { font-size: 0.85rem; font-variant-numeric: tabular-nums; }

.import-count {
  font-weight: 600;
  color: var(--p-green-600, #16a34a);
}

.row-action {
  display: flex;
  gap: 0.25rem;
  justify-content: flex-end;
}

.empty-msg  {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 2.5rem 1rem;
  color: var(--p-text-muted-color, #6b7280);
}
.empty-icon { font-size: 2.5rem; opacity: 0.35; }

/* Pulse animation for running jobs */
.status-running { animation: pulse 1.5s infinite; }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.5; }
}

.start-agent-form .field-label {
  display: block;
  font-size: 0.82rem;
  font-weight: 500;
  margin-bottom: 0.3rem;
  color: var(--p-text-muted-color, #6b7280);
}
.start-agent-form .full-width { width: 100%; }
.start-agent-form .check-row  { display: flex; align-items: center; gap: 0.5rem; }
.start-agent-form .check-label { font-size: 0.88rem; cursor: pointer; }

.start-result {
  margin-top: 1rem;
  padding: 0.6rem 0.8rem;
  border-radius: 6px;
  font-size: 0.85rem;
}
.result-ok  { background: var(--p-green-50, #f0fdf4); border: 1px solid var(--p-green-300, #86efac); color: var(--p-green-800, #166534); }
.result-err { background: var(--p-red-50,   #fef2f2); border: 1px solid var(--p-red-300,   #fca5a5); color: var(--p-red-800,   #991b1b); }
.result-pre { font-size: 0.75rem; margin-top: 0.4rem; white-space: pre-wrap; word-break: break-all; }
.result-hint { font-size: 0.78rem; margin-top: 0.3rem; opacity: 0.8; font-style: italic; }
</style>
