<script setup lang="ts">
import { ref, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import Select from 'primevue/select'
import MultiSelect from 'primevue/multiselect'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Textarea from 'primevue/textarea'
import Checkbox from 'primevue/checkbox'
import Password from 'primevue/password'
import Divider from 'primevue/divider'
import Toast from 'primevue/toast'
import type { Collection, Asset } from '../api/types'
import { api } from '../api/client'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'

// ── Props / Emits ─────────────────────────────────────────────────────────────
const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'launched', jobId: number): void
}>()

const toast = useToast()

// ── Stepper state ─────────────────────────────────────────────────────────────
const step = ref(1)
const totalSteps = 4

// ── Step 1 — Collection ───────────────────────────────────────────────────────
const collections = ref<Collection[]>([])
const selectedCollection = ref<Collection | null>(null)
const collectionsLoading = ref(false)

// ── Step 2 — Target Hosts ─────────────────────────────────────────────────────
const assets = ref<Asset[]>([])
const assetsLoading = ref(false)
const hostInputMode = ref<'assets' | 'manual'>('assets')
const selectedAssets = ref<string[]>([])
const manualHosts = ref('')
const bulkHosts = ref('')

// ── Step 3 — STIGs ────────────────────────────────────────────────────────────
const allStigs = ref(true)
const availableStigs = ref<{ label: string; value: string; group: string }[]>([])
const selectedStigs = ref<string[]>([])
const stigsLoading = ref(false)

const stigGroups = [
  'Windows', 'Browsers', 'Office', 'Security', 'Database', 'Server', 'Other'
]

function stigGroupFor(title: string): string {
  const t = title.toLowerCase()
  if (t.includes('windows')) return 'Windows'
  if (t.includes('chrome') || t.includes('firefox') || t.includes('edge') || t.includes('browser')) return 'Browsers'
  if (t.includes('office') || t.includes('word') || t.includes('excel') || t.includes('outlook') || t.includes('teams')) return 'Office'
  if (t.includes('defender') || t.includes('firewall') || t.includes('bitlocker') || t.includes('antivirus')) return 'Security'
  if (t.includes('sql') || t.includes('oracle') || t.includes('database')) return 'Database'
  if (t.includes('iis') || t.includes('apache') || t.includes('nginx') || t.includes('server')) return 'Server'
  return 'Other'
}

function groupedStigs() {
  const map = new Map<string, { label: string; items: { label: string; value: string }[] }>()
  for (const g of stigGroups) map.set(g, { label: g, items: [] })
  for (const s of availableStigs.value) {
    map.get(s.group)?.items.push({ label: s.label, value: s.value })
  }
  return [...map.values()].filter(g => g.items.length > 0)
}

// ── Step 4 — Credentials & Options ────────────────────────────────────────────
const username = ref('')
const password = ref('')
const outputPath = ref('C:\\Temp\\EvalSTIG-Results')
const showAdvanced = ref(false)
const vdiMode = ref(false)
const checkTimeout = ref(15)
// WinRM connection — default HTTPS/5986 per DoD standard
const winrmUseSSL = ref(true)
const winrmPort = ref(5986)
const winrmSkipCert = ref(true)

// ── Submission state ──────────────────────────────────────────────────────────
const launching = ref(false)

// ── Auth helper ───────────────────────────────────────────────────────────────
async function authHeaders(): Promise<HeadersInit> {
  const token = await getAccessToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

// ── Reset on open ─────────────────────────────────────────────────────────────
watch(() => props.visible, async (v) => {
  if (v) {
    step.value = 1
    selectedCollection.value = null
    assets.value = []
    hostInputMode.value = 'assets'
    selectedAssets.value = []
    manualHosts.value = ''
    bulkHosts.value = ''
    allStigs.value = true
    selectedStigs.value = []
    username.value = ''
    password.value = ''
    outputPath.value = 'C:\\Temp\\EvalSTIG-Results'
    showAdvanced.value = false
    vdiMode.value = false
    checkTimeout.value = 15
    winrmUseSSL.value = true
    winrmPort.value = 5986
    winrmSkipCert.value = true
    await loadCollections()
  }
})

// ── Load collections ──────────────────────────────────────────────────────────
async function loadCollections() {
  collectionsLoading.value = true
  const { data } = await api.GET('/collections')
  collections.value = data ?? []
  collectionsLoading.value = false
}

// ── On collection select — load assets ────────────────────────────────────────
async function onCollectionSelect() {
  if (!selectedCollection.value) return
  assetsLoading.value = true
  const { data } = await api.GET('/collections/{id}/assets', {
    params: { path: { id: selectedCollection.value.collectionId } }
  })
  assets.value = data ?? []
  assetsLoading.value = false
}

// ── Load STIGs on step 3 ──────────────────────────────────────────────────────
async function loadStigs() {
  if (availableStigs.value.length > 0) return
  stigsLoading.value = true
  try {
    const res = await fetch(`${config.apiBase}/eval-stig/stigs`, {
      headers: await authHeaders()
    })
    if (res.ok) {
      const data: string[] = await res.json()
      availableStigs.value = data.map(s => ({
        label: s,
        value: s,
        group: stigGroupFor(s)
      }))
    }
  } finally {
    stigsLoading.value = false
  }
}

// ── Navigation ────────────────────────────────────────────────────────────────
async function nextStep() {
  if (step.value === 3) await loadStigs()
  if (step.value < totalSteps) step.value++
}

function prevStep() {
  if (step.value > 1) step.value--
}

// ── Build target hosts list ───────────────────────────────────────────────────
function buildTargetHosts(): string[] {
  if (hostInputMode.value === 'assets') {
    return selectedAssets.value
  }
  // Manual — combine comma-separated and bulk (line-separated)
  const fromManual = manualHosts.value
    .split(',')
    .map(h => h.trim())
    .filter(h => h.length > 0)
  const fromBulk = bulkHosts.value
    .split('\n')
    .map(h => h.trim())
    .filter(h => h.length > 0)
  return [...new Set([...fromManual, ...fromBulk])]
}

// ── Validation ────────────────────────────────────────────────────────────────
function canProceed(): boolean {
  if (step.value === 1) return !!selectedCollection.value
  if (step.value === 2) return buildTargetHosts().length > 0
  if (step.value === 3) return allStigs.value || selectedStigs.value.length > 0
  return true
}

// ── Launch ────────────────────────────────────────────────────────────────────
async function launch() {
  if (!selectedCollection.value) return
  launching.value = true
  try {
    const body = {
      collectionId: selectedCollection.value.collectionId,
      targetHosts: buildTargetHosts(),
      selectedStigs: allStigs.value ? null : selectedStigs.value,
      outputPath: outputPath.value,
      credential: (username.value && password.value)
        ? { username: username.value, password: password.value }
        : undefined,
      vdiMode: vdiMode.value,
      vulnTimeout: checkTimeout.value,
      // WinRM connection settings
      winrmUseSSL: winrmUseSSL.value,
      winrmPort: winrmPort.value,
      winrmSkipCertCheck: winrmSkipCert.value
    }
    const res = await fetch(`${config.apiBase}/eval-stig/jobs`, {
      method: 'POST',
      headers: {
        ...(await authHeaders()),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    })
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}))
      throw new Error(String((errData as Record<string, unknown>).error ?? `HTTP ${res.status}`))
    }
    const newJob = await res.json() as { jobId: number }
    emit('launched', newJob.jobId)
    close()
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Launch failed', detail: (e as Error).message, life: 5000 })
  } finally {
    launching.value = false
  }
}

function close() {
  emit('update:visible', false)
}
</script>

<template>
  <Toast />

  <Dialog
    :visible="visible"
    modal
    header="Launch New Evaluation"
    :style="{ width: '620px', maxWidth: '95vw' }"
    @update:visible="close"
  >
    <!-- Step indicator -->
    <div class="stepper-header">
      <div
        v-for="n in totalSteps"
        :key="n"
        class="step-dot"
        :class="{ active: n === step, done: n < step }"
      >
        <span class="step-num">{{ n }}</span>
      </div>
      <span class="step-label">Step {{ step }} of {{ totalSteps }}</span>
    </div>

    <Divider style="margin: 0.5rem 0 1rem" />

    <!-- ── Step 1: Select Collection ── -->
    <div v-if="step === 1" class="step-body">
      <h3 class="step-title">Select Collection</h3>
      <p class="step-desc muted">Choose which STIG Manager collection will receive the scan results.</p>

      <label class="field-label">Collection</label>
      <Select
        v-model="selectedCollection"
        :options="collections"
        :loading="collectionsLoading"
        optionLabel="name"
        placeholder="Select a collection..."
        filter
        class="full-width"
        @change="onCollectionSelect"
      />
    </div>

    <!-- ── Step 2: Target Hosts ── -->
    <div v-if="step === 2" class="step-body">
      <h3 class="step-title">Target Hosts</h3>
      <p class="step-desc muted">Select or enter the hosts to scan.</p>

      <div class="toggle-row">
        <Button
          label="From Collection Assets"
          size="small"
          :severity="hostInputMode === 'assets' ? 'primary' : 'secondary'"
          :outlined="hostInputMode !== 'assets'"
          @click="hostInputMode = 'assets'"
        />
        <Button
          label="Manual Entry"
          size="small"
          :severity="hostInputMode === 'manual' ? 'primary' : 'secondary'"
          :outlined="hostInputMode !== 'manual'"
          @click="hostInputMode = 'manual'"
        />
      </div>

      <!-- From assets -->
      <template v-if="hostInputMode === 'assets'">
        <label class="field-label">Assets in Collection</label>
        <MultiSelect
          v-model="selectedAssets"
          :options="assets.map(a => a.name)"
          :loading="assetsLoading"
          placeholder="Select assets..."
          filter
          display="chip"
          class="full-width"
        />
        <p v-if="assets.length === 0 && !assetsLoading" class="muted hint">
          No assets found in the selected collection.
        </p>
      </template>

      <!-- Manual -->
      <template v-else>
        <label class="field-label">Hostnames (comma-separated)</label>
        <InputText
          v-model="manualHosts"
          placeholder="host1.domain.com, host2, 192.168.1.10"
          class="full-width"
        />
        <label class="field-label" style="margin-top: 0.75rem">Bulk Paste (one per line)</label>
        <Textarea
          v-model="bulkHosts"
          placeholder="host3.domain.com&#10;host4.domain.com&#10;192.168.1.20"
          rows="5"
          class="full-width"
        />
      </template>

      <div class="host-count" v-if="buildTargetHosts().length > 0">
        <i class="pi pi-check-circle" style="color: #4ade80" />
        {{ buildTargetHosts().length }} host{{ buildTargetHosts().length !== 1 ? 's' : '' }} selected
      </div>
    </div>

    <!-- ── Step 3: Select STIGs ── -->
    <div v-if="step === 3" class="step-body">
      <h3 class="step-title">Select STIGs</h3>
      <p class="step-desc muted">Choose which STIG checklists to run against the target hosts.</p>

      <div class="check-row">
        <Checkbox v-model="allStigs" :binary="true" inputId="allStigs" />
        <label for="allStigs" class="check-label">All applicable STIGs (recommended)</label>
      </div>

      <template v-if="!allStigs">
        <label class="field-label" style="margin-top: 0.75rem">Select STIGs</label>
        <MultiSelect
          v-model="selectedStigs"
          :options="groupedStigs()"
          optionLabel="label"
          optionValue="value"
          optionGroupLabel="label"
          optionGroupChildren="items"
          :loading="stigsLoading"
          placeholder="Search and select STIGs..."
          filter
          display="chip"
          class="full-width"
          style="max-height: 220px"
        />
      </template>
    </div>

    <!-- ── Step 4: Credentials & Options ── -->
    <div v-if="step === 4" class="step-body">
      <h3 class="step-title">Credentials &amp; Options</h3>

      <div class="cred-note">
        <i class="pi pi-info-circle" />
        Credentials are used for this scan only and are not stored in the database.
      </div>

      <label class="field-label">Username</label>
      <InputText
        v-model="username"
        placeholder="domain\\username or username@domain"
        class="full-width"
        autocomplete="off"
      />

      <label class="field-label" style="margin-top: 0.75rem">Password</label>
      <Password
        v-model="password"
        placeholder="Scan account password"
        class="full-width"
        :feedback="false"
        toggleMask
      />

      <label class="field-label" style="margin-top: 0.75rem">Output Path</label>
      <InputText
        v-model="outputPath"
        placeholder="C:\Temp\EvalSTIG-Results"
        class="full-width"
      />

      <!-- Advanced toggle -->
      <div style="margin-top: 1rem">
        <Button
          :label="showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Options'"
          icon="pi pi-sliders-h"
          text
          size="small"
          @click="showAdvanced = !showAdvanced"
        />
      </div>

      <template v-if="showAdvanced">
        <Divider />

        <div class="check-row" style="margin-bottom: 0.75rem">
          <Checkbox v-model="vdiMode" :binary="true" inputId="vdiMode" />
          <label for="vdiMode" class="check-label">
            VDI Mode
            <span class="muted" style="font-size: 0.8rem; margin-left: 0.3rem">(optimize for non-persistent virtual desktops)</span>
          </label>
        </div>

        <label class="field-label">Per-check Timeout (minutes)</label>
        <InputNumber
          v-model="checkTimeout"
          :min="1"
          :max="1440"
          showButtons
          style="width: 160px"
        />

        <!-- WinRM Connection Settings -->
        <Divider />
        <div style="font-weight:600;font-size:0.875rem;margin-bottom:0.5rem">
          <i class="pi pi-lock" style="margin-right:0.35rem;color:var(--p-primary-color,#58a6ff)" />
          WinRM Connection (remote scans)
        </div>

        <div class="winrm-row">
          <div class="winrm-field">
            <label class="field-label">Protocol</label>
            <Select
              v-model="winrmUseSSL"
              :options="[{label:'HTTPS (5986) — Recommended',value:true},{label:'HTTP (5985) — Lab only',value:false}]"
              optionLabel="label"
              optionValue="value"
              style="width:100%"
              @change="winrmPort = winrmUseSSL ? 5986 : 5985"
            />
          </div>
          <div class="winrm-field" style="max-width:110px">
            <label class="field-label">Port</label>
            <InputNumber v-model="winrmPort" :min="1" :max="65535" style="width:100%" />
          </div>
        </div>

        <div class="check-row" style="margin-top:0.5rem">
          <Checkbox v-model="winrmSkipCert" :binary="true" inputId="winrmSkipCert" />
          <label for="winrmSkipCert" class="check-label">
            Skip HTTPS certificate validation
            <span class="muted" style="font-size:0.78rem;margin-left:0.3rem">(required for self-signed / lab certs)</span>
          </label>
        </div>

        <div class="winrm-info muted" style="font-size:0.78rem;margin-top:0.4rem">
          Ensure WinRM HTTPS is enabled on each target:<br/>
          <code style="font-size:0.78rem">Enable-PSRemoting -Force</code> then
          <code style="font-size:0.78rem">winrm quickconfig -transport:https</code>
        </div>
      </template>
    </div>

    <!-- Footer -->
    <template #footer>
      <div class="dialog-footer">
        <Button
          v-if="step > 1"
          label="Back"
          icon="pi pi-arrow-left"
          severity="secondary"
          outlined
          @click="prevStep"
          :disabled="launching"
        />
        <Button
          v-if="step < totalSteps"
          label="Next"
          icon="pi pi-arrow-right"
          iconPos="right"
          :disabled="!canProceed()"
          @click="nextStep"
        />
        <Button
          v-if="step === totalSteps"
          label="Launch Scan"
          icon="pi pi-play"
          :loading="launching"
          :disabled="!canProceed() || launching"
          @click="launch"
        />
      </div>
    </template>
  </Dialog>
</template>

<style scoped>
.stepper-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.step-dot {
  width: 28px; height: 28px;
  border-radius: 50%;
  background: var(--p-surface-200, #e5e7eb);
  color: var(--p-text-muted-color, #6b7280);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.82rem;
  font-weight: 600;
  transition: background 0.2s, color 0.2s;
}
.step-dot.active {
  background: var(--p-primary-color, #3b82f6);
  color: #fff;
}
.step-dot.done {
  background: var(--p-green-500, #22c55e);
  color: #fff;
}
.step-num { line-height: 1; }
.step-label {
  margin-left: 0.5rem;
  font-size: 0.82rem;
  color: var(--p-text-muted-color, #6b7280);
}

.step-body { min-height: 220px; }

.step-title {
  margin: 0 0 0.25rem;
  font-size: 1.05rem;
  font-weight: 600;
}
.step-desc { margin: 0 0 1rem; font-size: 0.875rem; }
.muted     { color: var(--p-text-muted-color, #6b7280); }

.field-label {
  display: block;
  font-size: 0.82rem;
  font-weight: 600;
  margin-bottom: 0.3rem;
  color: var(--p-text-muted-color, #374151);
}

.full-width { width: 100%; }

.toggle-row {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}

.hint {
  font-size: 0.8rem;
  margin: 0.3rem 0 0;
}

.host-count {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin-top: 0.5rem;
  font-size: 0.85rem;
  font-weight: 500;
}

.check-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.check-label {
  font-size: 0.9rem;
  cursor: pointer;
}

.winrm-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: flex-end;
  margin-top: 0.4rem;
}
.winrm-field {
  flex: 1;
  min-width: 180px;
}
.winrm-info {
  color: var(--p-text-muted-color, #6b7280);
  background: var(--p-surface-100, #1a1a2e);
  border-left: 3px solid var(--p-primary-color, #58a6ff);
  padding: 0.4rem 0.6rem;
  border-radius: 0 4px 4px 0;
  margin-top: 0.4rem;
}

.cred-note {
  display: flex;
  align-items: flex-start;
  gap: 0.4rem;
  padding: 0.5rem 0.75rem;
  background: var(--p-blue-50, #eff6ff);
  border: 1px solid var(--p-blue-200, #bfdbfe);
  border-radius: 6px;
  font-size: 0.83rem;
  color: var(--p-blue-800, #1e40af);
  margin-bottom: 0.75rem;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
</style>
