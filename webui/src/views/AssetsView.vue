<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import { useConfirm } from 'primevue/useconfirm'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'
import { useToast } from 'primevue/usetoast'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'
import type { Stig } from '../api/types'
import CsvImportDialog from '../components/CsvImportDialog.vue'
import MetadataPanel from '../components/MetadataPanel.vue'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface Asset {
  assetId: number
  name: string
  fqdn?: string | null
  ip?: string | null
  mac?: string | null
  state?: string | null
  stigCount?: number
}

interface AssetForm {
  assetId: number | null
  name: string
  fqdn: string
  ip: string
  mac: string
}

// ---------------------------------------------------------------------------
// Props / router
// ---------------------------------------------------------------------------
const props = defineProps<{ collectionId: string }>()
const cid = Number(props.collectionId)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const assets = ref<Asset[]>([])
const loading = ref(true)
const error = ref('')

// Expanded rows for inline metadata panel
const expandedRows = ref<Record<number, boolean>>({})

const assetDialogVisible = ref(false)
const editMode = ref(false)
const saving = ref(false)

const csvImportVisible = ref(false)

const form = ref<AssetForm>({ assetId: null, name: '', fqdn: '', ip: '', mac: '' })

// STIG assignment
const stigDialogVisible = ref(false)
const stigDialogAsset = ref<Asset | null>(null)
const stigs = ref<Stig[]>([])
const stigsLoading = ref(false)
const selectedStig = ref<Stig | null>(null)
const assigning = ref(false)

const confirm = useConfirm()
const toast = useToast()

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------
async function bearerHeaders(): Promise<HeadersInit> {
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

async function loadAssets() {
  loading.value = true
  error.value = ''
  try {
    const headers = await bearerHeaders()
    const res = await fetch(`${config.apiBase}/collections/${cid}/assets`, { headers })
    if (!res.ok) throw new Error(await res.text())
    assets.value = await res.json()
  } catch (e) {
    error.value = `Failed to load assets: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

onMounted(loadAssets)

// ---------------------------------------------------------------------------
// Create / Edit asset dialog
// ---------------------------------------------------------------------------
function openAdd() {
  editMode.value = false
  form.value = { assetId: null, name: '', fqdn: '', ip: '', mac: '' }
  assetDialogVisible.value = true
}

function openEdit(a: Asset) {
  editMode.value = true
  form.value = {
    assetId: a.assetId,
    name: a.name,
    fqdn: a.fqdn ?? '',
    ip: a.ip ?? '',
    mac: a.mac ?? ''
  }
  assetDialogVisible.value = true
}

async function saveAsset() {
  if (!form.value.name.trim()) return
  saving.value = true
  error.value = ''
  try {
    const headers = await bearerHeaders()
    const body: Record<string, unknown> = {
      name: form.value.name.trim(),
      fqdn: form.value.fqdn.trim() || null,
      ip: form.value.ip.trim() || null,
      mac: form.value.mac.trim() || null,
      collectionId: cid
    }
    if (editMode.value && form.value.assetId != null) {
      const res = await fetch(`${config.apiBase}/assets/${form.value.assetId}`, {
        method: 'PUT', headers, body: JSON.stringify(body)
      })
      if (!res.ok) throw new Error(await res.text())
      toast.add({ severity: 'success', summary: 'Asset updated', life: 3000 })
    } else {
      const res = await fetch(`${config.apiBase}/collections/${cid}/assets`, {
        method: 'POST', headers, body: JSON.stringify(body)
      })
      if (!res.ok) throw new Error(await res.text())
      toast.add({ severity: 'success', summary: 'Asset created', life: 3000 })
    }
    assetDialogVisible.value = false
    await loadAssets()
  } catch (e) {
    error.value = `Save failed: ${(e as Error).message}`
  } finally {
    saving.value = false
  }
}

// ---------------------------------------------------------------------------
// Delete asset (soft-delete)
// ---------------------------------------------------------------------------
function deleteAsset(a: Asset) {
  confirm.require({
    message: `Archive asset "${a.name}"? It will be soft-deleted and removed from this collection.`,
    header: 'Archive Asset',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: 'Cancel',
    acceptLabel: 'Archive',
    acceptClass: 'p-button-danger',
    accept: async () => {
      error.value = ''
      try {
        const headers = await bearerHeaders()
        const res = await fetch(`${config.apiBase}/assets/${a.assetId}`, {
          method: 'DELETE', headers
        })
        if (!res.ok) throw new Error(await res.text())
        toast.add({ severity: 'info', summary: 'Asset archived', life: 3000 })
        await loadAssets()
      } catch (e) {
        error.value = `Delete failed: ${(e as Error).message}`
      }
    }
  })
}

// ---------------------------------------------------------------------------
// Assign STIG
// ---------------------------------------------------------------------------
async function openAssignStig(a: Asset) {
  stigDialogAsset.value = a
  selectedStig.value = null
  stigDialogVisible.value = true
  stigsLoading.value = true
  try {
    const headers = await bearerHeaders()
    const res = await fetch(`${config.apiBase}/stigs`, { headers })
    if (!res.ok) throw new Error(await res.text())
    stigs.value = await res.json()
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Failed to load STIGs', detail: (e as Error).message, life: 5000 })
  } finally {
    stigsLoading.value = false
  }
}

async function assignStig() {
  if (!selectedStig.value || !stigDialogAsset.value) return
  assigning.value = true
  try {
    const headers = await bearerHeaders()
    const res = await fetch(
      `${config.apiBase}/collections/${cid}/assets/${stigDialogAsset.value.assetId}/stigs`,
      {
        method: 'POST',
        headers,
        body: JSON.stringify({ benchmarkId: selectedStig.value.benchmarkId })
      }
    )
    if (!res.ok) throw new Error(await res.text())
    toast.add({ severity: 'success', summary: 'STIG assigned', detail: selectedStig.value.benchmarkId, life: 3000 })
    stigDialogVisible.value = false
    await loadAssets()
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Assignment failed', detail: (e as Error).message, life: 5000 })
  } finally {
    assigning.value = false
  }
}

// ---------------------------------------------------------------------------
// Download CKL / CKLB
// ---------------------------------------------------------------------------
async function downloadChecklist(a: Asset, format: 'ckl' | 'cklb') {
  try {
    const token = await getAccessToken()
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {}
    const res = await fetch(
      `${config.apiBase}/assets/${a.assetId}/checklists?format=${format}`,
      { headers }
    )
    if (!res.ok) throw new Error(await res.text())
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${a.name}.${format}`
    link.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    toast.add({ severity: 'error', summary: `Download ${format.toUpperCase()} failed`, detail: (e as Error).message, life: 5000 })
  }
}

// ---------------------------------------------------------------------------
// Export assets CSV
// ---------------------------------------------------------------------------
const exportingCsv = ref(false)

async function exportAssetsCsv() {
  exportingCsv.value = true
  error.value = ''
  try {
    const headers = await bearerHeaders()
    const res = await fetch(`${config.apiBase}/assets?collectionId=${cid}&format=csv`, { headers })
    if (!res.ok) throw new Error(await res.text())
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `collection-${cid}-assets.csv`
    link.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    error.value = `CSV export failed: ${(e as Error).message}`
  } finally {
    exportingCsv.value = false
  }
}

// ---------------------------------------------------------------------------
// Download XCCDF — fetches asset checklists then downloads one per benchmark
// ---------------------------------------------------------------------------
async function downloadXccdf(a: Asset) {
  try {
    const token = await getAccessToken()
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {}

    // Fetch the list of available checklists (benchmarkIds) for the asset
    const listRes = await fetch(`${config.apiBase}/assets/${a.assetId}/checklists`, { headers })
    if (!listRes.ok) throw new Error(await listRes.text())
    const checklists: { benchmarkId: string }[] = await listRes.json()

    if (checklists.length === 0) {
      toast.add({ severity: 'warn', summary: 'No checklists', detail: 'This asset has no reviewed benchmarks to export.', life: 4000 })
      return
    }

    // Download the first available benchmark as XCCDF
    const benchmarkId = checklists[0].benchmarkId
    const res = await fetch(
      `${config.apiBase}/assets/${a.assetId}/checklists/${encodeURIComponent(benchmarkId)}/xccdf`,
      { headers }
    )
    if (!res.ok) throw new Error(await res.text())
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${a.name}-${benchmarkId}.xccdf.xml`
    link.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Download XCCDF failed', detail: (e as Error).message, life: 5000 })
  }
}

// ---------------------------------------------------------------------------
// State badge
// ---------------------------------------------------------------------------
function stateSeverity(state?: string | null): 'success' | 'warn' | 'danger' | 'secondary' {
  switch (state) {
    case 'active':   return 'success'
    case 'inactive': return 'secondary'
    case 'archived': return 'danger'
    default:         return 'warn'
  }
}
</script>

<template>
  <Toast />
  <ConfirmDialog />
  <section>
    <div class="view-header">
      <div>
        <p><router-link :to="`/collections/${cid}`">&larr; Collection</router-link></p>
        <h2>Assets</h2>
      </div>
      <div class="toolbar-actions">
        <Button
          label="Export CSV"
          icon="pi pi-file-export"
          size="small"
          severity="secondary"
          :loading="exportingCsv"
          @click="exportAssetsCsv"
        />
        <Button
          label="Import Assets (CSV)"
          icon="pi pi-file-import"
          size="small"
          severity="secondary"
          @click="csvImportVisible = true"
        />
        <Button label="New Asset" icon="pi pi-plus" size="small" @click="openAdd" />
      </div>
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="assets"
      :loading="loading"
      dataKey="assetId"
      v-model:expandedRows="expandedRows"
      stripedRows
      paginator
      :rows="20"
      responsiveLayout="scroll"
    >
      <template #empty>
        <span class="muted">No assets in this collection. Create one or import a checklist.</span>
      </template>

      <!-- Row expansion: inline metadata panel -->
      <template #expansion="{ data }">
        <div class="asset-meta-expansion">
          <div class="asset-meta-label">Custom Metadata</div>
          <MetadataPanel entityType="asset" :entityId="data.assetId" />
        </div>
      </template>

      <!-- Expander toggle column -->
      <Column expander style="width: 3rem" />

      <Column field="name" header="Name" sortable style="min-width: 12rem" />
      <Column field="fqdn" header="FQDN" sortable style="min-width: 14rem">
        <template #body="{ data }">
          <span v-if="data.fqdn">{{ data.fqdn }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column field="ip" header="IP Address" style="width: 11rem">
        <template #body="{ data }">
          <span v-if="data.ip">{{ data.ip }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column header="State" style="width: 8rem">
        <template #body="{ data }">
          <Tag
            v-if="data.state"
            :value="data.state"
            :severity="stateSeverity(data.state)"
          />
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column header="STIGs" style="width: 6rem; text-align: right">
        <template #body="{ data }">
          <Tag
            v-if="data.stigCount != null"
            :value="String(data.stigCount)"
            severity="secondary"
          />
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column header="" style="width: 28rem; text-align: right">
        <template #body="{ data }">
          <div class="row-actions">
            <Button
              label="Assign STIG"
              icon="pi pi-plus-circle"
              size="small"
              severity="secondary"
              text
              @click="openAssignStig(data)"
            />
            <Button
              label="CKL"
              icon="pi pi-download"
              size="small"
              severity="secondary"
              text
              @click="downloadChecklist(data, 'ckl')"
            />
            <Button
              label="CKLB"
              icon="pi pi-download"
              size="small"
              severity="secondary"
              text
              @click="downloadChecklist(data, 'cklb')"
            />
            <Button
              label="XCCDF"
              icon="pi pi-download"
              size="small"
              severity="secondary"
              text
              @click="downloadXccdf(data)"
            />
            <Button icon="pi pi-pencil" size="small" text severity="secondary" @click="openEdit(data)" />
            <Button icon="pi pi-trash" size="small" text severity="danger" @click="deleteAsset(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- CSV import dialog -->
    <CsvImportDialog
      v-model:visible="csvImportVisible"
      :collection-id="cid"
      @imported="loadAssets"
    />

    <!-- Create / Edit asset dialog -->
    <Dialog
      v-model:visible="assetDialogVisible"
      :header="editMode ? 'Edit Asset' : 'New Asset'"
      modal
      :style="{ width: '32rem' }"
    >
      <div class="form-grid">
        <label>Name <span class="req">*</span></label>
        <InputText v-model="form.name" placeholder="e.g. web-server-01" maxlength="255" autofocus />

        <label>FQDN</label>
        <InputText v-model="form.fqdn" placeholder="e.g. web-server-01.example.com" maxlength="255" />

        <label>IP Address</label>
        <InputText v-model="form.ip" placeholder="e.g. 192.168.1.100" maxlength="64" />

        <label>MAC Address</label>
        <InputText v-model="form.mac" placeholder="e.g. AA:BB:CC:DD:EE:FF" maxlength="64" />
      </div>

      <p v-if="error" class="err" style="margin-top: 0.75rem">{{ error }}</p>

      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="assetDialogVisible = false" />
        <Button
          :label="editMode ? 'Save' : 'Create'"
          icon="pi pi-check"
          :loading="saving"
          :disabled="!form.name.trim()"
          @click="saveAsset"
        />
      </template>
    </Dialog>

    <!-- Assign STIG dialog -->
    <Dialog
      v-model:visible="stigDialogVisible"
      :header="`Assign STIG — ${stigDialogAsset?.name ?? ''}`"
      modal
      :style="{ width: '36rem' }"
    >
      <p class="muted" style="margin-top: 0">Select a STIG from the library to assign to this asset.</p>

      <Select
        v-model="selectedStig"
        :options="stigs"
        optionLabel="benchmarkId"
        :loading="stigsLoading"
        placeholder="Select STIG…"
        filter
        filterPlaceholder="Search benchmarks…"
        style="width: 100%"
      >
        <template #option="{ option }">
          <div>
            <span class="stig-id">{{ option.benchmarkId }}</span>
            <span class="stig-title muted"> — {{ option.title }}</span>
          </div>
        </template>
      </Select>

      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="stigDialogVisible = false" />
        <Button
          label="Assign"
          icon="pi pi-check"
          :loading="assigning"
          :disabled="!selectedStig"
          @click="assignStig"
        />
      </template>
    </Dialog>
  </section>
</template>

<style scoped>
.view-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}
.view-header h2 { margin: 0; }
.toolbar-actions { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
.row-actions { display: flex; gap: 0.15rem; justify-content: flex-end; align-items: center; flex-wrap: wrap; }
.form-grid {
  display: grid;
  grid-template-columns: 9rem 1fr;
  gap: 0.75rem 1rem;
  align-items: center;
  padding: 0.25rem 0;
}
.req { color: #f85149; }
.err { color: #f85149; }
.stig-id { font-family: monospace; font-size: 0.9rem; }
.stig-title { font-size: 0.85rem; }

/* Asset metadata expansion */
.asset-meta-expansion {
  padding: 0.75rem 1rem;
  background: var(--p-surface-50, #13131f);
}
.asset-meta-label {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--p-text-muted-color);
  margin-bottom: 0.5rem;
}
</style>
