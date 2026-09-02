<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import ColorPicker from 'primevue/colorpicker'
import { useConfirm } from 'primevue/useconfirm'
import ConfirmDialog from 'primevue/confirmdialog'

// ---------- types ----------
interface Label {
  labelId: number
  name: string
  color: string   // hex without '#', e.g. "3b82f6"
  description?: string | null
  uses?: number   // asset count from API if available
}

// ---------- props ----------
const props = defineProps<{ collectionId: string }>()
const cid = Number(props.collectionId)

// ---------- state ----------
const labels = ref<Label[]>([])
const loading = ref(true)
const error = ref('')

const dialogVisible = ref(false)
const editMode = ref(false)
const saving = ref(false)

const form = ref<{ labelId: number | null; name: string; color: string; description: string }>({
  labelId: null, name: '', color: '3b82f6', description: ''
})

const confirm = useConfirm()

// ---------- API helpers ----------
async function getBearerHeaders(): Promise<HeadersInit> {
  const { getAccessToken } = await import('../../auth/oidc')
  const token = await getAccessToken()
  return token ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' }
}

async function loadLabels() {
  loading.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const res = await fetch(`${config.apiBase}/collections/${cid}/labels`, { headers })
    if (!res.ok) throw new Error(await res.text())
    labels.value = await res.json()
  } catch (e) {
    error.value = `Failed to load labels: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

onMounted(loadLabels)

// ---------- dialog ----------
function openAdd() {
  editMode.value = false
  form.value = { labelId: null, name: '', color: '3b82f6', description: '' }
  dialogVisible.value = true
}

function openEdit(l: Label) {
  editMode.value = true
  form.value = {
    labelId: l.labelId,
    name: l.name,
    color: l.color.replace('#', ''),
    description: l.description ?? ''
  }
  dialogVisible.value = true
}

async function saveLabel() {
  if (!form.value.name.trim()) return
  saving.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const body = {
      name: form.value.name.trim(),
      color: form.value.color.replace('#', ''),
      description: form.value.description || null
    }
    if (editMode.value && form.value.labelId != null) {
      const res = await fetch(`${config.apiBase}/collections/${cid}/labels/${form.value.labelId}`, {
        method: 'PATCH', headers, body: JSON.stringify(body)
      })
      if (!res.ok) throw new Error(await res.text())
    } else {
      const res = await fetch(`${config.apiBase}/collections/${cid}/labels`, {
        method: 'POST', headers, body: JSON.stringify(body)
      })
      if (!res.ok) throw new Error(await res.text())
    }
    dialogVisible.value = false
    await loadLabels()
  } catch (e) {
    error.value = `Save failed: ${(e as Error).message}`
  } finally {
    saving.value = false
  }
}

function deleteLabel(l: Label) {
  confirm.require({
    message: `Delete label "${l.name}"? It will be removed from all assets.`,
    header: 'Delete Label',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: 'Cancel',
    acceptLabel: 'Delete',
    acceptClass: 'p-button-danger',
    accept: async () => {
      error.value = ''
      try {
        const { config } = await import('../../config')
        const headers = await getBearerHeaders()
        const res = await fetch(`${config.apiBase}/collections/${cid}/labels/${l.labelId}`, { method: 'DELETE', headers })
        if (!res.ok) throw new Error(await res.text())
        await loadLabels()
      } catch (e) {
        error.value = `Delete failed: ${(e as Error).message}`
      }
    }
  })
}

function colorHex(raw: string) {
  const h = raw.replace('#', '')
  return h.length === 6 ? `#${h}` : '#3b82f6'
}

function contrastClass(hex: string) {
  // Determine if the background is dark enough to warrant white text
  const h = hex.replace('#', '')
  const r = parseInt(h.substring(0, 2), 16)
  const g = parseInt(h.substring(2, 4), 16)
  const b = parseInt(h.substring(4, 6), 16)
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
  return luminance > 0.55 ? 'dark-text' : 'light-text'
}
</script>

<template>
  <section>
    <ConfirmDialog />
    <div class="view-header">
      <div>
        <p><router-link :to="`/collections/${cid}`">&larr; Collection</router-link></p>
        <h2>Labels</h2>
      </div>
      <Button label="New Label" icon="pi pi-plus" size="small" @click="openAdd" />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="labels"
      :loading="loading"
      dataKey="labelId"
      stripedRows
      responsiveLayout="scroll"
    >
      <template #empty><span class="muted">No labels defined for this collection.</span></template>

      <Column header="Label" sortField="name" sortable>
        <template #body="{ data }">
          <span
            class="label-chip"
            :class="contrastClass(data.color)"
            :style="{ backgroundColor: colorHex(data.color) }"
          >{{ data.name }}</span>
        </template>
      </Column>

      <Column header="Color" style="width: 7rem">
        <template #body="{ data }">
          <span class="color-swatch" :style="{ background: colorHex(data.color) }" :title="colorHex(data.color)" />
          <code class="color-code">{{ colorHex(data.color) }}</code>
        </template>
      </Column>

      <Column field="description" header="Description">
        <template #body="{ data }">
          <span v-if="data.description">{{ data.description }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <Column header="Assets" style="width: 6rem; text-align: right">
        <template #body="{ data }">
          <Tag v-if="data.uses != null" :value="String(data.uses)" severity="secondary" />
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <Column header="" style="width: 9rem; text-align: right">
        <template #body="{ data }">
          <div class="row-actions">
            <Button icon="pi pi-pencil" size="small" text severity="secondary" @click="openEdit(data)" />
            <Button icon="pi pi-trash" size="small" text severity="danger" @click="deleteLabel(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- Create / Edit dialog -->
    <Dialog
      v-model:visible="dialogVisible"
      :header="editMode ? 'Edit Label' : 'New Label'"
      modal
      :style="{ width: '30rem' }"
    >
      <div class="form-grid">
        <label>Name <span class="req">*</span></label>
        <InputText v-model="form.name" placeholder="e.g. High Value Asset" maxlength="64" />

        <label>Color</label>
        <div class="color-row">
          <ColorPicker v-model="form.color" format="hex" />
          <span
            class="label-chip preview-chip"
            :class="contrastClass(form.color)"
            :style="{ backgroundColor: colorHex(form.color) }"
          >{{ form.name || 'Preview' }}</span>
        </div>

        <label>Description</label>
        <InputText v-model="form.description" placeholder="Optional description" maxlength="256" />
      </div>

      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button
          :label="editMode ? 'Save' : 'Create'"
          icon="pi pi-check"
          :loading="saving"
          :disabled="!form.name.trim()"
          @click="saveLabel"
        />
      </template>
    </Dialog>
  </section>
</template>

<style scoped>
.view-header { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.5rem; }
.view-header h2 { margin: 0; }
.row-actions { display: flex; gap: 0.25rem; justify-content: flex-end; }
.form-grid { display: grid; grid-template-columns: 8rem 1fr; gap: 0.75rem 1rem; align-items: center; padding: 0.25rem 0; }
.req { color: #f85149; }
.color-row { display: flex; align-items: center; gap: 1rem; }
.label-chip {
  display: inline-block;
  padding: 0.2rem 0.65rem;
  border-radius: 1rem;
  font-size: 0.8rem;
  font-weight: 600;
  white-space: nowrap;
}
.label-chip.light-text { color: #fff; }
.label-chip.dark-text  { color: #1a1a1a; }
.preview-chip { min-width: 5rem; text-align: center; }
.color-swatch {
  display: inline-block;
  width: 1rem;
  height: 1rem;
  border-radius: 3px;
  border: 1px solid rgba(255,255,255,0.15);
  vertical-align: middle;
  margin-right: 0.4rem;
}
.color-code { font-size: 0.8rem; vertical-align: middle; }
.err { color: #f85149; }
</style>
