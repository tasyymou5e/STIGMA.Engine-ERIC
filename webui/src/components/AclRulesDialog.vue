<script setup lang="ts">
import { ref, watch } from 'vue'
import Dialog from 'primevue/dialog'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AclRule {
  cgAclId?: number
  grantId: number
  benchmarkId: string | null
  assetId: number | null
  clId: number | null
  access: 'none' | 'r' | 'rw'
}

// ---------------------------------------------------------------------------
// Props / emits
// ---------------------------------------------------------------------------

const props = defineProps<{
  visible: boolean
  collectionId: number
  grantId: number
  granteeName?: string
}>()

const emit = defineEmits<{
  (e: 'update:visible', val: boolean): void
}>()

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const rules   = ref<AclRule[]>([])
const loading = ref(false)
const saving  = ref(false)
const error   = ref('')

const ACCESS_OPTIONS = [
  { label: 'none', value: 'none' },
  { label: 'r (read)',  value: 'r'    },
  { label: 'rw (read/write)', value: 'rw' }
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getBearerHeaders(): Promise<HeadersInit> {
  const { getAccessToken } = await import('../auth/oidc')
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

async function loadRules() {
  loading.value = true
  error.value   = ''
  try {
    const { config } = await import('../config')
    const headers    = await getBearerHeaders()
    const res = await fetch(
      `${config.apiBase}/collections/${props.collectionId}/grants/${props.grantId}/acl`,
      { headers }
    )
    if (!res.ok) throw new Error(await res.text())
    rules.value = await res.json()
  } catch (e) {
    error.value = `Failed to load ACL rules: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

async function saveRules() {
  saving.value = true
  error.value  = ''
  try {
    const { config } = await import('../config')
    const headers    = await getBearerHeaders()
    const payload    = rules.value.map(({ benchmarkId, assetId, clId, access }) => ({
      benchmarkId: benchmarkId || null,
      assetId:     assetId     || null,
      clId:        clId        || null,
      access
    }))
    const res = await fetch(
      `${config.apiBase}/collections/${props.collectionId}/grants/${props.grantId}/acl`,
      { method: 'PUT', headers, body: JSON.stringify(payload) }
    )
    if (!res.ok) throw new Error(await res.text())
    rules.value = await res.json()
    emit('update:visible', false)
  } catch (e) {
    error.value = `Save failed: ${(e as Error).message}`
  } finally {
    saving.value = false
  }
}

// ---------------------------------------------------------------------------
// Row operations
// ---------------------------------------------------------------------------

function addRow() {
  rules.value.push({
    grantId:     props.grantId,
    benchmarkId: null,
    assetId:     null,
    clId:        null,
    access:      'r'
  })
}

function removeRow(index: number) {
  rules.value.splice(index, 1)
}

// ---------------------------------------------------------------------------
// Watch visibility — load when opened
// ---------------------------------------------------------------------------

watch(
  () => props.visible,
  (v) => { if (v) loadRules() }
)
</script>

<template>
  <Dialog
    :visible="visible"
    @update:visible="emit('update:visible', $event)"
    :header="`ACL Rules — ${granteeName ?? `Grant #${grantId}`}`"
    modal
    :style="{ width: '52rem' }"
  >
    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="rules"
      :loading="loading"
      dataKey="_idx"
      responsiveLayout="scroll"
      size="small"
    >
      <template #empty>
        <span class="muted">No ACL rules — grant has unrestricted access at its role level.</span>
      </template>

      <Column header="Benchmark ID" style="min-width: 14rem">
        <template #body="{ data }">
          <InputText
            v-model="data.benchmarkId"
            placeholder="(any)"
            size="small"
            fluid
          />
        </template>
      </Column>

      <Column header="Asset ID" style="width: 8rem">
        <template #body="{ data }">
          <InputText
            v-model.number="data.assetId"
            placeholder="(any)"
            size="small"
            fluid
          />
        </template>
      </Column>

      <Column header="Label ID" style="width: 8rem">
        <template #body="{ data }">
          <InputText
            v-model.number="data.clId"
            placeholder="(any)"
            size="small"
            fluid
          />
        </template>
      </Column>

      <Column header="Access" style="width: 11rem">
        <template #body="{ data }">
          <Select
            v-model="data.access"
            :options="ACCESS_OPTIONS"
            optionLabel="label"
            optionValue="value"
            size="small"
            fluid
          />
        </template>
      </Column>

      <Column header="" style="width: 3.5rem; text-align: right">
        <template #body="{ index }">
          <Button
            icon="pi pi-trash"
            size="small"
            text
            severity="danger"
            @click="removeRow(index)"
          />
        </template>
      </Column>
    </DataTable>

    <div class="add-row">
      <Button label="Add Rule" icon="pi pi-plus" size="small" severity="secondary" @click="addRow" />
    </div>

    <template #footer>
      <Button label="Cancel" severity="secondary" text @click="emit('update:visible', false)" />
      <Button label="Save" icon="pi pi-check" :loading="saving" @click="saveRules" />
    </template>
  </Dialog>
</template>

<style scoped>
.err     { color: #f85149; margin-bottom: 0.5rem; }
.muted   { color: #888; font-style: italic; }
.add-row { margin-top: 0.75rem; }
</style>
