<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import DataTable, { type DataTableRowClickEvent } from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'
import { api } from '../../api/client'
import type { Collection } from '../../api/types'
import CreateCollectionDialog from '../../components/CreateCollectionDialog.vue'
import EditCollectionDialog from '../../components/EditCollectionDialog.vue'

const router = useRouter()
const confirm = useConfirm()
const toast = useToast()

const collections = ref<Collection[]>([])
const loading = ref(true)
const error = ref('')

const createDialogVisible = ref(false)
const editDialogVisible = ref(false)
const editTarget = ref<Collection | null>(null)

onMounted(loadCollections)

async function loadCollections() {
  loading.value = true
  error.value = ''
  const { data, error: err } = await api.GET('/collections')
  loading.value = false
  if (err) { error.value = 'Failed to load collections'; return }
  collections.value = data ?? []
}

function onRowClick(e: DataTableRowClickEvent) {
  const target = e.originalEvent?.target as HTMLElement | null
  if (target?.closest('.row-action')) return
  router.push(`/collections/${(e.data as Collection).collectionId}`)
}

// ── Create ────────────────────────────────────────────────────────────────────
function onCreated(col: Collection) {
  collections.value = [...collections.value, col].sort((a, b) => a.name.localeCompare(b.name))
  toast.add({ severity: 'success', summary: 'Collection created', detail: col.name, life: 3000 })
}

// ── Edit ──────────────────────────────────────────────────────────────────────
function openEdit(col: Collection, event: Event) {
  event.stopPropagation()
  editTarget.value = col
  editDialogVisible.value = true
}

function onUpdated(updated: Collection) {
  const idx = collections.value.findIndex(c => c.collectionId === updated.collectionId)
  if (idx !== -1) {
    collections.value = [
      ...collections.value.slice(0, idx),
      updated,
      ...collections.value.slice(idx + 1)
    ]
  }
  toast.add({ severity: 'success', summary: 'Collection updated', detail: updated.name, life: 3000 })
}

// ── Delete ────────────────────────────────────────────────────────────────────
function confirmDelete(col: Collection, event: Event) {
  event.stopPropagation()
  confirm.require({
    message: `Delete collection "${col.name}"? This cannot be undone.`,
    header: 'Confirm Delete',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    acceptLabel: 'Delete',
    rejectLabel: 'Cancel',
    accept: () => doDelete(col)
  })
}

async function doDelete(col: Collection) {
  const { error: err } = await api.DELETE('/collections/{id}', {
    params: { path: { id: col.collectionId } }
  })
  if (err) {
    toast.add({ severity: 'error', summary: 'Delete failed', detail: String(err), life: 4000 })
    return
  }
  collections.value = collections.value.filter(c => c.collectionId !== col.collectionId)
  toast.add({ severity: 'success', summary: 'Collection deleted', detail: col.name, life: 3000 })
}

function formatDate(iso?: string | null) {
  if (!iso) return '—'
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric', month: 'short', day: '2-digit'
    }).format(new Date(iso))
  } catch {
    return iso
  }
}
</script>

<template>
  <Toast />
  <ConfirmDialog />

  <section>
    <div class="page-header">
      <h2>Collections — Admin</h2>
      <Button
        label="New Collection"
        icon="pi pi-plus"
        size="small"
        @click="createDialogVisible = true"
      />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="collections"
      :loading="loading"
      dataKey="collectionId"
      paginator
      :rows="20"
      stripedRows
      responsiveLayout="scroll"
      sortField="name"
      :sortOrder="1"
      :pt="{ bodyRow: { style: 'cursor: pointer' } }"
      @row-click="onRowClick"
    >
      <template #empty>
        <span class="muted">No collections found.</span>
      </template>

      <Column field="collectionId" header="ID" sortable style="width: 5rem" />
      <Column field="name" header="Name" sortable />
      <Column field="description" header="Description">
        <template #body="{ data }">
          <span v-if="data.description">{{ data.description }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column header="POC">
        <template #body="{ data }">
          <Tag v-if="data.metadata?.pocName" :value="data.metadata.pocName" severity="info" />
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column header="Owner" sortField="owner" sortable>
        <template #body="{ data }">
          <span v-if="data.owner">{{ data.owner }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column header="Created" sortField="createdAt" sortable style="width: 9rem">
        <template #body="{ data }">
          <span class="muted-mono">{{ formatDate(data.createdAt) }}</span>
        </template>
      </Column>
      <Column header="" style="width: 6rem; text-align: right">
        <template #body="{ data }">
          <span class="row-action">
            <Button
              icon="pi pi-pencil"
              size="small"
              severity="secondary"
              text
              rounded
              aria-label="Edit"
              title="Edit collection"
              @click="openEdit(data, $event)"
            />
            <Button
              icon="pi pi-trash"
              size="small"
              severity="danger"
              text
              rounded
              aria-label="Delete"
              title="Delete collection"
              @click="confirmDelete(data, $event)"
            />
          </span>
        </template>
      </Column>
    </DataTable>

    <CreateCollectionDialog
      v-model:visible="createDialogVisible"
      @created="onCreated"
    />

    <EditCollectionDialog
      v-model:visible="editDialogVisible"
      :collection="editTarget"
      @updated="onUpdated"
    />
  </section>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.page-header h2 {
  margin: 0;
}

.row-action {
  display: flex;
  gap: 0.25rem;
  justify-content: flex-end;
}

.err {
  color: #f85149;
}

.muted-mono {
  font-size: 0.85rem;
  color: var(--p-text-muted-color, #6b7280);
  font-variant-numeric: tabular-nums;
}
</style>
