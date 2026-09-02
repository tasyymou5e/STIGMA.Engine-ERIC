<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import DataTable, { type DataTableRowClickEvent } from 'primevue/datatable'
import Column from 'primevue/column'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import FileUpload, { type FileUploadSelectEvent } from 'primevue/fileupload'
import Toast from 'primevue/toast'
import { useToast } from 'primevue/usetoast'
import { api } from '../api/client'
import type { Stig } from '../api/types'

const router = useRouter()
const toast  = useToast()

const stigs    = ref<Stig[]>([])
const loading  = ref(true)
const error    = ref('')
const importing = ref(false)
const filter   = ref('')

// Client-side filter across benchmarkId + title
const filtered = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return stigs.value
  return stigs.value.filter(s =>
    s.benchmarkId.toLowerCase().includes(q) ||
    (s.title ?? '').toLowerCase().includes(q)
  )
})

onMounted(async () => {
  const { data, error: err } = await api.GET('/stigs')
  loading.value = false
  if (err) { error.value = 'Failed to load STIG library'; return }
  stigs.value = data ?? []
})

function openStig(e: DataTableRowClickEvent) {
  router.push(`/stigs/${(e.data as Stig).benchmarkId}`)
}

async function onFileSelect(e: FileUploadSelectEvent) {
  const file = e.files[0]
  if (!file) return
  importing.value = true
  try {
    const content = await file.text()
    const { error: err } = await api.POST('/stigs', { body: { content, source: 'xccdf' } })
    if (err) {
      toast.add({ severity: 'error', summary: 'Import failed', detail: String(err), life: 5000 })
    } else {
      toast.add({ severity: 'success', summary: 'STIG imported', detail: file.name, life: 4000 })
      const { data } = await api.GET('/stigs')
      stigs.value = data ?? []
    }
  } catch (ex) {
    toast.add({ severity: 'error', summary: 'Import error', detail: String(ex), life: 5000 })
  } finally {
    importing.value = false
  }
}
</script>

<template>
  <Toast />
  <section>

    <!-- Header row: title + import -->
    <div class="stigs-header">
      <h2 class="stigs-title">STIG Library</h2>
      <FileUpload
        mode="basic"
        accept=".xml"
        :auto="true"
        chooseLabel="Import STIG (XCCDF)"
        :disabled="importing"
        @select="onFileSelect"
      />
    </div>

    <!-- Filter bar -->
    <div class="stigs-filter">
      <span class="p-input-icon-left filter-wrap">
        <i class="pi pi-search" />
        <InputText
          v-model="filter"
          placeholder="Filter by Benchmark ID or title…"
          class="filter-input"
          @keydown.escape="filter = ''"
        />
      </span>
      <Button
        v-if="filter"
        icon="pi pi-times"
        severity="secondary"
        text
        rounded
        size="small"
        aria-label="Clear filter"
        @click="filter = ''"
      />
      <span class="muted filter-count">
        {{ filtered.length }} of {{ stigs.length }} STIGs
      </span>
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="filtered"
      :loading="loading"
      dataKey="benchmarkId"
      paginator
      :rows="20"
      :rows-per-page-options="[10, 20, 50]"
      stripedRows
      selectionMode="single"
      responsiveLayout="scroll"
      :pt="{ bodyRow: { style: 'cursor: pointer' } }"
      @row-click="openStig"
    >
      <template #empty>
        <span v-if="filter" class="muted">
          No STIGs match <strong>{{ filter }}</strong>.
          <a href="#" @click.prevent="filter = ''">Clear filter</a>
        </span>
        <span v-else class="muted">No STIGs in library. Import an XCCDF file to get started.</span>
      </template>

      <Column
        field="benchmarkId"
        header="Benchmark ID"
        sortable
        style="width: 24rem; font-family: monospace; font-size: 0.85rem"
      />
      <Column field="title" header="Title" sortable />
    </DataTable>

    <p class="muted hint">Click a row to view revisions and rules.</p>
  </section>
</template>

<style scoped>
.stigs-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}
.stigs-title { margin: 0; }

.stigs-filter {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}
.filter-wrap { display: inline-flex; align-items: center; position: relative; }
.filter-input { width: 22rem; padding-left: 2rem; }
.filter-count { font-size: 0.85rem; margin-left: 0.25rem; }

.err  { color: #f85149; }
.muted { color: var(--p-text-muted-color, #6b7280); }
.hint { margin-top: 0.5rem; font-size: 0.85rem; }
</style>
