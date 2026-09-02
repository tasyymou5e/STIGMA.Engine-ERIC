<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import { api } from '../api/client'
import type { Stig, Revision, Rule } from '../api/types'
import { severityTag } from '../util/chips'

const props = defineProps<{ benchmarkId: string }>()
const router = useRouter()

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const stig = ref<Stig | null>(null)
const revisions = ref<Revision[]>([])
const selectedRevision = ref<Revision | null>(null)
const rules = ref<Rule[]>([])
const expandedRows = ref<Rule[]>([])

const loadingStig = ref(true)
const loadingRules = ref(false)
const error = ref('')

// Column filter values
const filterSeverity = ref('')
const filterStigId = ref('')
const filterGroup = ref('')
const filterRuleId = ref('')
const filterTitle = ref('')

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

onMounted(async () => {
  const [s, r] = await Promise.all([
    api.GET('/stigs/{benchmarkId}', { params: { path: { benchmarkId: props.benchmarkId } } }),
    api.GET('/stigs/{benchmarkId}/revisions', { params: { path: { benchmarkId: props.benchmarkId } } })
  ])
  loadingStig.value = false
  if (s.error) { error.value = 'Failed to load STIG'; return }
  stig.value = s.data ?? null
  revisions.value = r.data ?? []

  // Pre-select the latest revision (first in list — backend sorts DESC by date)
  if (revisions.value.length > 0) {
    selectedRevision.value = revisions.value[0]
  }
})

// Load rules whenever selectedRevision changes
watch(selectedRevision, async (rev) => {
  if (!rev) return
  loadingRules.value = true
  expandedRows.value = []
  rules.value = []
  const { data } = await api.GET('/stigs/{benchmarkId}/revisions/{revisionStr}/rules', {
    params: {
      path: { benchmarkId: props.benchmarkId, revisionStr: rev.revisionStr },
      query: { projection: 'detail' }
    }
  })
  rules.value = data ?? []
  loadingRules.value = false
})

// ---------------------------------------------------------------------------
// Computed / helpers
// ---------------------------------------------------------------------------

const filteredRules = computed(() => {
  return rules.value.filter(r => {
    if (filterSeverity.value) {
      const label = severityTag(r.severity).label.toLowerCase()
      if (!label.includes(filterSeverity.value.toLowerCase())) return false
    }
    if (filterStigId.value && !(r.ruleVersion ?? '').toLowerCase().includes(filterStigId.value.toLowerCase())) return false
    if (filterGroup.value && !(r.groupId ?? '').toLowerCase().includes(filterGroup.value.toLowerCase())) return false
    if (filterRuleId.value && !r.ruleId.toLowerCase().includes(filterRuleId.value.toLowerCase())) return false
    if (filterTitle.value && !r.title.toLowerCase().includes(filterTitle.value.toLowerCase())) return false
    return true
  })
})

const rowCount = computed(() => filteredRules.value.length)

// revisions passed directly — v-model will hold the full Revision object

function formatCcis(ccis?: string[] | null): string {
  if (!ccis || ccis.length === 0) return ''
  return ccis.join(', ')
}

function cciUrl(cci: string): string {
  // CCI IDs like "CCI-000068" link to NIST RMF / IASE resources
  return `https://www.stigviewer.com/cci/${cci}/`
}

// ---------------------------------------------------------------------------
// CSV Export
// ---------------------------------------------------------------------------

function exportCsv() {
  const cols = ['CAT', 'STIG ID', 'Group ID', 'Group Title', 'Rule ID', 'Rule Title', 'Discussion', 'Check Content', 'Fix Text', 'CCIs']
  const escape = (v: unknown) => {
    const s = String(v ?? '')
    return `"${s.replace(/"/g, '""')}"`
  }
  const rows = filteredRules.value.map(r => [
    severityTag(r.severity).label,
    r.ruleVersion,
    r.groupId ?? '',
    r.groupTitle ?? '',
    r.ruleId,
    r.title,
    r.vulnDiscussion ?? '',
    r.checkContent ?? '',
    r.fixText ?? '',
    formatCcis(r.ccis)
  ].map(escape).join(','))

  const csv = [cols.map(escape).join(','), ...rows].join('\r\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${props.benchmarkId}_${selectedRevision.value?.revisionStr ?? 'rules'}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <section class="stig-detail">
    <p><router-link to="/stigs">&larr; STIG Library</router-link></p>
    <p v-if="error" style="color: #f85149">{{ error }}</p>

    <template v-if="loadingStig">
      <p class="muted">Loading&hellip;</p>
    </template>

    <template v-else-if="stig">
      <h2>{{ stig.title }}</h2>
      <p class="muted monospace">{{ stig.benchmarkId }}</p>

      <!-- Revision selector -->
      <div class="toolbar" style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap">
        <label style="font-weight: 600; white-space: nowrap">Revision:</label>
        <Select
          v-model="selectedRevision"
          :options="revisions"
          optionLabel="revisionStr"
          placeholder="Select revision"
          style="min-width: 10rem"
        />
        <template v-if="selectedRevision">
          <Tag :value="`CAT I: ${selectedRevision.highCount ?? 0}`" severity="danger" />
          <Tag :value="`CAT II: ${selectedRevision.mediumCount ?? 0}`" severity="warn" />
          <Tag :value="`CAT III: ${selectedRevision.lowCount ?? 0}`" severity="info" />
        </template>
        <div style="flex: 1" />
        <span v-if="!loadingRules && rules.length > 0" class="muted" style="white-space: nowrap">
          {{ rowCount }} record{{ rowCount !== 1 ? 's' : '' }}
        </span>
        <Button
          v-if="!loadingRules && rules.length > 0"
          label="CSV"
          icon="pi pi-download"
          severity="secondary"
          size="small"
          @click="exportCsv"
        />
        <Button
          label="Compare Revisions"
          icon="pi pi-code-branch"
          severity="secondary"
          size="small"
          @click="router.push(`/stigs/${props.benchmarkId}/diff`)"
        />
      </div>

      <!-- Column filters -->
      <div v-if="!loadingRules && rules.length > 0" class="col-filters" style="display: flex; gap: 0.5rem; margin-bottom: 0.5rem; flex-wrap: wrap">
        <InputText v-model="filterSeverity" placeholder="CAT filter" size="small" style="width: 8rem" />
        <InputText v-model="filterStigId"   placeholder="STIG ID"    size="small" style="width: 12rem" />
        <InputText v-model="filterGroup"    placeholder="Group ID"   size="small" style="width: 9rem" />
        <InputText v-model="filterRuleId"   placeholder="Rule ID"    size="small" style="width: 12rem" />
        <InputText v-model="filterTitle"    placeholder="Title"      size="small" style="width: 18rem" />
      </div>

      <!-- Rules DataTable -->
      <DataTable
        v-if="selectedRevision"
        :value="filteredRules"
        :loading="loadingRules"
        dataKey="ruleId"
        v-model:expandedRows="expandedRows"
        paginator
        :rows="50"
        :rowsPerPageOptions="[25, 50, 100]"
        stripedRows
        responsiveLayout="scroll"
        style="font-size: 0.875rem"
      >
        <template #empty>
          <span class="muted">No rules found.</span>
        </template>

        <!-- Row expander -->
        <Column expander style="width: 2.5rem" />

        <!-- CAT / Severity -->
        <Column header="CAT" sortable sortField="severity" style="width: 6rem">
          <template #body="{ data }">
            <Tag
              :value="severityTag(data.severity).label"
              :severity="severityTag(data.severity).severity"
              style="white-space: nowrap"
            />
          </template>
        </Column>

        <!-- STIG ID (ruleVersion, e.g. WN22-00-000010) -->
        <Column field="ruleVersion" header="STIG ID" sortable style="width: 12rem; font-family: monospace; font-size: 0.8rem" />

        <!-- Group ID -->
        <Column field="groupId" header="Group" sortable style="width: 7.5rem; font-family: monospace; font-size: 0.8rem" />

        <!-- Rule ID -->
        <Column field="ruleId" header="Rule ID" sortable style="width: 14rem; font-family: monospace; font-size: 0.8rem" />

        <!-- Rule Title -->
        <Column field="title" header="Rule Title" sortable style="min-width: 18rem">
          <template #body="{ data }">
            <span style="white-space: normal; word-break: break-word">{{ data.title }}</span>
          </template>
        </Column>

        <!-- Row expansion: full detail panel -->
        <template #expansion="{ data }">
          <div class="rule-expansion" style="padding: 1rem 1.5rem; display: flex; flex-direction: column; gap: 1rem; max-width: 900px">

            <!-- Group Title -->
            <div v-if="data.groupTitle">
              <div class="exp-label">Group Title</div>
              <div>{{ data.groupTitle }}</div>
            </div>

            <!-- Vulnerability Discussion -->
            <div v-if="data.vulnDiscussion">
              <div class="exp-label">Vulnerability Discussion</div>
              <div class="exp-text">{{ data.vulnDiscussion }}</div>
            </div>

            <!-- Check Content -->
            <div v-if="data.checkContent">
              <div class="exp-label">Check Content</div>
              <pre class="exp-code">{{ data.checkContent }}</pre>
            </div>

            <!-- Fix Text -->
            <div v-if="data.fixText">
              <div class="exp-label">Fix Text</div>
              <div class="exp-text">{{ data.fixText }}</div>
            </div>

            <!-- CCIs -->
            <div v-if="data.ccis && data.ccis.length > 0">
              <div class="exp-label">CCIs</div>
              <div style="display: flex; flex-wrap: wrap; gap: 0.4rem">
                <a
                  v-for="cci in data.ccis"
                  :key="cci"
                  :href="cciUrl(cci)"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="cci-link"
                >{{ cci }}</a>
              </div>
            </div>

          </div>
        </template>

      </DataTable>

      <p v-else-if="!loadingRules" class="muted" style="margin-top: 0.5rem">
        Select a revision to load rules.
      </p>
    </template>
  </section>
</template>

<style scoped>
.stig-detail {
  padding: 0 0.25rem;
}

.monospace {
  font-family: monospace;
}

.muted {
  color: var(--p-text-muted-color, #8b949e);
}

.exp-label {
  font-weight: 700;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--p-text-muted-color, #8b949e);
  margin-bottom: 0.25rem;
}

.exp-text {
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.5;
}

.exp-code {
  white-space: pre-wrap;
  word-break: break-word;
  font-family: monospace;
  font-size: 0.82rem;
  background: var(--p-surface-100, #1c1c1c);
  border: 1px solid var(--p-surface-300, #333);
  border-radius: 4px;
  padding: 0.75rem 1rem;
  line-height: 1.45;
  margin: 0;
  overflow-x: auto;
}

.cci-link {
  font-family: monospace;
  font-size: 0.82rem;
  padding: 0.15rem 0.45rem;
  border-radius: 4px;
  border: 1px solid var(--p-primary-300, #58a6ff);
  color: var(--p-primary-400, #58a6ff);
  text-decoration: none;
}

.cci-link:hover {
  background: var(--p-primary-950, #0d1117);
  text-decoration: underline;
}
</style>
