<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Select from 'primevue/select'
import Button from 'primevue/button'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import { api } from '../api/client'
import type { Revision, StigDiff, Rule } from '../api/types'
import { severityTag } from '../util/chips'

const props = defineProps<{ benchmarkId: string }>()

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const revisions = ref<Revision[]>([])
const rev1 = ref<Revision | null>(null)
const rev2 = ref<Revision | null>(null)
const diff = ref<StigDiff | null>(null)
const loading = ref(false)
const loadingRevisions = ref(true)
const error = ref('')

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

onMounted(async () => {
  const { data, error: err } = await api.GET('/stigs/{benchmarkId}/revisions', {
    params: { path: { benchmarkId: props.benchmarkId } }
  })
  loadingRevisions.value = false
  if (err) { error.value = 'Failed to load revisions'; return }
  revisions.value = data ?? []
  if (revisions.value.length >= 2) {
    rev1.value = revisions.value[1]  // second-newest as "before"
    rev2.value = revisions.value[0]  // newest as "after"
  } else if (revisions.value.length === 1) {
    rev1.value = revisions.value[0]
    rev2.value = revisions.value[0]
  }
})

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------

async function compare() {
  if (!rev1.value || !rev2.value) return
  error.value = ''
  diff.value = null
  loading.value = true
  const { data, error: err } = await api.GET('/stigs/{benchmarkId}/revisions/diff', {
    params: {
      path: { benchmarkId: props.benchmarkId },
      query: { rev1: rev1.value.revisionStr, rev2: rev2.value.revisionStr }
    }
  })
  loading.value = false
  if (err) { error.value = 'Failed to load diff'; return }
  diff.value = data ?? null
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function catLabel(rule: Rule): string {
  return severityTag(rule.severity).label
}

function catSeverity(rule: Rule) {
  return severityTag(rule.severity).severity
}
</script>

<template>
  <section class="stig-diff">
    <p><router-link :to="`/stigs/${benchmarkId}`">&larr; Back to STIG Detail</router-link></p>
    <h2>Compare Revisions</h2>
    <p class="muted monospace">{{ benchmarkId }}</p>

    <p v-if="error" style="color: #f85149">{{ error }}</p>

    <template v-if="loadingRevisions">
      <p class="muted">Loading revisions&hellip;</p>
    </template>

    <template v-else>
      <!-- Revision selectors + compare button -->
      <div class="toolbar" style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.25rem; flex-wrap: wrap">
        <label style="font-weight: 600; white-space: nowrap">Rev 1 (before):</label>
        <Select
          v-model="rev1"
          :options="revisions"
          optionLabel="revisionStr"
          placeholder="Select revision"
          style="min-width: 10rem"
        />

        <label style="font-weight: 600; white-space: nowrap; margin-left: 0.5rem">Rev 2 (after):</label>
        <Select
          v-model="rev2"
          :options="revisions"
          optionLabel="revisionStr"
          placeholder="Select revision"
          style="min-width: 10rem"
        />

        <Button
          label="Compare"
          icon="pi pi-code-branch"
          :disabled="!rev1 || !rev2 || loading"
          :loading="loading"
          @click="compare"
        />
      </div>

      <!-- Summary bar -->
      <template v-if="diff">
        <div class="summary-bar" style="display: flex; gap: 0.6rem; align-items: center; margin-bottom: 1.25rem; flex-wrap: wrap">
          <Tag
            :value="`Added: ${diff.added.length}`"
            severity="success"
            style="font-size: 0.9rem; padding: 0.35rem 0.75rem"
          />
          <Tag
            :value="`Removed: ${diff.removed.length}`"
            severity="danger"
            style="font-size: 0.9rem; padding: 0.35rem 0.75rem"
          />
          <Tag
            :value="`Changed: ${diff.changed.length}`"
            severity="warn"
            style="font-size: 0.9rem; padding: 0.35rem 0.75rem"
          />
          <span class="muted" style="font-size: 0.9rem">Unchanged: {{ diff.unchanged }}</span>
        </div>

        <!-- Tab panels -->
        <TabView>

          <!-- Added rules -->
          <TabPanel value="added" :header="`Added (${diff.added.length})`">
            <DataTable
              :value="diff.added"
              dataKey="ruleId"
              paginator
              :rows="50"
              :rowsPerPageOptions="[25, 50, 100]"
              stripedRows
              responsiveLayout="scroll"
              style="font-size: 0.875rem"
            >
              <template #empty><span class="muted">No rules added.</span></template>
              <Column header="CAT" sortable sortField="severity" style="width: 6rem">
                <template #body="{ data }">
                  <Tag :value="catLabel(data)" :severity="catSeverity(data)" style="white-space: nowrap" />
                </template>
              </Column>
              <Column field="groupId" header="Group" sortable style="width: 7.5rem; font-family: monospace; font-size: 0.8rem" />
              <Column field="ruleVersion" header="STIG ID" sortable style="width: 12rem; font-family: monospace; font-size: 0.8rem" />
              <Column field="ruleId" header="Rule ID" sortable style="width: 14rem; font-family: monospace; font-size: 0.8rem" />
              <Column field="title" header="Title" sortable style="min-width: 18rem">
                <template #body="{ data }">
                  <span style="white-space: normal; word-break: break-word">{{ data.title }}</span>
                </template>
              </Column>
            </DataTable>
          </TabPanel>

          <!-- Removed rules -->
          <TabPanel value="removed" :header="`Removed (${diff.removed.length})`">
            <DataTable
              :value="diff.removed"
              dataKey="ruleId"
              paginator
              :rows="50"
              :rowsPerPageOptions="[25, 50, 100]"
              stripedRows
              responsiveLayout="scroll"
              style="font-size: 0.875rem"
            >
              <template #empty><span class="muted">No rules removed.</span></template>
              <Column header="CAT" sortable sortField="severity" style="width: 6rem">
                <template #body="{ data }">
                  <Tag :value="catLabel(data)" :severity="catSeverity(data)" style="white-space: nowrap" />
                </template>
              </Column>
              <Column field="groupId" header="Group" sortable style="width: 7.5rem; font-family: monospace; font-size: 0.8rem" />
              <Column field="ruleVersion" header="STIG ID" sortable style="width: 12rem; font-family: monospace; font-size: 0.8rem" />
              <Column field="ruleId" header="Rule ID" sortable style="width: 14rem; font-family: monospace; font-size: 0.8rem" />
              <Column field="title" header="Title" sortable style="min-width: 18rem">
                <template #body="{ data }">
                  <span style="white-space: normal; word-break: break-word">{{ data.title }}</span>
                </template>
              </Column>
            </DataTable>
          </TabPanel>

          <!-- Changed rules — before/after columns -->
          <TabPanel value="changed" :header="`Changed (${diff.changed.length})`">
            <DataTable
              :value="diff.changed"
              dataKey="after.ruleId"
              paginator
              :rows="50"
              :rowsPerPageOptions="[25, 50, 100]"
              stripedRows
              responsiveLayout="scroll"
              style="font-size: 0.875rem"
            >
              <template #empty><span class="muted">No rules changed.</span></template>

              <!-- Rule ID (stable) -->
              <Column header="Rule ID" sortable style="width: 14rem; font-family: monospace; font-size: 0.8rem">
                <template #body="{ data }">{{ data.after.ruleId }}</template>
              </Column>

              <!-- Severity: before / after -->
              <Column header="CAT Before" style="width: 7.5rem">
                <template #body="{ data }">
                  <Tag
                    :value="catLabel(data.before)"
                    :severity="catSeverity(data.before)"
                    style="white-space: nowrap"
                  />
                </template>
              </Column>
              <Column header="CAT After" style="width: 7.5rem">
                <template #body="{ data }">
                  <Tag
                    :value="catLabel(data.after)"
                    :severity="catSeverity(data.after)"
                    style="white-space: nowrap"
                  />
                </template>
              </Column>

              <!-- STIG ID (ruleVersion): before / after -->
              <Column header="STIG ID Before" style="width: 11rem; font-family: monospace; font-size: 0.8rem">
                <template #body="{ data }">
                  <span :class="{ 'changed-field': data.before.ruleVersion !== data.after.ruleVersion }">
                    {{ data.before.ruleVersion }}
                  </span>
                </template>
              </Column>
              <Column header="STIG ID After" style="width: 11rem; font-family: monospace; font-size: 0.8rem">
                <template #body="{ data }">
                  <span :class="{ 'changed-field': data.before.ruleVersion !== data.after.ruleVersion }">
                    {{ data.after.ruleVersion }}
                  </span>
                </template>
              </Column>

              <!-- Title: before / after -->
              <Column header="Title Before" style="min-width: 16rem">
                <template #body="{ data }">
                  <span
                    style="white-space: normal; word-break: break-word"
                    :class="{ 'changed-field': data.before.title !== data.after.title }"
                  >{{ data.before.title }}</span>
                </template>
              </Column>
              <Column header="Title After" style="min-width: 16rem">
                <template #body="{ data }">
                  <span
                    style="white-space: normal; word-break: break-word"
                    :class="{ 'changed-field': data.before.title !== data.after.title }"
                  >{{ data.after.title }}</span>
                </template>
              </Column>
            </DataTable>
          </TabPanel>

        </TabView>
      </template>

      <p v-else-if="!loading" class="muted" style="margin-top: 0.75rem">
        Select two revisions and click Compare.
      </p>
    </template>
  </section>
</template>

<style scoped>
.stig-diff {
  padding: 0 0.25rem;
}

.monospace {
  font-family: monospace;
}

.muted {
  color: var(--p-text-muted-color, #8b949e);
}

.changed-field {
  color: var(--p-orange-400, #fb923c);
  font-weight: 600;
}
</style>
