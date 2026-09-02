<script setup lang="ts">
import { onMounted, ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import Toast from 'primevue/toast'
import ConfirmDialog from 'primevue/confirmdialog'
import Fieldset from 'primevue/fieldset'
import Card from 'primevue/card'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import InputSwitch from 'primevue/inputswitch'
import Textarea from 'primevue/textarea'
import Select from 'primevue/select'
import Checkbox from 'primevue/checkbox'
import Button from 'primevue/button'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'
import CollectionCloneDialog from '../components/CollectionCloneDialog.vue'
import MetadataPanel from '../components/MetadataPanel.vue'

// ── Props ─────────────────────────────────────────────────────────────────────
const props = defineProps<{ id: string }>()
const cid = Number(props.id)

const router = useRouter()
const toast = useToast()
const confirm = useConfirm()

// ── State ─────────────────────────────────────────────────────────────────────
const loading = ref(true)
const saving = ref(false)
const deleting = ref(false)
const error = ref('')
const collectionName = ref('') // display name in breadcrumb

// Form fields
const form = reactive({
  name: '',
  description: '',
  pocName: '',

  // Review Fields — Detail
  detailEnabled: 'always' as 'always' | 'findings',
  detailRequired: 'always' as 'always' | 'findings' | 'optional',

  // Review Fields — Comment
  commentEnabled: 'always' as 'always' | 'findings',
  commentRequired: 'optional' as 'always' | 'findings' | 'optional',

  // Status Workflow
  canAccept: true,
  minAcceptGrant: 3 as 3 | 4,
  resetCriteria: 'result-change' as 'result-change' | 'any-change' | 'never',

  // History
  maxReviews: null as number | null
})

// ── Dropdown option lists ─────────────────────────────────────────────────────
const enabledOptions = [
  { value: 'always',   label: 'Always' },
  { value: 'findings', label: 'Findings only' }
]

const requiredOptions = [
  { value: 'always',   label: 'Always' },
  { value: 'findings', label: 'Findings only' },
  { value: 'optional', label: 'Optional' }
]

const minGrantOptions = [
  { value: 3, label: 'Manage (level 3)' },
  { value: 4, label: 'Owner (level 4)' }
]

const resetCriteriaOptions = [
  { value: 'result-change', label: 'Result change' },
  { value: 'any-change',    label: 'Any change' },
  { value: 'never',         label: 'Never' }
]

const maxReviewsOptions = [
  { value: null, label: 'Disabled' },
  ...Array.from({ length: 15 }, (_, i) => ({ value: i + 1, label: String(i + 1) }))
]

// ── Review Aging (new card) ───────────────────────────────────────────────────
const agingLoaded   = ref(false)
const agingSaving   = ref(false)
const agingRunning  = ref(false)
const agingExists   = ref(false)

const aging = reactive({
  enabled:       false,
  daysUntilStale: 90,
  targetStatus:  'notchecked' as string,
  lastRun:       null as string | null
})

const targetStatusOptions = [
  { value: 'notchecked',    label: 'Not Reviewed (notchecked)' },
  { value: 'informational', label: 'Informational (informational)' }
]

function formatLastRun(val: string | null): string {
  if (!val) return 'never'
  try {
    const d = new Date(val)
    if (isNaN(d.getTime())) return val
    return d.toLocaleString(undefined, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    })
  } catch {
    return val
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
async function bearerHeaders(): Promise<HeadersInit> {
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

// ── Load collection ───────────────────────────────────────────────────────────
onMounted(async () => {
  loading.value = true
  try {
    const headers = await bearerHeaders()
    const res = await fetch(`${config.apiBase}/collections/${cid}`, { headers })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json()

    collectionName.value = data.name ?? ''
    form.name        = data.name ?? ''
    form.description = data.description ?? ''

    const meta = data.metadata ?? {}
    form.pocName = meta.pocName ?? ''

    const s = data.settings ?? {}

    // Review Fields
    const rf = s.reviewFields ?? {}
    const detail  = rf.detail  ?? {}
    const comment = rf.comment ?? {}
    form.detailEnabled   = detail.enabled   ?? 'always'
    form.detailRequired  = detail.required  ?? 'always'
    form.commentEnabled  = comment.enabled  ?? 'always'
    form.commentRequired = comment.required ?? 'optional'

    // Status
    const status = s.status ?? {}
    form.canAccept      = status.canAccept      ?? true
    form.minAcceptGrant = status.minAcceptGrant  ?? 3
    form.resetCriteria  = status.resetCriteria   ?? 'result-change'

    // History
    const history = s.history ?? {}
    form.maxReviews = history.maxReviews ?? null

    // Load review aging config (separate endpoint — 404 is normal when not configured)
    try {
      const agingRes = await fetch(`${config.apiBase}/collections/${cid}/task-config/review-aging`, { headers })
      if (agingRes.ok) {
        const ac = await agingRes.json()
        agingExists.value      = true
        aging.enabled          = ac.enabled          ?? false
        aging.daysUntilStale   = ac.daysUntilStale   ?? 90
        aging.targetStatus     = ac.targetStatus      ?? 'notchecked'
        aging.lastRun          = ac.lastRun           ?? null
      } else {
        agingExists.value = false
      }
    } catch {
      agingExists.value = false
    }
    agingLoaded.value = true
  } catch (e) {
    error.value = `Failed to load collection: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
})

// ── Save ──────────────────────────────────────────────────────────────────────
async function save() {
  saving.value = true
  try {
    const headers = await bearerHeaders()
    const body = {
      name: form.name.trim(),
      description: form.description.trim() || null,
      metadata: form.pocName.trim() ? { pocName: form.pocName.trim() } : null,
      settings: {
        reviewFields: {
          detail:  { enabled: form.detailEnabled,  required: form.detailRequired  },
          comment: { enabled: form.commentEnabled, required: form.commentRequired }
        },
        status: {
          canAccept:      form.canAccept,
          minAcceptGrant: form.minAcceptGrant,
          resetCriteria:  form.resetCriteria
        },
        history: {
          maxReviews: form.maxReviews
        }
      }
    }

    const res = await fetch(`${config.apiBase}/collections/${cid}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify(body)
    })

    if (!res.ok) {
      const msg = await res.text()
      throw new Error(msg || `HTTP ${res.status}`)
    }

    const updated = await res.json()
    collectionName.value = updated.name ?? form.name

    toast.add({ severity: 'success', summary: 'Saved', detail: 'Collection settings updated.', life: 3000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Save failed', detail: (e as Error).message, life: 5000 })
  } finally {
    saving.value = false
  }
}

// ── Review Aging save ─────────────────────────────────────────────────────────
async function saveAging() {
  agingSaving.value = true
  try {
    const headers = await bearerHeaders()
    const body = {
      enabled:       aging.enabled,
      daysUntilStale: aging.daysUntilStale,
      targetStatus:  aging.targetStatus
    }
    const res = await fetch(`${config.apiBase}/collections/${cid}/task-config/review-aging`, {
      method: 'PUT',
      headers,
      body: JSON.stringify(body)
    })
    if (!res.ok) {
      const msg = await res.text()
      throw new Error(msg || `HTTP ${res.status}`)
    }
    agingExists.value = true
    toast.add({ severity: 'success', summary: 'Saved', detail: 'Review aging configuration saved.', life: 3000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Save failed', detail: (e as Error).message, life: 5000 })
  } finally {
    agingSaving.value = false
  }
}

// ── Review Aging run now ──────────────────────────────────────────────────────
function confirmRunAging() {
  confirm.require({
    message: `This will reset all reviews not touched in ${aging.daysUntilStale} day(s) to "${aging.targetStatus}". Continue?`,
    header: 'Run Review Aging Now',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: 'Cancel',
    acceptLabel: 'Run Now',
    accept: async () => {
      agingRunning.value = true
      try {
        const headers = await bearerHeaders()
        const res = await fetch(`${config.apiBase}/collections/${cid}/tasks/review-aging/run`, {
          method: 'POST',
          headers
        })
        if (!res.ok) {
          const msg = await res.text()
          throw new Error(msg || `HTTP ${res.status}`)
        }
        let detail = 'Review aging task completed.'
        try {
          const result = await res.json()
          if (typeof result.affected === 'number') {
            const statusLabel = targetStatusOptions.find(o => o.value === aging.targetStatus)?.label ?? aging.targetStatus
            detail = `Reset ${result.affected} review(s) to ${statusLabel}.`
          }
        } catch { /* response may be empty 204 */ }
        // Refresh lastRun from server
        try {
          const refreshHeaders = await bearerHeaders()
          const refreshRes = await fetch(`${config.apiBase}/collections/${cid}/task-config/review-aging`, { headers: refreshHeaders })
          if (refreshRes.ok) {
            const ac = await refreshRes.json()
            aging.lastRun = ac.lastRun ?? null
          }
        } catch { /* non-fatal */ }
        toast.add({ severity: 'success', summary: 'Task ran', detail, life: 5000 })
      } catch (e) {
        toast.add({ severity: 'error', summary: 'Run failed', detail: (e as Error).message, life: 5000 })
      } finally {
        agingRunning.value = false
      }
    }
  })
}

// ── Clone ─────────────────────────────────────────────────────────────────────
const cloneDialogVisible = ref(false)

function onCloned(newCollection: Record<string, unknown>) {
  const newId = newCollection.collectionId ?? newCollection.id
  if (newId) {
    router.push(`/collections/${newId}/settings`)
  }
}

// ── Delete ────────────────────────────────────────────────────────────────────
function confirmDelete() {
  confirm.require({
    message: `Permanently delete "${form.name}"? This cannot be undone.`,
    header: 'Delete Collection',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: 'Cancel',
    acceptLabel: 'Delete',
    acceptClass: 'p-button-danger',
    accept: async () => {
      deleting.value = true
      try {
        const headers = await bearerHeaders()
        const res = await fetch(`${config.apiBase}/collections/${cid}`, {
          method: 'DELETE',
          headers
        })
        if (!res.ok && res.status !== 204) {
          const msg = await res.text()
          throw new Error(msg || `HTTP ${res.status}`)
        }
        toast.add({ severity: 'success', summary: 'Deleted', detail: 'Collection deleted.', life: 3000 })
        router.push('/collections')
      } catch (e) {
        toast.add({ severity: 'error', summary: 'Delete failed', detail: (e as Error).message, life: 5000 })
      } finally {
        deleting.value = false
      }
    }
  })
}
</script>

<template>
  <Toast />
  <ConfirmDialog />
  <CollectionCloneDialog
    v-model:visible="cloneDialogVisible"
    :sourceCollectionId="cid"
    :sourceCollectionName="collectionName"
    @cloned="onCloned"
  />

  <section class="cs-root">
    <!-- Breadcrumb -->
    <p class="breadcrumb">
      <router-link :to="`/collections/${cid}`">&larr; {{ collectionName || 'Collection' }}</router-link>
    </p>

    <h2 class="cs-title">Collection Settings</h2>

    <p v-if="error" class="err">{{ error }}</p>
    <p v-if="loading" class="muted">Loading…</p>

    <template v-if="!loading && !error">
      <div class="cs-form">

        <!-- ── 1. General ─────────────────────────────────────────────────── -->
        <Fieldset legend="General" class="cs-fieldset">
          <div class="field">
            <label class="field-label" for="cs-name">Name <span class="required">*</span></label>
            <InputText id="cs-name" v-model="form.name" class="field-input" placeholder="Collection name" />
          </div>
          <div class="field">
            <label class="field-label" for="cs-desc">Description</label>
            <Textarea id="cs-desc" v-model="form.description" class="field-input" rows="3" autoResize placeholder="Optional description" />
          </div>
          <div class="field">
            <label class="field-label" for="cs-poc">POC Name</label>
            <InputText id="cs-poc" v-model="form.pocName" class="field-input" placeholder="Point of contact" />
          </div>
        </Fieldset>

        <!-- ── 2. Review Fields ───────────────────────────────────────────── -->
        <Fieldset legend="Review Fields" class="cs-fieldset">
          <div class="rf-grid">

            <div class="rf-section">
              <div class="rf-section-header muted">Detail field</div>
              <div class="field field-row">
                <label class="field-label">Enabled</label>
                <Select
                  v-model="form.detailEnabled"
                  :options="enabledOptions"
                  optionLabel="label"
                  optionValue="value"
                  class="field-select"
                />
              </div>
              <div class="field field-row">
                <label class="field-label">Required</label>
                <Select
                  v-model="form.detailRequired"
                  :options="requiredOptions"
                  optionLabel="label"
                  optionValue="value"
                  class="field-select"
                />
              </div>
            </div>

            <div class="rf-section">
              <div class="rf-section-header muted">Comment field</div>
              <div class="field field-row">
                <label class="field-label">Enabled</label>
                <Select
                  v-model="form.commentEnabled"
                  :options="enabledOptions"
                  optionLabel="label"
                  optionValue="value"
                  class="field-select"
                />
              </div>
              <div class="field field-row">
                <label class="field-label">Required</label>
                <Select
                  v-model="form.commentRequired"
                  :options="requiredOptions"
                  optionLabel="label"
                  optionValue="value"
                  class="field-select"
                />
              </div>
            </div>

          </div>
        </Fieldset>

        <!-- ── 3. Status Workflow ─────────────────────────────────────────── -->
        <Fieldset legend="Status Workflow" class="cs-fieldset">
          <div class="field field-row">
            <label class="field-label" for="cs-canaccept">Allow Accept status</label>
            <Checkbox id="cs-canaccept" v-model="form.canAccept" :binary="true" />
          </div>
          <div class="field field-row">
            <label class="field-label">Minimum grant to accept</label>
            <Select
              v-model="form.minAcceptGrant"
              :options="minGrantOptions"
              optionLabel="label"
              optionValue="value"
              :disabled="!form.canAccept"
              class="field-select"
            />
          </div>
          <div class="field field-row">
            <label class="field-label">Reset status on</label>
            <Select
              v-model="form.resetCriteria"
              :options="resetCriteriaOptions"
              optionLabel="label"
              optionValue="value"
              class="field-select"
            />
          </div>
        </Fieldset>

        <!-- ── 4. History ─────────────────────────────────────────────────── -->
        <Fieldset legend="History" class="cs-fieldset">
          <div class="field field-row">
            <label class="field-label">Max reviews kept</label>
            <Select
              v-model="form.maxReviews"
              :options="maxReviewsOptions"
              optionLabel="label"
              optionValue="value"
              class="field-select"
            />
          </div>
        </Fieldset>

        <!-- ── 5. Custom Metadata ────────────────────────────────────────── -->
        <Fieldset legend="Custom Metadata" class="cs-fieldset">
          <MetadataPanel entityType="collection" :entityId="cid" />
        </Fieldset>

        <!-- ── Save button ────────────────────────────────────────────────── -->
        <div class="save-row">
          <Button
            label="Save Settings"
            icon="pi pi-check"
            :loading="saving"
            :disabled="!form.name.trim()"
            @click="save"
          />
        </div>

        <!-- ── 6. Automated Review Aging ─────────────────────────────────── -->
        <Card v-if="agingLoaded" class="aging-card">
          <template #title>
            <div class="aging-card-title">
              <span>Automated Review Aging</span>
              <span v-if="agingExists" class="aging-badge">Configured</span>
            </div>
          </template>
          <template #content>

            <!-- Enable toggle -->
            <div class="field field-row">
              <div class="aging-toggle-label">
                <span class="field-label">Enable automatic review aging</span>
                <span class="field-sublabel">When enabled, reviews older than the configured threshold are automatically reset</span>
              </div>
              <InputSwitch v-model="aging.enabled" inputId="cs-aging-enabled" />
            </div>

            <!-- Days until stale -->
            <div class="field field-row">
              <label class="field-label" for="cs-aging-days">
                Reset reviews not touched in
              </label>
              <div class="aging-days-row">
                <InputNumber
                  id="cs-aging-days"
                  v-model="aging.daysUntilStale"
                  :min="1"
                  :max="365"
                  showButtons
                  buttonLayout="horizontal"
                  :step="1"
                  style="width: 160px"
                  :disabled="!aging.enabled"
                />
                <span class="aging-days-suffix">days</span>
              </div>
            </div>

            <!-- Target status -->
            <div class="field field-row">
              <label class="field-label" for="cs-aging-status">Reset to status</label>
              <Select
                id="cs-aging-status"
                v-model="aging.targetStatus"
                :options="targetStatusOptions"
                optionLabel="label"
                optionValue="value"
                class="field-select"
                :disabled="!aging.enabled"
              />
            </div>

            <!-- Action buttons -->
            <div class="aging-actions">
              <Button
                label="Save"
                icon="pi pi-check"
                :loading="agingSaving"
                @click="saveAging"
              />
              <Button
                label="Run Now"
                icon="pi pi-play"
                severity="secondary"
                outlined
                :loading="agingRunning"
                :disabled="!agingExists"
                @click="confirmRunAging"
                v-tooltip.top="agingExists ? 'Run the aging task immediately' : 'Save the configuration before running'"
              />
            </div>

            <!-- Last run status line -->
            <div class="aging-status-line">
              <span class="pi pi-clock aging-status-icon"></span>
              <span class="muted">Last run: <strong>{{ formatLastRun(aging.lastRun) }}</strong></span>
            </div>

          </template>
        </Card>

        <!-- ── 7. Clone & Danger Zone ────────────────────────────────────── -->
        <Fieldset legend="Actions" class="cs-fieldset">
          <p class="muted danger-desc">
            Clone this collection to create a new collection with the same settings. Optionally copy grants, labels, and the asset list.
          </p>
          <Button
            label="Clone Collection"
            icon="pi pi-copy"
            severity="secondary"
            outlined
            @click="cloneDialogVisible = true"
          />
        </Fieldset>

        <Fieldset legend="Danger Zone" class="cs-fieldset cs-danger-zone">
          <p class="muted danger-desc">
            Deleting this collection is permanent and cannot be undone. All associated assets, reviews, and data will be removed.
          </p>
          <Button
            label="Delete Collection"
            icon="pi pi-trash"
            severity="danger"
            :loading="deleting"
            @click="confirmDelete"
          />
        </Fieldset>

      </div>
    </template>
  </section>
</template>

<style scoped>
/* ── Root ─────────────────────────────────────────────────────────────────── */
.cs-root { padding: 0.5rem 1rem 3rem; max-width: 780px; }
.breadcrumb { margin: 0 0 0.5rem; }
.cs-title   { margin: 0 0 1.25rem; }
.err        { color: #f85149; }

/* ── Form container ───────────────────────────────────────────────────────── */
.cs-form { display: flex; flex-direction: column; gap: 1.25rem; }

/* ── Fieldset override ────────────────────────────────────────────────────── */
.cs-fieldset { width: 100%; }

/* ── Generic field row ────────────────────────────────────────────────────── */
.field { display: flex; flex-direction: column; gap: 0.35rem; margin-bottom: 0.9rem; }
.field:last-child { margin-bottom: 0; }

.field-row { flex-direction: row; align-items: center; gap: 1rem; }
.field-row .field-label { width: 220px; flex-shrink: 0; }

.field-label { font-size: 0.9rem; font-weight: 500; }
.field-sublabel { font-size: 0.8rem; font-weight: 400; opacity: 0.7; margin-top: 0.15rem; }
.required    { color: #f85149; }

.field-input  { width: 100%; }
.field-select { min-width: 200px; }

/* ── Review Fields two-column grid ───────────────────────────────────────── */
.rf-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
@media (max-width: 600px) { .rf-grid { grid-template-columns: 1fr; } }

.rf-section { display: flex; flex-direction: column; gap: 0.5rem; }
.rf-section-header { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem; }

/* ── Save row ─────────────────────────────────────────────────────────────── */
.save-row { display: flex; justify-content: flex-end; }

/* ── Danger zone ──────────────────────────────────────────────────────────── */
.cs-danger-zone :deep(.p-fieldset-legend) { color: #f85149; }
.cs-danger-zone :deep(.p-fieldset) { border-color: #f85149; }
.danger-desc { margin: 0 0 1rem; font-size: 0.88rem; }

/* ── Automated Review Aging card ─────────────────────────────────────────── */
.aging-card { width: 100%; }

.aging-card-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 1rem;
  font-weight: 600;
}

.aging-badge {
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  background: color-mix(in srgb, var(--p-primary-color, #6366f1) 15%, transparent);
  color: var(--p-primary-color, #6366f1);
  border: 1px solid color-mix(in srgb, var(--p-primary-color, #6366f1) 35%, transparent);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.aging-toggle-label {
  display: flex;
  flex-direction: column;
  width: 220px;
  flex-shrink: 0;
}

.aging-days-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.aging-days-suffix {
  font-size: 0.9rem;
  opacity: 0.75;
}

.aging-actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-top: 1.25rem;
}

.aging-status-line {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin-top: 1rem;
  font-size: 0.85rem;
  padding-top: 0.75rem;
  border-top: 1px solid color-mix(in srgb, currentColor 12%, transparent);
}

.aging-status-icon {
  opacity: 0.5;
  font-size: 0.85rem;
}
</style>
