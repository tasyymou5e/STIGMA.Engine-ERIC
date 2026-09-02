<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import Tag from 'primevue/tag'
import Card from 'primevue/card'
import Button from 'primevue/button'
import SelectButton from 'primevue/selectbutton'
import Textarea from 'primevue/textarea'
import InputText from 'primevue/inputtext'
import Accordion from 'primevue/accordion'
import AccordionPanel from 'primevue/accordionpanel'
import AccordionHeader from 'primevue/accordionheader'
import AccordionContent from 'primevue/accordioncontent'
import Toast from 'primevue/toast'
import { api } from '../api/client'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'
import type { Review, ReviewResult, ReviewHistoryEntry, ReviewAttachment } from '../api/types'
import { resultTag, severityTag } from '../util/chips'
import MetadataPanel from '../components/MetadataPanel.vue'

const props = defineProps<{
  collectionId: string
  assetId: string
  ruleId: string
}>()

const toast = useToast()

const cid = Number(props.collectionId)
const aid = Number(props.assetId)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const review = ref<Review | null>(null)
const history = ref<ReviewHistoryEntry[]>([])
const loading = ref(true)
const saving = ref(false)
const submitting = ref(false)
const accepting = ref(false)
const rejecting = ref(false)
const error = ref('')

// Editable fields
const localResult = ref<ReviewResult>('notchecked')
const localDetail = ref('')
const localComment = ref('')

// Reject workflow
const showRejectInput = ref(false)
const rejectText = ref('')

// ---------------------------------------------------------------------------
// Result options for SelectButton
// ---------------------------------------------------------------------------
const resultOptions: { label: string; value: ReviewResult; severity: string }[] = [
  { label: 'Not a Finding', value: 'pass', severity: 'success' },
  { label: 'Open', value: 'fail', severity: 'danger' },
  { label: 'Not Applicable', value: 'notapplicable', severity: 'secondary' },
  { label: 'Not Reviewed', value: 'notchecked', severity: 'warn' }
]

// ---------------------------------------------------------------------------
// Computed
// ---------------------------------------------------------------------------
const isSubmittable = computed(() =>
  localResult.value === 'pass' || localResult.value === 'fail' || localResult.value === 'notapplicable'
)

const isSubmitted = computed(() => review.value?.status === 'submitted')
const isAccepted = computed(() => review.value?.status === 'accepted')

const statusSeverity = computed(() => {
  switch (review.value?.status) {
    case 'submitted': return 'info'
    case 'accepted': return 'success'
    case 'rejected': return 'danger'
    default: return 'secondary'
  }
})

const isDirty = computed(() =>
  review.value &&
  (localResult.value !== review.value.result ||
    localDetail.value !== (review.value.detail ?? '') ||
    localComment.value !== (review.value.comment ?? ''))
)

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------
onMounted(async () => {
  await loadReview()
  await loadAttachments()
})

async function loadReview() {
  loading.value = true
  error.value = ''
  const { data, error: err } = await api.GET('/collections/{cid}/reviews/{assetId}/{ruleId}', {
    params: { path: { cid, assetId: aid, ruleId: props.ruleId } }
  })
  loading.value = false
  if (err || !data) {
    error.value = 'Failed to load review.'
    return
  }
  applyReview(data)

  // Load history and attachments if we have a reviewId
  if (data.reviewId) {
    const { data: hist } = await api.GET('/reviews/{reviewId}/history', {
      params: { path: { reviewId: data.reviewId } }
    })
    history.value = hist ?? []

    const { data: atts } = await api.GET('/reviews/{reviewId}/attachments', {
      params: { path: { reviewId: data.reviewId } }
    })
    attachments.value = atts ?? []
  }
}

function applyReview(r: Review) {
  review.value = r
  localResult.value = r.result ?? 'notchecked'
  localDetail.value = r.detail ?? ''
  localComment.value = r.comment ?? ''
}

// ---------------------------------------------------------------------------
// Save (PATCH)
// ---------------------------------------------------------------------------
async function save() {
  saving.value = true
  const { data, error: err } = await api.PATCH('/collections/{cid}/reviews/{assetId}/{ruleId}', {
    params: { path: { cid, assetId: aid, ruleId: props.ruleId } },
    body: { result: localResult.value, detail: localDetail.value, comment: localComment.value }
  })
  saving.value = false
  if (err || !data) {
    toast.add({ severity: 'error', summary: 'Save failed', detail: 'Could not save review.', life: 4000 })
    return
  }
  applyReview(data)
  toast.add({ severity: 'success', summary: 'Saved', detail: 'Review saved.', life: 3000 })
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------
async function submit() {
  // Auto-save if dirty before submitting
  if (isDirty.value) await save()
  submitting.value = true
  const { data, error: err } = await api.POST('/collections/{cid}/reviews/{assetId}/{ruleId}/submit', {
    params: { path: { cid, assetId: aid, ruleId: props.ruleId } },
    body: {}
  })
  submitting.value = false
  if (err || !data) {
    toast.add({ severity: 'error', summary: 'Submit failed', detail: 'Could not submit review.', life: 4000 })
    return
  }
  applyReview(data)
  toast.add({ severity: 'success', summary: 'Submitted', detail: 'Review submitted for acceptance.', life: 3000 })
}

// ---------------------------------------------------------------------------
// Accept
// ---------------------------------------------------------------------------
async function accept() {
  accepting.value = true
  const { data, error: err } = await api.POST('/collections/{cid}/reviews/{assetId}/{ruleId}/accept', {
    params: { path: { cid, assetId: aid, ruleId: props.ruleId } },
    body: {}
  })
  accepting.value = false
  if (err || !data) {
    toast.add({ severity: 'error', summary: 'Accept failed', detail: 'Could not accept review.', life: 4000 })
    return
  }
  applyReview(data)
  toast.add({ severity: 'success', summary: 'Accepted', detail: 'Review accepted.', life: 3000 })
}

// ---------------------------------------------------------------------------
// Reject
// ---------------------------------------------------------------------------
function beginReject() {
  showRejectInput.value = true
  rejectText.value = ''
}

function cancelReject() {
  showRejectInput.value = false
  rejectText.value = ''
}

async function confirmReject() {
  if (!rejectText.value.trim()) {
    toast.add({ severity: 'warn', summary: 'Status text required', detail: 'Provide a reason for rejection.', life: 3000 })
    return
  }
  rejecting.value = true
  const { data, error: err } = await api.POST('/collections/{cid}/reviews/{assetId}/{ruleId}/reject', {
    params: { path: { cid, assetId: aid, ruleId: props.ruleId } },
    body: { statusText: rejectText.value.trim() }
  })
  rejecting.value = false
  if (err || !data) {
    toast.add({ severity: 'error', summary: 'Reject failed', detail: 'Could not reject review.', life: 4000 })
    return
  }
  applyReview(data)
  showRejectInput.value = false
  toast.add({ severity: 'warn', summary: 'Rejected', detail: 'Review rejected.', life: 3000 })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatTs(ts: string) {
  return new Date(ts).toLocaleString()
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------
const attachments = ref<ReviewAttachment[]>([])
const attachmentsLoading = ref(false)
const uploading = ref(false)
const attachFileInput = ref<HTMLInputElement | null>(null)

async function loadAttachments() {
  if (!review.value?.reviewId) return
  attachmentsLoading.value = true
  const { data } = await api.GET('/reviews/{reviewId}/attachments', {
    params: { path: { reviewId: review.value.reviewId } }
  })
  attachmentsLoading.value = false
  attachments.value = data ?? []
}

function triggerFileInput() {
  attachFileInput.value?.click()
}

async function onFileSelected(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = '' // reset so the same file can be re-selected
  if (!file || !review.value?.reviewId) return

  if (file.size > 10 * 1024 * 1024) {
    toast.add({ severity: 'warn', summary: 'File too large', detail: 'Maximum upload size is 10 MB.', life: 4000 })
    return
  }

  uploading.value = true
  try {
    const token = await getAccessToken()
    const formData = new FormData()
    formData.append('file', file)
    const res = await fetch(
      `${config.apiBase}/reviews/${review.value.reviewId}/attachments`,
      {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData
      }
    )
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`)
    }
    const att: ReviewAttachment = await res.json()
    attachments.value.unshift(att)
    toast.add({ severity: 'success', summary: 'Uploaded', detail: `${att.filename} attached.`, life: 3000 })
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Upload failed', detail: (err as Error).message, life: 4000 })
  } finally {
    uploading.value = false
  }
}

async function downloadAttachment(att: ReviewAttachment) {
  if (!review.value?.reviewId) return
  const token = await getAccessToken()
  const res = await fetch(
    `${config.apiBase}/reviews/${review.value.reviewId}/attachments/${att.attachmentId}`,
    { headers: token ? { Authorization: `Bearer ${token}` } : {} }
  )
  if (!res.ok) {
    toast.add({ severity: 'error', summary: 'Download failed', detail: `HTTP ${res.status}`, life: 4000 })
    return
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = att.filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

async function deleteAttachment(att: ReviewAttachment) {
  if (!review.value?.reviewId) return
  const { error: err } = await api.DELETE('/reviews/{reviewId}/attachments/{id}', {
    params: { path: { reviewId: review.value.reviewId, id: att.attachmentId } }
  })
  if (err) {
    toast.add({ severity: 'error', summary: 'Delete failed', detail: 'Could not remove attachment.', life: 4000 })
    return
  }
  attachments.value = attachments.value.filter(a => a.attachmentId !== att.attachmentId)
  toast.add({ severity: 'success', summary: 'Removed', detail: `${att.filename} deleted.`, life: 3000 })
}
</script>

<template>
  <section>
    <Toast />
    <p>
      <router-link :to="`/collections/${collectionId}`">&larr; Back to Collection</router-link>
    </p>

    <p v-if="error" style="color: #f85149">{{ error }}</p>
    <p v-if="loading" class="muted">Loading review…</p>

    <template v-if="review && !loading">
      <!-- ----------------------------------------------------------------- -->
      <!-- Rule details                                                        -->
      <!-- ----------------------------------------------------------------- -->
      <Card class="rule-card">
        <template #title>
          <div class="rule-header">
            <span class="mono">{{ review.ruleId }}</span>
            <Tag
              :value="severityTag(review.severity).label"
              :severity="severityTag(review.severity).severity"
            />
            <span v-if="review.groupId" class="mono muted" style="font-size: 0.85rem">{{ review.groupId }}</span>
          </div>
        </template>
        <template #content>
          <p class="rule-title">{{ review.title }}</p>
          <template v-if="review.vulnDiscussion">
            <p class="section-label">Vulnerability Discussion</p>
            <pre class="vuln-discussion">{{ review.vulnDiscussion }}</pre>
          </template>
        </template>
      </Card>

      <!-- ----------------------------------------------------------------- -->
      <!-- Status badge                                                        -->
      <!-- ----------------------------------------------------------------- -->
      <div class="status-row" v-if="review.status">
        <span class="section-label" style="margin: 0">Status:</span>
        <Tag :value="review.status" :severity="statusSeverity" />
        <span v-if="review.statusText" class="muted status-text">{{ review.statusText }}</span>
      </div>

      <!-- ----------------------------------------------------------------- -->
      <!-- Review editor                                                       -->
      <!-- ----------------------------------------------------------------- -->
      <Card class="editor-card">
        <template #title>Review</template>
        <template #content>
          <!-- Result picker -->
          <div class="field">
            <label class="field-label">Result</label>
            <SelectButton
              v-model="localResult"
              :options="resultOptions"
              optionLabel="label"
              optionValue="value"
              :pt="{
                root: { class: 'result-select' }
              }"
            >
              <template #option="{ option }">
                <Tag
                  :value="option.label"
                  :severity="option.severity"
                  style="pointer-events: none"
                />
              </template>
            </SelectButton>
          </div>

          <!-- Finding detail -->
          <div class="field">
            <label class="field-label">Finding Details</label>
            <Textarea
              v-model="localDetail"
              rows="5"
              autoResize
              style="width: 100%; font-family: monospace; font-size: 0.85rem"
              placeholder="Describe the finding or evidence of compliance…"
            />
          </div>

          <!-- Comment -->
          <div class="field">
            <label class="field-label">Comments</label>
            <Textarea
              v-model="localComment"
              rows="3"
              autoResize
              style="width: 100%; font-size: 0.9rem"
              placeholder="Optional reviewer comments…"
            />
          </div>

          <!-- Action buttons -->
          <div class="action-row">
            <Button
              label="Save"
              icon="pi pi-save"
              severity="secondary"
              :loading="saving"
              :disabled="!isDirty"
              @click="save"
            />

            <!-- Submit: shown when result is actionable and not yet submitted/accepted -->
            <Button
              v-if="isSubmittable && !isSubmitted && !isAccepted"
              label="Submit"
              icon="pi pi-send"
              severity="info"
              :loading="submitting"
              @click="submit"
            />

            <!-- Accept / Reject: shown when submitted -->
            <template v-if="isSubmitted">
              <Button
                label="Accept"
                icon="pi pi-check"
                severity="success"
                :loading="accepting"
                @click="accept"
              />
              <Button
                label="Reject"
                icon="pi pi-times"
                severity="danger"
                :loading="rejecting"
                :disabled="showRejectInput"
                @click="beginReject"
              />
            </template>
          </div>

          <!-- Reject reason input -->
          <div v-if="showRejectInput" class="reject-block">
            <label class="field-label">Rejection Reason</label>
            <div style="display: flex; gap: 0.5rem; align-items: flex-start; flex-wrap: wrap">
              <InputText
                v-model="rejectText"
                placeholder="Required — describe the reason for rejection"
                style="flex: 1; min-width: 220px"
              />
              <Button
                label="Confirm Reject"
                severity="danger"
                size="small"
                :loading="rejecting"
                @click="confirmReject"
              />
              <Button
                label="Cancel"
                severity="secondary"
                size="small"
                text
                @click="cancelReject"
              />
            </div>
          </div>
        </template>
      </Card>

      <!-- ----------------------------------------------------------------- -->
      <!-- Review history                                                      -->
      <!-- ----------------------------------------------------------------- -->
      <div v-if="history.length" style="margin-top: 1.5rem">
        <Accordion>
          <AccordionPanel value="history">
            <AccordionHeader>
              Review History
              <span class="muted" style="margin-left: 0.5rem; font-size: 0.85rem">({{ history.length }} entries)</span>
            </AccordionHeader>
            <AccordionContent>
              <div
                v-for="(entry, idx) in history"
                :key="idx"
                class="history-entry"
              >
                <div class="history-meta">
                  <Tag
                    :value="resultTag(entry.result).label"
                    :severity="resultTag(entry.result).severity"
                    style="font-size: 0.8rem"
                  />
                  <Tag
                    v-if="entry.status"
                    :value="entry.status"
                    severity="secondary"
                    style="font-size: 0.8rem"
                  />
                  <span class="muted" style="font-size: 0.8rem">{{ entry.username ?? entry.userId ?? 'unknown' }}</span>
                  <span class="muted" style="font-size: 0.8rem">{{ formatTs(entry.ts) }}</span>
                </div>
                <p v-if="entry.detail" class="history-text mono">{{ entry.detail }}</p>
                <p v-if="entry.comment" class="history-text" style="color: var(--p-text-muted-color)">{{ entry.comment }}</p>
                <p v-if="entry.statusText" class="history-text" style="color: #f85149; font-size: 0.85rem">
                  Rejection reason: {{ entry.statusText }}
                </p>
              </div>
            </AccordionContent>
          </AccordionPanel>
        </Accordion>
      </div>
      <p v-else-if="!loading && review.reviewId" class="muted" style="margin-top: 1rem">No history available.</p>

      <!-- ----------------------------------------------------------------- -->
      <!-- Attachments                                                         -->
      <!-- ----------------------------------------------------------------- -->
      <div v-if="review.reviewId" style="margin-top: 1.5rem">
        <div class="att-header">
          <span class="section-label" style="margin: 0">Attachments</span>
          <!-- hidden file input -->
          <input
            ref="attachFileInput"
            type="file"
            style="display: none"
            @change="onFileSelected"
          />
          <Button
            label="Attach File"
            icon="pi pi-paperclip"
            severity="secondary"
            size="small"
            :loading="uploading"
            @click="triggerFileInput"
          />
        </div>

        <p v-if="attachmentsLoading" class="muted" style="font-size: 0.875rem">Loading…</p>
        <p v-else-if="attachments.length === 0" class="muted" style="font-size: 0.875rem">No attachments.</p>

        <ul v-else class="att-list">
          <li v-for="att in attachments" :key="att.attachmentId" class="att-row">
            <span class="pi pi-file att-icon" />
            <span class="att-name" :title="att.filename">{{ att.filename }}</span>
            <span class="att-meta muted">{{ formatBytes(att.size) }}</span>
            <span v-if="att.uploadedBy" class="att-meta muted">{{ att.uploadedBy }}</span>
            <span class="att-meta muted">{{ formatTs(att.uploadedAt) }}</span>
            <div class="att-actions">
              <Button
                icon="pi pi-download"
                severity="secondary"
                size="small"
                text
                rounded
                v-tooltip.top="'Download'"
                @click="downloadAttachment(att)"
              />
              <Button
                icon="pi pi-trash"
                severity="danger"
                size="small"
                text
                rounded
                v-tooltip.top="'Delete'"
                @click="deleteAttachment(att)"
              />
            </div>
          </li>
        </ul>
      </div>

      <!-- ----------------------------------------------------------------- -->
      <!-- Custom Metadata                                                     -->
      <!-- ----------------------------------------------------------------- -->
      <div v-if="review.reviewId" style="margin-top: 1.5rem">
        <Accordion>
          <AccordionPanel value="metadata">
            <AccordionHeader>Custom Metadata</AccordionHeader>
            <AccordionContent>
              <MetadataPanel entityType="review" :entityId="review.reviewId" />
            </AccordionContent>
          </AccordionPanel>
        </Accordion>
      </div>
    </template>
  </section>
</template>

<style scoped>
.rule-card { margin-bottom: 1rem; }
.rule-header { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
.rule-title { font-size: 1rem; font-weight: 500; margin: 0 0 0.75rem 0; }
.section-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--p-text-muted-color); margin-bottom: 0.25rem; }
.vuln-discussion {
  white-space: pre-wrap;
  font-family: inherit;
  font-size: 0.875rem;
  background: var(--p-surface-100, #1e1e2e);
  border: 1px solid var(--p-surface-border, #333);
  border-radius: 6px;
  padding: 0.75rem;
  margin: 0;
  max-height: 14rem;
  overflow-y: auto;
}
.status-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
.status-text { font-style: italic; font-size: 0.875rem; }
.editor-card { }
.field { margin-bottom: 1.25rem; }
.field-label { display: block; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--p-text-muted-color); margin-bottom: 0.35rem; }
.action-row { display: flex; gap: 0.6rem; flex-wrap: wrap; align-items: center; margin-top: 0.5rem; }
.reject-block { margin-top: 1rem; padding: 0.75rem; border: 1px solid #f85149; border-radius: 6px; background: rgba(248, 81, 73, 0.06); }
.history-entry { padding: 0.75rem 0; border-bottom: 1px solid var(--p-surface-border, #333); }
.history-entry:last-child { border-bottom: none; }
.history-meta { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.35rem; }
.history-text { margin: 0.2rem 0; font-size: 0.875rem; white-space: pre-wrap; }
.mono { font-family: monospace; }
/* Attachments */
.att-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.6rem; }
.att-list { list-style: none; margin: 0; padding: 0; }
.att-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.45rem 0;
  border-bottom: 1px solid var(--p-surface-border, #333);
  flex-wrap: wrap;
}
.att-row:last-child { border-bottom: none; }
.att-icon { color: var(--p-text-muted-color); font-size: 0.9rem; flex-shrink: 0; }
.att-name { font-size: 0.875rem; font-weight: 500; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.att-meta { font-size: 0.8rem; white-space: nowrap; }
.att-actions { display: flex; gap: 0.2rem; flex-shrink: 0; }
</style>
