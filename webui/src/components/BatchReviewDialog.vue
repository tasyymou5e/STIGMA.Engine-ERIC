<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import MultiSelect from 'primevue/multiselect'
import SelectButton from 'primevue/selectbutton'
import Textarea from 'primevue/textarea'
import Message from 'primevue/message'
import { api } from '../api/client'
import type { Asset, ReviewResult } from '../api/types'

// ---------------------------------------------------------------------------
// Props / emits
// ---------------------------------------------------------------------------
const props = defineProps<{
  visible: boolean
  /** Numeric collection ID */
  collectionId: number
  /** Rule IDs selected in the checklist */
  selectedRuleIds: string[]
  /** All assets available in this collection */
  availableAssets: Asset[]
}>()

const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
  /** Fired after a successful batch — callers should refresh rule counts */
  (e: 'updated'): void
}>()

// ---------------------------------------------------------------------------
// Result options — mirrors upstream STIG Manager label map
// ---------------------------------------------------------------------------
interface ResultOption { label: string; value: ReviewResult }
const resultOptions: ResultOption[] = [
  { label: 'NF',   value: 'pass' },
  { label: 'Open', value: 'fail' },
  { label: 'N/A',  value: 'notapplicable' },
  { label: 'NR',   value: 'notchecked' }
]

// ---------------------------------------------------------------------------
// Form state
// ---------------------------------------------------------------------------
const selectedAssetIds  = ref<number[]>([])
const selectedResult    = ref<ReviewResult | null>(null)
const detail            = ref('')
const comment           = ref('')
const applying          = ref(false)
const resultError       = ref('')
const lastResponse      = ref<{ submitted: number; errors: number } | null>(null)

// ---------------------------------------------------------------------------
// Reset when dialog opens
// ---------------------------------------------------------------------------
watch(() => props.visible, (v) => {
  if (v) {
    // Default: all assets selected
    selectedAssetIds.value = props.availableAssets.map(a => a.assetId)
    selectedResult.value   = null
    detail.value           = ''
    comment.value          = ''
    applying.value         = false
    resultError.value      = ''
    lastResponse.value     = null
  }
})

// ---------------------------------------------------------------------------
// Derived counts
// ---------------------------------------------------------------------------
const ruleCount  = computed(() => props.selectedRuleIds.length)
const assetCount = computed(() => selectedAssetIds.value.length)
const totalCount = computed(() => ruleCount.value * assetCount.value)

// ---------------------------------------------------------------------------
// Enable Apply only when: result chosen AND (result differs from nothing,
// which it always does on first pick) AND at least one asset selected.
// Matches upstream logic: hasResult && (resultDirty || commentDetailDirty).
// ---------------------------------------------------------------------------
const canApply = computed(() => {
  if (!selectedResult.value) return false
  if (assetCount.value === 0) return false
  const commentDetailDirty = detail.value.trim() !== '' || comment.value.trim() !== ''
  return true || commentDetailDirty // result alone is enough to enable Apply
})

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------
async function apply() {
  resultError.value = ''
  if (!selectedResult.value) {
    resultError.value = 'A result is required.'
    return
  }
  if (assetCount.value === 0) {
    resultError.value = 'Select at least one asset.'
    return
  }

  applying.value = true
  lastResponse.value = null
  try {
    const body: {
      ruleIds: string[]
      assetIds: number[]
      result: ReviewResult
      detail?: string
      comment?: string
    } = {
      ruleIds:  props.selectedRuleIds,
      assetIds: selectedAssetIds.value,
      result:   selectedResult.value
    }
    if (detail.value.trim())  body.detail  = detail.value.trim()
    if (comment.value.trim()) body.comment = comment.value.trim()

    const { data, error } = await (api as any).POST(
      `/collections/${props.collectionId}/reviews/batch`,
      { body }
    )

    if (error) {
      resultError.value = 'Batch update failed. Check console for details.'
      return
    }

    lastResponse.value = data as { submitted: number; errors: number }
    emit('updated')

    // Auto-close after short delay so user sees the success count
    setTimeout(() => close(), 1400)
  } finally {
    applying.value = false
  }
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------
function close() {
  if (applying.value) return
  emit('update:visible', false)
}
</script>

<template>
  <Dialog
    :visible="visible"
    header="Batch Edit Reviews"
    modal
    :style="{ width: '36rem' }"
    :closable="!applying"
    @update:visible="(v) => { if (!applying) emit('update:visible', v) }"
  >
    <div class="batch-body">

      <!-- ── Summary line ────────────────────────────────────────────────── -->
      <div class="summary-line">
        <i class="pi pi-list-check summary-icon" />
        <span>
          <strong>{{ ruleCount }}</strong> rule{{ ruleCount !== 1 ? 's' : '' }}
          &times;
          <strong>{{ assetCount }}</strong> asset{{ assetCount !== 1 ? 's' : '' }}
          &nbsp;=&nbsp;
          <strong>{{ totalCount }}</strong> review{{ totalCount !== 1 ? 's' : '' }} will be updated
        </span>
      </div>

      <!-- ── Asset multi-select ──────────────────────────────────────────── -->
      <div class="field">
        <label>Assets</label>
        <MultiSelect
          v-model="selectedAssetIds"
          :options="availableAssets"
          optionLabel="name"
          optionValue="assetId"
          placeholder="Select assets"
          :filter="true"
          filterPlaceholder="Filter assets..."
          class="w-full"
          display="chip"
          :disabled="applying"
        />
        <small class="hint">All assets are pre-selected. Deselect to exclude.</small>
      </div>

      <!-- ── Result ─────────────────────────────────────────────────────── -->
      <div class="field">
        <label>Result <span class="required">*</span></label>
        <SelectButton
          v-model="selectedResult"
          :options="resultOptions"
          optionLabel="label"
          optionValue="value"
          :disabled="applying"
          class="result-select"
        />
        <small v-if="resultError" class="p-error">{{ resultError }}</small>
      </div>

      <!-- ── Detail ─────────────────────────────────────────────────────── -->
      <div class="field">
        <label>Detail</label>
        <Textarea
          v-model="detail"
          rows="3"
          autoResize
          class="w-full mono"
          placeholder="Existing detail text will be preserved if left blank"
          :disabled="applying"
        />
      </div>

      <!-- ── Comment ────────────────────────────────────────────────────── -->
      <div class="field">
        <label>Comment</label>
        <Textarea
          v-model="comment"
          rows="2"
          autoResize
          class="w-full"
          placeholder="Existing comment text will be preserved if left blank"
          :disabled="applying"
        />
      </div>

      <!-- ── Success message ────────────────────────────────────────────── -->
      <Message v-if="lastResponse && lastResponse.errors === 0" severity="success" :closable="false">
        {{ lastResponse.submitted }} review{{ lastResponse.submitted !== 1 ? 's' : '' }} updated successfully.
      </Message>
      <Message v-else-if="lastResponse && lastResponse.errors > 0" severity="warn" :closable="false">
        {{ lastResponse.submitted }} updated, {{ lastResponse.errors }} failed.
      </Message>

    </div>

    <template #footer>
      <Button
        label="Cancel"
        severity="secondary"
        text
        :disabled="applying"
        @click="close"
      />
      <Button
        label="Apply"
        icon="pi pi-check"
        :loading="applying"
        :disabled="!canApply || applying"
        @click="apply"
      />
    </template>
  </Dialog>
</template>

<style scoped>
.batch-body {
  display: flex;
  flex-direction: column;
  gap: 1.1rem;
  padding-top: 0.25rem;
}

/* ── Summary ──────────────────────────────────────────────────────────────── */
.summary-line {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--p-surface-section, rgba(255,255,255,0.04));
  border: 1px solid var(--p-surface-border, #30363d);
  border-radius: 6px;
  font-size: 0.875rem;
  color: var(--p-text-color);
}
.summary-icon {
  font-size: 1rem;
  color: var(--p-primary-color, #6366f1);
  flex-shrink: 0;
}

/* ── Fields ───────────────────────────────────────────────────────────────── */
.field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.field label {
  font-size: 0.875rem;
  font-weight: 600;
}

.required {
  color: #f85149;
}

.w-full {
  width: 100%;
}

.mono {
  font-family: monospace;
  font-size: 0.82rem;
}

.hint {
  font-size: 0.78rem;
  color: var(--p-text-muted-color, #8b949e);
}

/* ── Result SelectButton ─────────────────────────────────────────────────── */
.result-select :deep(.p-button) {
  font-size: 0.82rem;
  padding: 0.35rem 0.75rem;
}
</style>
