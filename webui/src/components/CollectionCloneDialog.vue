<script setup lang="ts">
import { ref, watch } from 'vue'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Checkbox from 'primevue/checkbox'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'

// ---------- props & emits ----------
const props = defineProps<{
  visible: boolean
  sourceCollectionId: number | string
  sourceCollectionName: string
}>()

const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
  (e: 'cloned', newCollection: Record<string, unknown>): void
}>()

// ---------- form state ----------
const newName = ref('')
const description = ref('')
const copyGrants = ref(false)
const copyLabels = ref(false)
const copyAssets = ref(false)

const saving = ref(false)
const errorMsg = ref('')

const toast = useToast()

// Pre-fill name each time dialog opens
watch(
  () => props.visible,
  (open) => {
    if (open) {
      newName.value = props.sourceCollectionName
        ? `${props.sourceCollectionName} (Clone)`
        : '(Clone)'
      description.value = ''
      copyGrants.value = false
      copyLabels.value = false
      copyAssets.value = false
      errorMsg.value = ''
    }
  }
)

// ---------- API helpers ----------
async function getBearerHeaders(): Promise<HeadersInit> {
  const { getAccessToken } = await import('../auth/oidc')
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

// ---------- submit ----------
async function submit() {
  if (!newName.value.trim()) return
  saving.value = true
  errorMsg.value = ''
  try {
    const { config } = await import('../config')
    const headers = await getBearerHeaders()

    const body: Record<string, unknown> = {
      name: newName.value.trim(),
      options: {
        grants: copyGrants.value,
        labels: copyLabels.value,
        assets: copyAssets.value
      }
    }
    if (description.value.trim()) {
      body.description = description.value.trim()
    }

    const res = await fetch(`${config.apiBase}/collections/${Number(props.sourceCollectionId)}/clones`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body)
    })

    if (!res.ok) {
      const msg = await res.text()
      throw new Error(msg || `HTTP ${res.status}`)
    }

    const created = await res.json() as Record<string, unknown>

    toast.add({
      severity: 'success',
      summary: 'Collection cloned',
      detail: `"${newName.value.trim()}" was created successfully.`,
      life: 4000
    })

    emit('update:visible', false)
    emit('cloned', created)
  } catch (e) {
    errorMsg.value = `Clone failed: ${(e as Error).message}`
    toast.add({
      severity: 'error',
      summary: 'Clone failed',
      detail: (e as Error).message,
      life: 6000
    })
  } finally {
    saving.value = false
  }
}

function cancel() {
  emit('update:visible', false)
}
</script>

<template>
  <Dialog
    :visible="visible"
    @update:visible="(v) => emit('update:visible', v)"
    header="Clone Collection"
    modal
    :style="{ width: '32rem' }"
    :closable="!saving"
  >
    <div class="clone-form">
      <p class="clone-source muted">
        Source: <strong>{{ sourceCollectionName }}</strong>
      </p>

      <p v-if="errorMsg" class="err">{{ errorMsg }}</p>

      <!-- New name -->
      <div class="field">
        <label class="field-label" for="clone-name">
          New Collection Name <span class="required">*</span>
        </label>
        <InputText
          id="clone-name"
          v-model="newName"
          class="field-input"
          placeholder="Enter a name for the new collection"
          maxlength="128"
          autofocus
        />
      </div>

      <!-- Description -->
      <div class="field">
        <label class="field-label" for="clone-desc">Description</label>
        <Textarea
          id="clone-desc"
          v-model="description"
          class="field-input"
          rows="3"
          autoResize
          placeholder="Optional description"
        />
      </div>

      <!-- Clone options -->
      <fieldset class="options-fieldset">
        <legend class="options-legend">Copy options</legend>

        <div class="option-row">
          <Checkbox id="clone-grants" v-model="copyGrants" :binary="true" />
          <label for="clone-grants" class="option-label">
            Copy grants
            <span class="option-hint muted">— user and group access permissions</span>
          </label>
        </div>

        <div class="option-row">
          <Checkbox id="clone-labels" v-model="copyLabels" :binary="true" />
          <label for="clone-labels" class="option-label">
            Copy labels
            <span class="option-hint muted">— label definitions</span>
          </label>
        </div>

        <div class="option-row">
          <Checkbox id="clone-assets" v-model="copyAssets" :binary="true" />
          <label for="clone-assets" class="option-label">
            Copy asset list
            <span class="option-hint muted">— assets without reviews</span>
          </label>
        </div>
      </fieldset>
    </div>

    <template #footer>
      <Button
        label="Cancel"
        severity="secondary"
        text
        :disabled="saving"
        @click="cancel"
      />
      <Button
        label="Clone Collection"
        icon="pi pi-copy"
        :loading="saving"
        :disabled="!newName.trim()"
        @click="submit"
      />
    </template>
  </Dialog>
</template>

<style scoped>
.clone-form    { display: flex; flex-direction: column; gap: 1rem; padding: 0.25rem 0; }
.clone-source  { margin: 0; font-size: 0.88rem; }

.field         { display: flex; flex-direction: column; gap: 0.35rem; }
.field-label   { font-size: 0.9rem; font-weight: 500; }
.field-input   { width: 100%; }
.required      { color: #f85149; }

.options-fieldset {
  border: 1px solid var(--p-surface-300, #dee2e6);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  margin: 0;
}
.options-legend {
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 0 0.4rem;
  color: var(--p-text-muted-color, #6b7280);
}

.option-row {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  padding: 0.35rem 0;
}
.option-label {
  font-size: 0.9rem;
  cursor: pointer;
  user-select: none;
}
.option-hint {
  font-size: 0.8rem;
}

.muted { color: var(--p-text-muted-color, #6b7280); }
.err   { color: #f85149; margin: 0; }
</style>
