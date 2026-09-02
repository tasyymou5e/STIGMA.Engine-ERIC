<script setup lang="ts">
import { ref, watch } from 'vue'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import { api } from '../api/client'
import type { Collection } from '../api/types'

// ---------------------------------------------------------------------------
// Props / emits
// ---------------------------------------------------------------------------
const props = defineProps<{ visible: boolean; collection: Collection | null }>()
const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
  (e: 'updated', collection: Collection): void
}>()

// ---------------------------------------------------------------------------
// Form state
// ---------------------------------------------------------------------------
const name = ref('')
const description = ref('')
const pocName = ref('')
const submitting = ref(false)
const nameError = ref('')
const saveError = ref('')

// Populate form when collection prop changes or dialog opens
watch(
  [() => props.visible, () => props.collection],
  ([visible, col]) => {
    if (visible && col) {
      name.value = col.name
      description.value = col.description ?? ''
      pocName.value = col.metadata?.pocName ?? ''
      nameError.value = ''
      saveError.value = ''
      submitting.value = false
    }
  },
  { immediate: true }
)

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------
async function submit() {
  nameError.value = ''
  saveError.value = ''

  if (!name.value.trim()) {
    nameError.value = 'Name is required.'
    return
  }
  if (!props.collection) return

  submitting.value = true
  try {
    const metadata: Record<string, string> = { ...(props.collection.metadata ?? {}) }
    if (pocName.value.trim()) {
      metadata.pocName = pocName.value.trim()
    } else {
      delete metadata.pocName
    }

    const { data, error } = await api.PATCH('/collections/{id}', {
      params: { path: { id: props.collection.collectionId } },
      body: {
        name: name.value.trim(),
        description: description.value.trim() || null,
        metadata: Object.keys(metadata).length ? metadata : null
      }
    })

    if (error || !data) {
      saveError.value = 'Failed to update collection.'
      return
    }

    emit('updated', data as Collection)
    close()
  } finally {
    submitting.value = false
  }
}

function close() {
  if (submitting.value) return
  emit('update:visible', false)
}
</script>

<template>
  <Dialog
    :visible="visible"
    header="Edit Collection"
    modal
    :style="{ width: '32rem' }"
    :closable="!submitting"
    @update:visible="(v) => { if (!submitting) emit('update:visible', v) }"
  >
    <div class="form-body">
      <div class="field">
        <label for="edit-col-name">Name <span class="required">*</span></label>
        <InputText
          id="edit-col-name"
          v-model="name"
          class="w-full"
          :class="{ 'p-invalid': nameError }"
          placeholder="Collection name"
          :disabled="submitting"
          @keydown.enter="submit"
        />
        <small v-if="nameError" class="p-error">{{ nameError }}</small>
      </div>

      <div class="field">
        <label for="edit-col-desc">Description</label>
        <Textarea
          id="edit-col-desc"
          v-model="description"
          class="w-full"
          rows="3"
          placeholder="Optional description"
          :disabled="submitting"
          autoResize
        />
      </div>

      <div class="field">
        <label for="edit-col-poc">POC Name</label>
        <InputText
          id="edit-col-poc"
          v-model="pocName"
          class="w-full"
          placeholder="Point of contact name"
          :disabled="submitting"
        />
      </div>

      <p v-if="saveError" class="save-error">{{ saveError }}</p>
    </div>

    <template #footer>
      <Button
        label="Cancel"
        severity="secondary"
        text
        :disabled="submitting"
        @click="close"
      />
      <Button
        label="Save"
        icon="pi pi-check"
        :loading="submitting"
        :disabled="submitting"
        @click="submit"
      />
    </template>
  </Dialog>
</template>

<style scoped>
.form-body {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  padding-top: 0.25rem;
}

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

.save-error {
  color: #f85149;
  font-size: 0.875rem;
  margin: 0;
}
</style>
