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
const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
  (e: 'created', collection: Collection): void
}>()

// ---------------------------------------------------------------------------
// Form state
// ---------------------------------------------------------------------------
const name = ref('')
const description = ref('')
const pocName = ref('')
const submitting = ref(false)
const nameError = ref('')

// Reset form when dialog opens
watch(() => props.visible, (v) => {
  if (v) {
    name.value = ''
    description.value = ''
    pocName.value = ''
    nameError.value = ''
    submitting.value = false
  }
})

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------
async function submit() {
  nameError.value = ''
  if (!name.value.trim()) {
    nameError.value = 'Name is required.'
    return
  }

  submitting.value = true
  try {
    const metadata: Record<string, string> = {}
    if (pocName.value.trim()) metadata.pocName = pocName.value.trim()

    const { data, error } = await api.POST('/collections', {
      body: {
        name: name.value.trim(),
        description: description.value.trim() || undefined,
        metadata: Object.keys(metadata).length ? metadata : undefined
      }
    })

    if (error) {
      nameError.value = typeof error === 'object' ? JSON.stringify(error) : String(error)
      return
    }

    emit('created', (data ?? { collectionId: 0, name: name.value.trim() }) as Collection)
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
    header="New Collection"
    modal
    :style="{ width: '32rem' }"
    :closable="!submitting"
    @update:visible="(v) => { if (!submitting) emit('update:visible', v) }"
  >
    <div class="form-body">
      <div class="field">
        <label for="col-name">Name <span class="required">*</span></label>
        <InputText
          id="col-name"
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
        <label for="col-desc">Description</label>
        <Textarea
          id="col-desc"
          v-model="description"
          class="w-full"
          rows="3"
          placeholder="Optional description"
          :disabled="submitting"
          autoResize
        />
      </div>

      <div class="field">
        <label for="col-poc">POC Name</label>
        <InputText
          id="col-poc"
          v-model="pocName"
          class="w-full"
          placeholder="Point of contact name"
          :disabled="submitting"
        />
      </div>
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
        label="Create"
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
</style>
