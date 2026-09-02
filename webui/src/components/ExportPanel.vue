<script setup lang="ts">
import { ref } from 'vue'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

const props = defineProps<{
  collectionId: number
  collectionName: string
}>()

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const toast = useToast()
const downloadingCkl = ref(false)
const downloadingCklb = ref(false)

// ---------------------------------------------------------------------------
// Download helper
// ---------------------------------------------------------------------------

async function triggerDownload(format: 'ckl' | 'cklb'): Promise<void> {
  const busy = format === 'ckl' ? downloadingCkl : downloadingCklb
  busy.value = true

  try {
    const token = await getAccessToken()
    const url = `${config.apiBase}/collections/${props.collectionId}/archive/${format}`

    const response = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })

    if (!response.ok) {
      let detail = `HTTP ${response.status}`
      try {
        const body = await response.json() as { error?: string }
        if (body.error) detail = body.error
      } catch {
        // ignore parse errors; use the status code message
      }
      throw new Error(detail)
    }

    const blob = await response.blob()

    // Derive filename from Content-Disposition header when present.
    const cd = response.headers.get('Content-Disposition') ?? ''
    const match = cd.match(/filename="?([^";\n]+)"?/)
    const filename = match
      ? match[1]
      : `${props.collectionName.replace(/[^A-Za-z0-9_-]/g, '_')}_${new Date().toISOString().slice(0, 10)}.${format}.zip`

    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(a.href)

    toast.add({
      severity: 'success',
      summary: 'Download started',
      detail: filename,
      life: 4000
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    toast.add({
      severity: 'error',
      summary: `Export ${format.toUpperCase()} failed`,
      detail: msg,
      life: 6000
    })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="export-panel">
    <!-- CKL button -->
    <div class="export-row">
      <Button
        label="Export CKL Archive"
        icon="pi pi-download"
        severity="secondary"
        size="small"
        class="export-btn"
        :disabled="downloadingCkl || downloadingCklb"
        @click="triggerDownload('ckl')"
      />
      <ProgressSpinner
        v-if="downloadingCkl"
        class="export-spinner"
        strokeWidth="6"
        animationDuration=".8s"
      />
    </div>

    <!-- CKLB button -->
    <div class="export-row">
      <Button
        label="Export CKLB Archive"
        icon="pi pi-download"
        severity="secondary"
        size="small"
        class="export-btn"
        :disabled="downloadingCkl || downloadingCklb"
        @click="triggerDownload('cklb')"
      />
      <ProgressSpinner
        v-if="downloadingCklb"
        class="export-spinner"
        strokeWidth="6"
        animationDuration=".8s"
      />
    </div>
  </div>
</template>

<style scoped>
.export-panel {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.export-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.export-btn {
  flex: 1;
}

.export-spinner {
  width: 1.4rem;
  height: 1.4rem;
  flex-shrink: 0;
}
</style>
