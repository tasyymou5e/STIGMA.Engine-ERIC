<script setup lang="ts">
// HomeView redirects to the Application Overview (Meta Dashboard).
// The router entry for '/' now renders MetaDashboardView directly;
// this file is kept as a thin redirect shim for any bookmarked /home links.
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
onMounted(() => router.replace({ name: 'dashboard' }))
</script>

<template>
  <section>
    <p class="muted">Redirecting to Application Overview…</p>
  </section>
</template>

<style scoped>
.muted { color: var(--text-color-secondary, #888); font-size: 0.875rem; }
</style>
