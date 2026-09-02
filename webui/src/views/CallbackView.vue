<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { completeLogin } from '../auth/oidc'

const router = useRouter()
const error = ref('')

onMounted(async () => {
  try {
    const target = await completeLogin()
    await router.replace(target)
  } catch (e) {
    error.value = (e as Error).message
  }
})
</script>

<template>
  <div class="app-main">
    <p v-if="!error" class="muted">Completing sign-in…</p>
    <p v-else style="color: #f85149">Sign-in failed: {{ error }}</p>
  </div>
</template>
