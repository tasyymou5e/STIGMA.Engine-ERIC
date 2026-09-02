<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { getUser, getAccessToken } from './auth/oidc'
import { useDarkMode } from './composables/useDarkMode'
import NavSidebar from './components/NavSidebar.vue'
import { config } from './config'

const route = useRoute()
const username = ref<string>('')
const isAuthenticated = ref(false)
const { isDark, toggle: toggleDark } = useDarkMode()

const classification = ref('CUI')

onMounted(async () => {
  const user = await getUser()
  if (user && !user.expired) {
    isAuthenticated.value = true
    username.value = (user?.profile?.preferred_username as string) ?? ''
  }

  try {
    const token = await getAccessToken()
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    const res = await fetch(`${config.apiBase}/op/configuration`, { headers })
    if (res.ok) {
      const data = await res.json() as { classification?: string }
      if (data.classification) classification.value = data.classification
    }
  } catch {
    // leave default CUI
  }
})

const showSidebar = () => route.name !== 'callback' && isAuthenticated.value

const classificationBanner = computed(() => {
  switch (classification.value) {
    case 'UNCLASSIFIED': return 'UNCLASSIFIED'
    case 'CUI':          return 'CONTROLLED // UNCLASSIFIED'
    case 'SECRET':       return 'SECRET'
    case 'TOP SECRET':   return 'TOP SECRET'
    default:             return classification.value
  }
})

const bannerColor = computed(() => {
  switch (classification.value) {
    case 'UNCLASSIFIED': return '#007a33'
    case 'CUI':          return '#003087'
    case 'SECRET':       return '#c8102e'
    case 'TOP SECRET':   return '#ff6600'
    default:             return '#003087'
  }
})

const bannerTextColor = computed(() => classification.value === 'CUI' ? '#ffd700' : '#fff')
</script>

<template>
  <div class="app-shell">
    <div
      class="classification-banner"
      :style="{ background: bannerColor, color: bannerTextColor }"
    >
      {{ classificationBanner }}
    </div>
    <div class="app-body">
      <NavSidebar
        v-if="showSidebar()"
        :username="username"
        :dark-mode="isDark"
        @dark-mode-change="toggleDark"
      />
      <main class="app-main">
        <router-view />
      </main>
    </div>
    <div
      class="classification-banner"
      :style="{ background: bannerColor, color: bannerTextColor }"
    >
      {{ classificationBanner }}
    </div>
  </div>
</template>

<style>
html, body {
  margin: 0;
  padding: 0;
  height: 100%;
}

.app-shell {
  display: flex;
  flex-direction: column;
  height: 100vh;
  width: 100vw;
  overflow: hidden;
}

.app-body {
  display: flex;
  flex-direction: row;
  flex: 1;
  overflow: hidden;
}

.app-main {
  flex: 1;
  overflow: auto;
  padding: 1.5rem;
  box-sizing: border-box;
}

.classification-banner {
  width: 100%;
  text-align: center;
  font-weight: 700;
  font-size: 0.95rem;
  padding: 4px 0;
  letter-spacing: 2px;
  flex-shrink: 0;
  line-height: 20px;
  height: 28px;
  box-sizing: border-box;
  user-select: none;
}
</style>
