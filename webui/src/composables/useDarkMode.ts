import { ref, onMounted } from 'vue'

export function useDarkMode() {
  const isDark = ref(localStorage.getItem('darkMode') === 'true')

  const toggle = () => {
    isDark.value = !isDark.value
    localStorage.setItem('darkMode', String(isDark.value))
    document.documentElement.classList.toggle('p-dark', isDark.value)
  }

  // Apply on mount so the class is present before first paint
  onMounted(() => document.documentElement.classList.toggle('p-dark', isDark.value))

  return { isDark, toggle }
}
