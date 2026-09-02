import { createApp } from 'vue'
import { Chart, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, PointElement, LineElement, DoughnutController, BarController } from "chart.js"
Chart.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, PointElement, LineElement, DoughnutController, BarController)
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'
import ConfirmService from 'primevue/confirmationservice'
import Aura from '@primevue/themes/aura'
import 'primeicons/primeicons.css'

import App from './App.vue'
import router from './router'
import './style.css'

const app = createApp(App)
app.use(router)
app.use(PrimeVue, {
  theme: {
    preset: Aura,
    options: { darkModeSelector: '.p-dark' }
  }
})
app.use(ToastService)
app.use(ConfirmService)
app.mount('#app')

// Bootstrap dark mode from persisted preference before first paint
document.documentElement.classList.toggle('p-dark', localStorage.getItem('darkMode') === 'true')
