import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// During `npm run dev` the SPA is served from http://localhost:5173. To avoid
// CORS against the running stack, we proxy the STIG Manager API (and Keycloak,
// if you choose relative auth) through Vite to the local nginx on https://localhost.
// The stack uses a self-signed cert, so `secure: false` accepts it in dev.
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/stigman': {
        target: 'https://localhost',
        changeOrigin: true,
        secure: false
      },
      '/kc': {
        target: 'https://localhost',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
