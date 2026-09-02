/// <reference types="vite/client" />

// Runtime config injected by public/config.js (or the container entrypoint).
interface AppConfig {
  oidcAuthority: string
  oidcClientId: string
  oidcScope: string
  apiBase: string
}
interface Window {
  __APP_CONFIG__: AppConfig
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, unknown>
  export default component
}
