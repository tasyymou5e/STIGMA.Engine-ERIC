// Typed accessor for the runtime config injected by public/config.js.
// Falls back to sane dev defaults if the script did not load.
const cfg: AppConfig = window.__APP_CONFIG__ ?? {
  oidcAuthority: 'https://localhost/kc/realms/stigman',
  oidcClientId: 'stig-manager',
  oidcScope: 'openid stig-manager:collection stig-manager:stig stig-manager:user stig-manager:op',
  apiBase: '/stigman/api'
}

export const config = cfg
