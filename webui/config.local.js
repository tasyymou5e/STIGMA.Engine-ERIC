// Local Docker demo runtime config (mounted over public/config.js in the container).
// Points the SPA directly at the local Keycloak (:8080) and the engine API (:54100),
// both published on the host so the browser can reach them. Source public/config.js
// is left untouched.
window.__APP_CONFIG__ = {
  oidcAuthority: 'http://localhost:8080/realms/stigman',
  oidcClientId: 'stig-manager',
  oidcScope: 'openid stig-manager:collection stig-manager:stig stig-manager:user stig-manager:op',
  apiBase: 'http://localhost:54100/api'
}
