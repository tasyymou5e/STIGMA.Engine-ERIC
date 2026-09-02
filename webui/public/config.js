// Runtime configuration (appliance pattern).
// In dev this file ships these defaults. In the Docker image, docker-entrypoint.sh
// regenerates it from environment variables at container start, so ONE built image
// works in any environment without rebuilding.
window.__APP_CONFIG__ = {
  // Keycloak realm issuer (absolute - must match the realm's issuer for OIDC discovery).
  oidcAuthority: 'https://localhost/kc/realms/stigman',
  oidcClientId: 'stig-manager',
  // OAuth scopes required by the STIG Manager API for read/write.
  oidcScope: 'openid stig-manager:collection stig-manager:stig stig-manager:user stig-manager:op',
  // API base. In dev this is proxied by Vite to https://localhost (see vite.config.ts).
  apiBase: '/stigman/api'
}
