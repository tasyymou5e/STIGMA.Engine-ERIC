#!/bin/sh
# Regenerate the front-end runtime config from environment variables at start.
# This is what lets ONE built image work in any environment without rebuilding.
set -eu

cat > /usr/share/nginx/html/config.js <<EOF
window.__APP_CONFIG__ = {
  oidcAuthority: "${OIDC_AUTHORITY}",
  oidcClientId: "${OIDC_CLIENT_ID}",
  oidcScope: "${OIDC_SCOPE}",
  apiBase: "${API_BASE}"
};
EOF

echo "[stigman-webui] wrote /config.js (authority=${OIDC_AUTHORITY}, apiBase=${API_BASE})"
