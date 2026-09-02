# ---- build stage ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

# ---- runtime stage (appliance) ----
FROM nginx:1.27-alpine
# Static SPA
COPY --from=build /app/dist /usr/share/nginx/html
# nginx config template - the official image runs envsubst on /etc/nginx/templates/*.template
COPY deploy/nginx.conf.template /etc/nginx/templates/default.conf.template
# Generates /config.js (front-end runtime config) from env at container start
COPY deploy/30-stigman-config.sh /docker-entrypoint.d/30-stigman-config.sh
RUN chmod +x /docker-entrypoint.d/30-stigman-config.sh

# Defaults assume the SPA sits next to the existing STIG Manager + Keycloak
# containers on the same Docker network. Override at `docker run`/compose time.
ENV API_UPSTREAM=http://stigman:54000/ \
    KC_UPSTREAM=http://keycloak:8080/kc/ \
    OIDC_AUTHORITY=https://localhost/kc/realms/stigman \
    OIDC_CLIENT_ID=stig-manager \
    OIDC_SCOPE="openid stig-manager:collection stig-manager:stig stig-manager:user stig-manager:op" \
    API_BASE=/stigman/api

EXPOSE 80
