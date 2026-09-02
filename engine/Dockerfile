# ---- build ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY tsconfig.json ./
COPY src ./src
RUN npm run build \
 && cp src/db/schema.sql dist/db/schema.sql \
 && cp src/db/seed.sql dist/db/seed.sql 2>/dev/null || true \
 && cp -r src/db/migrations dist/db/migrations 2>/dev/null || true \
 && npm prune --omit=dev

# ---- runtime ----
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
EXPOSE 54100
# Run `node dist/db/migrate.js` once to create the schema, then start the API.
CMD ["node", "dist/index.js"]
