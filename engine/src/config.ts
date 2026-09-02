import { z } from 'zod'
import fs from 'fs'

// Helper: read a Docker Secret file, return trimmed content, or fall back to a default.
function readSecret(secretPath: string, fallback: string): string {
  try {
    return fs.readFileSync(secretPath, 'utf8').trim()
  } catch {
    return fallback
  }
}

// Environment-driven config (12-factor). Defaults target the local dev stack.
// Sensitive values fall back to /run/secrets/<name> when the env var is absent,
// which is the Docker Secrets mount path inside the container.
const Env = z.object({
  PORT: z.coerce.number().default(54100),
  HOST: z.string().default('0.0.0.0'),

  DB_HOST: z.string().default('127.0.0.1'),
  DB_PORT: z.coerce.number().default(3306),
  DB_USER: z.string().default('stigman'),
  DB_PASSWORD: z.string().default(
    () => readSecret('/run/secrets/mysql_pw', 'stigmanpw')
  ),
  DB_NAME: z.string().default('stigman_engine'),
  DB_POOL_SIZE: z.coerce.number().default(10),

  // OIDC / Keycloak token validation
  OIDC_ISSUER: z.string().default('https://localhost/kc/realms/stigman'),
  OIDC_JWKS_URI: z.string().optional(), // defaults to <issuer>/protocol/openid-connect/certs
  OIDC_AUDIENCE: z.string().optional(),
  // Mirrors STIG Manager: accept the demo Keycloak's publicly-known signing key (DEV ONLY).
  ALLOW_INSECURE_TOKENS: z
    .string()
    .optional()
    .transform((v) => v === 'true' || v === '1'),

  CORS_ORIGIN: z.string().default('*'),

  CLASSIFICATION: z.enum(['UNCLASSIFIED', 'CUI', 'SECRET', 'TOP SECRET']).default('CUI')
})

export const config = Env.parse(process.env)

export const jwksUri =
  config.OIDC_JWKS_URI ?? `${config.OIDC_ISSUER.replace(/\/$/, '')}/protocol/openid-connect/certs`
