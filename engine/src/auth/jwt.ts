// Keycloak token verification via JWKS (jose). Mirrors STIG Manager's claims model:
// scopes from `scope`, privileges from realm_access.roles.
import { createRemoteJWKSet, jwtVerify, decodeJwt, type JWTPayload } from 'jose'
import { config, jwksUri } from '../config.js'

export interface AuthUser {
  sub: string
  username: string
  scopes: Set<string>
  roles: Set<string>
}

const JWKS = createRemoteJWKSet(new URL(jwksUri))

interface KcClaims extends JWTPayload {
  scope?: string
  preferred_username?: string
  realm_access?: { roles?: string[] }
}

function toUser(p: KcClaims): AuthUser {
  return {
    sub: String(p.sub ?? ''),
    username: String(p.preferred_username ?? p.sub ?? ''),
    scopes: new Set((p.scope ?? '').split(' ').filter(Boolean)),
    roles: new Set(p.realm_access?.roles ?? [])
  }
}

export async function verifyToken(token: string): Promise<AuthUser> {
  if (config.ALLOW_INSECURE_TOKENS) {
    // DEV ONLY: the demo Keycloak ships a publicly-known signing key. Decode without
    // signature verification so local testing works. NEVER enable in production.
    return toUser(decodeJwt(token) as KcClaims)
  }
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: config.OIDC_ISSUER,
    ...(config.OIDC_AUDIENCE ? { audience: config.OIDC_AUDIENCE } : {})
  })
  return toUser(payload as KcClaims)
}
