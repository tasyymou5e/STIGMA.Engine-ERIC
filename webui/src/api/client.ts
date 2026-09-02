// Typed STIG Manager API client (openapi-fetch) with automatic bearer-token auth.
import createClient, { type Middleware } from 'openapi-fetch'
import { config } from '../config'
import { getAccessToken } from '../auth/oidc'
import type { paths } from './types'

// Attaches the current OIDC access token to every request.
const authMiddleware: Middleware = {
  async onRequest({ request }) {
    const token = await getAccessToken()
    if (token) request.headers.set('Authorization', `Bearer ${token}`)
    return request
  }
}

export const api = createClient<paths>({ baseUrl: config.apiBase })
api.use(authMiddleware)
