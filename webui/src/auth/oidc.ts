// OIDC Authorization Code + PKCE wiring (oidc-client-ts) against Keycloak.
// PKCE is on by default for response_type 'code' in oidc-client-ts.
import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts'
import { config } from '../config'

const origin = window.location.origin

export const userManager = new UserManager({
  authority: config.oidcAuthority,
  client_id: config.oidcClientId,
  redirect_uri: `${origin}/callback`,
  post_logout_redirect_uri: origin,
  response_type: 'code',
  scope: config.oidcScope,
  // Keep the user in localStorage so a refresh doesn't bounce through Keycloak.
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  automaticSilentRenew: true,
  // STIG Manager's realm uses fragment response mode; query also works for SPAs.
  monitorSession: false
})

export async function getUser(): Promise<User | null> {
  return userManager.getUser()
}

export async function login(): Promise<void> {
  // Remember where the user was headed so the callback can return them.
  sessionStorage.setItem('post_login_redirect', window.location.pathname + window.location.search)
  await userManager.signinRedirect()
}

export async function completeLogin(): Promise<string> {
  await userManager.signinRedirectCallback()
  const target = sessionStorage.getItem('post_login_redirect') || '/'
  sessionStorage.removeItem('post_login_redirect')
  return target
}

export async function logout(): Promise<void> {
  await userManager.signoutRedirect()
}

export async function getAccessToken(): Promise<string | null> {
  const user = await getUser()
  return user && !user.expired ? user.access_token : null
}
