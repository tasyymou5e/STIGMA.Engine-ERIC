import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { getUser, login } from '../auth/oidc'

const routes: RouteRecordRaw[] = [
  // Application Overview (Meta Dashboard) — the default / route
  { path: '/', name: 'dashboard', component: () => import('../views/MetaDashboardView.vue'), meta: { auth: true } },
  { path: '/dashboard', redirect: { name: 'dashboard' } },
  { path: '/meta', redirect: { name: 'dashboard' } },
  // Legacy home redirect (HomeView now forwards to dashboard)
  { path: '/home', name: 'home', component: () => import('../views/HomeView.vue'), meta: { auth: true } },
  { path: '/collections', name: 'collections', component: () => import('../views/CollectionsView.vue'), meta: { auth: true } },
  { path: '/collections/:id', name: 'collection', component: () => import('../views/CollectionView.vue'), meta: { auth: true }, props: true },
  { path: '/collections/:id/settings', name: 'collection-settings', component: () => import('../views/CollectionSettingsView.vue'), meta: { auth: true }, props: true },
  { path: '/collections/:id/findings', name: 'findings', component: () => import('../views/FindingsView.vue'), meta: { auth: true }, props: true },
  { path: '/collections/:id/metrics', name: 'metrics', component: () => import('../views/MetricsView.vue'), meta: { auth: true }, props: true },
  {
    path: '/collections/:collectionId/assets',
    name: 'collection-assets',
    component: () => import('../views/AssetsView.vue'),
    meta: { auth: true },
    props: true
  },
  {
    path: '/collections/:collectionId/admin/grants',
    name: 'collection-grants',
    component: () => import('../views/admin/GrantsView.vue'),
    meta: { auth: true },
    props: true
  },
  {
    path: '/collections/:collectionId/admin/labels',
    name: 'collection-labels',
    component: () => import('../views/admin/LabelsView.vue'),
    meta: { auth: true },
    props: true
  },
  { path: '/collections/new', redirect: '/collections' },
  { path: '/admin/collections', name: 'admin-collections', component: () => import('../views/admin/CollectionsAdminView.vue'), meta: { auth: true } },
  { path: '/admin/users', name: 'admin-users', component: () => import('../views/admin/UsersView.vue'), meta: { auth: true } },
  { path: '/admin/user-groups', name: 'admin-user-groups', component: () => import('../views/admin/UserGroupsView.vue'), meta: { auth: true } },
  { path: '/admin/jobs', name: 'admin-jobs', component: () => import('../views/admin/JobsView.vue'), meta: { auth: true } },
  { path: '/admin/logs', name: 'admin-logs', component: () => import('../views/admin/LogsView.vue'), meta: { auth: true } },
  {
    path: '/collections/:collectionId/assets/:assetId/reviews/:ruleId',
    name: 'review',
    component: () => import('../views/ReviewView.vue'),
    meta: { auth: true },
    props: true
  },
  {
    path: '/collections/:id/checklist/:benchmarkId',
    name: 'checklist',
    component: () => import('../views/ChecklistView.vue'),
    meta: { auth: true },
    props: (route) => ({
      id: route.params.id,
      benchmarkId: route.params.benchmarkId,
      assetId: route.query.assetId ? String(route.query.assetId) : undefined
    })
  },
  { path: '/eval-stig', name: 'eval-stig', component: () => import('../views/EvalStigView.vue'), meta: { auth: true } },
  { path: '/eval-stig/new', name: 'eval-stig-new', component: () => import('../views/EvalStigView.vue'), meta: { auth: true }, props: { openNew: true } },
  { path: '/eval-stig/:jobId', name: 'eval-stig-job', component: () => import('../views/EvalStigJobView.vue'), meta: { auth: true }, props: true },
  { path: '/stigs', name: 'stigs', component: () => import('../views/StigsView.vue'), meta: { auth: true } },
  { path: '/stigs/:benchmarkId', name: 'stig-detail', component: () => import('../views/StigDetailView.vue'), meta: { auth: true }, props: true },
  { path: '/stigs/:benchmarkId/diff', name: 'stig-diff', component: () => import('../views/StigDiffView.vue'), meta: { auth: true }, props: true },
  { path: '/info', name: 'app-info', component: () => import('../views/AppInfoView.vue'), meta: { auth: true } },
  { path: '/docs', name: 'docs', component: () => import('../views/DocsView.vue'), meta: { auth: true } },
  { path: '/docs/:section', name: 'docs-section', component: () => import('../views/DocsView.vue'), meta: { auth: true }, props: true },
  { path: '/callback', name: 'callback', component: () => import('../views/CallbackView.vue') }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Auth guard: routes flagged meta.auth require a valid (non-expired) OIDC user;
// otherwise kick off the Keycloak login redirect.
router.beforeEach(async (to) => {
  if (!to.meta.auth) return true
  const user = await getUser()
  if (user && !user.expired) return true
  await login()
  return false
})

export default router
