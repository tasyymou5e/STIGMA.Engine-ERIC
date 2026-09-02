<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import ToggleSwitch from 'primevue/toggleswitch'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'

// ---------- types ----------
type UserStatus = 'enabled' | 'disabled'

interface AppUser {
  userId: string
  username: string
  displayName?: string | null
  email?: string | null
  status: UserStatus
  lastAccess?: string | null
}

// ---------- state ----------
const users        = ref<AppUser[]>([])
const loading      = ref(true)
const error        = ref('')
const toggling     = ref<Set<string>>(new Set())

// Create dialog
const showCreate   = ref(false)
const newUsername  = ref('')
const creating     = ref(false)
const createError  = ref('')

// ---------- API helpers ----------
async function getBearerHeaders(): Promise<HeadersInit> {
  const { getAccessToken } = await import('../../auth/oidc')
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

async function loadUsers() {
  loading.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const res = await fetch(`${config.apiBase}/users`, { headers })
    if (!res.ok) throw new Error(await res.text())
    users.value = await res.json()
  } catch (e) {
    error.value = `Failed to load users: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

onMounted(loadUsers)

// ---------- create user ----------
function openCreateDialog() {
  newUsername.value = ''
  createError.value = ''
  showCreate.value = true
}

async function submitCreateUser() {
  if (!newUsername.value.trim()) {
    createError.value = 'Username is required.'
    return
  }
  creating.value = true
  createError.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const res = await fetch(`${config.apiBase}/users`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ username: newUsername.value.trim() })
    })
    if (!res.ok) throw new Error(await res.text())
    const created: AppUser = await res.json()
    users.value = [...users.value, created].sort((a, b) =>
      a.username.localeCompare(b.username)
    )
    showCreate.value = false
  } catch (e) {
    createError.value = `Create failed: ${(e as Error).message}`
  } finally {
    creating.value = false
  }
}

// ---------- toggle status ----------
async function toggleStatus(u: AppUser) {
  if (toggling.value.has(u.userId)) return
  toggling.value = new Set([...toggling.value, u.userId])
  const newStatus: UserStatus = u.status === 'enabled' ? 'disabled' : 'enabled'
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const res = await fetch(`${config.apiBase}/users/${u.userId}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ status: newStatus })
    })
    if (!res.ok) throw new Error(await res.text())
    const idx = users.value.findIndex(x => x.userId === u.userId)
    if (idx !== -1) users.value[idx] = { ...users.value[idx], status: newStatus }
  } catch (e) {
    error.value = `Toggle failed: ${(e as Error).message}`
  } finally {
    const s = new Set(toggling.value)
    s.delete(u.userId)
    toggling.value = s
  }
}

function formatDate(iso?: string | null) {
  if (!iso) return '—'
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    }).format(new Date(iso))
  } catch {
    return iso
  }
}
</script>

<template>
  <section>
    <div class="header-row">
      <h2>Users</h2>
      <Button label="Create User" icon="pi pi-plus" @click="openCreateDialog" />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="users"
      :loading="loading"
      dataKey="userId"
      paginator
      :rows="20"
      stripedRows
      responsiveLayout="scroll"
      sortField="username"
      :sortOrder="1"
    >
      <template #empty><span class="muted">No users found.</span></template>

      <Column field="username" header="Username" sortable />

      <Column field="displayName" header="Display Name" sortable>
        <template #body="{ data }">
          <span v-if="data.displayName">{{ data.displayName }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <Column field="email" header="Email">
        <template #body="{ data }">
          <span v-if="data.email">{{ data.email }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <Column header="Last Access" sortField="lastAccess" sortable>
        <template #body="{ data }">
          <span class="muted-mono">{{ formatDate(data.lastAccess) }}</span>
        </template>
      </Column>

      <Column header="Status" style="width: 9rem" sortField="status" sortable>
        <template #body="{ data }">
          <Tag
            :value="data.status === 'enabled' ? 'Enabled' : 'Disabled'"
            :severity="data.status === 'enabled' ? 'success' : 'secondary'"
          />
        </template>
      </Column>

      <Column header="Active" style="width: 6rem; text-align: center">
        <template #body="{ data }">
          <ToggleSwitch
            :modelValue="data.status === 'enabled'"
            :disabled="toggling.has(data.userId)"
            @update:modelValue="() => toggleStatus(data)"
          />
        </template>
      </Column>
    </DataTable>

    <!-- Create User Dialog -->
    <Dialog
      v-model:visible="showCreate"
      header="Create User"
      :modal="true"
      :closable="true"
      style="width: 28rem"
    >
      <div class="dialog-body">
        <label for="new-username">Username</label>
        <InputText
          id="new-username"
          v-model="newUsername"
          placeholder="Enter username"
          autofocus
          @keyup.enter="submitCreateUser"
        />
        <p v-if="createError" class="err">{{ createError }}</p>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showCreate = false" />
        <Button label="Create" icon="pi pi-check" :loading="creating" @click="submitCreateUser" />
      </template>
    </Dialog>
  </section>
</template>

<style scoped>
.header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}
.header-row h2 { margin: 0; }
.err { color: #f85149; }
.muted { color: var(--p-text-muted-color, #6b7280); }
.muted-mono { font-size: 0.85rem; color: var(--p-text-muted-color, #6b7280); font-variant-numeric: tabular-nums; }
.dialog-body { display: flex; flex-direction: column; gap: 0.5rem; }
.dialog-body label { font-weight: 600; }
</style>
