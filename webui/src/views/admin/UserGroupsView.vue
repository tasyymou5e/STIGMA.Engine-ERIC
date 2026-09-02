<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import { useConfirm } from 'primevue/useconfirm'
import ConfirmDialog from 'primevue/confirmdialog'
import { useToast } from 'primevue/usetoast'
import Toast from 'primevue/toast'

// ---------- types ----------
interface UserGroupMember {
  userId: number
  username: string
  status: string
}

interface UserGroup {
  userGroupId: number
  name: string
  description: string | null
  memberCount?: number
  members?: UserGroupMember[]
  membersLoaded?: boolean
  membersLoading?: boolean
}

// ---------- state ----------
const groups = ref<UserGroup[]>([])
const loading = ref(true)
const error = ref('')

const expandedRows = ref<Record<number, boolean>>({})

const dialogVisible = ref(false)
const editMode = ref(false)
const saving = ref(false)
const form = ref<{ userGroupId: number | null; name: string; description: string }>({
  userGroupId: null, name: '', description: ''
})

const confirm = useConfirm()
const toast = useToast()

// ---------- API helpers ----------
async function getBearerHeaders(): Promise<HeadersInit> {
  const { getAccessToken } = await import('../../auth/oidc')
  const token = await getAccessToken()
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
}

// ---------- data loading ----------
async function loadGroups() {
  loading.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const res = await fetch(`${config.apiBase}/user-groups`, { headers })
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
    const raw: UserGroup[] = await res.json()
    groups.value = raw.map(g => ({ ...g, membersLoaded: false, membersLoading: false }))
  } catch (e) {
    error.value = `Failed to load user groups: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

async function loadMembers(group: UserGroup) {
  if (group.membersLoaded || group.membersLoading) return
  group.membersLoading = true
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const res = await fetch(`${config.apiBase}/user-groups/${group.userGroupId}/users`, { headers })
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
    group.members = await res.json()
    group.memberCount = group.members!.length
    group.membersLoaded = true
  } catch (e) {
    toast.add({ severity: 'warn', summary: 'Could not load members', detail: (e as Error).message, life: 4000 })
  } finally {
    group.membersLoading = false
  }
}

onMounted(loadGroups)

// ---------- row expand ----------
async function onRowExpand(event: { data: UserGroup }) {
  await loadMembers(event.data)
}

// ---------- dialog ----------
function openAdd() {
  editMode.value = false
  form.value = { userGroupId: null, name: '', description: '' }
  dialogVisible.value = true
}

function openEdit(g: UserGroup) {
  editMode.value = true
  form.value = { userGroupId: g.userGroupId, name: g.name, description: g.description ?? '' }
  dialogVisible.value = true
}

async function saveGroup() {
  if (!form.value.name.trim()) return
  saving.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const body = {
      name: form.value.name.trim(),
      description: form.value.description.trim() || undefined
    }

    let res: Response
    if (editMode.value && form.value.userGroupId != null) {
      res = await fetch(`${config.apiBase}/user-groups/${form.value.userGroupId}`, {
        method: 'PUT', headers, body: JSON.stringify(body)
      })
    } else {
      res = await fetch(`${config.apiBase}/user-groups`, {
        method: 'POST', headers, body: JSON.stringify(body)
      })
    }

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)

    toast.add({
      severity: 'success',
      summary: editMode.value ? 'Group updated' : 'Group created',
      detail: `"${form.value.name.trim()}" saved.`,
      life: 3000
    })
    dialogVisible.value = false
    await loadGroups()
  } catch (e) {
    error.value = `Save failed: ${(e as Error).message}`
  } finally {
    saving.value = false
  }
}

function confirmDelete(g: UserGroup) {
  confirm.require({
    message: `Delete group "${g.name}"? Members will be removed from the group, and any collection grants assigned to this group will also be removed.`,
    header: 'Delete User Group',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: 'Cancel',
    acceptLabel: 'Delete',
    acceptClass: 'p-button-danger',
    accept: async () => {
      error.value = ''
      try {
        const { config } = await import('../../config')
        const headers = await getBearerHeaders()
        const res = await fetch(`${config.apiBase}/user-groups/${g.userGroupId}`, {
          method: 'DELETE', headers
        })
        if (!res.ok && res.status !== 204) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
        toast.add({ severity: 'success', summary: 'Group deleted', detail: `"${g.name}" removed.`, life: 3000 })
        await loadGroups()
      } catch (e) {
        error.value = `Delete failed: ${(e as Error).message}`
      }
    }
  })
}

// ---------- member status ----------
function memberSeverity(status: string): 'success' | 'secondary' {
  return status === 'enabled' ? 'success' : 'secondary'
}
</script>

<template>
  <Toast />
  <ConfirmDialog />

  <section class="ug-root">
    <div class="ug-header">
      <h2 class="ug-title">User Groups</h2>
      <Button
        label="New Group"
        icon="pi pi-plus"
        size="small"
        @click="openAdd"
      />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="groups"
      :loading="loading"
      dataKey="userGroupId"
      stripedRows
      responsiveLayout="scroll"
      v-model:expandedRows="expandedRows"
      @row-expand="onRowExpand"
    >
      <template #empty>
        <span class="muted">No user groups defined.</span>
      </template>

      <!-- Expander toggle -->
      <Column expander style="width: 3rem" />

      <Column field="name" header="Name" sortable />

      <Column field="description" header="Description">
        <template #body="{ data }">
          <span v-if="data.description">{{ data.description }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <Column header="Members" style="width: 7rem; text-align: center">
        <template #body="{ data }">
          <Tag
            v-if="data.memberCount != null"
            :value="String(data.memberCount)"
            severity="secondary"
          />
          <span v-else class="muted">—</span>
        </template>
      </Column>

      <Column header="" style="width: 9rem; text-align: right">
        <template #body="{ data }">
          <div class="row-actions">
            <Button icon="pi pi-pencil" size="small" text severity="secondary" title="Edit group" @click="openEdit(data)" />
            <Button icon="pi pi-trash" size="small" text severity="danger" title="Delete group" @click="confirmDelete(data)" />
          </div>
        </template>
      </Column>

      <!-- Expanded row: members list -->
      <template #expansion="{ data }">
        <div class="members-panel">
          <div class="members-header">
            <span class="members-title">Members of "{{ data.name }}"</span>
            <span v-if="data.membersLoading" class="muted members-loading">
              <i class="pi pi-spin pi-spinner" /> Loading…
            </span>
          </div>

          <template v-if="data.membersLoaded">
            <div v-if="!data.members?.length" class="muted members-empty">
              No members in this group.
            </div>
            <ul v-else class="members-list">
              <li
                v-for="member in data.members"
                :key="member.userId"
                class="member-row"
              >
                <i class="pi pi-user member-icon" />
                <span class="member-username">{{ member.username }}</span>
                <Tag
                  :value="member.status === 'enabled' ? 'Enabled' : 'Disabled'"
                  :severity="memberSeverity(member.status)"
                  class="member-tag"
                />
              </li>
            </ul>
          </template>
        </div>
      </template>
    </DataTable>

    <!-- Create / Edit dialog -->
    <Dialog
      v-model:visible="dialogVisible"
      :header="editMode ? 'Edit User Group' : 'New User Group'"
      modal
      :style="{ width: '30rem' }"
    >
      <div class="form-grid">
        <label>Name <span class="req">*</span></label>
        <InputText
          v-model="form.name"
          placeholder="e.g. ISSO Team"
          maxlength="128"
        />

        <label>Description</label>
        <Textarea
          v-model="form.description"
          placeholder="Optional description"
          rows="3"
          autoResize
        />
      </div>

      <p v-if="error && dialogVisible" class="err dialog-err">{{ error }}</p>

      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button
          :label="editMode ? 'Save' : 'Create'"
          icon="pi pi-check"
          :loading="saving"
          :disabled="!form.name.trim()"
          @click="saveGroup"
        />
      </template>
    </Dialog>
  </section>
</template>

<style scoped>
.ug-root   { padding: 0.5rem 1rem 3rem; }
.ug-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.75rem; }
.ug-title  { margin: 0; }

.err       { color: #f85149; }
.muted     { color: var(--p-text-muted-color, #6b7280); }

.row-actions { display: flex; gap: 0.25rem; justify-content: flex-end; }

/* Expanded members panel */
.members-panel {
  padding: 0.75rem 1.25rem 0.75rem 2.5rem;
  background: var(--p-surface-50, #f9fafb);
}
.members-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 0.6rem;
}
.members-title { font-weight: 600; font-size: 0.88rem; }
.members-loading { font-size: 0.82rem; display: flex; align-items: center; gap: 0.35rem; }
.members-empty { font-size: 0.85rem; padding: 0.25rem 0; }

.members-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.member-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.88rem;
}
.member-icon { font-size: 0.8rem; opacity: 0.6; }
.member-username { flex: 1; }
.member-tag { flex-shrink: 0; }

/* Dialog form */
.form-grid {
  display: grid;
  grid-template-columns: 8rem 1fr;
  gap: 0.75rem 1rem;
  align-items: start;
  padding: 0.25rem 0;
}
.req { color: #f85149; }
.dialog-err { margin: 0.5rem 0 0; }
</style>
