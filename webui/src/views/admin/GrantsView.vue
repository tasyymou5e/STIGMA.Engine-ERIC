<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Select from 'primevue/select'
import { useConfirm } from 'primevue/useconfirm'
import ConfirmDialog from 'primevue/confirmdialog'
import AclRulesDialog from '../../components/AclRulesDialog.vue'

// ---------- types ----------
type GrantRole = 1 | 2 | 3 | 4
type PrincipalType = 'user' | 'group'

interface Grant {
  grantId: number
  principalType: PrincipalType
  principalId: string
  principalName: string
  role: GrantRole
}

interface UserOption {
  userId: string
  username: string
}

interface GroupOption {
  groupId: string
  name: string
}

// ---------- props ----------
const props = defineProps<{ collectionId: string }>()
const cid = Number(props.collectionId)

// ---------- state ----------
const grants = ref<Grant[]>([])
const users = ref<UserOption[]>([])
const groups = ref<GroupOption[]>([])
const loading = ref(true)
const error = ref('')

const dialogVisible = ref(false)
const editMode = ref(false)
const saving = ref(false)

const form = ref<{
  grantId: number | null
  principalType: PrincipalType
  principalId: string
  role: GrantRole
}>({ grantId: null, principalType: 'user', principalId: '', role: 1 })

const confirm = useConfirm()

// ---------- ACL dialog ----------
const aclDialogVisible = ref(false)
const aclGrant = ref<Grant | null>(null)

function openAclDialog(g: Grant) {
  aclGrant.value = g
  aclDialogVisible.value = true
}

// ---------- role helpers ----------
const ROLE_LABELS: Record<GrantRole, string> = {
  1: 'Restricted',
  2: 'Full',
  3: 'Manage',
  4: 'Owner'
}
const ROLE_SEVERITIES: Record<GrantRole, 'secondary' | 'info' | 'warn' | 'danger'> = {
  1: 'secondary',
  2: 'info',
  3: 'warn',
  4: 'danger'
}
const ROLE_OPTIONS = ([1, 2, 3, 4] as GrantRole[]).map(r => ({ value: r, label: `${r} — ${ROLE_LABELS[r]}` }))
const PRINCIPAL_OPTIONS = [
  { value: 'user', label: 'User' },
  { value: 'group', label: 'Group' }
]

const principalOptions = () =>
  form.value.principalType === 'user'
    ? users.value.map(u => ({ value: u.userId, label: u.username }))
    : groups.value.map(g => ({ value: g.groupId, label: g.name }))

// ---------- data fetch ----------
// NOTE: These endpoints are not yet in the typed paths surface; we call fetch
// directly with the bearer token so we stay decoupled from the generated schema.
async function getBearerHeaders(): Promise<HeadersInit> {
  const { getAccessToken } = await import('../../auth/oidc')
  const token = await getAccessToken()
  return token ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' }
}

async function loadGrants() {
  loading.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const res = await fetch(`${config.apiBase}/collections/${cid}/grants`, { headers })
    if (!res.ok) throw new Error(await res.text())
    grants.value = await res.json()
  } catch (e) {
    error.value = `Failed to load grants: ${(e as Error).message}`
  } finally {
    loading.value = false
  }
}

async function loadPrincipals() {
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    const [ur, gr] = await Promise.all([
      fetch(`${config.apiBase}/users`, { headers }),
      fetch(`${config.apiBase}/groups`, { headers })
    ])
    if (ur.ok) users.value = await ur.json()
    if (gr.ok) groups.value = await gr.json()
  } catch {
    // non-fatal; principal lists may be empty if endpoints aren't implemented yet
  }
}

onMounted(() => { loadGrants(); loadPrincipals() })

// ---------- dialog ----------
function openAdd() {
  editMode.value = false
  form.value = { grantId: null, principalType: 'user', principalId: '', role: 1 }
  dialogVisible.value = true
}

function openEdit(g: Grant) {
  editMode.value = true
  form.value = {
    grantId: g.grantId,
    principalType: g.principalType,
    principalId: g.principalId,
    role: g.role
  }
  dialogVisible.value = true
}

async function saveGrant() {
  saving.value = true
  error.value = ''
  try {
    const { config } = await import('../../config')
    const headers = await getBearerHeaders()
    if (editMode.value && form.value.grantId != null) {
      const res = await fetch(`${config.apiBase}/collections/${cid}/grants/${form.value.grantId}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ role: form.value.role })
      })
      if (!res.ok) throw new Error(await res.text())
    } else {
      const res = await fetch(`${config.apiBase}/collections/${cid}/grants`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          principalType: form.value.principalType,
          principalId: form.value.principalId,
          role: form.value.role
        })
      })
      if (!res.ok) throw new Error(await res.text())
    }
    dialogVisible.value = false
    await loadGrants()
  } catch (e) {
    error.value = `Save failed: ${(e as Error).message}`
  } finally {
    saving.value = false
  }
}

function deleteGrant(g: Grant) {
  confirm.require({
    message: `Remove ${g.principalName} from this collection?`,
    header: 'Remove Grant',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: 'Cancel',
    acceptLabel: 'Remove',
    acceptClass: 'p-button-danger',
    accept: async () => {
      error.value = ''
      try {
        const { config } = await import('../../config')
        const headers = await getBearerHeaders()
        const res = await fetch(`${config.apiBase}/collections/${cid}/grants/${g.grantId}`, { method: 'DELETE', headers })
        if (!res.ok) throw new Error(await res.text())
        await loadGrants()
      } catch (e) {
        error.value = `Delete failed: ${(e as Error).message}`
      }
    }
  })
}
</script>

<template>
  <section>
    <ConfirmDialog />
    <div class="view-header">
      <div>
        <p><router-link :to="`/collections/${cid}`">&larr; Collection</router-link></p>
        <h2>Grants</h2>
      </div>
      <Button label="Add Grant" icon="pi pi-plus" size="small" @click="openAdd" />
    </div>

    <p v-if="error" class="err">{{ error }}</p>

    <DataTable
      :value="grants"
      :loading="loading"
      dataKey="grantId"
      stripedRows
      responsiveLayout="scroll"
    >
      <template #empty><span class="muted">No grants configured for this collection.</span></template>

      <Column header="Type" style="width: 7rem">
        <template #body="{ data }">
          <Tag :value="data.principalType === 'user' ? 'User' : 'Group'"
               :severity="data.principalType === 'user' ? 'info' : 'secondary'" />
        </template>
      </Column>

      <Column field="principalName" header="Name" sortable />

      <Column header="Role" style="width: 9rem">
        <template #body="{ data }">
          <Tag
            :value="`${data.role} — ${ROLE_LABELS[data.role as GrantRole]}`"
            :severity="ROLE_SEVERITIES[data.role as GrantRole]"
          />
        </template>
      </Column>

      <Column header="" style="width: 13rem; text-align: right">
        <template #body="{ data }">
          <div class="row-actions">
            <Button label="ACL" icon="pi pi-lock" size="small" text severity="info" @click="openAclDialog(data)" />
            <Button icon="pi pi-pencil" size="small" text severity="secondary" @click="openEdit(data)" />
            <Button icon="pi pi-trash" size="small" text severity="danger" @click="deleteGrant(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- ACL Rules dialog -->
    <AclRulesDialog
      v-if="aclGrant"
      v-model:visible="aclDialogVisible"
      :collectionId="cid"
      :grantId="aclGrant.grantId"
      :granteeName="aclGrant.principalName"
    />

    <!-- Add / Edit dialog -->
    <Dialog
      v-model:visible="dialogVisible"
      :header="editMode ? 'Edit Role' : 'Add Grant'"
      modal
      :style="{ width: '28rem' }"
    >
      <div class="form-grid">
        <template v-if="!editMode">
          <label>Principal type</label>
          <Select
            v-model="form.principalType"
            :options="PRINCIPAL_OPTIONS"
            optionLabel="label"
            optionValue="value"
            placeholder="Select type"
          />
          <label>{{ form.principalType === 'user' ? 'User' : 'Group' }}</label>
          <Select
            v-model="form.principalId"
            :options="principalOptions()"
            optionLabel="label"
            optionValue="value"
            :placeholder="`Select ${form.principalType}`"
            filter
          />
        </template>
        <label>Role</label>
        <Select
          v-model="form.role"
          :options="ROLE_OPTIONS"
          optionLabel="label"
          optionValue="value"
          placeholder="Select role"
        />
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button
          :label="editMode ? 'Save' : 'Add'"
          icon="pi pi-check"
          :loading="saving"
          :disabled="!form.principalId && !editMode"
          @click="saveGrant"
        />
      </template>
    </Dialog>
  </section>
</template>

<style scoped>
.view-header { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.5rem; }
.view-header h2 { margin: 0; }
.row-actions { display: flex; gap: 0.25rem; justify-content: flex-end; }
.form-grid { display: grid; grid-template-columns: 9rem 1fr; gap: 0.75rem 1rem; align-items: center; padding: 0.25rem 0; }
.err { color: #f85149; }
</style>
