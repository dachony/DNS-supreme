<template>
  <div class="users-page">
    <h2>User Management</h2>

    <!-- Create User -->
    <div class="section">
      <h3>Create User</h3>
      <form class="user-form" @submit.prevent="createUser">
        <input v-model="form.username" placeholder="Username" required />
        <input v-model="form.password" type="password" placeholder="Password" required />
        <input v-model="form.first_name" placeholder="First Name" />
        <input v-model="form.last_name" placeholder="Last Name" />
        <input v-model="form.email" type="email" placeholder="Email" />
        <select v-model="form.role">
          <option value="viewer">Viewer</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit" class="btn-create">Create</button>
      </form>
      <div v-if="formError" class="error-msg">{{ formError }}</div>
      <div v-if="formSuccess" class="success-msg">{{ formSuccess }}</div>
    </div>

    <!-- Users List -->
    <div class="section">
      <h3>Users</h3>
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>MFA</th>
            <th>Last Login</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td class="username">{{ u.username }}</td>
            <td>{{ u.first_name }} {{ u.last_name }}</td>
            <td>{{ u.email || '-' }}</td>
            <td><span class="badge" :class="u.role">{{ u.role }}</span></td>
            <td>
              <span v-if="u.mfa_enabled" class="mfa-on">TOTP</span>
              <span v-else class="mfa-off">Off</span>
            </td>
            <td class="time">{{ u.last_login ? formatTime(u.last_login) : 'Never' }}</td>
            <td class="actions">
              <button @click="editUser(u)" class="btn-sm">Edit</button>
              <button @click="resetPw(u)" class="btn-sm warn">Reset PW</button>
              <button @click="deleteUser(u)" class="btn-sm danger"
                v-if="u.username !== currentUser?.username">Delete</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Edit Modal -->
    <div v-if="editing" class="modal-overlay" @click.self="editing = null">
      <div class="modal">
        <h3>Edit User: {{ editing.username }}</h3>
        <form @submit.prevent="saveEdit">
          <div class="field">
            <label>First Name</label>
            <input v-model="editing.first_name" />
          </div>
          <div class="field">
            <label>Last Name</label>
            <input v-model="editing.last_name" />
          </div>
          <div class="field">
            <label>Email</label>
            <input v-model="editing.email" type="email" />
          </div>
          <div class="field">
            <label>Role</label>
            <select v-model="editing.role">
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="modal-actions">
            <button type="submit" class="btn-create">Save</button>
            <button type="button" @click="editing = null" class="btn-cancel">Cancel</button>
          </div>
        </form>
      </div>
    </div>

    <!-- MFA Section for current user -->
    <div class="section">
      <h3>My MFA Settings</h3>
      <div v-if="myUser?.mfa_enabled" class="mfa-status">
        <span class="mfa-on">MFA is enabled (TOTP)</span>
        <button @click="disableMFA" class="btn-sm danger">Disable MFA</button>
      </div>
      <div v-else>
        <button v-if="!mfaSetup" @click="setupMFA" class="btn-create">Setup TOTP</button>
        <div v-else class="mfa-setup">
          <p>Scan this code with your authenticator app or enter the secret manually:</p>
          <div class="mfa-secret">{{ mfaSetup.secret }}</div>
          <p class="mfa-uri">{{ mfaSetup.uri }}</p>
          <form @submit.prevent="enableMFA" class="mfa-verify">
            <input v-model="mfaVerifyCode" placeholder="Enter 6-digit code" maxlength="6" />
            <button type="submit" class="btn-create">Enable MFA</button>
          </form>
          <div v-if="mfaError" class="error-msg">{{ mfaError }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { currentUser } from '../auth'

const users = ref<any[]>([])
const myUser = ref<any>(null)
const editing = ref<any>(null)
const mfaSetup = ref<any>(null)
const mfaVerifyCode = ref('')
const mfaError = ref('')
const formError = ref('')
const formSuccess = ref('')

const form = ref({
  username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer'
})

async function loadUsers() {
  const { data } = await axios.get('/api/users')
  users.value = data
}

async function loadMe() {
  const { data } = await axios.get('/api/auth/me')
  myUser.value = data
}

async function createUser() {
  formError.value = ''; formSuccess.value = ''
  try {
    await axios.post('/api/users', form.value)
    formSuccess.value = `User '${form.value.username}' created`
    form.value = { username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer' }
    loadUsers()
  } catch (e: any) {
    formError.value = e.response?.data?.error || 'Failed to create user'
  }
}

function editUser(u: any) {
  editing.value = { ...u }
}

async function saveEdit() {
  await axios.put(`/api/users/${editing.value.id}`, editing.value)
  editing.value = null
  loadUsers()
}

async function resetPw(u: any) {
  const pw = prompt(`New password for ${u.username}:`)
  if (!pw) return
  await axios.put(`/api/users/${u.id}/password`, { new_password: pw })
  alert('Password reset successfully')
}

async function deleteUser(u: any) {
  if (!confirm(`Delete user '${u.username}'?`)) return
  await axios.delete(`/api/users/${u.id}`)
  loadUsers()
}

async function setupMFA() {
  const { data } = await axios.post('/api/auth/mfa/setup')
  mfaSetup.value = data
}

async function enableMFA() {
  mfaError.value = ''
  try {
    await axios.post('/api/auth/mfa/enable', { code: mfaVerifyCode.value })
    mfaSetup.value = null
    mfaVerifyCode.value = ''
    loadMe()
  } catch (e: any) {
    mfaError.value = e.response?.data?.error || 'Invalid code'
  }
}

async function disableMFA() {
  if (!confirm('Disable MFA?')) return
  await axios.delete('/api/auth/mfa')
  loadMe()
}

function formatTime(ts: string) {
  return new Date(ts).toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  })
}

onMounted(() => { loadUsers(); loadMe() })
</script>

<style scoped>
.users-page h2 { margin-bottom: 24px; }

.section {
  background: #1e293b; border-radius: 12px; padding: 20px;
  border: 1px solid #334155; margin-bottom: 20px;
}
.section h3 { color: #94a3b8; font-size: 1rem; margin-bottom: 16px; }

.user-form {
  display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end;
}
.user-form input, .user-form select {
  padding: 8px 12px; background: #0f172a; border: 1px solid #334155;
  border-radius: 6px; color: #e2e8f0; font-size: 0.9rem; flex: 1; min-width: 120px;
}
.user-form input::placeholder { color: #475569; }

.btn-create {
  padding: 8px 20px; background: #0ea5e9; color: #fff; border: none;
  border-radius: 6px; cursor: pointer;
}
.btn-cancel {
  padding: 8px 20px; background: transparent; color: #94a3b8;
  border: 1px solid #334155; border-radius: 6px; cursor: pointer;
}

table { width: 100%; border-collapse: collapse; }
thead th {
  text-align: left; padding: 8px; color: #64748b; font-size: 0.8rem;
  text-transform: uppercase; border-bottom: 1px solid #334155;
}
tbody tr { border-bottom: 1px solid #1e293b; }
tbody tr:hover { background: rgba(255,255,255,0.02); }
td { padding: 10px 8px; font-size: 0.9rem; }
.username { font-weight: 600; color: #e2e8f0; }
.time { color: #64748b; font-size: 0.8rem; white-space: nowrap; }
.actions { display: flex; gap: 6px; }

.btn-sm {
  padding: 4px 10px; background: #334155; border: none; color: #94a3b8;
  border-radius: 4px; cursor: pointer; font-size: 0.8rem;
}
.btn-sm.warn { color: #f59e0b; }
.btn-sm.danger { color: #ef4444; }

.badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.badge.admin { background: rgba(139,92,246,0.15); color: #8b5cf6; }
.badge.viewer { background: rgba(34,197,94,0.15); color: #22c55e; }

.mfa-on { color: #22c55e; font-weight: 600; font-size: 0.85rem; }
.mfa-off { color: #64748b; font-size: 0.85rem; }

.mfa-status { display: flex; align-items: center; gap: 16px; }
.mfa-setup p { color: #94a3b8; font-size: 0.9rem; margin-bottom: 8px; }
.mfa-secret {
  font-family: monospace; font-size: 1.1rem; color: #f59e0b; background: #0f172a;
  padding: 12px; border-radius: 8px; margin-bottom: 8px; word-break: break-all;
}
.mfa-uri { font-size: 0.75rem; color: #475569; word-break: break-all; margin-bottom: 12px; }
.mfa-verify { display: flex; gap: 8px; }
.mfa-verify input {
  padding: 8px 12px; background: #0f172a; border: 1px solid #334155;
  border-radius: 6px; color: #e2e8f0; font-size: 1rem; width: 160px;
}

.error-msg {
  background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444;
  padding: 8px 12px; border-radius: 6px; margin-top: 8px; font-size: 0.85rem;
}
.success-msg {
  background: rgba(34,197,94,0.1); border: 1px solid #22c55e; color: #22c55e;
  padding: 8px 12px; border-radius: 6px; margin-top: 8px; font-size: 0.85rem;
}

.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex;
  align-items: center; justify-content: center; z-index: 100;
}
.modal {
  background: #1e293b; border: 1px solid #334155; border-radius: 16px;
  padding: 24px; width: 420px; max-width: 90vw;
}
.modal h3 { color: #e2e8f0; margin-bottom: 16px; }
.field { margin-bottom: 12px; }
.field label { display: block; color: #94a3b8; font-size: 0.85rem; margin-bottom: 4px; }
.field input, .field select {
  width: 100%; padding: 8px 12px; background: #0f172a; border: 1px solid #334155;
  border-radius: 6px; color: #e2e8f0;
}
.modal-actions { display: flex; gap: 8px; margin-top: 16px; }
</style>
