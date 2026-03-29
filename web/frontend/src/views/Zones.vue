<template>
  <div class="zones-page">
    <h2>DNS Zones</h2>

    <!-- Create Zone -->
    <div class="section" v-if="!selectedZone">
      <h3>Create New Zone</h3>
      <p class="section-desc">Create a forward zone (e.g. example.com) or reverse zone (e.g. 168.192.in-addr.arpa for 192.168.x.x)</p>
      <form class="create-form" @submit.prevent="createZone">
        <div class="form-grid">
          <div class="field">
            <label>Zone Name</label>
            <input v-model="newZone.name" placeholder="example.com or 168.192.in-addr.arpa" required />
          </div>
          <div class="field">
            <label>Zone Type</label>
            <select v-model="newZone.type">
              <option value="primary">Primary (authoritative)</option>
              <option value="secondary">Secondary (replica)</option>
            </select>
          </div>
          <div class="field">
            <label>Primary Nameserver</label>
            <input v-model="newZone.primary_ns" placeholder="ns1.example.com" />
          </div>
          <div class="field">
            <label>Admin Email</label>
            <input v-model="newZone.admin_email" placeholder="admin.example.com" />
          </div>
          <div class="field">
            <label>Default TTL (seconds)</label>
            <input v-model.number="newZone.ttl" type="number" />
          </div>
        </div>
        <div class="reverse-helper" v-if="!newZone.name.includes('arpa')">
          <button type="button" @click="generateReverse" class="btn-link">Generate reverse zone for a subnet</button>
          <div v-if="showReverseHelper" class="reverse-input">
            <input v-model="reverseSubnet" placeholder="e.g. 192.168.1" />
            <button type="button" @click="applyReverse" class="btn-xs primary">Create</button>
          </div>
        </div>
        <button type="submit" :disabled="!newZone.name" class="btn-primary">Create Zone</button>
      </form>
      <div v-if="error" class="msg-error">{{ error }}</div>
    </div>

    <!-- Zones List -->
    <div class="section" v-if="zones.length && !selectedZone">
      <h3>Zones</h3>
      <div class="zones-grid">
        <div v-for="z in zones" :key="z.id" class="zone-card" @click="selectZone(z)">
          <div class="zone-header">
            <span class="zone-name">{{ z.name }}</span>
            <span class="zone-type-badge" :class="z.type">{{ z.type }}</span>
            <span v-if="z.dnssec_signed" class="zone-dnssec-badge">DNSSEC</span>
            <span v-if="z.name.includes('arpa')" class="zone-reverse-badge">Reverse</span>
          </div>
          <div class="zone-meta">
            <span>{{ z.record_count }} records</span>
            <span>SOA serial: {{ z.soa_serial }}</span>
            <span>TTL: {{ z.ttl }}s</span>
          </div>
          <button @click.stop="deleteZone(z)" class="btn-delete-zone">Delete</button>
        </div>
      </div>
    </div>

    <!-- Zone Detail -->
    <div v-if="selectedZone">
      <div class="zone-toolbar">
        <button @click="selectedZone = null; loadZones()" class="btn-back">Back to zones</button>
        <h3 class="zone-title">{{ selectedZone.name }}</h3>
        <span class="zone-type-badge" :class="selectedZone.type">{{ selectedZone.type }}</span>
      </div>

      <!-- SOA Info -->
      <div class="section">
        <div class="section-header-row">
          <h3>Zone Information</h3>
          <button @click="showSystemRecords = !showSystemRecords" class="btn-link">
            {{ showSystemRecords ? 'Hide' : 'Show' }} SOA & NS records
          </button>
        </div>

        <div class="zone-info-grid">
          <div class="info-item"><span class="info-label">Zone</span><span class="info-value">{{ selectedZone.name }}</span></div>
          <div class="info-item"><span class="info-label">Type</span><span class="info-value">{{ selectedZone.type === 'primary' ? 'Primary (authoritative)' : 'Secondary (replica)' }}</span></div>
          <div class="info-item"><span class="info-label">SOA Serial</span><span class="info-value mono">{{ selectedZone.soa_serial }}</span></div>
          <div class="info-item"><span class="info-label">Default TTL</span><span class="info-value">{{ selectedZone.ttl }} seconds</span></div>
        </div>

        <!-- System records (SOA, NS, DNSKEY, DS, CAA) -->
        <div v-if="showSystemRecords" class="system-records">
          <h4>Zone Infrastructure Records</h4>
          <p class="section-desc">These records are required for the zone to function correctly. They were created automatically.</p>
          <div v-for="group in systemRecordGroups" :key="group.type" class="sys-group">
            <div class="sys-group-header">
              <span class="rec-type-badge" :class="group.type.toLowerCase()">{{ group.type }}</span>
              <span class="sys-group-desc">{{ recordTypeDesc(group.type) }}</span>
            </div>
            <div v-for="r in group.records" :key="r.id" class="sys-record">
              <span class="sys-name" v-if="r.name !== '@'">{{ r.name }}</span>
              <span class="sys-value">{{ r.value }}</span>
              <span class="sys-ttl">TTL {{ r.ttl }}s</span>
            </div>
          </div>
        </div>
      </div>

      <!-- DNSSEC -->
      <div class="section">
        <h3>DNSSEC Signing</h3>
        <div v-if="zoneDNSSEC">
          <div class="dnssec-status">
            <div class="toggle-wrap" @click="toggleZoneDNSSEC">
              <div class="toggle" :class="{ on: zoneDNSSEC.enabled }"><div class="toggle-knob"></div></div>
              <span>{{ zoneDNSSEC.enabled ? 'Zone signing active' : 'Signing disabled' }}</span>
            </div>
          </div>
          <div class="dnssec-details">
            <div class="detail-row">
              <span class="detail-label">Algorithm</span>
              <span class="detail-value">{{ zoneDNSSEC.algorithm }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Key Tag</span>
              <span class="detail-value mono">{{ zoneDNSSEC.key_tag }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">DS Record</span>
              <span class="detail-value mono small">{{ zoneDNSSEC.ds_record }}</span>
              <button @click="copyText(zoneDNSSEC.ds_record)" class="btn-copy">Copy</button>
            </div>
            <p class="section-desc">Add the DS record above to your domain registrar to complete DNSSEC chain of trust.</p>
          </div>
          <button @click="removeZoneDNSSEC" class="btn-text-danger">Remove DNSSEC key</button>
        </div>
        <div v-else>
          <p class="section-desc">This zone is not signed. Enable DNSSEC to protect against DNS spoofing.</p>
          <button @click="signZone" class="btn-primary">Enable DNSSEC Signing</button>
        </div>
      </div>

      <!-- User Records -->
      <div class="section">
        <h3>DNS Records</h3>
        <form class="record-form" @submit.prevent="addRecord">
          <div class="form-row">
            <div class="field small">
              <label>Name</label>
              <input v-model="newRecord.name" placeholder="@ or subdomain" required />
            </div>
            <div class="field tiny">
              <label>Type</label>
              <select v-model="newRecord.type">
                <option v-for="t in recordTypes" :key="t" :value="t">{{ t }}</option>
              </select>
            </div>
            <div class="field">
              <label>Value</label>
              <input v-model="newRecord.value" :placeholder="valuePlaceholder" required />
            </div>
            <div class="field tiny">
              <label>TTL</label>
              <input v-model.number="newRecord.ttl" type="number" />
            </div>
            <div class="field tiny" v-if="['MX','SRV'].includes(newRecord.type)">
              <label>Priority</label>
              <input v-model.number="newRecord.priority" type="number" />
            </div>
            <button type="submit" class="btn-primary add-btn">Add Record</button>
          </div>
        </form>

        <table class="records-table">
          <thead>
            <tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th>Priority</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="r in userRecords" :key="r.id">
              <template v-if="editingRecord?.id === r.id">
                <td><input v-model="editingRecord.name" class="inline-input" /></td>
                <td>
                  <select v-model="editingRecord.type" class="inline-select">
                    <option v-for="t in recordTypes" :key="t" :value="t">{{ t }}</option>
                  </select>
                </td>
                <td><input v-model="editingRecord.value" class="inline-input wide" /></td>
                <td><input v-model.number="editingRecord.ttl" type="number" class="inline-input narrow" /></td>
                <td><input v-model.number="editingRecord.priority" type="number" class="inline-input narrow" /></td>
                <td class="action-cell">
                  <button @click="saveEdit" class="btn-icon-save" title="Save">&#x2714;</button>
                  <button @click="editingRecord = null" class="btn-icon-cancel" title="Cancel">&#x2715;</button>
                </td>
              </template>
              <template v-else>
                <td class="rec-name">{{ r.name }}</td>
                <td><span class="rec-type-badge" :class="r.type.toLowerCase()">{{ r.type }}</span></td>
                <td class="rec-value">{{ r.value }}</td>
                <td>{{ r.ttl }}</td>
                <td>{{ r.priority || '' }}</td>
                <td class="action-cell">
                  <button @click="startEdit(r)" class="btn-icon-edit" title="Edit">&#x270E;</button>
                  <button @click="deleteRecord(r)" class="btn-icon-remove" title="Delete">&#x2715;</button>
                </td>
              </template>
            </tr>
            <tr v-if="!userRecords.length">
              <td colspan="6" class="empty-small">No records yet. Add one above.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'

const zones = ref<any[]>([])
const selectedZone = ref<any>(null)
const records = ref<any[]>([])
const zoneDNSSEC = ref<any>(null)
const showSystemRecords = ref(false)
const error = ref('')
const showReverseHelper = ref(false)
const reverseSubnet = ref('')

const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA']

const newZone = ref({ name: '', type: 'primary', ttl: 3600, primary_ns: '', admin_email: '' })
const newRecord = ref({ name: '', type: 'A', value: '', ttl: 3600, priority: 0 })
const editingRecord = ref<any>(null)

const valuePlaceholder = computed(() => {
  const ph: Record<string, string> = {
    A: '192.168.1.1', AAAA: '2001:db8::1', CNAME: 'other.example.com',
    MX: 'mail.example.com', TXT: 'v=spf1 include:example.com ~all',
    NS: 'ns1.example.com', SRV: '0 5060 sip.example.com', PTR: 'host.example.com',
    CAA: '0 issue letsencrypt.org',
  }
  return ph[newRecord.value.type] || 'Value'
})

const systemTypes = ['SOA', 'NS', 'DNSKEY', 'DS', 'CAA']
const systemRecords = computed(() => records.value.filter(r => systemTypes.includes(r.type)))
const userRecords = computed(() => records.value.filter(r => !systemTypes.includes(r.type)))

const systemRecordGroups = computed(() => {
  const groups: Record<string, any[]> = {}
  for (const r of systemRecords.value) {
    if (!groups[r.type]) groups[r.type] = []
    groups[r.type].push(r)
  }
  return Object.entries(groups).map(([type, records]) => ({ type, records }))
})

function recordTypeDesc(type: string): string {
  const descs: Record<string, string> = {
    SOA: 'Start of Authority — defines the zone\'s primary nameserver, admin contact, and timing parameters',
    NS: 'Name Server — authoritative nameservers for this zone',
    DNSKEY: 'DNSSEC public key — used to verify signed records',
    DS: 'Delegation Signer — submit this to your registrar for DNSSEC chain of trust',
    CAA: 'Certificate Authority Authorization — which CAs can issue certificates for this domain',
  }
  return descs[type] || ''
}

async function loadZones() {
  const { data } = await axios.get('/api/zones')
  zones.value = data || []
}

async function createZone() {
  error.value = ''
  try {
    await axios.post('/api/zones', newZone.value)
    newZone.value = { name: '', type: 'primary', ttl: 3600, primary_ns: '', admin_email: '' }
    loadZones()
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to create zone'
  }
}

async function deleteZone(z: any) {
  if (!confirm(`Delete zone "${z.name}" and all its records?`)) return
  await axios.delete(`/api/zones/${z.id}`)
  loadZones()
}

async function selectZone(z: any) {
  const { data } = await axios.get(`/api/zones/${z.id}`)
  selectedZone.value = data.zone
  records.value = data.records || []
  zoneDNSSEC.value = data.dnssec || null
}

async function addRecord() {
  await axios.post(`/api/zones/${selectedZone.value.id}/records`, newRecord.value)
  newRecord.value = { name: '', type: 'A', value: '', ttl: 3600, priority: 0 }
  selectZone(selectedZone.value)
}

function startEdit(r: any) {
  editingRecord.value = { ...r }
}

async function saveEdit() {
  const r = editingRecord.value
  await axios.put(`/api/zones/${selectedZone.value.id}/records/${r.id}`, {
    name: r.name, type: r.type, value: r.value, ttl: r.ttl, priority: r.priority || 0,
  })
  editingRecord.value = null
  selectZone(selectedZone.value)
}

async function deleteRecord(r: any) {
  if (!confirm(`Delete ${r.type} record "${r.name}" ?`)) return
  await axios.delete(`/api/zones/${selectedZone.value.id}/records/${r.id}`)
  selectZone(selectedZone.value)
}

async function signZone() {
  await axios.post('/api/dnssec/generate', { zone_name: selectedZone.value.name })
  selectZone(selectedZone.value)
}

async function toggleZoneDNSSEC() {
  await axios.put(`/api/dnssec/${selectedZone.value.name}`, { enabled: !zoneDNSSEC.value.enabled })
  selectZone(selectedZone.value)
}

async function removeZoneDNSSEC() {
  if (!confirm('Remove DNSSEC key? This will disable zone signing.')) return
  await axios.delete(`/api/dnssec/${selectedZone.value.name}`)
  selectZone(selectedZone.value)
}

function copyText(t: string) { navigator.clipboard.writeText(t) }

function generateReverse() { showReverseHelper.value = !showReverseHelper.value }
function applyReverse() {
  const parts = reverseSubnet.value.trim().split('.').reverse()
  newZone.value.name = parts.join('.') + '.in-addr.arpa'
  showReverseHelper.value = false
}

onMounted(loadZones)
</script>

<style scoped>
.zones-page h2 { margin-bottom: 24px; }

.section {
  background: #1e293b; border-radius: 12px; padding: 24px;
  border: 1px solid #334155; margin-bottom: 16px;
}
.section h3 { color: #e2e8f0; font-size: 1rem; margin-bottom: 4px; }
.section h4 { color: #94a3b8; font-size: 0.9rem; margin: 12px 0 8px; }
.section-desc { color: #64748b; font-size: 0.85rem; margin-bottom: 16px; line-height: 1.5; }
.section-header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }

.btn-primary { padding: 9px 20px; background: #0ea5e9; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; }
.btn-primary:disabled { opacity: 0.3; }
.btn-back { padding: 8px 16px; background: #334155; border: none; color: #94a3b8; border-radius: 8px; cursor: pointer; font-size: 0.85rem; }
.btn-link { background: none; border: none; color: #0ea5e9; cursor: pointer; font-size: 0.85rem; text-decoration: underline; }
.btn-text-danger { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 0.85rem; padding: 4px 0; }
.btn-copy { padding: 2px 8px; background: #334155; color: #94a3b8; border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem; }
.action-cell { display: flex; gap: 6px; }
.btn-icon-edit { background: none; border: none; color: #475569; cursor: pointer; font-size: 0.9rem; }
.btn-icon-edit:hover { color: #0ea5e9; }
.btn-icon-remove { background: none; border: none; color: #475569; cursor: pointer; font-size: 0.9rem; }
.btn-icon-remove:hover { color: #ef4444; }
.btn-icon-save { background: none; border: none; color: #22c55e; cursor: pointer; font-size: 1rem; }
.btn-icon-cancel { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 0.9rem; }

.inline-input {
  padding: 4px 8px; background: #0f172a; border: 1px solid #334155;
  border-radius: 4px; color: #e2e8f0; font-size: 0.85rem; width: 100%;
}
.inline-input.wide { min-width: 180px; }
.inline-input.narrow { width: 70px; }
.inline-select {
  padding: 4px 6px; background: #0f172a; border: 1px solid #334155;
  border-radius: 4px; color: #e2e8f0; font-size: 0.85rem;
}
.btn-xs { padding: 5px 12px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem; color: #fff; }
.btn-xs.primary { background: #0ea5e9; }

.msg-error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #ef4444; padding: 8px 14px; border-radius: 8px; margin-top: 12px; font-size: 0.85rem; }
.empty-small { padding: 16px; text-align: center; color: #475569; font-size: 0.85rem; }

/* Create form */
.form-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }
.field { display: flex; flex-direction: column; gap: 4px; }
.field label { color: #64748b; font-size: 0.8rem; }
.field input, .field select {
  padding: 9px 12px; background: #0f172a; border: 1px solid #334155;
  border-radius: 8px; color: #e2e8f0; font-size: 0.9rem;
}
.field input::placeholder { color: #475569; }

.reverse-helper { margin-bottom: 12px; }
.reverse-input { display: flex; gap: 8px; margin-top: 6px; }
.reverse-input input { padding: 6px 10px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #e2e8f0; font-size: 0.85rem; width: 180px; }

/* Zone toolbar */
.zone-toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.zone-title { color: #e2e8f0; font-size: 1.2rem; }

/* Zones grid */
.zones-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
.zone-card {
  background: #0f172a; border: 1px solid #334155; border-radius: 10px;
  padding: 16px; cursor: pointer; transition: border-color 0.15s; position: relative;
}
.zone-card:hover { border-color: #0ea5e9; }
.zone-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
.zone-name { color: #e2e8f0; font-weight: 600; font-size: 1rem; }
.zone-type-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
.zone-type-badge.primary { background: rgba(14,165,233,0.15); color: #0ea5e9; }
.zone-type-badge.secondary { background: rgba(168,85,247,0.15); color: #a855f7; }
.zone-dnssec-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; background: rgba(34,197,94,0.15); color: #22c55e; }
.zone-reverse-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; background: rgba(249,115,22,0.15); color: #f97316; }
.zone-meta { display: flex; gap: 16px; color: #64748b; font-size: 0.8rem; }
.btn-delete-zone { position: absolute; top: 12px; right: 12px; padding: 3px 8px; background: transparent; border: 1px solid #475569; color: #475569; border-radius: 4px; cursor: pointer; font-size: 0.75rem; }
.btn-delete-zone:hover { border-color: #ef4444; color: #ef4444; }

/* Zone info */
.zone-info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; }
.info-item { display: flex; flex-direction: column; gap: 2px; padding: 8px 12px; background: #0f172a; border-radius: 8px; }
.info-label { color: #64748b; font-size: 0.75rem; }
.info-value { color: #e2e8f0; font-size: 0.9rem; }
.info-value.mono { font-family: monospace; }

.system-records { margin-top: 12px; padding-top: 12px; border-top: 1px solid #334155; }
.sys-group { margin-bottom: 14px; }
.sys-group-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.sys-group-desc { color: #475569; font-size: 0.78rem; font-style: italic; }
.sys-record { display: flex; align-items: center; gap: 12px; padding: 6px 12px; background: #0f172a; border-radius: 6px; margin-bottom: 3px; font-size: 0.83rem; }
.sys-name { color: #0ea5e9; font-family: monospace; min-width: 60px; }
.sys-value { color: #94a3b8; flex: 1; word-break: break-all; font-family: monospace; font-size: 0.78rem; }
.sys-ttl { color: #475569; font-size: 0.75rem; white-space: nowrap; }
.rec-type-badge.soa { background: rgba(249,115,22,0.15); color: #f97316; }
.rec-type-badge.ns { background: rgba(168,85,247,0.15); color: #a855f7; }
.rec-type-badge.dnskey { background: rgba(34,197,94,0.15); color: #22c55e; }
.rec-type-badge.ds { background: rgba(234,179,8,0.15); color: #eab308; }
.rec-type-badge.caa { background: rgba(14,165,233,0.15); color: #0ea5e9; }

/* Records */
.record-form { margin-bottom: 16px; }
.form-row { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
.field.small { flex: 1; min-width: 120px; }
.field.tiny { flex: 0; min-width: 80px; }
.add-btn { align-self: flex-end; margin-bottom: 1px; }

.records-table { width: 100%; border-collapse: collapse; }
.records-table thead th { text-align: left; padding: 8px; color: #64748b; font-size: 0.78rem; text-transform: uppercase; border-bottom: 1px solid #334155; }
.records-table tbody tr { border-bottom: 1px solid rgba(51,65,85,0.5); }
.records-table tbody tr:hover { background: rgba(255,255,255,0.02); }
.records-table td { padding: 8px; font-size: 0.85rem; }
.rec-name { color: #e2e8f0; font-weight: 500; }
.rec-value { color: #94a3b8; word-break: break-all; max-width: 300px; }
.rec-type-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.75rem; font-weight: 600; background: rgba(14,165,233,0.15); color: #0ea5e9; }
.rec-type-badge.system { background: rgba(100,116,139,0.15); color: #64748b; }
.rec-type-badge.ptr { background: rgba(249,115,22,0.15); color: #f97316; }
.rec-type-badge.mx { background: rgba(168,85,247,0.15); color: #a855f7; }
.rec-type-badge.txt { background: rgba(234,179,8,0.15); color: #eab308; }
.rec-type-badge.cname { background: rgba(34,197,94,0.15); color: #22c55e; }

/* DNSSEC */
.dnssec-status { margin-bottom: 12px; }
.dnssec-details { background: #0f172a; border-radius: 8px; padding: 14px; margin-bottom: 8px; }
.detail-row { display: flex; align-items: flex-start; gap: 12px; padding: 4px 0; flex-wrap: wrap; }
.detail-label { color: #64748b; font-size: 0.8rem; min-width: 90px; }
.detail-value { color: #e2e8f0; font-size: 0.85rem; flex: 1; }
.detail-value.mono { font-family: monospace; }
.detail-value.small { font-size: 0.75rem; color: #94a3b8; word-break: break-all; }

.toggle-wrap { display: flex; align-items: center; gap: 8px; cursor: pointer; }
.toggle { width: 36px; height: 20px; border-radius: 10px; background: #475569; position: relative; transition: background 0.2s; }
.toggle.on { background: #22c55e; }
.toggle-knob { width: 16px; height: 16px; border-radius: 50%; background: #fff; position: absolute; top: 2px; left: 2px; transition: transform 0.2s; }
.toggle.on .toggle-knob { transform: translateX(16px); }
</style>
