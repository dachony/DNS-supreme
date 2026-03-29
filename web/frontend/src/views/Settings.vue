<template>
  <div class="settings-page">
    <h2>Settings</h2>

    <!-- Server Identity -->
    <div class="section">
      <h3>Server Identity</h3>
      <p class="section-desc">The hostname identifies this DNS Supreme instance. It's used in SOA records and cluster communication.</p>
      <div class="add-row">
        <input v-model="hostname" placeholder="dns-supreme" />
        <button @click="saveHostname" class="btn-primary">Save</button>
      </div>
      <div v-if="hostnameMsg" class="msg-success">{{ hostnameMsg }}</div>
    </div>

    <!-- Cluster -->
    <div class="section">
      <h3>Cluster</h3>
      <p class="section-desc">Connect two DNS Supreme instances as primary and secondary for high availability and zone replication.</p>

      <div class="mode-cards three-col">
        <div class="mode-card" :class="{ active: cluster.role === 'standalone' }" @click="setClusterRole('standalone')">
          <div class="mode-icon">1</div>
          <div class="mode-info">
            <span class="mode-title">Standalone</span>
            <span class="mode-desc">Single server, no replication</span>
          </div>
        </div>
        <div class="mode-card" :class="{ active: cluster.role === 'primary' }" @click="setClusterRole('primary')">
          <div class="mode-icon">P</div>
          <div class="mode-info">
            <span class="mode-title">Primary</span>
            <span class="mode-desc">Authoritative master, pushes zones to secondary</span>
          </div>
        </div>
        <div class="mode-card" :class="{ active: cluster.role === 'secondary' }" @click="setClusterRole('secondary')">
          <div class="mode-icon">S</div>
          <div class="mode-info">
            <span class="mode-title">Secondary</span>
            <span class="mode-desc">Replica, pulls zones from primary</span>
          </div>
        </div>
      </div>

      <div v-if="cluster.role !== 'standalone'" class="cluster-config">
        <div class="settings-grid">
          <div class="field">
            <label>Peer Address</label>
            <input v-model="cluster.peer_address" placeholder="192.168.1.2 or dns2.example.com" />
          </div>
          <div class="field">
            <label>Peer Port</label>
            <input v-model.number="cluster.peer_port" type="number" placeholder="53" />
          </div>
          <div class="field">
            <label>Shared Secret</label>
            <input v-model="cluster.shared_secret" type="password" placeholder="Used for TSIG authentication" />
          </div>
        </div>
        <div class="sync-options">
          <label class="checkbox-label"><input type="checkbox" v-model="cluster.sync_zones" /> Sync DNS zones</label>
          <label class="checkbox-label"><input type="checkbox" v-model="cluster.sync_blocklists" /> Sync blocklists</label>
          <label class="checkbox-label"><input type="checkbox" v-model="cluster.sync_settings" /> Sync settings</label>
        </div>
        <button @click="saveCluster" class="btn-primary" style="margin-top:12px">Save Cluster Settings</button>
        <div v-if="clusterMsg" class="msg-success">{{ clusterMsg }}</div>
      </div>
    </div>

    <!-- DNS Server -->
    <div class="section">
      <h3>DNS Server</h3>
      <p class="section-desc">Configure which protocols are enabled and network settings.</p>

      <div class="subsection">
        <h4>Protocols</h4>
        <div class="protocol-grid">
          <label class="protocol-item" v-for="p in protocols" :key="p.id">
            <input type="checkbox" v-model="p.enabled" @change="saveServerSettings" />
            <div class="protocol-info">
              <span class="protocol-name">{{ p.name }}</span>
              <span class="protocol-port">{{ p.port }}</span>
              <span class="protocol-desc">{{ p.desc }}</span>
            </div>
          </label>
        </div>
      </div>

      <div class="subsection">
        <h4>Listener Addresses</h4>
        <p class="section-desc">Which addresses the DNS server will respond on.</p>
        <div class="settings-grid">
          <div class="field">
            <label>IPv4 Address</label>
            <input v-model="serverSettings.ipv4" placeholder="0.0.0.0 (all interfaces)" @change="saveServerSettings" />
          </div>
          <div class="field">
            <label>IPv6 Address</label>
            <input v-model="serverSettings.ipv6" placeholder=":: (all interfaces)" :disabled="!serverSettings.ipv6Enabled" @change="saveServerSettings" />
          </div>
          <div class="field">
            <label class="checkbox-label">
              <input type="checkbox" v-model="serverSettings.ipv6Enabled" @change="saveServerSettings" />
              Enable IPv6 support
            </label>
          </div>
        </div>
      </div>

      <div class="subsection">
        <h4>Cache & TTL</h4>
        <div class="settings-grid">
          <div class="field">
            <label>Cache Size (entries)</label>
            <input v-model.number="serverSettings.cacheSize" type="number" @change="saveServerSettings" />
          </div>
          <div class="field">
            <label>Default TTL (seconds)</label>
            <input v-model.number="serverSettings.defaultTTL" type="number" @change="saveServerSettings" />
          </div>
          <div class="field">
            <label>Minimum TTL (seconds)</label>
            <input v-model.number="serverSettings.minTTL" type="number" @change="saveServerSettings" />
          </div>
          <div class="field">
            <label>Maximum TTL (seconds)</label>
            <input v-model.number="serverSettings.maxTTL" type="number" @change="saveServerSettings" />
          </div>
        </div>
      </div>

      <div class="subsection">
        <h4>Management Panel HTTPS</h4>
        <p class="section-desc">Enable HTTPS for the management panel on port 53443.</p>
        <label class="checkbox-label">
          <input type="checkbox" v-model="serverSettings.mgmtHTTPS" @change="saveServerSettings" />
          Enable HTTPS for management panel (requires restart)
        </label>
      </div>
      <div v-if="serverMsg" class="msg-success">{{ serverMsg }}</div>
    </div>

    <!-- Upstream Forwarders -->
    <div class="section">
      <h3>Upstream DNS Forwarders</h3>
      <p class="section-desc">
        DNS queries that aren't resolved locally are forwarded to these servers.
        Servers are tried in order — the first one to respond wins.
      </p>

      <div class="forwarders-list">
        <div v-for="(fw, i) in forwarders" :key="i" class="forwarder-item">
          <div class="forwarder-num">{{ i + 1 }}</div>
          <div class="forwarder-info">
            <span class="forwarder-addr">{{ fw.address }}</span>
            <span class="forwarder-name">{{ fw.name }}</span>
          </div>
          <button @click="removeForwarder(i)" class="btn-icon-remove" title="Remove">&#x2715;</button>
        </div>
        <div v-if="!forwarders.length" class="empty-small">No forwarders configured</div>
      </div>

      <div class="add-row">
        <input v-model="newForwarder" placeholder="IP address (e.g. 9.9.9.9:53)" @keyup.enter="addForwarder" />
        <select v-model="newForwarderPreset" @change="applyPreset">
          <option value="">Quick add...</option>
          <option value="8.8.8.8:53">Google DNS (8.8.8.8)</option>
          <option value="1.1.1.1:53">Cloudflare (1.1.1.1)</option>
          <option value="9.9.9.9:53">Quad9 (9.9.9.9)</option>
          <option value="208.67.222.222:53">OpenDNS (208.67.222.222)</option>
          <option value="94.140.14.14:53">AdGuard DNS (94.140.14.14)</option>
        </select>
        <button @click="addForwarder" :disabled="!newForwarder" class="btn-primary">Add</button>
      </div>
    </div>

    <!-- DNSSEC -->
    <div class="section">
      <h3>DNSSEC</h3>
      <p class="section-desc">
        Sign your DNS zones with DNSSEC to protect against spoofing.
        After generating a key, add the DS record to your domain registrar.
      </p>

      <div v-if="dnssecKeys.length" class="dnssec-list">
        <div v-for="key in dnssecKeys" :key="key.zone_name" class="dnssec-card">
          <div class="dnssec-header">
            <span class="dnssec-zone">{{ key.zone_name }}</span>
            <span class="dnssec-algo">{{ key.algorithm }}</span>
            <div class="toggle-wrap" @click="toggleDNSSEC(key)">
              <div class="toggle" :class="{ on: key.enabled }"><div class="toggle-knob"></div></div>
              <span class="toggle-label">{{ key.enabled ? 'Signing active' : 'Disabled' }}</span>
            </div>
          </div>
          <div class="dnssec-detail">
            <div class="detail-row">
              <span class="detail-label">Key Tag</span>
              <span class="detail-value mono">{{ key.key_tag }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">DS Record</span>
              <span class="detail-value mono small">{{ key.ds_record }}</span>
              <button @click="copyText(key.ds_record)" class="btn-copy" title="Copy DS Record">Copy</button>
            </div>
            <div class="detail-row">
              <span class="detail-label">DNSKEY</span>
              <span class="detail-value mono small">{{ key.dnskey_record?.substring(0, 80) }}...</span>
              <button @click="copyText(key.dnskey_record)" class="btn-copy" title="Copy DNSKEY">Copy</button>
            </div>
          </div>
          <button @click="removeDNSSEC(key.zone_name)" class="btn-text-danger">Remove key</button>
        </div>
      </div>

      <div class="add-row">
        <input v-model="dnssecZone" placeholder="Zone name (e.g. example.com)" />
        <button @click="generateDNSSEC" :disabled="!dnssecZone" class="btn-primary">Generate DNSSEC Key</button>
      </div>
    </div>

    <!-- TLS Certificates -->
    <div class="section">
      <h3>TLS Certificates</h3>
      <p class="section-desc">
        Certificates used for DNS-over-TLS, DNS-over-HTTPS, and the block page HTTPS.
      </p>

      <div v-if="certInfo" class="cert-info">
        <div class="detail-row">
          <span class="detail-label">Status</span>
          <span class="detail-value">{{ certInfo.subject || certInfo.status || 'Auto-generated self-signed' }}</span>
        </div>
        <div class="detail-row" v-if="certInfo.issuer">
          <span class="detail-label">Issuer</span>
          <span class="detail-value">{{ certInfo.issuer }}</span>
        </div>
        <div class="detail-row" v-if="certInfo.not_after">
          <span class="detail-label">Expires</span>
          <span class="detail-value">{{ formatDate(certInfo.not_after) }}</span>
        </div>
        <div class="detail-row" v-if="certInfo.dns_names?.length">
          <span class="detail-label">DNS Names</span>
          <span class="detail-value">{{ certInfo.dns_names.join(', ') }}</span>
        </div>
      </div>

      <div class="section-actions">
        <button @click="generateCert" class="btn-primary">Generate Self-Signed</button>
        <label class="btn-secondary upload-btn">
          Upload Certificate
          <input type="file" ref="certFileInput" @change="handleCertUpload" style="display:none" accept=".pem,.crt" />
        </label>
      </div>
      <div v-if="certMsg" class="msg-success">{{ certMsg }}</div>
    </div>

    <!-- Block Page Template -->
    <div class="section">
      <h3>Block Page</h3>
      <p class="section-desc">
        Customize the page shown when a user visits a blocked domain.
        Use <code v-pre>{{.Domain}}</code> for the blocked domain and <code v-pre>{{.Reason}}</code> for the block reason.
      </p>
      <textarea v-model="blockPageHTML" class="code-editor" rows="14"
        placeholder="Leave empty to use the default block page template..."></textarea>
      <div class="section-actions">
        <button @click="saveBlockPage" class="btn-primary">Save Template</button>
        <button @click="previewBlockPage" class="btn-secondary">Preview</button>
        <button @click="blockPageHTML = ''; saveBlockPage()" class="btn-text">Reset to Default</button>
      </div>
      <div v-if="bpMsg" class="msg-success">{{ bpMsg }}</div>
    </div>

    <!-- Log Management -->
    <div class="section">
      <h3>Log Management</h3>
      <p class="section-desc">Configure how long query logs are kept, and manage log data.</p>

      <div class="settings-grid" style="margin-bottom:16px">
        <div class="field">
          <label>Retention Period (days)</label>
          <input v-model.number="logRetention.days" type="number" min="1" />
        </div>
        <div class="field">
          <label class="checkbox-label">
            <input type="checkbox" v-model="logRetention.autoCleanup" />
            Auto-delete logs older than retention period
          </label>
        </div>
      </div>
      <button @click="saveLogRetention" class="btn-primary" style="margin-bottom:16px">Save Retention Settings</button>

      <div v-if="logStats" class="log-stats-grid">
        <div class="info-item"><span class="info-label">Total Entries</span><span class="info-value">{{ logStats.total_entries?.toLocaleString() }}</span></div>
        <div class="info-item"><span class="info-label">Oldest Entry</span><span class="info-value">{{ logStats.oldest_entry ? formatDate(logStats.oldest_entry) : 'None' }}</span></div>
        <div class="info-item"><span class="info-label">Newest Entry</span><span class="info-value">{{ logStats.newest_entry ? formatDate(logStats.newest_entry) : 'None' }}</span></div>
        <div class="info-item"><span class="info-label">Est. Size</span><span class="info-value">{{ logStats.size_estimate }}</span></div>
      </div>

      <div class="section-actions" style="margin-top:12px">
        <button @click="exportLogs(7)" class="btn-secondary">Export Last 7 Days (CSV)</button>
        <button @click="exportLogs(30)" class="btn-secondary">Export Last 30 Days</button>
        <button @click="deleteOldLogs" class="btn-danger">Delete Logs Older Than...</button>
        <button @click="deleteAllLogs" class="btn-danger-outline">Delete All Logs</button>
      </div>
      <div v-if="logMsg" class="msg-success">{{ logMsg }}</div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'

// --- State ---
const hostname = ref('dns-supreme')
const hostnameMsg = ref('')
const cluster = ref<any>({
  enabled: false, role: 'standalone', peer_address: '', peer_port: 53,
  shared_secret: '', sync_zones: true, sync_blocklists: true, sync_settings: false, peers: [],
})
const clusterMsg = ref('')

const protocols = ref([
  { id: 'udp', name: 'DNS (UDP)', port: 'Port 53', desc: 'Standard DNS over UDP — fastest, most common', enabled: true },
  { id: 'tcp', name: 'DNS (TCP)', port: 'Port 53', desc: 'Standard DNS over TCP — for large responses', enabled: true },
  { id: 'dot', name: 'DNS-over-TLS', port: 'Port 853', desc: 'Encrypted DNS using TLS (RFC 7858)', enabled: true },
  { id: 'doh', name: 'DNS-over-HTTPS', port: 'Port 8443', desc: 'Encrypted DNS over HTTPS (RFC 8484)', enabled: true },
  { id: 'doq', name: 'DNS-over-QUIC', port: 'Port 8853', desc: 'Encrypted DNS over QUIC (RFC 9250)', enabled: true },
])

const serverSettings = ref({
  ipv4: '0.0.0.0', ipv6: '::', ipv6Enabled: true,
  cacheSize: 10000, defaultTTL: 3600, minTTL: 10, maxTTL: 86400,
  mgmtHTTPS: false,
})
const serverMsg = ref('')

const forwarders = ref<any[]>([])
const newForwarder = ref('')
const newForwarderPreset = ref('')

const dnssecKeys = ref<any[]>([])
const dnssecZone = ref('')

const certInfo = ref<any>(null)
const certMsg = ref('')

const blockPageHTML = ref('')
const bpMsg = ref('')

const logRetention = ref({ days: 30, autoCleanup: true })
const logStats = ref<any>(null)
const logMsg = ref('')


// --- Load ---
async function loadAll() {
  const [fw, dk, certs, bp, ss, hn, cl, ls, lr] = await Promise.all([
    axios.get('/api/settings/forwarders'),
    axios.get('/api/dnssec'),
    axios.get('/api/certs'),
    axios.get('/api/settings/blockpage'),
    axios.get('/api/settings/server'),
    axios.get('/api/settings/hostname'),
    axios.get('/api/settings/cluster'),
    axios.get('/api/log-management/stats'),
    axios.get('/api/log-management/settings'),
  ])
  forwarders.value = fw.data || []
  dnssecKeys.value = dk.data || []
  certInfo.value = certs.data
  blockPageHTML.value = bp.data.html || ''
  hostname.value = hn.data.hostname || 'dns-supreme'
  cluster.value = cl.data || cluster.value
  logStats.value = ls.data
  logRetention.value.days = lr.data.retention_days || 30
  logRetention.value.autoCleanup = lr.data.auto_cleanup ?? true

  // Map server settings
  if (ss.data.protocols) {
    protocols.value.forEach(p => { if (p.id in ss.data.protocols) p.enabled = ss.data.protocols[p.id] })
  }
  if (ss.data.listen_addresses) {
    serverSettings.value.ipv4 = ss.data.listen_addresses.ipv4 || '0.0.0.0'
    serverSettings.value.ipv6 = ss.data.listen_addresses.ipv6 || '::'
  }
  serverSettings.value.ipv6Enabled = ss.data.ipv6_enabled ?? true
  serverSettings.value.cacheSize = ss.data.cache_size || 10000
  serverSettings.value.defaultTTL = ss.data.default_ttl || 3600
  serverSettings.value.minTTL = ss.data.min_ttl || 10
  serverSettings.value.maxTTL = ss.data.max_ttl || 86400
  serverSettings.value.mgmtHTTPS = ss.data.management_https || false
}

async function saveServerSettings() {
  serverMsg.value = ''
  const prots: Record<string, boolean> = {}
  protocols.value.forEach(p => prots[p.id] = p.enabled)
  await axios.put('/api/settings/server', {
    protocols: prots,
    listen_addresses: { ipv4: serverSettings.value.ipv4, ipv6: serverSettings.value.ipv6 },
    ipv6_enabled: serverSettings.value.ipv6Enabled,
    cache_size: serverSettings.value.cacheSize,
    default_ttl: serverSettings.value.defaultTTL,
    min_ttl: serverSettings.value.minTTL,
    max_ttl: serverSettings.value.maxTTL,
    management_https: serverSettings.value.mgmtHTTPS,
  })
  serverMsg.value = 'Settings saved. Some changes require a restart.'
  setTimeout(() => serverMsg.value = '', 4000)
}

async function saveHostname() {
  hostnameMsg.value = ''
  await axios.put('/api/settings/hostname', { hostname: hostname.value })
  hostnameMsg.value = 'Hostname saved'
  setTimeout(() => hostnameMsg.value = '', 3000)
}

function setClusterRole(role: string) {
  cluster.value.role = role
  cluster.value.enabled = role !== 'standalone'
  if (role === 'standalone') saveCluster()
}

async function saveCluster() {
  clusterMsg.value = ''
  const { data } = await axios.put('/api/settings/cluster', cluster.value)
  clusterMsg.value = data.message || 'Saved'
  setTimeout(() => clusterMsg.value = '', 4000)
}

// --- Log Management ---
async function saveLogRetention() {
  await axios.put('/api/log-management/settings', {
    retention_days: logRetention.value.days,
    auto_cleanup: logRetention.value.autoCleanup,
  })
  logMsg.value = 'Retention settings saved'
  setTimeout(() => logMsg.value = '', 3000)
}

function exportLogs(days: number) {
  window.open(`/api/log-management/export?days=${days}`, '_blank')
}

async function deleteOldLogs() {
  const days = prompt('Delete logs older than how many days?', '30')
  if (!days) return
  const d = parseInt(days)
  if (isNaN(d) || d < 1) return
  if (!confirm(`Delete all query logs older than ${d} days?`)) return
  const { data } = await axios.delete(`/api/log-management/older-than?days=${d}`)
  logMsg.value = `Deleted ${data.deleted?.toLocaleString()} log entries`
  loadAll()
  setTimeout(() => logMsg.value = '', 5000)
}

async function deleteAllLogs() {
  if (!confirm('Delete ALL query logs? This cannot be undone.')) return
  if (!confirm('Are you sure? All log data will be permanently deleted.')) return
  const { data } = await axios.delete('/api/log-management/all')
  logMsg.value = `Deleted ${data.deleted?.toLocaleString()} log entries`
  loadAll()
  setTimeout(() => logMsg.value = '', 5000)
}

// --- Forwarders ---
function applyPreset() {
  if (newForwarderPreset.value) {
    newForwarder.value = newForwarderPreset.value
    newForwarderPreset.value = ''
    addForwarder()
  }
}

async function addForwarder() {
  if (!newForwarder.value) return
  let addr = newForwarder.value.trim()
  if (!addr.includes(':')) addr += ':53'
  const current = forwarders.value.map((f: any) => f.address)
  current.push(addr)
  await axios.put('/api/settings/forwarders', { forwarders: current })
  newForwarder.value = ''
  loadAll()
}

async function removeForwarder(index: number) {
  const current = forwarders.value.map((f: any) => f.address)
  current.splice(index, 1)
  await axios.put('/api/settings/forwarders', { forwarders: current })
  loadAll()
}

// --- DNSSEC ---
async function generateDNSSEC() {
  await axios.post('/api/dnssec/generate', { zone_name: dnssecZone.value })
  dnssecZone.value = ''
  loadAll()
}

async function toggleDNSSEC(key: any) {
  await axios.put(`/api/dnssec/${key.zone_name}`, { enabled: !key.enabled })
  loadAll()
}

async function removeDNSSEC(zone: string) {
  if (!confirm(`Remove DNSSEC key for ${zone}? This will disable zone signing.`)) return
  await axios.delete(`/api/dnssec/${zone}`)
  loadAll()
}

function copyText(text: string) {
  navigator.clipboard.writeText(text)
}

// --- Certificates ---
async function generateCert() {
  certMsg.value = ''
  const { data } = await axios.post('/api/certs/generate')
  certMsg.value = data.message
  loadAll()
}

async function handleCertUpload(e: Event) {
  const input = e.target as HTMLInputElement
  if (!input.files?.length) return
  const certFile = input.files[0]
  const keyFile = prompt('Paste the private key PEM content:')
  if (!keyFile) return
  const formData = new FormData()
  formData.append('cert', certFile)
  formData.append('key', new Blob([keyFile], { type: 'text/plain' }), 'server.key')
  certMsg.value = ''
  try {
    const { data } = await axios.post('/api/certs/upload', formData)
    certMsg.value = data.message
    loadAll()
  } catch (err: any) {
    certMsg.value = 'Upload failed: ' + (err.response?.data?.error || err.message)
  }
}

function formatDate(d: string) {
  return new Date(d).toLocaleDateString([], { year: 'numeric', month: 'long', day: 'numeric' })
}

// --- Block Page ---
async function saveBlockPage() {
  bpMsg.value = ''
  const html = blockPageHTML.value || '<h1>Blocked</h1>'
  await axios.put('/api/settings/blockpage', { html })
  if (!blockPageHTML.value) blockPageHTML.value = ''
  bpMsg.value = 'Template saved'
  setTimeout(() => bpMsg.value = '', 3000)
}

function previewBlockPage() {
  const w = window.open('', '_blank', 'width=600,height=500')
  if (!w) return
  let html = blockPageHTML.value || '<h1>Blocked</h1>'
  html = html.replace(/\{\{\.Domain\}\}/g, 'example-blocked.com')
  html = html.replace(/\{\{\.Reason\}\}/g, '[ads] stevenblack-hosts')
  w.document.write(html)
}

onMounted(loadAll)
</script>

<style scoped>
.settings-page h2 { margin-bottom: 24px; font-size: 1.5rem; }

.section {
  background: #1e293b; border-radius: 12px; padding: 24px;
  border: 1px solid #334155; margin-bottom: 20px;
}
.section h3 { color: #e2e8f0; font-size: 1.05rem; margin-bottom: 4px; }
.section-desc { color: #64748b; font-size: 0.85rem; margin-bottom: 16px; line-height: 1.5; }
.section-desc code { color: #f59e0b; background: #0f172a; padding: 2px 6px; border-radius: 3px; font-size: 0.8rem; }

/* Shared components */
.add-row { display: flex; gap: 8px; flex-wrap: wrap; }
.add-row input, .add-row select {
  padding: 9px 14px; background: #0f172a; border: 1px solid #334155;
  border-radius: 8px; color: #e2e8f0; font-size: 0.9rem; flex: 1; min-width: 150px;
}
.add-row input::placeholder { color: #475569; }

.btn-primary { padding: 9px 20px; background: #0ea5e9; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; white-space: nowrap; }
.btn-primary:disabled { opacity: 0.3; cursor: not-allowed; }
.btn-secondary, .upload-btn { padding: 9px 20px; background: #334155; color: #94a3b8; border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; }
.btn-text { padding: 9px 16px; background: none; color: #64748b; border: none; cursor: pointer; font-size: 0.85rem; }
.btn-text-danger { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 0.8rem; padding: 4px 0; }
.btn-copy { padding: 2px 8px; background: #334155; color: #94a3b8; border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem; }

.section-actions { display: flex; gap: 8px; margin-top: 12px; }
.msg-success { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: #22c55e; padding: 8px 14px; border-radius: 8px; margin-top: 12px; font-size: 0.85rem; }
.empty-small { padding: 16px; text-align: center; color: #475569; font-size: 0.85rem; }

.detail-row { display: flex; align-items: flex-start; gap: 12px; padding: 6px 0; flex-wrap: wrap; }
.detail-label { color: #64748b; font-size: 0.8rem; min-width: 100px; padding-top: 2px; }
.detail-value { color: #e2e8f0; font-size: 0.85rem; flex: 1; }
.detail-value.mono { font-family: monospace; }
.detail-value.small { font-size: 0.75rem; color: #94a3b8; word-break: break-all; }

/* Forwarders */
.forwarders-list { margin-bottom: 12px; }
.forwarder-item {
  display: flex; align-items: center; gap: 12px; padding: 10px 12px;
  background: #0f172a; border-radius: 8px; margin-bottom: 6px;
}
.forwarder-num { width: 24px; height: 24px; background: #334155; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; color: #94a3b8; font-weight: 600; }
.forwarder-info { flex: 1; }
.forwarder-addr { color: #e2e8f0; font-family: monospace; font-size: 0.9rem; }
.forwarder-name { color: #64748b; font-size: 0.8rem; margin-left: 8px; }
.btn-icon-remove { background: none; border: none; color: #475569; cursor: pointer; font-size: 1rem; padding: 4px 8px; }
.btn-icon-remove:hover { color: #ef4444; }

/* DNSSEC */
.dnssec-list { margin-bottom: 12px; }
.dnssec-card { background: #0f172a; border-radius: 10px; padding: 16px; margin-bottom: 10px; }
.dnssec-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.dnssec-zone { color: #e2e8f0; font-weight: 600; font-size: 1rem; }
.dnssec-algo { color: #64748b; font-size: 0.75rem; background: #1e293b; padding: 2px 8px; border-radius: 4px; }
.dnssec-detail { margin-bottom: 8px; }

.toggle-wrap { display: flex; align-items: center; gap: 8px; margin-left: auto; cursor: pointer; }
.toggle { width: 36px; height: 20px; border-radius: 10px; background: #475569; position: relative; transition: background 0.2s; }
.toggle.on { background: #22c55e; }
.toggle-knob { width: 16px; height: 16px; border-radius: 50%; background: #fff; position: absolute; top: 2px; left: 2px; transition: transform 0.2s; }
.toggle.on .toggle-knob { transform: translateX(16px); }
.toggle-label { font-size: 0.8rem; color: #64748b; }

/* Cert info */
.cert-info { background: #0f172a; border-radius: 8px; padding: 14px; margin-bottom: 12px; }

/* Code editor */
.code-editor {
  width: 100%; padding: 14px; background: #0f172a; border: 1px solid #334155;
  border-radius: 8px; color: #e2e8f0; font-family: monospace; font-size: 0.85rem;
  resize: vertical; line-height: 1.5;
}

/* Policies */
.policy-card { background: #0f172a; border-radius: 10px; padding: 16px; margin-top: 12px; }
.policy-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.policy-ip { color: #e2e8f0; font-weight: 600; font-family: monospace; }
.policy-name { color: #64748b; font-size: 0.85rem; flex: 1; }
.policy-row { margin-bottom: 10px; }

.cat-toggles { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 4px; }
.cat-check { display: flex; align-items: center; gap: 5px; cursor: pointer; }
.cat-check input { accent-color: #ef4444; }
.cat-check span { color: #94a3b8; font-size: 0.85rem; }

.inline-add { display: flex; gap: 6px; margin-top: 4px; }
.inline-add input {
  padding: 5px 10px; background: #1e293b; border: 1px solid #334155;
  border-radius: 6px; color: #e2e8f0; font-size: 0.85rem; flex: 1; max-width: 220px;
}
.btn-xs { padding: 5px 12px; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }
.btn-xs.danger { background: #ef4444; }
.btn-xs.allow { background: #22c55e; }

.tag-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tag { display: flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 6px; font-size: 0.8rem; }
.blocked-tag { background: rgba(239,68,68,0.1); color: #ef4444; }
.allow-tag { background: rgba(34,197,94,0.1); color: #22c55e; }
.tag button { background: none; border: none; color: inherit; cursor: pointer; font-size: 1rem; line-height: 1; }

/* Server settings */
.subsection { margin-bottom: 20px; }
.subsection h4 { color: #94a3b8; font-size: 0.9rem; margin-bottom: 8px; }
.settings-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; }
.field { display: flex; flex-direction: column; gap: 4px; }
.field label { color: #64748b; font-size: 0.8rem; }
.field input, .field select {
  padding: 9px 12px; background: #0f172a; border: 1px solid #334155;
  border-radius: 8px; color: #e2e8f0; font-size: 0.9rem;
}
.field input::placeholder { color: #475569; }
.checkbox-label { display: flex; align-items: center; gap: 8px; color: #94a3b8; font-size: 0.85rem; cursor: pointer; padding-top: 8px; }
.checkbox-label input { accent-color: #0ea5e9; }

/* Protocol grid */
.protocol-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 8px; }
.protocol-item {
  display: flex; align-items: center; gap: 12px; padding: 12px;
  background: #0f172a; border: 1px solid #334155; border-radius: 10px; cursor: pointer;
}
.protocol-item input { accent-color: #22c55e; width: 18px; height: 18px; }
.protocol-info { display: flex; flex-direction: column; }
.protocol-name { color: #e2e8f0; font-weight: 500; font-size: 0.9rem; }
.protocol-port { color: #0ea5e9; font-size: 0.75rem; font-family: monospace; }
.protocol-desc { color: #475569; font-size: 0.75rem; }

/* Filtering mode */
.mode-cards { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.mode-card {
  padding: 20px; background: #0f172a; border: 2px solid #334155; border-radius: 12px;
  cursor: pointer; transition: all 0.15s;
}
.mode-card:hover { border-color: #475569; }
.mode-card.active { border-color: #0ea5e9; background: rgba(14,165,233,0.05); }
.mode-icon { font-size: 1.5rem; margin-bottom: 8px; }
.mode-info { display: flex; flex-direction: column; gap: 4px; }
.mode-title { color: #e2e8f0; font-weight: 600; font-size: 0.95rem; }
.mode-desc { color: #64748b; font-size: 0.8rem; line-height: 1.4; }
.mode-cards.three-col { grid-template-columns: repeat(3, 1fr); }
.cluster-config { margin-top: 16px; }
.sync-options { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 8px; }

/* Log management */
.log-stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.info-item { display: flex; flex-direction: column; gap: 2px; padding: 10px 14px; background: var(--bg-input); border-radius: 8px; }
.info-label { color: var(--text-muted); font-size: 0.75rem; }
.info-value { color: var(--text-primary); font-size: 0.9rem; font-weight: 500; }
.btn-danger { padding: 9px 16px; background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem; }
.btn-danger-outline { padding: 9px 16px; background: none; color: #ef4444; border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem; }
</style>
