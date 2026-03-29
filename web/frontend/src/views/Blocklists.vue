<template>
  <div class="blocklists">
    <h2>DNS Filtering</h2>

    <!-- Filtering Mode -->
    <div class="section">
      <h3>Filtering Mode</h3>
      <div class="mode-cards">
        <div class="mode-card" :class="{ active: filterMode === 'blocklist' }" @click="setFilterMode('blocklist')">
          <div class="mode-icon">&#x2705;</div>
          <div class="mode-info">
            <span class="mode-title">Blocklist Mode</span>
            <span class="mode-desc">Allow all traffic, except domains on your blocklists. Standard mode for ad/malware blocking.</span>
          </div>
        </div>
        <div class="mode-card" :class="{ active: filterMode === 'allowlist' }" @click="setFilterMode('allowlist')">
          <div class="mode-icon">&#x1F512;</div>
          <div class="mode-info">
            <span class="mode-title">Allowlist Mode</span>
            <span class="mode-desc">Block all traffic, except domains you explicitly allow. Maximum security or parental controls.</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Categories -->
    <div class="section">
      <h3>Categories</h3>
      <p class="section-desc">Enable or disable entire filtering categories</p>
      <div class="categories-grid">
        <div v-for="cat in categories" :key="cat.name" class="cat-card"
          :class="{ disabled: !cat.enabled }" @click="toggleCategory(cat)">
          <div class="cat-icon">{{ categoryIcon(cat.name) }}</div>
          <div class="cat-info">
            <span class="cat-name">{{ cat.name }}</span>
            <span class="cat-count">{{ cat.domains?.toLocaleString() || 0 }} domains</span>
          </div>
          <div class="cat-toggle">
            <div class="toggle" :class="{ on: cat.enabled }">
              <div class="toggle-knob"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Active Lists -->
    <div class="section">
      <h3>Active Lists</h3>
      <div class="add-form">
        <input v-model="newName" placeholder="List name..." />
        <input v-model="newUrl" placeholder="URL (hosts file, domain list, GitHub raw)..." class="url-input" />
        <select v-model="newCategory">
          <option value="ads">Ads</option>
          <option value="malware">Malware</option>
          <option value="adult">Adult</option>
          <option value="social">Social</option>
          <option value="gambling">Gambling</option>
          <option value="tracking">Tracking</option>
          <option value="uncategorized">Other</option>
        </select>
        <button @click="addList" :disabled="!newName || !newUrl" class="btn-add">Add List</button>
      </div>
      <div v-if="addError" class="error-msg">{{ addError }}</div>
      <div class="lists">
        <div v-for="list in lists" :key="list.name" class="list-item">
          <div class="list-info">
            <div class="list-header">
              <span class="list-name">{{ list.name }}</span>
              <span class="list-cat-badge" :class="list.category">{{ list.category }}</span>
            </div>
            <span class="list-count">{{ list.count?.toLocaleString() }} domains</span>
            <span class="list-url">{{ list.url }}</span>
          </div>
          <button @click="removeList(list.name)" class="btn-remove">Remove</button>
        </div>
        <div v-if="!lists.length" class="empty">No blocklists configured</div>
      </div>
      <div class="stats-bar" v-if="totalDomains > 0">
        Total: {{ totalDomains.toLocaleString() }} domains across {{ totalLists }} lists
      </div>
    </div>

    <!-- Custom Block Rules -->
    <div class="section">
      <h3>Custom Block Rules</h3>
      <div class="add-form">
        <input v-model="customDomain" placeholder="Domain to block..." />
        <input v-model="customReason" placeholder="Reason (optional)..." />
        <button @click="addCustom" :disabled="!customDomain" class="btn-add">Block</button>
      </div>
      <div class="lists">
        <div v-for="(reason, domain) in customBlocks" :key="domain" class="list-item">
          <div class="list-info">
            <span class="list-name">{{ domain }}</span>
            <span class="list-url" v-if="reason">{{ reason }}</span>
          </div>
          <button @click="removeCustom(domain as string)" class="btn-remove">Unblock</button>
        </div>
        <div v-if="!Object.keys(customBlocks).length" class="empty">No custom blocks</div>
      </div>
    </div>

    <!-- Allowlist -->
    <div class="section">
      <h3>Allowlist (Override)</h3>
      <div class="add-form">
        <input v-model="allowDomain" placeholder="Domain to allow..." />
        <button @click="addAllow" :disabled="!allowDomain" class="btn-add allow">Allow</button>
      </div>
      <div class="lists">
        <div v-for="domain in allowlist" :key="domain" class="list-item">
          <div class="list-info">
            <span class="list-name">{{ domain }}</span>
          </div>
          <button @click="removeAllow(domain)" class="btn-remove">Remove</button>
        </div>
        <div v-if="!allowlist.length" class="empty">No allowlist entries</div>
      </div>
    </div>

    <!-- Geo-blocking -->
    <div class="section">
      <h3>Geo-blocking</h3>
      <p class="section-desc">Block DNS queries from specific countries (requires GeoIP database)</p>
      <div class="add-form">
        <input v-model="geoInput" placeholder="Country codes (comma separated: RU, CN, KP...)" class="url-input" />
        <button @click="saveGeo" class="btn-add geo">Save</button>
      </div>
      <div class="geo-tags" v-if="geoBlocked.length">
        <span v-for="cc in geoBlocked" :key="cc" class="geo-tag">
          {{ cc }}
          <button @click="removeGeoCountry(cc)" class="geo-remove">&times;</button>
        </span>
      </div>
      <div v-else class="empty">No countries blocked</div>
    </div>

    <!-- Per-Device Policies -->
    <div class="section">
      <h3>Per-Device Policies</h3>
      <p class="section-desc">Override global filtering rules for specific devices by IP address.</p>

      <div class="add-form">
        <input v-model="newPolicy.client_ip" placeholder="Device IP (e.g. 192.168.1.50)" />
        <input v-model="newPolicy.name" placeholder="Friendly name (e.g. Kids Laptop)" />
        <button @click="addPolicy" :disabled="!newPolicy.client_ip" class="btn-add">Add Device</button>
      </div>

      <div v-for="p in policies" :key="p.client_ip" class="policy-card">
        <div class="policy-header">
          <span class="policy-ip">{{ p.client_ip }}</span>
          <span class="policy-name" v-if="p.name">{{ p.name }}</span>
          <button @click="removePolicy(p.client_ip)" class="btn-remove">Remove</button>
        </div>

        <div class="policy-row">
          <span class="policy-label">Disable categories for this device:</span>
          <div class="cat-toggles">
            <label v-for="cat in allPolicyCats" :key="cat" class="cat-check">
              <input type="checkbox" :checked="p.disabled_categories?.[cat]"
                @change="togglePolicyCat(p, cat, $event)" />
              <span>{{ policyCatLabel(cat) }}</span>
            </label>
          </div>
        </div>

        <div class="policy-row">
          <span class="policy-label">Extra blocked domains:</span>
          <div class="inline-add">
            <input v-model="policyBlockDomain[p.client_ip]" placeholder="domain.com" @keyup.enter="addPolicyBlock(p)" />
            <button @click="addPolicyBlock(p)" class="btn-add">Block</button>
          </div>
          <div class="tag-list" v-if="Object.keys(p.custom_blocks || {}).length">
            <span v-for="(_, domain) in (p.custom_blocks || {})" :key="domain" class="tag blocked-tag">
              {{ domain }}
              <button @click="removePolicyBlock(p, domain as string)">&times;</button>
            </span>
          </div>
        </div>

        <div class="policy-row">
          <span class="policy-label">Extra allowed domains (overrides blocks):</span>
          <div class="inline-add">
            <input v-model="policyAllowDomain[p.client_ip]" placeholder="domain.com" @keyup.enter="addPolicyAllow(p)" />
            <button @click="addPolicyAllow(p)" class="btn-add allow">Allow</button>
          </div>
          <div class="tag-list" v-if="Object.keys(p.custom_allows || {}).length">
            <span v-for="(_, domain) in (p.custom_allows || {})" :key="domain" class="tag allow-tag">
              {{ domain }}
              <button @click="removePolicyAllow(p, domain as string)">&times;</button>
            </span>
          </div>
        </div>
      </div>

      <div v-if="!policies.length" class="empty">No device-specific policies configured</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import axios from 'axios'

const filterMode = ref('blocklist')
const lists = ref<any[]>([])
const totalDomains = ref(0)
const totalLists = ref(0)
const customBlocks = ref<Record<string, string>>({})
const allowlist = ref<string[]>([])
const categories = ref<any[]>([])
const geoBlocked = ref<string[]>([])
const policies = ref<any[]>([])
const policyBlockDomain = reactive<Record<string, string>>({})
const policyAllowDomain = reactive<Record<string, string>>({})

const newName = ref('')
const newUrl = ref('')
const newCategory = ref('ads')
const addError = ref('')
const customDomain = ref('')
const customReason = ref('')
const allowDomain = ref('')
const geoInput = ref('')
const newPolicy = ref({ client_ip: '', name: '' })
const allPolicyCats = ['ads', 'malware', 'adult', 'social', 'gambling', 'tracking']

function policyCatLabel(cat: string) {
  const labels: Record<string, string> = {
    ads: 'Ads & Trackers', malware: 'Malware & Phishing', adult: 'Adult Content',
    social: 'Social Media', gambling: 'Gambling', tracking: 'Analytics & Tracking'
  }
  return labels[cat] || cat
}

const categoryIcons: Record<string, string> = {
  ads: 'AD', malware: 'MW', adult: '18', social: 'SC', gambling: 'GM', tracking: 'TR'
}

function categoryIcon(name: string) {
  return categoryIcons[name] || name.substring(0, 2).toUpperCase()
}

async function loadAll() {
  try {
    const [bl, cb, al, cats, geo, fm, pol] = await Promise.all([
      axios.get('/api/blocklists'),
      axios.get('/api/custom-blocks'),
      axios.get('/api/allowlist'),
      axios.get('/api/categories'),
      axios.get('/api/geo-blocked'),
      axios.get('/api/settings/filtering-mode'),
      axios.get('/api/policies'),
    ])
    lists.value = bl.data.lists || []
    totalDomains.value = bl.data.total_domains || 0
    totalLists.value = bl.data.total_lists || 0
    customBlocks.value = cb.data || {}
    allowlist.value = al.data || []
    categories.value = cats.data || []
    geoBlocked.value = geo.data || []
    geoInput.value = geoBlocked.value.join(', ')
    filterMode.value = fm.data.mode || 'blocklist'
    policies.value = pol.data || []
  } catch (e) {
    console.error('Failed to load', e)
  }
}

async function setFilterMode(mode: string) {
  filterMode.value = mode
  await axios.put('/api/settings/filtering-mode', { mode })
}

async function toggleCategory(cat: any) {
  await axios.put(`/api/categories/${cat.name}`, { enabled: !cat.enabled })
  loadAll()
}

async function addList() {
  addError.value = ''
  try {
    await axios.post('/api/blocklists', { name: newName.value, url: newUrl.value, category: newCategory.value })
    newName.value = ''; newUrl.value = ''
    loadAll()
  } catch (e: any) {
    addError.value = e.response?.data?.error || 'Failed to add list'
  }
}

async function removeList(name: string) {
  await axios.delete(`/api/blocklists/${name}`)
  loadAll()
}

async function addCustom() {
  await axios.post('/api/custom-blocks', { domain: customDomain.value, reason: customReason.value })
  customDomain.value = ''; customReason.value = ''
  loadAll()
}

async function removeCustom(domain: string) {
  await axios.delete(`/api/custom-blocks/${domain}`)
  loadAll()
}

async function addAllow() {
  await axios.post('/api/allowlist', { domain: allowDomain.value })
  allowDomain.value = ''
  loadAll()
}

async function removeAllow(domain: string) {
  await axios.delete(`/api/allowlist/${domain}`)
  loadAll()
}

async function saveGeo() {
  const countries = geoInput.value.split(',').map(s => s.trim().toUpperCase()).filter(Boolean)
  await axios.put('/api/geo-blocked', { countries })
  loadAll()
}

function removeGeoCountry(cc: string) {
  const updated = geoBlocked.value.filter(c => c !== cc)
  geoInput.value = updated.join(', ')
  axios.put('/api/geo-blocked', { countries: updated }).then(() => loadAll())
}

// --- Policies ---
async function addPolicy() {
  await axios.post('/api/policies', {
    client_ip: newPolicy.value.client_ip, name: newPolicy.value.name,
    disabled_categories: {}, custom_blocks: {}, custom_allows: {},
  })
  newPolicy.value = { client_ip: '', name: '' }
  loadAll()
}
async function removePolicy(ip: string) { await axios.delete(`/api/policies/${ip}`); loadAll() }

async function togglePolicyCat(p: any, cat: string, e: Event) {
  if (!p.disabled_categories) p.disabled_categories = {}
  const checked = (e.target as HTMLInputElement).checked
  if (checked) { p.disabled_categories[cat] = true } else { delete p.disabled_categories[cat] }
  await axios.post('/api/policies', p)
}

async function addPolicyBlock(p: any) {
  const d = policyBlockDomain[p.client_ip]; if (!d) return
  if (!p.custom_blocks) p.custom_blocks = {}; p.custom_blocks[d] = 'device policy'
  await axios.post('/api/policies', p); policyBlockDomain[p.client_ip] = ''; loadAll()
}
async function removePolicyBlock(p: any, d: string) { delete p.custom_blocks[d]; await axios.post('/api/policies', p); loadAll() }

async function addPolicyAllow(p: any) {
  const d = policyAllowDomain[p.client_ip]; if (!d) return
  if (!p.custom_allows) p.custom_allows = {}; p.custom_allows[d] = true
  await axios.post('/api/policies', p); policyAllowDomain[p.client_ip] = ''; loadAll()
}
async function removePolicyAllow(p: any, d: string) { delete p.custom_allows[d]; await axios.post('/api/policies', p); loadAll() }

onMounted(loadAll)
</script>

<style scoped>
.blocklists h2 { margin-bottom: 24px; }

.section {
  background: #1e293b; border-radius: 12px; padding: 20px;
  border: 1px solid #334155; margin-bottom: 20px;
}
.section h3 { color: #94a3b8; font-size: 1rem; margin-bottom: 4px; }
.section-desc { color: #475569; font-size: 0.8rem; margin-bottom: 16px; }

/* Categories grid */
.categories-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px;
}
.cat-card {
  display: flex; align-items: center; gap: 12px; padding: 14px;
  background: #0f172a; border: 1px solid #334155; border-radius: 10px;
  cursor: pointer; transition: all 0.15s;
}
.cat-card:hover { border-color: #475569; }
.cat-card.disabled { opacity: 0.4; }
.cat-icon {
  width: 40px; height: 40px; border-radius: 8px; background: #334155;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.75rem; font-weight: 700; color: #94a3b8;
}
.cat-info { flex: 1; }
.cat-name { display: block; color: #e2e8f0; font-weight: 600; font-size: 0.9rem; text-transform: capitalize; }
.cat-count { font-size: 0.75rem; color: #64748b; }

.toggle {
  width: 40px; height: 22px; border-radius: 11px; background: #475569;
  position: relative; transition: background 0.2s;
}
.toggle.on { background: #22c55e; }
.toggle-knob {
  width: 18px; height: 18px; border-radius: 50%; background: #fff;
  position: absolute; top: 2px; left: 2px; transition: transform 0.2s;
}
.toggle.on .toggle-knob { transform: translateX(18px); }

/* Forms */
.add-form {
  display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;
}
.add-form input, .add-form select {
  padding: 8px 12px; background: #0f172a; border: 1px solid #334155;
  border-radius: 6px; color: #e2e8f0; font-size: 0.9rem; flex: 1; min-width: 120px;
}
.add-form input::placeholder { color: #475569; }
.url-input { flex: 2 !important; }

.btn-add {
  padding: 8px 20px; background: #ef4444; color: #fff; border: none;
  border-radius: 6px; cursor: pointer; white-space: nowrap;
}
.btn-add.allow { background: #22c55e; }
.btn-add.geo { background: #8b5cf6; }
.btn-add:disabled { opacity: 0.3; cursor: not-allowed; }

/* Lists */
.list-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 0; border-bottom: 1px solid #334155;
}
.list-info { display: flex; flex-direction: column; gap: 2px; }
.list-header { display: flex; align-items: center; gap: 8px; }
.list-name { color: #e2e8f0; font-weight: 500; }
.list-cat-badge {
  padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: 600;
  text-transform: uppercase;
}
.list-cat-badge.ads { background: rgba(239,68,68,0.15); color: #ef4444; }
.list-cat-badge.malware { background: rgba(249,115,22,0.15); color: #f97316; }
.list-cat-badge.adult { background: rgba(168,85,247,0.15); color: #a855f7; }
.list-cat-badge.social { background: rgba(59,130,246,0.15); color: #3b82f6; }
.list-cat-badge.gambling { background: rgba(234,179,8,0.15); color: #eab308; }
.list-cat-badge.tracking { background: rgba(14,165,233,0.15); color: #0ea5e9; }
.list-cat-badge.uncategorized { background: rgba(100,116,139,0.15); color: #64748b; }

.list-count { color: #0ea5e9; font-size: 0.8rem; }
.list-url { color: #475569; font-size: 0.8rem; word-break: break-all; }

.btn-remove {
  padding: 4px 12px; background: transparent; border: 1px solid #ef4444;
  color: #ef4444; border-radius: 4px; cursor: pointer; font-size: 0.8rem;
}

.stats-bar {
  margin-top: 12px; padding: 8px 12px; background: #0f172a;
  border-radius: 6px; color: #64748b; font-size: 0.85rem;
}

/* Geo tags */
.geo-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
.geo-tag {
  display: flex; align-items: center; gap: 6px; padding: 4px 10px;
  background: rgba(139,92,246,0.15); color: #8b5cf6; border-radius: 6px;
  font-size: 0.85rem; font-weight: 600;
}
.geo-remove {
  background: none; border: none; color: #8b5cf6; cursor: pointer;
  font-size: 1.1rem; line-height: 1;
}

.error-msg {
  background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444;
  padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; font-size: 0.85rem;
}
.empty { padding: 20px; text-align: center; color: #475569; }

/* Filtering mode */
.mode-cards { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.mode-card {
  padding: 20px; background: var(--bg-input, #0f172a); border: 2px solid var(--border, #334155);
  border-radius: 12px; cursor: pointer; transition: all 0.15s;
}
.mode-card:hover { border-color: #475569; }
.mode-card.active { border-color: var(--accent, #0ea5e9); background: rgba(14,165,233,0.05); }
.mode-icon { font-size: 1.5rem; margin-bottom: 8px; }
.mode-info { display: flex; flex-direction: column; gap: 4px; }
.mode-title { color: var(--text-primary, #e2e8f0); font-weight: 600; font-size: 0.95rem; }
.mode-desc { color: var(--text-muted, #64748b); font-size: 0.8rem; line-height: 1.4; }

/* Policies */
.section-desc { color: #475569; font-size: 0.8rem; margin-bottom: 16px; }
.policy-card {
  background: var(--bg-input, #0f172a); border: 1px solid var(--border, #334155);
  border-radius: 10px; padding: 16px; margin-top: 12px;
}
.policy-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.policy-ip { color: var(--text-primary, #e2e8f0); font-weight: 600; font-family: monospace; }
.policy-name { color: var(--text-muted, #64748b); font-size: 0.85rem; flex: 1; }
.policy-row { margin-bottom: 10px; }
.policy-label { color: var(--text-muted, #64748b); font-size: 0.8rem; display: block; margin-bottom: 6px; }

.cat-toggles { display: flex; gap: 12px; flex-wrap: wrap; }
.cat-check { display: flex; align-items: center; gap: 5px; cursor: pointer; }
.cat-check input { accent-color: #ef4444; }
.cat-check span { color: var(--text-secondary, #94a3b8); font-size: 0.85rem; }

.inline-add { display: flex; gap: 6px; margin-top: 4px; }
.inline-add input {
  padding: 5px 10px; background: var(--bg-card, #1e293b); border: 1px solid var(--border, #334155);
  border-radius: 6px; color: var(--text-primary, #e2e8f0); font-size: 0.85rem; flex: 1; max-width: 220px;
}

.tag-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tag { display: flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 6px; font-size: 0.8rem; }
.blocked-tag { background: rgba(239,68,68,0.1); color: #ef4444; }
.allow-tag { background: rgba(34,197,94,0.1); color: #22c55e; }
.tag button { background: none; border: none; color: inherit; cursor: pointer; font-size: 1rem; line-height: 1; }
</style>
