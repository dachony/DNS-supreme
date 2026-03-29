<template>
  <div class="app" v-if="isAuthenticated">
    <nav class="sidebar">
      <div class="logo">
        <h1>DNS Supreme</h1>
        <span class="version">v0.1.0</span>
      </div>
      <ul class="nav-links">
        <li><router-link to="/" active-class="active" exact>Dashboard</router-link></li>
        <li><router-link to="/zones" active-class="active">DNS Zones</router-link></li>
        <li><router-link to="/blocklists" active-class="active">DNS Filtering</router-link></li>
        <li><router-link to="/logs" active-class="active">Query Log</router-link></li>
        <li><router-link to="/settings" active-class="active">Settings</router-link></li>
        <li><router-link to="/users" active-class="active">Users</router-link></li>
      </ul>
      <div class="sidebar-bottom">
        <div class="status" v-if="status">
          <div class="status-dot" :class="{ online: status.status === 'running' }"></div>
          <span>{{ status.total_domains?.toLocaleString() }} blocked domains</span>
        </div>
        <button @click="toggleTheme" class="btn-theme" :title="isDark ? 'Switch to light mode' : 'Switch to dark mode'">
          {{ isDark ? 'Light Mode' : 'Dark Mode' }}
        </button>
        <div class="user-info">
          <div class="user-details">
            <span class="user-name">{{ currentUser?.first_name || currentUser?.username }}</span>
            <span class="user-role">{{ currentUser?.role }}</span>
          </div>
          <button @click="handleLogout" class="btn-logout">Sign out</button>
        </div>
      </div>
    </nav>
    <main class="content">
      <router-view />
    </main>
  </div>
  <router-view v-else />
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { isAuthenticated, currentUser, logout } from './auth'

const router = useRouter()
const status = ref<any>(null)
const isDark = ref(localStorage.getItem('theme') !== 'light')

function toggleTheme() {
  isDark.value = !isDark.value
  localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
  applyTheme()
}

function applyTheme() {
  document.documentElement.setAttribute('data-theme', isDark.value ? 'dark' : 'light')
}

applyTheme()

async function loadStatus() {
  try {
    const { data } = await axios.get('/api/status')
    status.value = data
  } catch (e) {}
}

function handleLogout() {
  logout()
  router.push('/login')
}

watch(isAuthenticated, (val) => { if (val) loadStatus() })
onMounted(() => { if (isAuthenticated.value) loadStatus() })
</script>

<style>
:root, [data-theme="dark"] {
  --bg-body: #0f172a;
  --bg-sidebar: #1e293b;
  --bg-card: #1e293b;
  --bg-input: #0f172a;
  --bg-hover: #334155;
  --border: #334155;
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --text-dim: #475569;
  --accent: #0ea5e9;
  --accent-hover: #0284c7;
  --brand: #38bdf8;
}

[data-theme="light"] {
  --bg-body: #f1f5f9;
  --bg-sidebar: #ffffff;
  --bg-card: #ffffff;
  --bg-input: #f8fafc;
  --bg-hover: #e2e8f0;
  --border: #e2e8f0;
  --text-primary: #0f172a;
  --text-secondary: #475569;
  --text-muted: #64748b;
  --text-dim: #94a3b8;
  --accent: #0ea5e9;
  --accent-hover: #0284c7;
  --brand: #0284c7;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-body); color: var(--text-primary);
  transition: background 0.2s, color 0.2s;
}

.app { display: flex; height: 100vh; overflow: hidden; }

.sidebar {
  width: 260px; min-width: 260px; height: 100vh;
  background: var(--bg-sidebar); padding: 24px 16px;
  display: flex; flex-direction: column;
  border-right: 1px solid var(--border);
  position: fixed; left: 0; top: 0; z-index: 10;
  transition: background 0.2s, border-color 0.2s;
}

.logo h1 { font-size: 1.3rem; color: var(--brand); font-weight: 700; letter-spacing: -0.5px; }
.logo .version { font-size: 0.7rem; color: var(--text-dim); margin-left: 6px; }

.nav-links { list-style: none; margin-top: 28px; flex: 1; }
.nav-links li { margin-bottom: 2px; }
.nav-links a {
  display: block; padding: 10px 16px; color: var(--text-secondary);
  text-decoration: none; border-radius: 8px; font-size: 0.9rem; transition: all 0.15s;
}
.nav-links a:hover { background: var(--bg-hover); color: var(--text-primary); }
.nav-links a.active { background: var(--accent); color: #fff; }

.sidebar-bottom { display: flex; flex-direction: column; gap: 8px; }

.status {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 12px; background: var(--bg-input); border-radius: 8px;
  font-size: 0.78rem; color: var(--text-muted);
}
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: #ef4444; flex-shrink: 0; }
.status-dot.online { background: #22c55e; }

.btn-theme {
  padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text-secondary); border-radius: 8px; cursor: pointer; font-size: 0.8rem;
  transition: all 0.15s;
}
.btn-theme:hover { border-color: var(--accent); color: var(--accent); }

.user-info {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 12px; background: var(--bg-input); border-radius: 8px;
}
.user-details { display: flex; flex-direction: column; }
.user-name { color: var(--text-primary); font-size: 0.85rem; font-weight: 500; }
.user-role { color: var(--text-dim); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; }

.btn-logout {
  padding: 4px 12px; background: transparent; border: 1px solid var(--border);
  color: var(--text-muted); border-radius: 6px; cursor: pointer; font-size: 0.78rem;
}
.btn-logout:hover { border-color: #ef4444; color: #ef4444; }

.content {
  flex: 1; margin-left: 260px; padding: 32px;
  height: 100vh; overflow-y: auto;
  scrollbar-width: none; -ms-overflow-style: none;
}
.content::-webkit-scrollbar { display: none; }

/* Global theme overrides for child components */
.section, .stat-card, .chart-card, .table-card, .policy-card, .zone-card,
.dnssec-card, .list-item, .protocol-item, .mode-card, .forwarder-item,
.cert-info, .dnssec-details, .sys-record, .info-item, .system-records,
.zone-card, .login-card, .modal {
  background: var(--bg-card) !important;
  border-color: var(--border) !important;
  transition: background 0.2s, border-color 0.2s;
}

.forwarder-item, .sys-record, .info-item, .protocol-item, .cert-info,
.dnssec-details, .policy-card, .mode-card, .zone-card {
  background: var(--bg-input) !important;
}

.section h3, .zone-name, .rec-name, .list-name, .policy-ip, .user-name,
.forwarder-addr, .dnssec-zone, .mode-title, .protocol-name, .zone-title,
h2, h3 {
  color: var(--text-primary) !important;
}

.section-desc, .rec-value, .sys-value, .list-url, .zone-meta span,
.policy-name, .protocol-desc, .sys-group-desc, .mode-desc,
.detail-label, .info-label, .cert-label, .toggle-label, .forwarder-name,
p.section-desc {
  color: var(--text-muted) !important;
}

input, select, textarea, .code-editor, .inline-input, .inline-select {
  background: var(--bg-input) !important;
  border-color: var(--border) !important;
  color: var(--text-primary) !important;
  transition: background 0.2s, border-color 0.2s, color 0.2s;
}

input::placeholder, textarea::placeholder { color: var(--text-dim) !important; }

table thead th { color: var(--text-muted) !important; border-color: var(--border) !important; }
table tbody tr { border-color: var(--border) !important; }
table tbody tr:hover { background: var(--bg-hover) !important; }

.mode-card.active { border-color: var(--accent) !important; }

.login-page { background: var(--bg-body) !important; }
.login-card { background: var(--bg-card) !important; border-color: var(--border) !important; }
</style>
