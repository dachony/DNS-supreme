<template>
  <div class="dashboard">
    <h2>Dashboard</h2>
    <div class="toolbar">
      <div class="time-filter">
        <span class="toolbar-label">Period:</span>
        <button v-for="h in [1, 6, 24, 72, 168]" :key="h"
          :class="{ active: hours === h }" @click="loadStats(h)">
          {{ h < 24 ? h + 'h' : (h / 24) + 'd' }}
        </button>
      </div>
      <div class="refresh-filter">
        <span class="toolbar-label">Refresh:</span>
        <button v-for="r in refreshOptions" :key="r.value"
          :class="{ active: refreshInterval === r.value }" @click="setRefresh(r.value)">
          {{ r.label }}
        </button>
      </div>
    </div>

    <div class="stats-grid" v-if="stats">
      <div class="stat-card total">
        <div class="stat-icon">Q</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.total_queries?.toLocaleString() }}</div>
          <div class="stat-label">Total Queries</div>
        </div>
      </div>
      <div class="stat-card blocked">
        <div class="stat-icon">B</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.blocked_queries?.toLocaleString() }}</div>
          <div class="stat-label">Blocked</div>
        </div>
      </div>
      <div class="stat-card allowed">
        <div class="stat-icon">A</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.allowed_queries?.toLocaleString() }}</div>
          <div class="stat-label">Allowed</div>
        </div>
      </div>
      <div class="stat-card percent">
        <div class="stat-icon">%</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.blocked_percent?.toFixed(1) }}%</div>
          <div class="stat-label">Block Rate</div>
        </div>
      </div>
    </div>

    <!-- System Metrics -->
    <div class="system-grid" v-if="sysMetrics">
      <div class="sys-card">
        <div class="sys-header">
          <span class="sys-title">CPU</span>
          <span class="sys-value-big">{{ sysMetrics.cpu.usage_percent?.toFixed(0) }}%</span>
        </div>
        <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: sysMetrics.cpu.usage_percent + '%' }" :class="barColor(sysMetrics.cpu.usage_percent)"></div></div>
        <div class="sys-detail">{{ sysMetrics.cpu.num_cpu }} cores</div>
      </div>
      <div class="sys-card">
        <div class="sys-header">
          <span class="sys-title">Memory</span>
          <span class="sys-value-big">{{ sysMetrics.memory.usage_percent?.toFixed(0) }}%</span>
        </div>
        <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: sysMetrics.memory.usage_percent + '%' }" :class="barColor(sysMetrics.memory.usage_percent)"></div></div>
        <div class="sys-detail">{{ fmtBytes(sysMetrics.memory.used_bytes) }} / {{ fmtBytes(sysMetrics.memory.total_bytes) }} &middot; App: {{ fmtBytes(sysMetrics.memory.app_alloc_bytes) }}</div>
      </div>
      <div class="sys-card">
        <div class="sys-header">
          <span class="sys-title">Disk</span>
          <span class="sys-value-big">{{ sysMetrics.disk.usage_percent?.toFixed(0) }}%</span>
        </div>
        <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: sysMetrics.disk.usage_percent + '%' }" :class="barColor(sysMetrics.disk.usage_percent)"></div></div>
        <div class="sys-detail">{{ fmtBytes(sysMetrics.disk.used_bytes) }} / {{ fmtBytes(sysMetrics.disk.total_bytes) }} &middot; App: {{ fmtBytes(sysMetrics.disk.app_size_bytes) }}</div>
      </div>
      <div class="sys-card">
        <div class="sys-header">
          <span class="sys-title">Database</span>
          <span class="sys-value-big">{{ sysMetrics.database.size_human }}</span>
        </div>
        <div class="sys-detail">{{ sysMetrics.database.query_count?.toLocaleString() }} log entries</div>
        <div class="sys-detail" v-if="sysMetrics.uptime_seconds">Uptime: {{ fmtUptime(sysMetrics.uptime_seconds) }}</div>
      </div>
    </div>

    <!-- Security & Protection Status -->
    <div class="protection-bar" v-if="serverStatus">
      <div class="prot-item">
        <span class="prot-label">Blocklists</span>
        <span class="prot-value">{{ serverStatus.total_lists }} lists &middot; {{ serverStatus.total_domains?.toLocaleString() }} domains</span>
      </div>
      <div class="prot-item">
        <span class="prot-label">Network Protection</span>
        <span class="prot-value" :class="serverStatus.np_active_feeds > 0 ? 'active' : 'inactive'">{{ serverStatus.np_active_feeds }} feeds active</span>
      </div>
      <div class="prot-item">
        <span class="prot-label">Geo-Blocking</span>
        <span class="prot-value" :class="serverStatus.geo_blocked_countries > 0 ? 'active' : 'inactive'">{{ serverStatus.geo_blocked_countries }} countries</span>
      </div>
      <div class="prot-item">
        <span class="prot-label">Fail2Ban</span>
        <span class="prot-value" :class="serverStatus.banned_ips > 0 ? 'warn' : 'active'">{{ serverStatus.banned_ips }} banned IPs</span>
      </div>
    </div>

    <div class="charts-row" v-if="stats">
      <div class="chart-card wide">
        <h3>Queries Over Time</h3>
        <div class="chart-container">
          <Line v-if="chartData" :data="chartData" :options="chartOptions" />
        </div>
      </div>
    </div>

    <div class="tables-row" v-if="stats">
      <div class="table-card top-domains">
        <h3>Top Domains</h3>
        <table>
          <tr v-for="d in stats.top_domains" :key="d.domain">
            <td class="domain">{{ d.domain }}</td>
            <td class="count">{{ d.count.toLocaleString() }}</td>
          </tr>
          <tr v-if="!stats.top_domains?.length"><td colspan="2" class="empty">No data</td></tr>
        </table>
      </div>
      <div class="table-card top-blocked">
        <h3>Top Blocked</h3>
        <table>
          <tr v-for="d in stats.top_blocked" :key="d.domain">
            <td class="domain">{{ d.domain }}</td>
            <td class="count">{{ d.count.toLocaleString() }}</td>
          </tr>
          <tr v-if="!stats.top_blocked?.length"><td colspan="2" class="empty">No data</td></tr>
        </table>
      </div>
      <div class="table-card top-clients">
        <h3>Top Clients</h3>
        <table>
          <tr v-for="c in stats.top_clients" :key="c.client_ip">
            <td class="domain">{{ c.client_ip }}</td>
            <td class="count">{{ c.count.toLocaleString() }}</td>
          </tr>
          <tr v-if="!stats.top_clients?.length"><td colspan="2" class="empty">No data</td></tr>
        </table>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading...</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import axios from 'axios'
import { Line } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler } from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

const stats = ref<any>(null)
const sysMetrics = ref<any>(null)
const serverStatus = ref<any>(null)
const hours = ref(24)
const loading = ref(false)
const refreshInterval = ref(5)
let refreshTimer: any = null
let eventSource: EventSource | null = null

const refreshOptions = [
  { label: '1s', value: 1 },
  { label: '5s', value: 5 },
  { label: '10s', value: 10 },
  { label: '30s', value: 30 },
  { label: 'Off', value: 0 },
]

function setRefresh(seconds: number) {
  refreshInterval.value = seconds
  clearInterval(refreshTimer)
  if (seconds > 0) {
    refreshTimer = setInterval(() => loadStats(hours.value), seconds * 1000)
  }
}

const chartData = computed(() => {
  if (!stats.value?.queries_over_time?.length) return null
  const labels = stats.value.queries_over_time.map((t: any) =>
    new Date(t.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  )
  return {
    labels,
    datasets: [
      {
        label: 'Total',
        data: stats.value.queries_over_time.map((t: any) => t.total),
        borderColor: '#0ea5e9',
        backgroundColor: 'rgba(14,165,233,0.1)',
        fill: true,
        tension: 0.3,
      },
      {
        label: 'Blocked',
        data: stats.value.queries_over_time.map((t: any) => t.blocked),
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239,68,68,0.1)',
        fill: true,
        tension: 0.3,
      }
    ]
  }
})

const chartOptions = computed(() => {
  const style = getComputedStyle(document.documentElement)
  const muted = style.getPropertyValue('--text-muted').trim() || '#64748b'
  const dim = style.getPropertyValue('--text-dim').trim() || '#475569'
  const border = style.getPropertyValue('--border').trim() || '#1e293b'
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: muted } } },
    scales: {
      x: { ticks: { color: dim }, grid: { color: border } },
      y: { ticks: { color: dim }, grid: { color: border } },
    }
  }
})

async function loadStats(h: number) {
  hours.value = h
  const isFirstLoad = !stats.value
  if (isFirstLoad) loading.value = true
  try {
    const [statsResp, metricsResp, statusResp] = await Promise.all([
      axios.get(`/api/stats?hours=${h}`),
      axios.get('/api/system-metrics'),
      axios.get('/api/status'),
    ])
    stats.value = statsResp.data
    sysMetrics.value = metricsResp.data
    serverStatus.value = statusResp.data
  } catch (e) {
    // Stats load failed silently — auto-refresh will retry
  } finally {
    loading.value = false
  }
}

function fmtBytes(b: number): string {
  if (!b) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = b
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i]
}

function fmtUptime(s: number): string {
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

function barColor(pct: number): string {
  if (pct > 90) return 'bar-red'
  if (pct > 70) return 'bar-yellow'
  return 'bar-green'
}

function connectSSE() {
  const token = localStorage.getItem('token')
  if (!token) return

  if (eventSource) {
    eventSource.close()
    eventSource = null
  }

  eventSource = new EventSource(`/api/events?token=${token}`)

  eventSource.addEventListener('stats', (event: MessageEvent) => {
    try {
      const newStats = JSON.parse(event.data)
      // Only update via SSE when viewing last 1 hour (real-time view)
      if (hours.value === 1) {
        stats.value = newStats
      }
    } catch (e) {
      // Ignore parse errors
    }
  })

  eventSource.onerror = () => {
    if (eventSource) {
      eventSource.close()
      eventSource = null
    }
    // Reconnect after 5 seconds
    setTimeout(connectSSE, 5000)
  }
}

onMounted(() => {
  loadStats(24)
  setRefresh(refreshInterval.value)
  connectSSE()
})

onUnmounted(() => {
  clearInterval(refreshTimer)
  if (eventSource) {
    eventSource.close()
    eventSource = null
  }
})
</script>

<style scoped>
.dashboard h2 { margin-bottom: 20px; font-size: 1.5rem; }

.toolbar {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 24px; flex-wrap: wrap; gap: 12px;
}
.toolbar-label {
  font-size: 0.8rem; color: var(--text-muted); margin-right: 4px;
}
.time-filter, .refresh-filter {
  display: flex; gap: 6px; align-items: center;
}
.time-filter button, .refresh-filter button {
  padding: 6px 14px; border: 1px solid var(--border); background: var(--bg-card);
  color: var(--text-secondary); border-radius: 6px; cursor: pointer; font-size: 0.85rem;
  transition: all 0.15s;
}
.time-filter button:hover, .refresh-filter button:hover { border-color: var(--text-dim); color: var(--text-primary); }
.time-filter button.active { background: linear-gradient(135deg, #0ea5e9, #38bdf8); color: #fff; border-color: transparent; }
.refresh-filter button.active { background: linear-gradient(135deg, #7c3aed, #a78bfa); color: #fff; border-color: transparent; }

/* Stat cards with colored accents */
.stats-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;
}
.stat-card {
  background: var(--bg-card); border-radius: 12px; padding: 18px; border: 1px solid var(--border);
  transition: all 0.2s; display: flex; align-items: center; gap: 14px;
  border-top: 3px solid var(--border);
}
.stat-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
.stat-card.total { border-top-color: #38bdf8; }
.stat-card.blocked { border-top-color: #f87171; }
.stat-card.allowed { border-top-color: #34d399; }
.stat-card.percent { border-top-color: #fbbf24; }

.stat-icon {
  width: 40px; height: 40px; border-radius: 10px; display: flex;
  align-items: center; justify-content: center;
  font-size: 0.85rem; font-weight: 800; flex-shrink: 0;
}
.stat-card.total .stat-icon { background: rgba(56,189,248,0.12); color: #38bdf8; }
.stat-card.blocked .stat-icon { background: rgba(248,113,113,0.12); color: #f87171; }
.stat-card.allowed .stat-icon { background: rgba(52,211,153,0.12); color: #34d399; }
.stat-card.percent .stat-icon { background: rgba(251,191,36,0.12); color: #fbbf24; }

.stat-content { flex: 1; }
.stat-value { font-size: 1.8rem; font-weight: 700; color: var(--text-primary); line-height: 1.1; }
.stat-label { font-size: 0.82rem; color: var(--text-muted); margin-top: 2px; }
.stat-card.blocked .stat-value { color: #f87171; }
.stat-card.allowed .stat-value { color: #34d399; }
.stat-card.percent .stat-value { color: #fbbf24; }

/* Protection status bar */
.protection-bar {
  display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap;
}
.prot-item {
  flex: 1; min-width: 160px; padding: 10px 16px;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px;
  display: flex; flex-direction: column; gap: 2px;
}
.prot-label { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
.prot-value { color: var(--text-primary); font-size: 0.88rem; font-weight: 500; }
.prot-value.active { color: #22c55e; }
.prot-value.inactive { color: var(--text-dim); }
.prot-value.warn { color: #f59e0b; }

/* Chart */
.charts-row { margin-bottom: 24px; }
.chart-card {
  background: var(--bg-card); border-radius: 12px; padding: 20px; border: 1px solid var(--border);
}
.chart-card h3 { margin-bottom: 16px; font-size: 1rem; color: var(--text-secondary); }
.chart-container { height: 250px; }

/* Table cards with colored left borders */
.tables-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.table-card {
  background: var(--bg-card); border-radius: 12px; padding: 20px; border: 1px solid var(--border);
  border-left: 3px solid var(--border); transition: all 0.15s;
}
.table-card.top-domains { border-left-color: #38bdf8; }
.table-card.top-blocked { border-left-color: #f87171; }
.table-card.top-clients { border-left-color: #a78bfa; }

.table-card.top-domains h3 { color: #38bdf8; }
.table-card.top-blocked h3 { color: #f87171; }
.table-card.top-clients h3 { color: #a78bfa; }

.table-card h3 { margin-bottom: 12px; font-size: 0.95rem; }
table { width: 100%; }
tr { border-bottom: 1px solid var(--border); }
td { padding: 8px 4px; font-size: 0.85rem; }
.domain { color: var(--text-primary); word-break: break-all; }
.count { text-align: right; color: var(--text-muted); font-variant-numeric: tabular-nums; }
.empty { text-align: center; color: var(--text-dim); padding: 20px; }
.loading { text-align: center; padding: 40px; color: var(--text-muted); }

/* System metrics with gradient bars */
.system-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;
}
.sys-card {
  background: var(--bg-card); border-radius: 12px; padding: 16px;
  border: 1px solid var(--border); transition: all 0.2s;
}
.sys-card:hover { transform: translateY(-1px); box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.sys-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.sys-title { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }
.sys-value-big { color: var(--text-primary); font-size: 1.4rem; font-weight: 700; }
.sys-bar {
  height: 6px; background: rgba(100,116,139,0.15); border-radius: 3px; overflow: hidden; margin-bottom: 8px;
}
.sys-bar-fill { height: 100%; border-radius: 3px; transition: width 0.5s ease-out; }
.sys-bar-fill.bar-green { background: linear-gradient(90deg, #22c55e, #4ade80); }
.sys-bar-fill.bar-yellow { background: linear-gradient(90deg, #eab308, #facc15); }
.sys-bar-fill.bar-red { background: linear-gradient(90deg, #ef4444, #f87171); }
.sys-detail { color: var(--text-muted); font-size: 0.75rem; line-height: 1.5; }
</style>
