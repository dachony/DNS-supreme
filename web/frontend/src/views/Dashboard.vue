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
      <div class="stat-card">
        <div class="stat-value">{{ stats.total_queries?.toLocaleString() }}</div>
        <div class="stat-label">Total Queries</div>
      </div>
      <div class="stat-card blocked">
        <div class="stat-value">{{ stats.blocked_queries?.toLocaleString() }}</div>
        <div class="stat-label">Blocked</div>
      </div>
      <div class="stat-card allowed">
        <div class="stat-value">{{ stats.allowed_queries?.toLocaleString() }}</div>
        <div class="stat-label">Allowed</div>
      </div>
      <div class="stat-card percent">
        <div class="stat-value">{{ stats.blocked_percent?.toFixed(1) }}%</div>
        <div class="stat-label">Block Rate</div>
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

    <div class="charts-row" v-if="stats">
      <div class="chart-card wide">
        <h3>Queries Over Time</h3>
        <div class="chart-container">
          <Line v-if="chartData" :data="chartData" :options="chartOptions" />
        </div>
      </div>
    </div>

    <div class="tables-row" v-if="stats">
      <div class="table-card">
        <h3>Top Domains</h3>
        <table>
          <tr v-for="d in stats.top_domains" :key="d.domain">
            <td class="domain">{{ d.domain }}</td>
            <td class="count">{{ d.count.toLocaleString() }}</td>
          </tr>
          <tr v-if="!stats.top_domains?.length"><td colspan="2" class="empty">No data</td></tr>
        </table>
      </div>
      <div class="table-card">
        <h3>Top Blocked</h3>
        <table>
          <tr v-for="d in stats.top_blocked" :key="d.domain">
            <td class="domain">{{ d.domain }}</td>
            <td class="count">{{ d.count.toLocaleString() }}</td>
          </tr>
          <tr v-if="!stats.top_blocked?.length"><td colspan="2" class="empty">No data</td></tr>
        </table>
      </div>
      <div class="table-card">
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
const hours = ref(24)
const loading = ref(false)
const refreshInterval = ref(5)
let refreshTimer: any = null

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

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#94a3b8' } } },
  scales: {
    x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
    y: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
  }
}

async function loadStats(h: number) {
  hours.value = h
  const isFirstLoad = !stats.value
  if (isFirstLoad) loading.value = true
  try {
    const [statsResp, metricsResp] = await Promise.all([
      axios.get(`/api/stats?hours=${h}`),
      axios.get('/api/system-metrics'),
    ])
    stats.value = statsResp.data
    sysMetrics.value = metricsResp.data
  } catch (e) {
    console.error('Failed to load stats', e)
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

onMounted(() => {
  loadStats(24)
  setRefresh(refreshInterval.value)
})

onUnmounted(() => {
  clearInterval(refreshTimer)
})
</script>

<style scoped>
.dashboard h2 { margin-bottom: 20px; font-size: 1.5rem; }

.toolbar {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 24px; flex-wrap: wrap; gap: 12px;
}
.toolbar-label {
  font-size: 0.8rem; color: #64748b; margin-right: 4px;
}
.time-filter, .refresh-filter {
  display: flex; gap: 6px; align-items: center;
}
.time-filter button, .refresh-filter button {
  padding: 6px 14px; border: 1px solid #334155; background: #1e293b;
  color: #94a3b8; border-radius: 6px; cursor: pointer; font-size: 0.85rem;
}
.time-filter button.active { background: #0ea5e9; color: #fff; border-color: #0ea5e9; }
.refresh-filter button.active { background: #8b5cf6; color: #fff; border-color: #8b5cf6; }

.stats-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;
}
.stat-card {
  background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155;
}
.stat-value { font-size: 2rem; font-weight: 700; color: #f1f5f9; }
.stat-label { font-size: 0.85rem; color: #64748b; margin-top: 4px; }
.stat-card.blocked .stat-value { color: #ef4444; }
.stat-card.allowed .stat-value { color: #22c55e; }
.stat-card.percent .stat-value { color: #f59e0b; }

.charts-row { margin-bottom: 24px; }
.chart-card {
  background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155;
}
.chart-card h3 { margin-bottom: 16px; font-size: 1rem; color: #94a3b8; }
.chart-container { height: 250px; }

.tables-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.table-card {
  background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155;
}
.table-card h3 { margin-bottom: 12px; font-size: 1rem; color: #94a3b8; }
table { width: 100%; }
tr { border-bottom: 1px solid #334155; }
td { padding: 8px 4px; font-size: 0.85rem; }
.domain { color: #e2e8f0; word-break: break-all; }
.count { text-align: right; color: #64748b; }
.empty { text-align: center; color: #475569; padding: 20px; }
.loading { text-align: center; padding: 40px; color: #64748b; }

/* System metrics */
.system-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;
}
.sys-card {
  background: var(--bg-card, #1e293b); border-radius: 12px; padding: 16px;
  border: 1px solid var(--border, #334155);
}
.sys-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.sys-title { color: var(--text-muted, #64748b); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }
.sys-value-big { color: var(--text-primary, #f1f5f9); font-size: 1.4rem; font-weight: 700; }
.sys-bar {
  height: 6px; background: rgba(100,116,139,0.2); border-radius: 3px; overflow: hidden; margin-bottom: 8px;
}
.sys-bar-fill { height: 100%; border-radius: 3px; transition: width 0.5s; }
.sys-bar-fill.bar-green { background: #22c55e; }
.sys-bar-fill.bar-yellow { background: #eab308; }
.sys-bar-fill.bar-red { background: #ef4444; }
.sys-detail { color: var(--text-muted, #64748b); font-size: 0.75rem; line-height: 1.5; }
</style>
