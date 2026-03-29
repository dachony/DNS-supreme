<template>
  <div class="settings-page">
    <h2>Settings</h2>

    <div class="tabs">
      <button v-for="t in settingsTabs" :key="t.id" :class="{ active: activeTab === t.id }" @click="activeTab = t.id" class="tab-btn">{{ t.label }}</button>
    </div>

    <!-- TAB: Server Identity -->
    <div v-if="activeTab === 'identity'" class="tab-content">
      <p class="section-desc">The hostname identifies this DNS Supreme instance (FQDN). It's used in SOA records and cluster communication.</p>
      <div class="settings-grid" style="margin-bottom: 12px">
        <div class="field">
          <label>Hostname (FQDN)</label>
          <input v-model="hostname" placeholder="ns1.example.com" />
        </div>
        <div class="field">
          <label>Primary Domain</label>
          <input v-model="primaryDomain" placeholder="example.com" />
        </div>
      </div>
      <p class="section-desc" style="font-size:0.75rem;margin-bottom:8px">Default: <code style="color:var(--accent)">dnssupreme.local</code>. When you change the primary domain, a zone is automatically created for it.</p>
      <button @click="saveIdentity" class="btn-primary">Save</button>
      <div v-if="hostnameMsg" class="msg-success">{{ hostnameMsg }}</div>
    </div>

    <!-- TAB: Clustering -->
    <div v-if="activeTab === 'cluster'" class="tab-content">
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

    <!-- TAB: DNS Services -->
    <div v-if="activeTab === 'dns'" class="tab-content">
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

    <!-- TAB: DNS Forwarders -->
    <div v-if="activeTab === 'forwarders'" class="tab-content">
      <div class="fw-split">
        <div class="fw-left">
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

          <h4 class="fw-presets-title">Add from known providers</h4>
          <div class="fw-presets-rows">
            <div v-for="p in upstreamProviders" :key="p.name" class="fw-preset-row">
              <div class="fw-preset-row-info">
                <span class="fw-preset-name">{{ p.name }}</span>
                <span class="fw-preset-privacy">{{ p.privacy }}</span>
              </div>
              <div class="fw-preset-protocols">
                <button v-for="proto in p.protocols" :key="proto.addr"
                  @click="addForwarderDirect(proto.addr)"
                  :disabled="isForwarderAdded(proto.addr)"
                  :class="{ added: isForwarderAdded(proto.addr) }"
                  class="fw-proto-btn" :title="proto.addr">
                  <span class="fw-proto-badge" :class="proto.type">{{ proto.label }}</span>
                </button>
              </div>
            </div>
          </div>

          <div class="add-row" style="margin-top: 12px">
            <input v-model="newForwarder" placeholder="Manual: tls://..., https://..., or IP:port" @keyup.enter="addForwarder" class="url-input" />
            <button @click="addForwarder" :disabled="!newForwarder" class="btn-primary">Add</button>
          </div>
        </div>

        <div class="fw-right">
          <h4>How DNS Forwarding Works</h4>
          <div class="fw-explainer">
            <div class="fw-explain-step">
              <span class="fw-explain-num">1</span>
              <div><strong>Client query</strong><br><span class="section-desc">A device on your network asks DNS Supreme to resolve a domain.</span></div>
            </div>
            <div class="fw-explain-step">
              <span class="fw-explain-num">2</span>
              <div><strong>Local check</strong><br><span class="section-desc">DNS Supreme checks local zones, cache, and filtering rules first.</span></div>
            </div>
            <div class="fw-explain-step">
              <span class="fw-explain-num">3</span>
              <div><strong>Forward upstream</strong><br><span class="section-desc">If not resolved locally, the query is forwarded to the first available upstream server.</span></div>
            </div>
            <div class="fw-explain-step">
              <span class="fw-explain-num">4</span>
              <div><strong>Cache &amp; respond</strong><br><span class="section-desc">The response is cached and returned to the client.</span></div>
            </div>
          </div>
          <div class="fw-proto-legend">
            <h4 style="margin-top:16px">Protocols</h4>
            <div class="fw-legend-item"><span class="fw-proto-badge dns">DNS</span> Standard, unencrypted (port 53)</div>
            <div class="fw-legend-item"><span class="fw-proto-badge dot">DoT</span> DNS-over-TLS — encrypted (port 853)</div>
            <div class="fw-legend-item"><span class="fw-proto-badge doh">DoH</span> DNS-over-HTTPS — encrypted, firewall-friendly</div>
            <div class="fw-legend-item"><span class="fw-proto-badge doq">DoQ</span> DNS-over-QUIC — fastest encrypted protocol</div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: Certificates -->
    <div v-if="activeTab === 'certs'" class="tab-content">
      <p class="section-desc">
        TLS certificates for DNS-over-TLS, DNS-over-HTTPS, and HTTPS block page.
      </p>

      <!-- Global / Server cert -->
      <div class="subsection">
        <h4>Server Certificate</h4>
        <p class="section-desc">Default certificate used for all protocols. Applied to all zones unless overridden.</p>

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

      <!-- Cert key upload modal -->
      <div v-if="certUploadShow" class="modal-overlay" @click.self="certUploadShow = false">
        <div class="edit-modal">
          <h3>Upload Private Key</h3>
          <p class="section-desc">Paste the PEM-encoded private key content for the certificate you just selected.</p>
          <div class="field">
            <label>Private Key (PEM)</label>
            <textarea v-model="certUploadKeyText" class="code-editor" rows="8" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"></textarea>
          </div>
          <div class="section-actions" style="margin-top:12px">
            <button @click="submitCertUpload" :disabled="!certUploadKeyText" class="btn-primary">Upload</button>
            <button @click="certUploadShow = false" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>

      <!-- Export -->
      <div class="cert-export" v-if="certInfo">
        <h4 style="margin-top:16px">Export Certificate</h4>
        <p class="section-desc">Download the CA certificate to distribute to clients. Install it as a trusted root CA so browsers and devices trust your self-signed HTTPS connections.</p>
        <div class="section-actions">
          <button @click="exportCert('pem')" class="btn-secondary">Download CA Certificate (.pem)</button>
          <button @click="exportCert('der')" class="btn-secondary">Download CA Certificate (.crt / DER)</button>
        </div>
        <div class="cert-install-hints">
          <details>
            <summary>How to install on clients</summary>
            <div class="cert-hint-content">
              <p><strong>Windows:</strong> Double-click the .crt file, select "Install Certificate", choose "Local Machine" > "Trusted Root Certification Authorities".</p>
              <p><strong>macOS:</strong> Double-click the .pem file, add to Keychain, then in Keychain Access set it to "Always Trust".</p>
              <p><strong>Linux:</strong> Copy .pem to <code>/usr/local/share/ca-certificates/</code> and run <code>update-ca-certificates</code>.</p>
              <p><strong>iOS:</strong> Email or host the .pem file, open on device, install profile in Settings > General > Profiles, then enable in Settings > General > About > Certificate Trust Settings.</p>
              <p><strong>Android:</strong> Settings > Security > Install from storage, select the .pem file.</p>
              <p><strong>Group Policy (Windows domain):</strong> Distribute via GPO under Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root CAs.</p>
            </div>
          </details>
        </div>
      </div>
      </div>

      <!-- Per-zone certificates -->
      <div class="subsection" style="margin-top:20px">
        <h4>Zone Certificates</h4>
        <p class="section-desc">Generate or upload TLS certificates per domain. Useful for DoH and HTTPS block pages with proper domain names.</p>
        <div v-if="certZones.length" class="cert-zones-list">
          <div v-for="z in certZones" :key="z.name" class="cert-zone-row">
            <div class="cert-zone-info">
              <span class="cert-zone-name">{{ z.name }}</span>
              <span v-if="z.has_cert" class="cert-zone-status has">Certificate installed</span>
              <span v-else class="cert-zone-status none">No certificate</span>
            </div>
            <div class="cert-zone-actions">
              <button @click="generateZoneCert(z.name)" class="btn-sm">Generate</button>
              <button v-if="z.has_cert" @click="exportCert('pem', z.name)" class="btn-sm">Export</button>
            </div>
          </div>
        </div>
        <div v-else class="empty-small">No zones configured. Create zones first in DNS Zones.</div>
      </div>

      <!-- ACME / Let's Encrypt -->
      <div class="subsection" style="margin-top:20px">
        <h4>Automatic Certificates (ACME)</h4>
        <p class="section-desc">Automatically obtain and renew trusted certificates from Let's Encrypt or another ACME provider. Requires port 80 or DNS-01 challenge access.</p>
        <div class="settings-grid" style="margin-bottom:12px">
          <div class="field">
            <label>ACME Provider</label>
            <select v-model="acmeProvider">
              <option value="letsencrypt">Let's Encrypt</option>
              <option value="letsencrypt-staging">Let's Encrypt (Staging)</option>
              <option value="zerossl">ZeroSSL</option>
              <option value="custom">Custom ACME URL</option>
            </select>
          </div>
          <div class="field">
            <label>Email (required for ACME)</label>
            <input v-model="acmeEmail" placeholder="admin@example.com" />
          </div>
          <div class="field" v-if="acmeProvider === 'custom'">
            <label>ACME Directory URL</label>
            <input v-model="acmeUrl" placeholder="https://acme.provider.com/directory" />
          </div>
          <div class="field">
            <label>Challenge Type</label>
            <select v-model="acmeChallenge">
              <option value="dns-01">DNS-01 (recommended — uses DNS Supreme as solver)</option>
              <option value="http-01">HTTP-01 (requires port 80 access)</option>
            </select>
          </div>
        </div>
        <p class="section-desc" style="font-size:0.75rem">DNS-01 is recommended because DNS Supreme can automatically solve the challenge using its own zones. HTTP-01 requires port 80 to be accessible from the internet.</p>
        <div class="section-actions">
          <button @click="saveAcme" class="btn-primary">Save ACME Settings</button>
          <button @click="requestAcmeCert" :disabled="!acmeEmail" class="btn-secondary">Request Certificate Now</button>
        </div>
        <div v-if="acmeMsg" class="msg-success">{{ acmeMsg }}</div>
      </div>
    </div>

    <!-- TAB: Block Page -->
    <div v-if="activeTab === 'blockpage'" class="tab-content">
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

    <!-- TAB: Log Management -->
    <div v-if="activeTab === 'logs'" class="tab-content">
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

    <!-- TAB: Mail -->
    <div v-if="activeTab === 'mail'" class="tab-content">
      <p class="section-desc">Configure SMTP server for sending email notifications (alerts, reports, password resets).</p>

      <div class="settings-grid">
        <div class="field">
          <label>SMTP Server</label>
          <input v-model="mailSettings.host" placeholder="smtp.example.com" />
        </div>
        <div class="field">
          <label>Port</label>
          <input v-model.number="mailSettings.port" type="number" placeholder="587" />
        </div>
        <div class="field">
          <label>Username</label>
          <input v-model="mailSettings.username" placeholder="user@example.com" />
        </div>
        <div class="field">
          <label>Password</label>
          <input v-model="mailSettings.password" type="password" placeholder="App password or SMTP password" />
        </div>
        <div class="field">
          <label>From Address</label>
          <input v-model="mailSettings.from" placeholder="dns-supreme@example.com" />
        </div>
        <div class="field">
          <label>From Name</label>
          <input v-model="mailSettings.fromName" placeholder="DNS Supreme" />
        </div>
        <div class="field">
          <label>Encryption</label>
          <select v-model="mailSettings.encryption">
            <option value="starttls">STARTTLS (port 587)</option>
            <option value="ssl">SSL/TLS (port 465)</option>
            <option value="none">None (port 25)</option>
          </select>
        </div>
      </div>

      <div class="section-actions" style="margin-top:16px">
        <button @click="saveMailSettings" class="btn-primary">Save</button>
        <button @click="testMail" :disabled="!mailSettings.host || !mailSettings.from" class="btn-secondary">Send Test Email</button>
      </div>
      <div v-if="mailMsg" class="msg-success">{{ mailMsg }}</div>

      <div class="subsection" style="margin-top:24px">
        <h4>Email Notifications</h4>
        <p class="section-desc">Choose which events trigger email notifications.</p>
        <div class="mail-notif-list">
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.securityAlerts" /> Security alerts (failed logins, new admin users)</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.dailyReport" /> Daily summary report</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.weeklyReport" /> Weekly summary report</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.certExpiry" /> Certificate expiry warnings (30 days before)</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.feedErrors" /> Blocklist/feed update errors</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.highBlockRate" /> High block rate alerts (>90%)</label>
        </div>
        <button @click="saveMailSettings" class="btn-primary" style="margin-top:12px">Save Notifications</button>
      </div>
    </div>

    <!-- TAB: Users & Security -->
    <div v-if="activeTab === 'users'" class="tab-content">
      <div class="users-split">
        <!-- Left: Users -->
        <div class="users-left">
          <h4>Create User</h4>
          <form class="user-form" @submit.prevent="createUser">
            <input v-model="userForm.username" placeholder="Username" required />
            <input v-model="userForm.password" type="password" placeholder="Password" required />
            <input v-model="userForm.first_name" placeholder="First Name" />
            <input v-model="userForm.last_name" placeholder="Last Name" />
            <input v-model="userForm.email" type="email" placeholder="Email" />
            <select v-model="userForm.role">
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
            <button type="submit" class="btn-primary">Create</button>
          </form>
          <div v-if="userFormError" class="error-msg" style="margin-top:8px">{{ userFormError }}</div>
          <div v-if="userFormSuccess" class="msg-success">{{ userFormSuccess }}</div>

          <h4 style="margin-top:20px">Users</h4>
          <table>
            <thead>
              <tr><th>Username</th><th>Name</th><th>Role</th><th>MFA</th><th>Actions</th></tr>
            </thead>
            <tbody>
              <tr v-for="u in users" :key="u.id">
                <td class="username">{{ u.username }}</td>
                <td>{{ u.first_name }} {{ u.last_name }}</td>
                <td><span class="user-badge" :class="u.role">{{ u.role }}</span></td>
                <td>
                  <span v-if="u.mfa_enabled" class="mfa-on">TOTP</span>
                  <button v-else @click="setupUserMFA(u)" class="btn-sm">Enable</button>
                </td>
                <td class="actions">
                  <button @click="editUser(u)" class="btn-sm">Edit</button>
                  <button @click="openResetPw(u)" class="btn-sm warn">Reset PW</button>
                  <button v-if="u.mfa_enabled" @click="disableUserMFA(u)" class="btn-sm">Disable MFA</button>
                  <button @click="deleteUser(u)" class="btn-sm danger" v-if="u.username !== currentUsername">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Right: Security -->
        <div class="users-right">
          <!-- Fail2Ban -->
          <div class="security-card">
            <div class="security-card-header">
              <h4>Fail2Ban</h4>
              <div class="toggle" :class="{ on: f2bSettings.enabled }" @click="toggleFail2Ban"><div class="toggle-knob"></div></div>
            </div>
            <p class="section-desc">Automatically block IPs after repeated failed login attempts.</p>
            <div class="settings-grid" style="margin-bottom:12px">
              <div class="field">
                <label>Max retries</label>
                <input v-model.number="f2bSettings.max_retries" type="number" min="1" @change="saveFail2Ban" />
              </div>
              <div class="field">
                <label>Ban duration (minutes)</label>
                <input v-model.number="f2bBanMinutes" type="number" min="1" @change="saveFail2Ban" />
              </div>
            </div>

            <div v-if="f2bBanned.length" class="f2b-banned">
              <h4>Blocked IPs <span class="f2b-count">{{ f2bBanned.length }}</span></h4>
              <div v-for="b in f2bBanned" :key="b.ip" class="f2b-row">
                <div class="f2b-row-info">
                  <span class="f2b-ip">{{ b.ip }}</span>
                  <span class="f2b-detail">{{ b.attempts }} attempts &middot; expires {{ formatRelative(b.expires_at) }}</span>
                </div>
                <button @click="unbanIP(b.ip)" class="btn-sm">Unban</button>
              </div>
            </div>
            <div v-else class="empty-small">No blocked IPs</div>
          </div>

          <!-- Access Control -->
          <div class="security-card" style="margin-top:16px">
            <h4>Access Control</h4>
            <p class="section-desc">Restrict management panel access to specific IP addresses. Leave empty to allow all.</p>
            <div class="add-row" style="margin-bottom:8px">
              <input v-model="newAllowedIP" placeholder="IP address (e.g. 192.168.1.0/24)" @keyup.enter="addAllowedIP" />
              <button @click="addAllowedIP" :disabled="!newAllowedIP" class="btn-primary">Add</button>
            </div>
            <div class="f2b-banned" v-if="allowedIPs.length">
              <div v-for="ip in allowedIPs" :key="ip" class="f2b-row">
                <span class="f2b-ip">{{ ip }}</span>
                <button @click="removeAllowedIP(ip)" class="btn-sm danger">Remove</button>
              </div>
            </div>
            <div v-else class="empty-small">No restrictions — all IPs can access the panel</div>
          </div>

          <!-- MFA Method -->
          <div class="security-card" style="margin-top:16px">
            <h4>MFA Methods</h4>
            <p class="section-desc">Available multi-factor authentication methods for users.</p>
            <label class="checkbox-label"><input type="checkbox" checked disabled /> TOTP (Authenticator app)</label>
            <label class="checkbox-label"><input type="checkbox" v-model="mfaEmailEnabled" /> Email code (requires SMTP configured in Mail tab)</label>
          </div>
        </div>
      </div>

      <!-- Modals (same as before) -->
      <div v-if="resetPwUser" class="modal-overlay" @click.self="resetPwUser = null">
        <div class="edit-modal">
          <h3>Reset Password: {{ resetPwUser.username }}</h3>
          <div class="field"><label>New Password</label><input v-model="resetPwValue" type="password" placeholder="Enter new password" /></div>
          <div class="field"><label>Confirm Password</label><input v-model="resetPwConfirm" type="password" placeholder="Confirm password" /></div>
          <div v-if="resetPwError" class="error-msg" style="margin-top:8px">{{ resetPwError }}</div>
          <div class="section-actions" style="margin-top:16px">
            <button @click="submitResetPw" :disabled="!resetPwValue || resetPwValue !== resetPwConfirm" class="btn-primary">Reset Password</button>
            <button @click="resetPwUser = null" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>

      <div v-if="mfaSetupUser" class="modal-overlay" @click.self="mfaSetupUser = null">
        <div class="edit-modal">
          <h3>Setup TOTP: {{ mfaSetupUser.username }}</h3>
          <div v-if="mfaSetup">
            <p class="section-desc">Scan with authenticator app or enter secret manually:</p>
            <div class="mfa-secret">{{ mfaSetup.secret }}</div>
            <p class="mfa-uri">{{ mfaSetup.uri }}</p>
            <form @submit.prevent="enableMFA" class="mfa-verify">
              <input v-model="mfaVerifyCode" placeholder="6-digit code" maxlength="6" />
              <button type="submit" class="btn-primary">Enable</button>
            </form>
            <div v-if="mfaError" class="error-msg" style="margin-top:8px">{{ mfaError }}</div>
          </div>
        </div>
      </div>

      <div v-if="editingUser" class="modal-overlay" @click.self="editingUser = null">
        <div class="edit-modal">
          <h3>Edit: {{ editingUser.username }}</h3>
          <form @submit.prevent="saveUserEdit">
            <div class="field"><label>First Name</label><input v-model="editingUser.first_name" /></div>
            <div class="field"><label>Last Name</label><input v-model="editingUser.last_name" /></div>
            <div class="field"><label>Email</label><input v-model="editingUser.email" type="email" /></div>
            <div class="field"><label>Role</label>
              <select v-model="editingUser.role"><option value="viewer">Viewer</option><option value="admin">Admin</option></select>
            </div>
            <div class="section-actions" style="margin-top:16px">
              <button type="submit" class="btn-primary">Save</button>
              <button type="button" @click="editingUser = null" class="btn-secondary">Cancel</button>
            </div>
          </form>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, inject, onMounted } from 'vue'
import axios from 'axios'
import { currentUser } from '../auth'

const confirm = inject('confirm') as (opts: any) => Promise<boolean>

// --- Tabs ---
const activeTab = ref('identity')
const settingsTabs = [
  { id: 'identity', label: 'Server Identity' },
  { id: 'cluster', label: 'Clustering' },
  { id: 'dns', label: 'DNS Services' },
  { id: 'forwarders', label: 'Forwarders' },
  { id: 'certs', label: 'Certificates' },
  { id: 'blockpage', label: 'Block Page' },
  { id: 'logs', label: 'Log Management' },
  { id: 'mail', label: 'Mail' },
  { id: 'users', label: 'Users' },
]

// --- Users ---
const users = ref<any[]>([])
const myUser = ref<any>(null)
const editingUser = ref<any>(null)
const mfaSetup = ref<any>(null)
const mfaSetupUser = ref<any>(null)
const mfaVerifyCode = ref('')
const mfaError = ref('')
const userFormError = ref('')
const userFormSuccess = ref('')
const currentUsername = currentUser.value?.username || ''
const resetPwUser = ref<any>(null)
const resetPwValue = ref('')
const resetPwConfirm = ref('')
const resetPwError = ref('')

const userForm = ref({ username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer' })

// --- Fail2Ban & Access Control ---
const f2bSettings = ref({ enabled: true, max_retries: 5, ban_seconds: 900 })
const f2bBanMinutes = ref(15)
const f2bBanned = ref<any[]>([])
const allowedIPs = ref<string[]>([])
const newAllowedIP = ref('')
const mfaEmailEnabled = ref(false)

async function loadFail2Ban() {
  try {
    const { data } = await axios.get('/api/fail2ban')
    f2bSettings.value = data.settings
    f2bBanMinutes.value = Math.round((data.settings.ban_seconds || 900) / 60)
    f2bBanned.value = data.banned || []
    allowedIPs.value = data.allowed_ips || []
  } catch {}
}

function toggleFail2Ban() {
  f2bSettings.value.enabled = !f2bSettings.value.enabled
  saveFail2Ban()
}

async function saveFail2Ban() {
  await axios.put('/api/fail2ban/settings', {
    enabled: f2bSettings.value.enabled,
    max_retries: f2bSettings.value.max_retries,
    ban_seconds: f2bBanMinutes.value * 60,
  })
}

async function unbanIP(ip: string) {
  await axios.delete(`/api/fail2ban/unban/${ip}`)
  loadFail2Ban()
}

async function addAllowedIP() {
  if (!newAllowedIP.value) return
  const updated = [...allowedIPs.value, newAllowedIP.value.trim()]
  await axios.put('/api/fail2ban/allowed-ips', { ips: updated })
  newAllowedIP.value = ''
  loadFail2Ban()
}

async function removeAllowedIP(ip: string) {
  const updated = allowedIPs.value.filter(i => i !== ip)
  await axios.put('/api/fail2ban/allowed-ips', { ips: updated })
  loadFail2Ban()
}

function formatRelative(d: string): string {
  const ms = new Date(d).getTime() - Date.now()
  if (ms <= 0) return 'expired'
  const min = Math.round(ms / 60000)
  return min > 60 ? `${Math.round(min/60)}h ${min%60}m` : `${min}m`
}

async function loadUsers() {
  try { const { data } = await axios.get('/api/users'); users.value = data } catch {}
}
async function loadMe() {
  try { const { data } = await axios.get('/api/auth/me'); myUser.value = data } catch {}
}
async function createUser() {
  userFormError.value = ''; userFormSuccess.value = ''
  try {
    await axios.post('/api/users', userForm.value)
    userFormSuccess.value = `User '${userForm.value.username}' created`
    userForm.value = { username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer' }
    loadUsers()
  } catch (e: any) { userFormError.value = e.response?.data?.error || 'Failed' }
}
function editUser(u: any) { editingUser.value = { ...u } }
async function saveUserEdit() {
  await axios.put(`/api/users/${editingUser.value.id}`, editingUser.value)
  editingUser.value = null; loadUsers()
}

// Reset password modal
function openResetPw(u: any) {
  resetPwUser.value = u
  resetPwValue.value = ''
  resetPwConfirm.value = ''
  resetPwError.value = ''
}
async function submitResetPw() {
  if (resetPwValue.value !== resetPwConfirm.value) {
    resetPwError.value = 'Passwords do not match'; return
  }
  try {
    await axios.put(`/api/users/${resetPwUser.value.id}/password`, { new_password: resetPwValue.value })
    resetPwUser.value = null
  } catch (e: any) { resetPwError.value = e.response?.data?.error || 'Failed' }
}

async function deleteUser(u: any) {
  if (!await confirm({ title: 'Delete User', message: `Delete user "${u.username}"?`, confirmText: 'Delete', danger: true })) return
  await axios.delete(`/api/users/${u.id}`); loadUsers()
}

// Per-user MFA
async function setupUserMFA(u: any) {
  mfaSetupUser.value = u
  mfaSetup.value = null
  mfaVerifyCode.value = ''
  mfaError.value = ''
  try {
    const { data } = await axios.post('/api/auth/mfa/setup')
    mfaSetup.value = data
  } catch {}
}
async function enableMFA() {
  mfaError.value = ''
  try {
    await axios.post('/api/auth/mfa/enable', { code: mfaVerifyCode.value })
    mfaSetup.value = null; mfaSetupUser.value = null; mfaVerifyCode.value = ''
    loadUsers(); loadMe()
  } catch (e: any) { mfaError.value = e.response?.data?.error || 'Invalid code' }
}
async function disableUserMFA(u: any) {
  if (!await confirm({ title: 'Disable MFA', message: `Disable TOTP for "${u.username}"?`, confirmText: 'Disable', danger: true })) return
  await axios.delete('/api/auth/mfa')
  loadUsers(); loadMe()
}

// --- State ---
const hostname = ref('ns1.dnssupreme.local')
const primaryDomain = ref('dnssupreme.local')
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

const upstreamProviders = [
  {
    name: 'Cloudflare', privacy: 'No logging',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '1.1.1.1:53' },
      { label: 'DNS', type: 'dns', addr: '1.0.0.1:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://1dot1dot1dot1.cloudflare-dns.com' },
      { label: 'DoH', type: 'doh', addr: 'https://cloudflare-dns.com/dns-query' },
    ]
  },
  {
    name: 'Google', privacy: 'Logged 24-48h',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '8.8.8.8:53' },
      { label: 'DNS', type: 'dns', addr: '8.8.4.4:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.google' },
      { label: 'DoH', type: 'doh', addr: 'https://dns.google/dns-query' },
    ]
  },
  {
    name: 'Quad9', privacy: 'No logging, malware blocking',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '9.9.9.9:53' },
      { label: 'DNS', type: 'dns', addr: '149.112.112.112:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.quad9.net' },
      { label: 'DoH', type: 'doh', addr: 'https://dns.quad9.net/dns-query' },
    ]
  },
  {
    name: 'AdGuard DNS', privacy: 'No logging, ad blocking',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '94.140.14.14:53' },
      { label: 'DNS', type: 'dns', addr: '94.140.15.15:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.adguard-dns.com' },
      { label: 'DoH', type: 'doh', addr: 'https://dns.adguard-dns.com/dns-query' },
      { label: 'DoQ', type: 'doq', addr: 'quic://dns.adguard-dns.com' },
    ]
  },
  {
    name: 'OpenDNS (Cisco)', privacy: 'Logged',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '208.67.222.222:53' },
      { label: 'DNS', type: 'dns', addr: '208.67.220.220:53' },
      { label: 'DoH', type: 'doh', addr: 'https://doh.opendns.com/dns-query' },
    ]
  },
  {
    name: 'Mullvad', privacy: 'No logging, privacy-focused',
    protocols: [
      { label: 'DoH', type: 'doh', addr: 'https://dns.mullvad.net/dns-query' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.mullvad.net' },
    ]
  },
  {
    name: 'NextDNS', privacy: 'Configurable logging',
    protocols: [
      { label: 'DoH', type: 'doh', addr: 'https://dns.nextdns.io' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.nextdns.io' },
      { label: 'DoQ', type: 'doq', addr: 'quic://dns.nextdns.io' },
    ]
  },
  {
    name: 'Control D', privacy: 'Configurable',
    protocols: [
      { label: 'DoH', type: 'doh', addr: 'https://freedns.controld.com/p0' },
      { label: 'DoT', type: 'dot', addr: 'tls://p0.freedns.controld.com' },
      { label: 'DoQ', type: 'doq', addr: 'quic://p0.freedns.controld.com' },
    ]
  },
]

function isForwarderAdded(addr: string): boolean {
  return forwarders.value.some((f: any) => f.address === addr)
}

async function addForwarderDirect(addr: string) {
  if (isForwarderAdded(addr)) return
  const current = forwarders.value.map((f: any) => f.address)
  current.push(addr)
  await axios.put('/api/settings/forwarders', { forwarders: current })
  loadAll()
}

const dnssecKeys = ref<any[]>([])
const dnssecZone = ref('')

// --- Mail ---
const mailSettings = ref({
  host: '', port: 587, username: '', password: '',
  from: '', fromName: 'DNS Supreme', encryption: 'starttls'
})
const mailNotifs = ref({
  securityAlerts: true, dailyReport: false, weeklyReport: false,
  certExpiry: true, feedErrors: true, highBlockRate: false
})
const mailMsg = ref('')

async function loadMailSettings() {
  try {
    const [cfg, notif] = await Promise.all([
      axios.get('/api/mail/settings'),
      axios.get('/api/mail/notifications'),
    ])
    if (cfg.data.host) mailSettings.value = cfg.data
    mailNotifs.value = { ...mailNotifs.value, ...notif.data }
  } catch {}
}

async function saveMailSettings() {
  mailMsg.value = ''
  try {
    await axios.put('/api/mail/settings', mailSettings.value)
    await axios.put('/api/mail/notifications', mailNotifs.value)
    mailMsg.value = 'Mail settings saved'
    setTimeout(() => mailMsg.value = '', 3000)
  } catch (e: any) {
    mailMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

async function testMail() {
  mailMsg.value = ''
  try {
    const { data } = await axios.post('/api/mail/test', { to: mailSettings.value.from })
    mailMsg.value = `Test email sent to ${data.sent_to}`
    setTimeout(() => mailMsg.value = '', 5000)
  } catch (e: any) {
    mailMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

const certInfo = ref<any>(null)
const certMsg = ref('')
const acmeProvider = ref('letsencrypt')
const acmeEmail = ref('')
const acmeUrl = ref('')
const acmeChallenge = ref('dns-01')
const acmeMsg = ref('')

function exportCert(format: string, domain?: string) {
  const params = new URLSearchParams({ format })
  if (domain) params.set('domain', domain)
  window.open(`/api/certs/export?${params}`, '_blank')
}

async function loadAcmeConfig() {
  try {
    const { data } = await axios.get('/api/acme/config')
    if (data.provider) acmeProvider.value = data.provider
    if (data.email) acmeEmail.value = data.email
    if (data.url) acmeUrl.value = data.url
    if (data.challenge) acmeChallenge.value = data.challenge
  } catch {}
}

async function saveAcme() {
  acmeMsg.value = ''
  try {
    await axios.put('/api/acme/config', {
      provider: acmeProvider.value, email: acmeEmail.value,
      url: acmeUrl.value, challenge: acmeChallenge.value,
    })
    acmeMsg.value = 'ACME settings saved'
    setTimeout(() => acmeMsg.value = '', 3000)
  } catch (e: any) { acmeMsg.value = 'Failed: ' + (e.response?.data?.error || e.message) }
}

async function requestAcmeCert() {
  acmeMsg.value = 'Requesting certificate...'
  try {
    const domain = primaryDomain.value || 'dnssupreme.local'
    await axios.post('/api/acme/request', { domain })
    acmeMsg.value = `Certificate request started for ${domain}. This may take a minute.`
    setTimeout(() => acmeMsg.value = '', 10000)
  } catch (e: any) { acmeMsg.value = 'Failed: ' + (e.response?.data?.error || e.message) }
}
const certZones = ref<any[]>([])

async function loadCertZones() {
  try {
    const { data } = await axios.get('/api/zones')
    certZones.value = (data || []).map((z: any) => ({ name: z.name, has_cert: false }))
  } catch {}
}

async function generateZoneCert(zoneName: string) {
  certMsg.value = ''
  try {
    const { data } = await axios.post('/api/certs/generate', { domain: zoneName })
    certMsg.value = data.message || `Certificate generated for ${zoneName}`
    loadCertZones()
  } catch (e: any) {
    certMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

const blockPageHTML = ref('')
const bpMsg = ref('')

const logRetention = ref({ days: 30, autoCleanup: true })
const logStats = ref<any>(null)
const logMsg = ref('')


// --- Load ---
async function loadAll() {
  const [fw, dk, certs, bp, ss, hn, pd, cl, ls, lr] = await Promise.all([
    axios.get('/api/settings/forwarders'),
    axios.get('/api/dnssec'),
    axios.get('/api/certs'),
    axios.get('/api/settings/blockpage'),
    axios.get('/api/settings/server'),
    axios.get('/api/settings/hostname'),
    axios.get('/api/settings/primary-domain'),
    axios.get('/api/settings/cluster'),
    axios.get('/api/log-management/stats'),
    axios.get('/api/log-management/settings'),
  ])
  forwarders.value = fw.data || []
  dnssecKeys.value = dk.data || []
  certInfo.value = certs.data
  blockPageHTML.value = bp.data.html || ''
  hostname.value = hn.data.hostname || 'ns1.dnssupreme.local'
  primaryDomain.value = pd.data.domain || 'dnssupreme.local'
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

async function saveIdentity() {
  hostnameMsg.value = ''
  await Promise.all([
    axios.put('/api/settings/hostname', { hostname: hostname.value }),
    axios.put('/api/settings/primary-domain', { domain: primaryDomain.value }),
  ])
  hostnameMsg.value = 'Identity saved. Zone auto-created if new.'
  setTimeout(() => hostnameMsg.value = '', 4000)
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
  // Use retention days as default
  const d = logRetention.value.days
  if (!await confirm({ title: 'Delete Old Logs', message: `Delete all query logs older than ${d} days?`, confirmText: 'Delete', danger: true })) return
  const { data } = await axios.delete(`/api/log-management/older-than?days=${d}`)
  logMsg.value = `Deleted ${data.deleted?.toLocaleString()} log entries`
  loadAll()
  setTimeout(() => logMsg.value = '', 5000)
}

async function deleteAllLogs() {
  if (!await confirm({ title: 'Delete All Logs', message: 'Delete ALL query logs? All log data will be permanently deleted. This cannot be undone.', confirmText: 'Delete All', danger: true })) return
  const { data } = await axios.delete('/api/log-management/all')
  logMsg.value = `Deleted ${data.deleted?.toLocaleString()} log entries`
  loadAll()
  setTimeout(() => logMsg.value = '', 5000)
}

// --- Forwarders ---
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
  if (!await confirm({ title: 'Remove DNSSEC Key', message: `Remove DNSSEC key for ${zone}? This will disable zone signing.`, confirmText: 'Remove', danger: true })) return
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
  // Store cert file, prompt for key file next
  certUploadCert.value = certFile
  certUploadShow.value = true
}

const certUploadShow = ref(false)
const certUploadCert = ref<File | null>(null)
const certUploadKeyText = ref('')

async function submitCertUpload() {
  if (!certUploadCert.value || !certUploadKeyText.value) return
  const formData = new FormData()
  formData.append('cert', certUploadCert.value)
  formData.append('key', new Blob([certUploadKeyText.value], { type: 'text/plain' }), 'server.key')
  certMsg.value = ''
  try {
    const { data } = await axios.post('/api/certs/upload', formData)
    certMsg.value = data.message
    certUploadShow.value = false
    certUploadKeyText.value = ''
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

onMounted(() => { loadAll(); loadUsers(); loadMe(); loadCertZones(); loadFail2Ban(); loadMailSettings(); loadAcmeConfig() })
</script>

<style scoped>
.settings-page h2 { margin-bottom: 16px; font-size: 1.5rem; }

/* Tabs */
.tabs {
  display: flex; gap: 2px; margin-bottom: 20px; background: var(--bg-card);
  border-radius: 10px; padding: 4px; border: 1px solid var(--border); flex-wrap: wrap;
}
.tab-btn {
  padding: 8px 14px; background: transparent; border: none;
  color: var(--text-secondary); border-radius: 8px; cursor: pointer;
  font-size: 0.82rem; font-weight: 500; transition: all 0.15s; white-space: nowrap;
}
.tab-btn:hover { color: var(--text-primary); background: var(--bg-hover); }
.tab-btn.active { background: var(--accent); color: #fff; }
.tab-content { animation: fadeIn 0.15s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

/* Users */
.user-form { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end; }
.user-form input, .user-form select {
  padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; flex: 1; min-width: 120px;
}
.user-form input::placeholder { color: var(--text-dim); }
.username { font-weight: 600; color: var(--text-primary); }
.time { color: var(--text-muted); font-size: 0.8rem; white-space: nowrap; }
.actions { display: flex; gap: 6px; }
.btn-sm { padding: 4px 10px; background: var(--bg-hover); border: none; color: var(--text-secondary); border-radius: 4px; cursor: pointer; font-size: 0.8rem; transition: all 0.15s; }
.btn-sm:hover { color: var(--text-primary); }
.btn-sm.warn { color: #f59e0b; }
.btn-sm.warn:hover { background: rgba(245,158,11,0.15); }
.btn-sm.danger { color: #ef4444; }
.btn-sm.danger:hover { background: rgba(239,68,68,0.15); }
.user-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.user-badge.admin { background: rgba(139,92,246,0.15); color: #8b5cf6; }
.user-badge.viewer { background: rgba(34,197,94,0.15); color: #22c55e; }
.mfa-on { color: #22c55e; font-weight: 600; font-size: 0.85rem; }
.mfa-off { color: var(--text-muted); font-size: 0.85rem; }
.mfa-status { display: flex; align-items: center; gap: 16px; }
.mfa-setup p { margin-bottom: 8px; }
.mfa-secret { font-family: monospace; font-size: 1.1rem; color: #f59e0b; background: var(--bg-input); padding: 12px; border-radius: 8px; margin-bottom: 8px; word-break: break-all; }
.mfa-uri { font-size: 0.75rem; color: var(--text-dim); word-break: break-all; margin-bottom: 12px; }
.mfa-verify { display: flex; gap: 8px; }
.mfa-verify input { padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); font-size: 1rem; width: 160px; }
.error-msg { background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444; padding: 8px 12px; border-radius: 6px; font-size: 0.85rem; }
.edit-modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 24px; width: 420px; max-width: 90vw; box-shadow: 0 16px 48px rgba(0,0,0,0.3); }
.edit-modal h3 { color: var(--text-primary); margin-bottom: 16px; }

/* Users split */
.users-split { display: grid; grid-template-columns: 3fr 2fr; gap: 20px; align-items: start; }
.users-left { min-width: 0; }
.users-right { display: flex; flex-direction: column; gap: 0; position: sticky; top: 20px; }

.security-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px;
}
.security-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
.security-card h4 { color: var(--text-primary); font-size: 0.95rem; margin: 0; }

.f2b-banned { margin-top: 8px; }
.f2b-banned h4 { font-size: 0.85rem; color: var(--text-primary); margin-bottom: 6px; }
.f2b-count { font-size: 0.72rem; background: rgba(239,68,68,0.15); color: #ef4444; padding: 1px 6px; border-radius: 8px; margin-left: 4px; }
.f2b-row {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 6px 10px; background: var(--bg-input); border-radius: 6px; margin-bottom: 4px;
}
.f2b-ip { color: var(--text-primary); font-family: monospace; font-size: 0.85rem; }
.f2b-row-info { display: flex; flex-direction: column; }
.f2b-detail { color: var(--text-dim); font-size: 0.72rem; }
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100; }

.section {
  background: var(--bg-card); border-radius: 12px; padding: 24px;
  border: 1px solid var(--border); margin-bottom: 20px;
}
.section h3 { color: var(--text-primary); font-size: 1.05rem; margin-bottom: 4px; }
.section-desc { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 16px; line-height: 1.5; }
.section-desc code { color: #f59e0b; background: var(--bg-input); padding: 2px 6px; border-radius: 3px; font-size: 0.8rem; }

/* Shared components */
.add-row { display: flex; gap: 8px; flex-wrap: wrap; }
.add-row input, .add-row select {
  padding: 9px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.9rem; flex: 1; min-width: 150px;
  transition: border-color 0.15s;
}
.add-row input::placeholder { color: var(--text-dim); }

.btn-primary { padding: 9px 20px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8)); color: #fff; border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; white-space: nowrap; transition: all 0.15s; }
.btn-primary:hover { opacity: 0.9; }
.btn-primary:disabled { opacity: 0.3; cursor: not-allowed; }
.btn-secondary, .upload-btn { padding: 9px 20px; background: var(--bg-hover); color: var(--text-secondary); border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; transition: all 0.15s; }
.btn-secondary:hover, .upload-btn:hover { color: var(--text-primary); }
.btn-text { padding: 9px 16px; background: none; color: var(--text-muted); border: none; cursor: pointer; font-size: 0.85rem; transition: color 0.15s; }
.btn-text:hover { color: var(--text-secondary); }
.btn-text-danger { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 0.8rem; padding: 4px 0; transition: opacity 0.15s; }
.btn-text-danger:hover { opacity: 0.8; }
.btn-copy { padding: 2px 8px; background: var(--bg-hover); color: var(--text-secondary); border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem; transition: color 0.15s; }
.btn-copy:hover { color: var(--text-primary); }

.section-actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.msg-success { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: #22c55e; padding: 8px 14px; border-radius: 8px; margin-top: 12px; font-size: 0.85rem; }
.empty-small { padding: 16px; text-align: center; color: var(--text-dim); font-size: 0.85rem; }

.detail-row { display: flex; align-items: flex-start; gap: 12px; padding: 6px 0; flex-wrap: wrap; }
.detail-label { color: var(--text-muted); font-size: 0.8rem; min-width: 100px; padding-top: 2px; }
.detail-value { color: var(--text-primary); font-size: 0.85rem; flex: 1; }
.detail-value.mono { font-family: monospace; }
.detail-value.small { font-size: 0.75rem; color: var(--text-secondary); word-break: break-all; }

/* Forwarders */
.forwarders-list { margin-bottom: 12px; }
.forwarder-item {
  display: flex; align-items: center; gap: 12px; padding: 10px 12px;
  background: var(--bg-input); border-radius: 8px; margin-bottom: 6px;
  transition: background 0.15s;
}
.forwarder-num { width: 24px; height: 24px; background: var(--bg-hover); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; color: var(--text-secondary); font-weight: 600; }

/* Forwarders split layout */
.fw-split { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; align-items: start; }
.fw-left { min-width: 0; }
.fw-right {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px;
  position: sticky; top: 20px;
}
.fw-right h4 { color: var(--text-primary); font-size: 0.95rem; margin-bottom: 12px; }

.fw-explainer { display: flex; flex-direction: column; gap: 0; }
.fw-explain-step {
  display: flex; gap: 12px; padding: 8px 0;
  border-bottom: 1px solid var(--border);
}
.fw-explain-step:last-child { border-bottom: none; }
.fw-explain-num {
  width: 24px; height: 24px; border-radius: 50%; background: var(--bg-hover);
  display: flex; align-items: center; justify-content: center;
  font-size: 0.72rem; font-weight: 700; color: var(--text-secondary); flex-shrink: 0; margin-top: 2px;
}
.fw-explain-step strong { color: var(--text-primary); font-size: 0.85rem; }
.fw-explain-step .section-desc { font-size: 0.78rem; margin: 0; }

.fw-proto-legend { display: flex; flex-direction: column; gap: 6px; }
.fw-legend-item { display: flex; align-items: center; gap: 8px; color: var(--text-secondary); font-size: 0.8rem; }

/* Upstream presets */
.fw-presets-title { color: var(--text-secondary); font-size: 0.88rem; margin: 16px 0 8px; }
.fw-presets-rows { display: flex; flex-direction: column; gap: 4px; }
.fw-preset-row {
  display: flex; align-items: center; gap: 12px; padding: 8px 12px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
}
.fw-preset-row-info { flex: 1; min-width: 0; }
.fw-preset-name { color: var(--text-primary); font-weight: 600; font-size: 0.88rem; display: block; }
.fw-preset-privacy { color: var(--text-dim); font-size: 0.7rem; }

.fw-preset-protocols { display: flex; gap: 4px; flex-shrink: 0; }
.fw-proto-btn {
  display: flex; align-items: center; gap: 4px; padding: 4px 10px;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px;
  cursor: pointer; transition: all 0.15s; font-size: 0.78rem;
}
.fw-proto-btn:hover:not(:disabled) { border-color: var(--accent); }
.fw-proto-btn:disabled { opacity: 0.4; cursor: default; }
.fw-proto-btn.added { opacity: 0.4; }

.fw-proto-badge {
  padding: 1px 5px; border-radius: 3px; font-size: 0.6rem; font-weight: 700;
  text-transform: uppercase; flex-shrink: 0;
}
.fw-proto-badge.dns { background: rgba(100,116,139,0.2); color: var(--text-secondary); }
.fw-proto-badge.dot { background: rgba(34,197,94,0.15); color: #22c55e; }
.fw-proto-badge.doh { background: rgba(56,189,248,0.15); color: #38bdf8; }
.fw-proto-badge.doq { background: rgba(168,85,247,0.15); color: #a855f7; }

/* Zone certificates */
.cert-zones-list { display: flex; flex-direction: column; gap: 6px; }
.cert-zone-row {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
}
.cert-zone-info { display: flex; align-items: center; gap: 12px; }
.cert-zone-name { color: var(--text-primary); font-weight: 600; font-size: 0.9rem; }
.cert-zone-status { font-size: 0.78rem; }
.cert-zone-status.has { color: #22c55e; }
.cert-zone-status.none { color: var(--text-dim); }
.cert-zone-actions { display: flex; gap: 6px; }

/* Cert export */
.cert-export { border-top: 1px solid var(--border); padding-top: 12px; }
.cert-install-hints { margin-top: 12px; }
.cert-install-hints summary {
  color: var(--accent); font-size: 0.85rem; cursor: pointer; padding: 4px 0;
}
.cert-hint-content { margin-top: 8px; }
.cert-hint-content p {
  color: var(--text-secondary); font-size: 0.82rem; margin-bottom: 8px; line-height: 1.5;
}
.cert-hint-content strong { color: var(--text-primary); }
.cert-hint-content code { color: #f59e0b; background: var(--bg-input); padding: 1px 5px; border-radius: 3px; font-size: 0.78rem; }
.forwarder-info { flex: 1; }
.forwarder-addr { color: var(--text-primary); font-family: monospace; font-size: 0.9rem; }
.forwarder-name { color: var(--text-muted); font-size: 0.8rem; margin-left: 8px; }
.btn-icon-remove { background: none; border: none; color: var(--text-dim); cursor: pointer; font-size: 1rem; padding: 4px 8px; transition: color 0.15s; }
.btn-icon-remove:hover { color: #ef4444; }

/* DNSSEC */
.dnssec-list { margin-bottom: 12px; }
.dnssec-card { background: var(--bg-input); border-radius: 10px; padding: 16px; margin-bottom: 10px; }
.dnssec-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.dnssec-zone { color: var(--text-primary); font-weight: 600; font-size: 1rem; }
.dnssec-algo { color: var(--text-muted); font-size: 0.75rem; background: var(--bg-card); padding: 2px 8px; border-radius: 4px; }
.dnssec-detail { margin-bottom: 8px; }

.toggle-wrap { display: flex; align-items: center; gap: 8px; margin-left: auto; cursor: pointer; }
.toggle { width: 36px; height: 20px; border-radius: 10px; background: var(--text-dim); position: relative; transition: background 0.2s; }
.toggle.on { background: #22c55e; }
.toggle-knob { width: 16px; height: 16px; border-radius: 50%; background: #fff; position: absolute; top: 2px; left: 2px; transition: transform 0.2s; }
.toggle.on .toggle-knob { transform: translateX(16px); }
.toggle-label { font-size: 0.8rem; color: var(--text-muted); }

/* Cert info */
.cert-info { background: var(--bg-input); border-radius: 8px; padding: 14px; margin-bottom: 12px; }

/* Code editor */
.code-editor {
  width: 100%; padding: 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-family: monospace; font-size: 0.85rem;
  resize: vertical; line-height: 1.5; transition: border-color 0.15s;
}

/* Policies */
.policy-card { background: var(--bg-input); border-radius: 10px; padding: 16px; margin-top: 12px; }
.policy-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.policy-ip { color: var(--text-primary); font-weight: 600; font-family: monospace; }
.policy-name { color: var(--text-muted); font-size: 0.85rem; flex: 1; }
.policy-row { margin-bottom: 10px; }

.cat-toggles { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 4px; }
.cat-check { display: flex; align-items: center; gap: 5px; cursor: pointer; }
.cat-check input { accent-color: #ef4444; }
.cat-check span { color: var(--text-secondary); font-size: 0.85rem; }

.inline-add { display: flex; gap: 6px; margin-top: 4px; }
.inline-add input {
  padding: 5px 10px; background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.85rem; flex: 1; max-width: 220px;
}
.btn-xs { padding: 5px 12px; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem; transition: opacity 0.15s; }
.btn-xs.danger { background: #ef4444; }
.btn-xs.allow { background: #22c55e; }
.btn-xs:hover { opacity: 0.85; }

.tag-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tag { display: flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 6px; font-size: 0.8rem; }
.blocked-tag { background: rgba(239,68,68,0.1); color: #ef4444; }
.allow-tag { background: rgba(34,197,94,0.1); color: #22c55e; }
.tag button { background: none; border: none; color: inherit; cursor: pointer; font-size: 1rem; line-height: 1; }

/* Server settings */
.subsection { margin-bottom: 20px; }
.subsection h4 { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 8px; }
.settings-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; }
.field { display: flex; flex-direction: column; gap: 4px; }
.field label { color: var(--text-muted); font-size: 0.8rem; }
.field input, .field select {
  padding: 9px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.9rem; transition: border-color 0.15s;
}
.field input::placeholder { color: var(--text-dim); }
.checkbox-label { display: flex; align-items: center; gap: 8px; color: var(--text-secondary); font-size: 0.85rem; cursor: pointer; padding-top: 8px; }
.checkbox-label input { accent-color: var(--accent); }

/* Protocol grid */
.protocol-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 8px; }
.protocol-item {
  display: flex; align-items: center; gap: 12px; padding: 12px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px; cursor: pointer;
  transition: border-color 0.15s;
}
.protocol-item:hover { border-color: var(--text-dim); }
.protocol-item input { accent-color: #22c55e; width: 18px; height: 18px; }
.protocol-info { display: flex; flex-direction: column; }
.protocol-name { color: var(--text-primary); font-weight: 500; font-size: 0.9rem; }
.protocol-port { color: var(--accent); font-size: 0.75rem; font-family: monospace; }
.protocol-desc { color: var(--text-dim); font-size: 0.75rem; }

/* Filtering mode */
.mode-cards { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.mode-card {
  padding: 20px; background: var(--bg-input); border: 2px solid var(--border); border-radius: 12px;
  cursor: pointer; transition: all 0.15s;
}
.mode-card:hover { border-color: var(--text-dim); }
.mode-card.active { border-color: var(--accent); background: var(--accent-glow); }
.mode-icon { font-size: 1.5rem; margin-bottom: 8px; }
.mode-info { display: flex; flex-direction: column; gap: 4px; }
.mode-title { color: var(--text-primary); font-weight: 600; font-size: 0.95rem; }
.mode-desc { color: var(--text-muted); font-size: 0.8rem; line-height: 1.4; }
.mode-cards.three-col { grid-template-columns: repeat(3, 1fr); }
.cluster-config { margin-top: 16px; }
.sync-options { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 8px; }

/* Log management */
.log-stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.info-item { display: flex; flex-direction: column; gap: 2px; padding: 10px 14px; background: var(--bg-input); border-radius: 8px; }
.info-label { color: var(--text-muted); font-size: 0.75rem; }
.info-value { color: var(--text-primary); font-size: 0.9rem; font-weight: 500; }
.btn-danger { padding: 9px 16px; background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: background 0.15s; }
.btn-danger:hover { background: rgba(239,68,68,0.25); }
.btn-danger-outline { padding: 9px 16px; background: none; color: #ef4444; border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: background 0.15s; }
.btn-danger-outline:hover { background: rgba(239,68,68,0.1); }
</style>
