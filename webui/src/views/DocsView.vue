<script setup lang="ts">
import { ref, watch } from 'vue'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import Tabs from 'primevue/tabs'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import { useToast } from 'primevue/usetoast'
import Toast from 'primevue/toast'
import Button from 'primevue/button'

const toast = useToast()

// ── Active doc selected via hash/prop ─────────────────────────────────────────
const props  = defineProps<{ section?: string }>()
const active = ref(props.section ?? 'docker')

// When navigating between /docs/winrm ↔ /docs/eval-stig the component is
// reused (same route, different param) — watch the prop to sync the tab.
watch(() => props.section, (sec) => {
  if (sec) active.value = sec
})

function copy(text: string) {
  navigator.clipboard.writeText(text).then(() => {
    toast.add({ severity: 'success', summary: 'Copied', life: 1800 })
  })
}

// Pre-defined copy snippets (avoids escaped-quote parse errors in templates)
const cmd = {
  enablePSRemoting:  'Enable-PSRemoting -Force',
  winrmHttps:        'winrm quickconfig -transport:https',
  selfSignedCert:    '$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\\LocalMachine\\My\nNew-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force',
  fwHttps:           'netsh advfirewall firewall add rule name="WinRM HTTPS" dir=in action=allow protocol=TCP localport=5986',
  fwHttp:            'netsh advfirewall firewall add rule name="WinRM HTTP"  dir=in action=allow protocol=TCP localport=5985',
  testWSMan:         'Test-WSMan -ComputerName TARGET-HOSTNAME -Port 5986 -UseSSL',
  enableRemote:      'Invoke-Command -ComputerName TARGET-HOSTNAME -ScriptBlock { Enable-PSRemoting -Force } -Credential (Get-Credential)',
  setupTask:         'pwsh -File C:\\STIGMA\\scripts\\setup-eval-stig-agent.ps1',
  startManual:       'pwsh -File C:\\Temp\\Evaulate.STIG\\eval-stig-agent.ps1',
  dbBackup:          'docker exec stigma-prod-engine-db-1 mysqldump -u root -p<ROOT_PW> stigman_engine > backup-$(date +%Y%m%d).sql',
  dbRestore:         'docker exec -i stigma-prod-engine-db-1 mysql -u root -p<ROOT_PW> stigman_engine < backup-20260101.sql',
  // Docker install
  cloneRepo:         'git clone https://github.com/your-org/STIGMA.Engine-ERIC.git C:\\STIGMA',
  cdProject:         'cd C:\\STIGMA',
  genSecrets:        'pwsh -File scripts\\generate-secrets.ps1',
  genCerts:          'pwsh -File scripts\\generate-certs.ps1',
  startStack:        'pwsh -File scripts\\stigma.ps1 start',
  stopStack:         'pwsh -File scripts\\stigma.ps1 stop',
  restartEngine:     'pwsh -File scripts\\stigma.ps1 restart engine',
  restartWebui:      'pwsh -File scripts\\stigma.ps1 restart webui',
  rebuildAll:        'pwsh -File scripts\\stigma.ps1 rebuild',
  statusCheck:       'pwsh -File scripts\\stigma.ps1 status',
  logsEngine:        'pwsh -File scripts\\stigma.ps1 logs engine',
  logsAll:           'pwsh -File scripts\\stigma.ps1 logs',
  backupDb:          'pwsh -File scripts\\stigma.ps1 backup',
  dockerDesktop:     'winget install Docker.DockerDesktop',
  pwsh7:             'winget install Microsoft.PowerShell',
}
</script>

<template>
  <Toast />
  <div class="docs-root">
    <div class="docs-header">
      <h2><i class="pi pi-book" style="margin-right:0.5rem;color:#58a6ff" />Documentation</h2>
      <p class="docs-subtitle">STIG Manager MEO Edition — Setup &amp; Operations Guide</p>
    </div>

    <Tabs v-model:value="active" class="docs-tabs">
      <TabList>
        <Tab value="docker">Docker Install</Tab>
        <Tab value="winrm">WinRM Setup</Tab>
        <Tab value="eval-stig">Evaluate-STIG Agent</Tab>
        <Tab value="classification">Classification</Tab>
        <Tab value="backup">Backup &amp; Recovery</Tab>
        <Tab value="monitoring">Monitoring</Tab>
      </TabList>

      <TabPanels>

        <!-- ── Docker Installation ────────────────────────────────────── -->
        <TabPanel value="docker">
          <div class="doc-section">
            <h3><i class="pi pi-box doc-icon" /> Docker Installation Guide</h3>
            <p>STIGMA Engine runs entirely in Docker. This guide walks through a fresh install on a Windows host with Docker Desktop.</p>

            <!-- Prerequisites -->
            <h4 class="doc-step">Prerequisites</h4>
            <table class="doc-table">
              <thead><tr><th>Requirement</th><th>Version</th><th>Install</th></tr></thead>
              <tbody>
                <tr>
                  <td>Docker Desktop</td><td>4.x+</td>
                  <td>
                    <div class="code-block" style="margin:0">
                      <pre>winget install Docker.DockerDesktop</pre>
                      <Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.dockerDesktop)" v-tooltip="'Copy'" />
                    </div>
                  </td>
                </tr>
                <tr>
                  <td>PowerShell 7+</td><td>7.x+</td>
                  <td>
                    <div class="code-block" style="margin:0">
                      <pre>winget install Microsoft.PowerShell</pre>
                      <Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.pwsh7)" v-tooltip="'Copy'" />
                    </div>
                  </td>
                </tr>
                <tr><td>Git</td><td>Any</td><td><code>winget install Git.Git</code></td></tr>
                <tr><td>4 GB RAM free</td><td>—</td><td>Allocated to Docker Desktop in Settings → Resources</td></tr>
                <tr><td>10 GB disk</td><td>—</td><td>For images, volumes, and log files</td></tr>
              </tbody>
            </table>

            <!-- Step 1 -->
            <h4 class="doc-step">Step 1 — Get the project</h4>
            <div class="code-block">
              <pre>git clone https://github.com/your-org/STIGMA.Engine-ERIC.git C:\STIGMA
cd C:\STIGMA</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.cloneRepo + '\n' + cmd.cdProject)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">Or copy your existing project folder to <code>C:\STIGMA</code>.</p>

            <!-- Step 2 -->
            <h4 class="doc-step">Step 2 — Generate secrets</h4>
            <p>The stack uses Docker Secrets for all passwords. A helper script generates random values and writes them to <code>secrets\</code>:</p>
            <div class="code-block">
              <pre>pwsh -File scripts\generate-secrets.ps1</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.genSecrets)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">This creates <code>secrets\mysql_pw.txt</code>, <code>mysql_root_pw.txt</code>, <code>kc_admin_pw.txt</code>, <code>kc_db_pw.txt</code> and the <code>.env.prod</code> file.</p>

            <!-- Step 3 -->
            <h4 class="doc-step">Step 3 — Generate TLS certificates</h4>
            <p>nginx requires a self-signed certificate for HTTPS:</p>
            <div class="code-block">
              <pre>pwsh -File scripts\generate-certs.ps1</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.genCerts)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">Creates <code>prod\certs\server.crt</code> and <code>server.key</code>. Your browser will show a security warning — accept it or install the cert into your Trusted Root store.</p>

            <!-- Step 4 -->
            <h4 class="doc-step">Step 4 — Start the stack</h4>
            <div class="code-block">
              <pre>pwsh -File scripts\stigma.ps1 start</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.startStack)" v-tooltip="'Copy'" />
            </div>
            <p>First run downloads ~1.5 GB of images. Subsequent starts take ~15 seconds.</p>
            <div class="doc-callout callout-warn">
              <i class="pi pi-clock" />
              Keycloak takes 60–90 seconds to start on first boot while it imports the realm. Wait for the engine container to show <strong>healthy</strong> before logging in.
            </div>

            <!-- Step 5 -->
            <h4 class="doc-step">Step 5 — Log in</h4>
            <table class="doc-table">
              <thead><tr><th>URL</th><th>Username</th><th>Password</th></tr></thead>
              <tbody>
                <tr><td><a href="https://localhost" target="_blank">https://localhost</a></td><td>admin</td><td><em>value in .env.prod → APP_USER_PW</em></td></tr>
                <tr><td><a href="https://localhost/kc/admin" target="_blank">https://localhost/kc/admin</a></td><td>admin</td><td><em>value in .env.prod → KC_ADMIN_PW</em></td></tr>
                <tr><td><a href="https://localhost/grafana" target="_blank">https://localhost/grafana</a></td><td><em>auto-login</em></td><td>—</td></tr>
              </tbody>
            </table>

            <!-- Container reference -->
            <h4 class="doc-step">Container Reference</h4>
            <table class="doc-table">
              <thead><tr><th>Service</th><th>Container Name</th><th>Role</th><th>Port</th></tr></thead>
              <tbody>
                <tr><td><code>engine</code></td><td>stigma-prod-engine-1</td><td>Fastify API backend</td><td>54100 (internal)</td></tr>
                <tr><td><code>webui</code></td><td>stigma-prod-webui-1</td><td>nginx + Vue SPA</td><td>443 → https://localhost</td></tr>
                <tr><td><code>engine-db</code></td><td>stigma-prod-engine-db-1</td><td>MySQL 8 — app data</td><td>3306 (internal)</td></tr>
                <tr><td><code>keycloak</code></td><td>stigma-prod-keycloak-1</td><td>OIDC auth server</td><td>8080 (internal)</td></tr>
                <tr><td><code>keycloak-db</code></td><td>stigma-prod-keycloak-db-1</td><td>PostgreSQL — Keycloak</td><td>5432 (internal)</td></tr>
                <tr><td><code>prometheus</code></td><td>stigma-prod-prometheus-1</td><td>Metrics scraper</td><td>9090</td></tr>
                <tr><td><code>grafana</code></td><td>stigma-prod-grafana-1</td><td>Dashboards</td><td>3000 (proxied → /grafana)</td></tr>
                <tr><td><code>mysqld-exporter</code></td><td>stigma-prod-mysqld-exporter-1</td><td>MySQL → Prometheus</td><td>9104 (internal)</td></tr>
              </tbody>
            </table>
          </div>
        </TabPanel>

        <!-- ── WinRM Setup ─────────────────────────────────────────────── -->
        <TabPanel value="winrm">
          <div class="doc-section">
            <h3><i class="pi pi-lock doc-icon" /> WinRM — Windows Remote Management</h3>
            <p>
              WinRM is required for the Evaluate-STIG agent to scan remote Windows assets and for the
              <strong>Start Agent Remotely</strong> feature to launch the agent process from the web console.
            </p>

            <div class="doc-callout callout-warn">
              <i class="pi pi-exclamation-triangle" />
              WinRM must be enabled on every Windows host before remote scanning or remote agent start will work.
              Run these commands in an elevated (Run as Administrator) PowerShell session.
            </div>

            <!-- Step 1 -->
            <h4 class="doc-step">Step 1 — Enable PowerShell Remoting</h4>
            <p>Run on the <strong>Windows host</strong> (the machine running Docker Desktop):</p>
            <div class="code-block">
              <pre>Enable-PSRemoting -Force</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.enablePSRemoting)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">
              This enables WinRM, starts the WinRM service, and adds a firewall rule for HTTP (port 5985).
            </p>

            <!-- Step 2 -->
            <h4 class="doc-step">Step 2 — Configure HTTPS (recommended)</h4>
            <p>HTTPS (port 5986) encrypts credentials in transit. Required in production environments.</p>
            <div class="code-block">
              <pre>winrm quickconfig -transport:https</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.winrmHttps)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">
              If you receive a certificate error, create a self-signed cert and bind it manually:
            </p>
            <div class="code-block">
              <pre>$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.selfSignedCert)" v-tooltip="'Copy'" />
            </div>

            <!-- Step 3 -->
            <h4 class="doc-step">Step 3 — Allow remote connections (firewall)</h4>
            <div class="code-block">
              <pre># HTTPS port 5986
netsh advfirewall firewall add rule name="WinRM HTTPS" dir=in action=allow protocol=TCP localport=5986

# HTTP port 5985 (lab/isolated networks only)
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.fwHttps)" v-tooltip="'Copy'" />
            </div>

            <!-- Step 4 -->
            <h4 class="doc-step">Step 4 — Verify connectivity</h4>
            <p>From the scanning host (or the machine running the agent):</p>
            <div class="code-block">
              <pre>Test-WSMan -ComputerName TARGET-HOSTNAME -Port 5986 -UseSSL</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.testWSMan)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">A successful response shows the WinRM service info. Any error means WinRM is not reachable.</p>

            <!-- Step 5 - Remote assets -->
            <h4 class="doc-step">Step 5 — Enable on remote scan targets</h4>
            <p>Each asset being scanned must also have WinRM enabled. If you have domain connectivity, push it via Group Policy or run remotely:</p>
            <div class="code-block">
              <pre>Invoke-Command -ComputerName TARGET-HOSTNAME -ScriptBlock { Enable-PSRemoting -Force } -Credential (Get-Credential)</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.enableRemote)" v-tooltip="'Copy'" />
            </div>

            <!-- Port Reference -->
            <h4 class="doc-step">Port Reference</h4>
            <table class="doc-table">
              <thead><tr><th>Port</th><th>Protocol</th><th>Use</th><th>Recommendation</th></tr></thead>
              <tbody>
                <tr><td>5985</td><td>HTTP</td><td>WinRM unencrypted</td><td class="warn-cell">Lab / isolated networks only</td></tr>
                <tr><td>5986</td><td>HTTPS</td><td>WinRM encrypted</td><td class="ok-cell">Production default</td></tr>
              </tbody>
            </table>
          </div>
        </TabPanel>

        <!-- ── Evaluate-STIG Agent ─────────────────────────────────────── -->
        <TabPanel value="eval-stig">
          <div class="doc-section">
            <h3><i class="pi pi-bolt doc-icon" /> Evaluate-STIG Agent</h3>
            <p>
              The Evaluate-STIG agent runs on the Windows host alongside Docker Desktop. It polls for scan jobs
              submitted from the web console, executes <code>Invoke-EvaluateSTIG.ps1</code> against target assets,
              and writes results back to a shared volume for ERIC to import automatically.
            </p>

            <h4 class="doc-step">Prerequisites</h4>
            <ul class="doc-list">
              <li>PowerShell 7+ (<code>pwsh.exe</code>) installed</li>
              <li>Evaluate-STIG placed at <code>C:\Temp\Evaulate.STIG\</code></li>
              <li>WinRM enabled on all target assets (see WinRM Setup tab)</li>
            </ul>

            <h4 class="doc-step">Install as a Scheduled Task (recommended)</h4>
            <div class="code-block">
              <pre>pwsh -File "C:\STIGMA\scripts\setup-eval-stig-agent.ps1"</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.setupTask)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">Creates scheduled task <strong>STIGMA-EvalStig-Agent</strong> that auto-starts on login and restarts on failure.</p>

            <h4 class="doc-step">Run manually (foreground)</h4>
            <div class="code-block">
              <pre>pwsh -File "C:\Temp\Evaulate.STIG\eval-stig-agent.ps1"</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.startManual)" v-tooltip="'Copy'" />
            </div>

            <h4 class="doc-step">Start remotely from the web console</h4>
            <p>Navigate to <strong>Eval STIG → Start Agent Remotely</strong> in the sidebar, enter Windows credentials, and click <em>Start Agent</em>. The engine connects via WinRM and launches the agent as a background process.</p>

            <h4 class="doc-step">File locations</h4>
            <table class="doc-table">
              <thead><tr><th>Path</th><th>Purpose</th></tr></thead>
              <tbody>
                <tr><td><code>C:\Temp\Evaulate.STIG\</code></td><td>Evaluate-STIG tool root</td></tr>
                <tr><td><code>.\scripts\eval-jobs\</code></td><td>Job queue (shared volume)</td></tr>
                <tr><td><code>.\scripts\eval-stig-agent.log</code></td><td>Agent activity log</td></tr>
                <tr><td><code>C:\Temp\EvalSTIG-Results\</code></td><td>Default scan output (CKL/CKLB files)</td></tr>
              </tbody>
            </table>
          </div>
        </TabPanel>

        <!-- ── Classification ─────────────────────────────────────────── -->
        <TabPanel value="classification">
          <div class="doc-section">
            <h3><i class="pi pi-shield doc-icon" /> Classification Markings</h3>
            <p>Set the <code>CLASSIFICATION</code> environment variable in <code>docker-compose.prod.yml</code> to control the banner and export markings.</p>
            <table class="doc-table">
              <thead><tr><th>Value</th><th>Banner Color</th><th>Use</th></tr></thead>
              <tbody>
                <tr><td><code>UNCLASSIFIED</code></td><td class="ok-cell">Green</td><td>Unclassified systems</td></tr>
                <tr><td><code>CUI</code></td><td style="color:#f97316">Orange</td><td>Controlled Unclassified Information</td></tr>
                <tr><td><code>SECRET</code></td><td class="warn-cell">Red</td><td>Secret networks</td></tr>
                <tr><td><code>TS</code></td><td style="color:#8b5cf6">Orange-Yellow</td><td>Top Secret</td></tr>
              </tbody>
            </table>
            <p class="doc-note">All POA&M exports include the classification marking in the header row. The X-Classification response header is set on all API responses.</p>
          </div>
        </TabPanel>

        <!-- ── Backup ─────────────────────────────────────────────────── -->
        <TabPanel value="backup">
          <div class="doc-section">
            <h3><i class="pi pi-database doc-icon" /> Backup &amp; Recovery</h3>

            <h4 class="doc-step">Management script (recommended)</h4>
            <p>Use the built-in management script — it handles passwords automatically:</p>
            <div class="code-block">
              <pre>pwsh -File scripts\stigma.ps1 backup</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.backupDb)" v-tooltip="'Copy'" />
            </div>
            <p class="doc-note">Backups are saved to <code>C:\Temp\STIGMA-Backups\stigma-backup-YYYY-MM-DD_HH-mm.sql</code></p>

            <h4 class="doc-step">Manual backup (raw docker)</h4>
            <div class="code-block">
              <pre>docker exec stigma-prod-engine-db-1 mysqldump -u root -p&lt;ROOT_PW&gt; stigman_engine &gt; backup.sql</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy(cmd.dbBackup)" v-tooltip="'Copy'" />
            </div>

            <h4 class="doc-step">Restore</h4>
            <div class="code-block">
              <pre>pwsh -File scripts\stigma.ps1 restore C:\Temp\STIGMA-Backups\stigma-backup-2026-05-31.sql</pre>
              <Button icon="pi pi-copy" text size="small" class="copy-btn"
                @click="copy('pwsh -File scripts\\stigma.ps1 restore C:\\Temp\\STIGMA-Backups\\stigma-backup-2026-05-31.sql')" v-tooltip="'Copy'" />
            </div>

            <h4 class="doc-step">Log files</h4>
            <p>Engine logs are written to <code>C:\Temp\STIGMA-Logs\</code> on the Windows host. Kept 14 days, 50 MB per file. View live in <strong>Administration → System Logs</strong>.</p>

            <!-- Management Scripts reference -->
            <h4 class="doc-step">Management Script Reference — <code>scripts\stigma.ps1</code></h4>
            <table class="doc-table">
              <thead><tr><th>Command</th><th>What it does</th></tr></thead>
              <tbody>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 start</pre><Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.startStack)" v-tooltip="'Copy'" /></div></td>
                  <td>Start all containers (builds if needed). Shows admin password.</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 stop</pre><Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.stopStack)" v-tooltip="'Copy'" /></div></td>
                  <td>Stop all containers. Data volumes are preserved.</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 status</pre><Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.statusCheck)" v-tooltip="'Copy'" /></div></td>
                  <td>Show container status, health checks for engine/Keycloak/Grafana, disk usage.</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 restart engine</pre><Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.restartEngine)" v-tooltip="'Copy'" /></div></td>
                  <td>Restart a single service. Aliases: engine, webui, db, keycloak, grafana.</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 rebuild</pre><Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.rebuildAll)" v-tooltip="'Copy'" /></div></td>
                  <td>Rebuild engine + webui Docker images and redeploy (picks up code changes).</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 logs engine</pre><Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.logsEngine)" v-tooltip="'Copy'" /></div></td>
                  <td>Tail logs from a container. Ctrl+C to exit.</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 backup</pre><Button icon="pi pi-copy" text size="small" class="copy-btn" @click="copy(cmd.backupDb)" v-tooltip="'Copy'" /></div></td>
                  <td>Dump MySQL database to <code>C:\Temp\STIGMA-Backups\</code>.</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 restore &lt;file&gt;</pre></div></td>
                  <td>Restore database from a .sql backup file.</td>
                </tr>
                <tr>
                  <td><div class="code-block" style="margin:0"><pre>pwsh -File scripts\stigma.ps1 shell engine</pre></div></td>
                  <td>Open an interactive shell inside a container for debugging.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </TabPanel>

        <!-- ── Monitoring ─────────────────────────────────────────────── -->
        <TabPanel value="monitoring">
          <div class="doc-section">
            <h3><i class="pi pi-chart-line doc-icon" /> Monitoring</h3>
            <p>Prometheus + Grafana are included in the production Docker stack.</p>
            <table class="doc-table">
              <thead><tr><th>Service</th><th>URL</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td>Grafana</td><td><a href="/grafana/" target="_blank">/grafana/</a></td><td>Auto-login as Viewer; admin user: admin/admin</td></tr>
                <tr><td>Prometheus</td><td>localhost:9090</td><td>Internal only — not proxied through nginx</td></tr>
                <tr><td>App Metrics</td><td>/stigman/api/metrics</td><td>Prometheus scrape endpoint</td></tr>
                <tr><td>Health</td><td>/stigman/health</td><td>Returns 200 when engine is up</td></tr>
              </tbody>
            </table>
            <p class="doc-note">The Grafana dashboard is provisioned automatically from <code>monitoring/grafana/provisioning/</code> and sources all data from MySQL — not from Prometheus scraped metrics — so it reflects true database state.</p>
          </div>
        </TabPanel>

      </TabPanels>
    </Tabs>
  </div>
</template>

<style scoped>
.docs-root    { padding: 0.75rem 1.5rem 3rem; max-width: 900px; }
.docs-header  { margin-bottom: 1rem; }
.docs-header h2 { margin: 0 0 0.2rem; font-size: 1.2rem; }
.docs-subtitle { color: var(--p-text-muted-color, #6b7280); font-size: 0.85rem; margin: 0; }

.doc-section  { padding: 0.5rem 0 1rem; }
.doc-section h3 { font-size: 1rem; margin: 0 0 0.6rem; display: flex; align-items: center; gap: 0.4rem; }
.doc-section p  { font-size: 0.875rem; line-height: 1.6; margin: 0.4rem 0; }
.doc-icon { color: #58a6ff; }

.doc-step {
  font-size: 0.9rem;
  margin: 1.2rem 0 0.4rem;
  padding-bottom: 0.25rem;
  border-bottom: 1px solid var(--p-surface-700, #2d2d3d);
  color: var(--p-text-color, #e6edf3);
}

.doc-callout {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.65rem 0.9rem;
  border-radius: 6px;
  font-size: 0.84rem;
  line-height: 1.5;
  margin: 0.75rem 0;
}
.callout-warn {
  background: rgba(245,158,11,0.1);
  border: 1px solid rgba(245,158,11,0.4);
  color: #d97706;
}

.code-block {
  position: relative;
  background: var(--p-surface-900, #0d1117);
  border: 1px solid var(--p-surface-700, #30363d);
  border-radius: 6px;
  margin: 0.4rem 0 0.6rem;
  padding: 0.6rem 2.5rem 0.6rem 0.9rem;
}
.code-block pre {
  margin: 0;
  font-family: 'Consolas', 'Fira Mono', monospace;
  font-size: 0.8rem;
  color: #e6edf3;
  white-space: pre-wrap;
  word-break: break-all;
}
.copy-btn {
  position: absolute;
  top: 0.35rem;
  right: 0.25rem;
  opacity: 0.5;
}
.copy-btn:hover { opacity: 1; }

.doc-note {
  font-size: 0.8rem;
  color: var(--p-text-muted-color, #6b7280);
  font-style: italic;
}

.doc-list {
  font-size: 0.875rem;
  line-height: 1.8;
  padding-left: 1.2rem;
}

.doc-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.84rem;
  margin: 0.5rem 0;
}
.doc-table th {
  text-align: left;
  padding: 0.4rem 0.6rem;
  background: var(--p-surface-800, #161b22);
  border-bottom: 2px solid var(--p-surface-600, #30363d);
  color: var(--p-text-muted-color, #8b949e);
  font-weight: 600;
}
.doc-table td {
  padding: 0.35rem 0.6rem;
  border-bottom: 1px solid var(--p-surface-700, #21262d);
  vertical-align: top;
}
.doc-table code { font-size: 0.78rem; }

.ok-cell   { color: #22c55e; font-weight: 600; }
.warn-cell { color: #ef4444; font-weight: 600; }

.docs-tabs { margin-top: 0.5rem; }
</style>
