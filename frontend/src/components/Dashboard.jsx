import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import ReactMarkdown from 'react-markdown'
import { useAuth } from 'react-oidc-context'
import { useLocation, useNavigate } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import {
  ShieldAlert,
  LayoutDashboard,
  Database,
  Activity,
  LogOut,
  Globe,
  Users,
  Zap,
  ChevronRight,
  Search,
  ShieldCheck,
  CheckCircle2,
  FileText,
  Download,
  XCircle,
  Cpu,
  Plus,
  X,
  UserCheck,
  Gauge,
  FlaskConical,
} from 'lucide-react'


import SupresionesView from './SupresionesView'
import PruebasFuncionalesView from './PruebasFuncionalesView'
import TokensIAView from './TokensIAView'
import OverviewView from './dashboard/OverviewView'
import SoarView from './dashboard/SoarView'
import ThreatHuntingView from './dashboard/ThreatHuntingView'
import InventoryView from './dashboard/InventoryView'
import ItdrView from './dashboard/ItdrView'
import HealthView from './dashboard/HealthView'
import UsersView from './dashboard/UsersView'
import SettingsView from './dashboard/SettingsView'
import AddModal from './dashboard/AddModal'
import InvestigateModal from './dashboard/InvestigateModal'
import ScriptModal from './dashboard/ScriptModal'
import VaultModal from './dashboard/VaultModal'
import DetailsModal from './dashboard/DetailsModal'
import AssetDetailsModal from './dashboard/AssetDetailsModal'
import ManualModal from './dashboard/ManualModal'
import AgentModal from './dashboard/AgentModal'
import { DashboardContext } from './dashboard/DashboardContext'
import { API_BASE, normSev, NavItem } from './dashboard/shared'

// Using relative path to utilize the Nginx proxy at /centinela/api/


// Runtime alerts arrive from several sensors with different priority vocabularies -- Falco
// uses syslog-style mixed case ('Critical', 'Warning', 'Notice', 'Debug'), Zeek writes
// 'MEDIUM'/'INFO', Centinela's own ITDR rules write 'CRITICAL'. The backend now normalises
// on read, but this keeps the UI correct regardless of what any row actually stores.




// /api/health reports honest intermediate states for on-demand/idle capabilities (e.g.
// "Available (On-Demand, Not Yet Run)", "No Data Yet") instead of faking "Online" -- these
// are not failures and must not render as red alongside genuine outages ("Unreachable",
// "Not Installed", "Offline").


export default function Dashboard() {
  const auth = useAuth()
  // ADR-0008 #8: every API call carries the Authentik access token (the backend validates it, see core/auth.py).
  if (auth.user?.access_token) axios.defaults.headers.common['Authorization'] = `Bearer ${auth.user.access_token}`
  else delete axios.defaults.headers.common['Authorization']
  // The Authentik access token lives 1 h and there is no silent renew: when it expires, sign in again instead of polling the API for
  // hours with a dead token (which enforce mode would turn into a broken dashboard). Authentik's SSO session makes this a quick redirect.
  useEffect(() => {
    if (!auth.events || !auth.isAuthenticated) return undefined
    return auth.events.addAccessTokenExpired(() => { auth.signinRedirect() })
  }, [auth.events, auth.isAuthenticated])
  // ADR-0008 #2: the active view lives in the URL (/soar, /inventory...), so reload, back/forward and shared links work.
  const location = useLocation()
  const navigate = useNavigate()
  const requestedView = location.pathname.replace(/^\/+|\/+$/g, '') || 'dashboard'
  const setCurrentView = (v) => navigate(v === 'dashboard' ? '/' : `/${v}`)
  const [stats, setStats] = useState({ alerts: 0, endpoints: 0, users: 0, private_hosts: 0, public_hosts: 0 })
  const [vulnStats, setVulnStats] = useState({ total: 0, real_vulnerabilities_total: 0, infra_vulnerabilities: 0, code_vulnerabilities: 0, infra_informational: 0, code_informational: 0, critical: 0, high: 0, pending_ia: 0, pending_approval: 0 })
  const [soarCategoryFilter, setSoarCategoryFilter] = useState('ALL')
  const [soarAssetCategoryFilter, setSoarAssetCategoryFilter] = useState('ALL')
  const [mapData, setMapData] = useState([])
  const [alerts, setAlerts] = useState([])
  const [inventory, setInventory] = useState([])
  const [riskData, setRiskData] = useState([])
  const [remediationLog, setRemediationLog] = useState([])
  const [healthStatus, setHealthStatus] = useState({ services: [] })
  const [cmmiReport, setCmmiReport] = useState({ overall_cmmi_compliance_rate: null, assets_audit: [] })
  const [isoReport, setIsoReport] = useState({ overall_iso_compliance_rate: null, assets_audit: [] })
  const [dailyDetections, setDailyDetections] = useState([])
  const [tops, setTops] = useState({ recent_assets: [], most_vulnerable: [], most_remediated: [] })
  const [dashboardCharts, setDashboardCharts] = useState({ cis_grade_distribution: [], top_mitre_techniques: [], crs_distribution: [], sla_compliance_percentage: null })
  const [severityByCategory, setSeverityByCategory] = useState({ infra: {}, code: {} })
  const [loading, setLoading] = useState(true)
  const [toasts, setToasts] = useState([])
  const toastIdCounter = useRef(0)
  const MAX_VISIBLE_TOASTS = 5
  const [roiStats, setRoiStats] = useState({
    avg_remediation_time_minutes: 0,
    effectiveness_rate_percentage: 0,
    comparison: { ai_resolved: 0, manual_resolved: 0 }
  })
  const [wazuhLogs, setWazuhLogs] = useState(null)
  const [showWazuhLogsModal, setShowWazuhLogsModal] = useState(false)
  const [wazuhActionLoading, setWazuhActionLoading] = useState(false)
  const [lastSync, setLastSync] = useState(new Date())
  const [selectedRemediation, setSelectedRemediation] = useState(null)
  const [severityFilter, setSeverityFilter] = useState(null)
  const [assetFilter, setAssetFilter] = useState(null)
  const [inventorySearch, setInventorySearch] = useState('')
  const [inventoryViewMode, setInventoryViewMode] = useState('grid') // 'grid' | 'table' | 'groups'
  const [inventorySortBy, setInventorySortBy] = useState('newest')   // 'newest' | 'alpha' | 'vulns' | 'alerts'
  const [inventoryTypeFilter, setInventoryTypeFilter] = useState('')
  const [threatSearch, setThreatSearch] = useState('')
  const [threatSortBy, setThreatSortBy] = useState('newest')   // 'newest' | 'oldest' | 'severity'
  
  const [assetStatusFilter, setAssetStatusFilter] = useState('ALL') // NEW: ALL, VULNERABLE, ATTACKED
  const [soarSeverityFilter, setSoarSeverityFilter] = useState('ALL')
  const [soarStatusFilter, setSoarStatusFilter] = useState('ALL')
  const [soarSearch, setSoarSearch] = useState('')
  
  // Modal State
  const [showAddModal, setShowAddModal] = useState(false)
  const [newAssetZip, setNewAssetZip] = useState(null)
  const [connTest, setConnTest] = useState(null)  // null | {loading} | {ok, steps}
  const isRootUser = (u) => (u || '').trim().toLowerCase() === 'root'
  const [newAsset, setNewAsset] = useState({ asset_name: '', asset_type: '', endpoint: '', criticality: 'MEDIUM', vault_sudo_token: '', vault_ansible_user: '', auth_type: 'PASSWORD', ssh_private_key: '', gitlab_user: '', gitlab_token: '' })
  
  // Investigation Modal
  const [showInvestigateModal, setShowInvestigateModal] = useState(false)
  const [investigationData, setInvestigationData] = useState(null)
  const [isInvestigating, setIsInvestigating] = useState(false)

  // Script Viewer Modal
  const [showScriptModal, setShowScriptModal] = useState(false)
  const [scriptContent, setScriptContent] = useState('')
  const [scriptLoading, setScriptLoading] = useState(false)

  // Report Modal
  const [showReportModal, setShowReportModal] = useState(false)

  // Vault Credential Modal
  const [showVaultModal, setShowVaultModal] = useState(false)
  const [vaultTarget, setVaultTarget] = useState('')        // asset_name del activo
  const [vaultPassword, setVaultPassword] = useState('')
  const [vaultUser, setVaultUser] = useState('')
  const [vaultAuthType, setVaultAuthType] = useState('PASSWORD') // 'PASSWORD' or 'SSH_KEY'
  const [vaultSshKey, setVaultSshKey] = useState('')
  const [vaultSaving, setVaultSaving] = useState(false)
  const [vaultResult, setVaultResult] = useState(null)     // { ok: bool, msg: string }
  
  // Asset Details Modal (local: agentInfo for OS/kernel; origin: ping + assetDetails)
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [detailsTarget, setDetailsTarget] = useState(null)  // el group completo
  const [agentInfo, setAgentInfo] = useState(null)          // datos live de Wazuh agent_control
  const [agentInfoLoading, setAgentInfoLoading] = useState(false)
  const [pingResults, setPingResults] = useState({}) // { [assetName]: { status, ping_ok, latency_ms, loading, message } }
  const [showAssetDetailsModal, setShowAssetDetailsModal] = useState(false)
  const [assetDetailsData, setAssetDetailsData] = useState(null)
  const [activeCmmiAreaFilter, setActiveCmmiAreaFilter] = useState(null) // area code ('CAR'|'PQA'|'CM'|'MC'|'VV') or null
  const [itdrEvents24h, setItdrEvents24h] = useState([])
  const [itdrEventsRecent, setItdrEventsRecent] = useState([])
  const [itdrAnomalies, setItdrAnomalies] = useState([])
  const [itdrLoading, setItdrLoading] = useState(false)
  const [assetDetailsLoading, setAssetDetailsLoading] = useState(false)
  // Agent installer modal
  const [showAgentModal, setShowAgentModal] = useState(false)
  const [agentModalAsset, setAgentModalAsset] = useState(null)  // { name, type, endpoint }
  const [agentModalTab, setAgentModalTab] = useState('download')  // 'download' | 'guide' | 'verify'
  const [agentDownloading, setAgentDownloading] = useState(false)


  // Manual Remediation Modal
  const [showManualModal, setShowManualModal] = useState(false)
  const [manualSolution, setManualSolution] = useState('')
  const [manualReason, setManualReason] = useState('')
  const [manualSaving, setManualSaving] = useState(false)

  const [usersList, setUsersList] = useState([])
  const [usersLoading, setUsersLoading] = useState(false)
  const [currentUserRole, setCurrentUserRole] = useState('Viewer')
  // The role comes from /api/users (a ~5 s call to Authentik). Until it answers, the role is UNKNOWN, not "Viewer": deciding too early silently
  // bounced administrators from /users and /settings to the dashboard (and kept doing so for as long as that call failed).
  const [roleChecked, setRoleChecked] = useState(false)
  const [roleError, setRoleError] = useState(null)
  const KNOWN_VIEWS = ['dashboard', 'threat-hunting', 'itdr', 'inventory', 'soar', 'suppressions', 'functional-tests', 'ai-tokens', 'health', 'users', 'settings']
  const ADMIN_ONLY_VIEWS = ['users', 'settings']
  const adminViewPending = ADMIN_ONLY_VIEWS.includes(requestedView) && !roleChecked
  const currentView = KNOWN_VIEWS.includes(requestedView) && (adminViewPending || !(ADMIN_ONLY_VIEWS.includes(requestedView) && currentUserRole !== 'Admin'))
    ? requestedView : 'dashboard'

  useEffect(() => {
    if (auth.isAuthenticated) fetchUsers()
  }, [auth.isAuthenticated])

  const fetchUsers = async () => {
    try {
      setUsersLoading(true)
      const res = await axios.get(`${API_BASE}/users`)
      if (Array.isArray(res.data)) {
        setUsersList(res.data)
        // Detect current user role accurately
        const profile = auth.user?.profile || {}
        const usernameCandidates = [
          profile.preferred_username,
          profile.nickname,
          profile.sub,
          profile.name
        ].filter(Boolean).map(s => s.toLowerCase())
        const emailCandidate = (profile.email || '').toLowerCase()

        const match = res.data.find(u => {
          const uName = (u.username || '').toLowerCase()
          const uEmail = (u.email || '').toLowerCase()
          return usernameCandidates.includes(uName) || (emailCandidate && uEmail === emailCandidate)
        })
        if (match) {
          setCurrentUserRole(match.role)
        }
        setRoleChecked(true)
        setRoleError(null)
      }
    } catch (e) {
      console.error("Error fetching Authentik users:", e)
      setRoleError(e?.response?.data?.detail || e.message || 'No se pudo consultar a Authentik')
    } finally {
      setUsersLoading(false)
    }
  }

  const handleUpdateUserRole = async (username, newRole) => {
    try {
      await axios.post(`${API_BASE}/users/role`, { username, role: newRole })
      alert(newRole === 'Disabled'
        ? `⛔ ${username} fue deshabilitado: ya no puede entrar a Centinela.`
        : `✅ Rol de ${username} actualizado exitosamente a '${newRole}' en Authentik.`)
      fetchUsers()
    } catch (error) {
      console.error("Error updating user role:", error)
      const st = error.response?.status
      if (st === 504 || st === 502 || !error.response) {
        // The gateway gave up waiting, but the change may have been applied: reload the real state.
        alert(`⚠️ Authentik tardó en responder; se recarga la lista para mostrar el rol real de ${username}.`)
        fetchUsers()
      } else {
        alert("Error al actualizar el rol en Authentik: " + (error.response?.data?.detail || error.message))
      }
    }
  }

  const [systemConfig, setSystemConfig] = useState([])
  const [configLoading, setConfigLoading] = useState(false)
  const [configSaving, setConfigSaving] = useState(false)

  const [availableModels, setAvailableModels] = useState([])
  const [loadingModels, setLoadingModels] = useState(false)

  const fetchModelsForProvider = async (providerName) => {
    try {
      setLoadingModels(true)
      const res = await axios.get(`${API_BASE}/llm/models?provider=${providerName}`)
      if (res.data && Array.isArray(res.data.models)) {
        setAvailableModels(res.data.models)
      }
    } catch (e) {
      console.error("Error fetching LLM models:", e)
    } finally {
      setLoadingModels(false)
    }
  }

  const fetchSystemConfig = async () => {
    try {
      setConfigLoading(true)
      const res = await axios.get(`${API_BASE}/config`)
      if (Array.isArray(res.data)) {
        setSystemConfig(res.data)
      }
    } catch (e) {
      console.error("Error fetching system config:", e)
    } finally {
      setConfigLoading(false)
    }
  }

  const handleSaveConfig = async () => {
    try {
      setConfigSaving(true)
      await axios.post(`${API_BASE}/config`, { settings: systemConfig })
      alert("✅ Configuración del sistema y agentes guardada exitosamente.")
      fetchSystemConfig()
    } catch (e) {
      console.error("Error saving system config:", e)
      alert("Error al guardar la configuración: " + (e.response?.data?.detail || e.message))
    } finally {
      setConfigSaving(false)
    }
  }

  const showNotification = (alertData) => {
    // Date.now() alone collides when multiple WebSocket alerts land in the same millisecond
    // (confirmed live during a real Falco burst -- "Drop and execute new binary in container"
    // firing repeatedly within seconds of itself), producing duplicate React keys. Duplicate
    // keys don't just warn in the console: React's own reconciliation across renders becomes
    // unreliable for those entries, which is what left stale toasts stuck on screen even
    // though each one's own 8s auto-dismiss timer was firing correctly. A monotonic counter
    // guarantees a unique id regardless of how fast alerts arrive.
    toastIdCounter.current += 1
    const newToast = {
      id: `${Date.now()}-${toastIdCounter.current}`,
      title: alertData.rule_name || "Nueva Alerta",
      message: alertData.alert_text || `Detectado en ${alertData.asset_name || 'desconocido'}`,
      priority: alertData.priority
    }
    // Cap how many toasts can pile up on screen at once -- during a sustained real alert
    // burst (as above), alerts can arrive faster than the 8s timer drains them, so relying on
    // the timer alone still lets the visible list grow without bound. Keeping only the most
    // recent MAX_VISIBLE_TOASTS matches the existing alerts-feed cap pattern (`.slice(0, 100)`)
    // used elsewhere in this component.
    setToasts(prev => [...prev, newToast].slice(-MAX_VISIBLE_TOASTS))
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== newToast.id))
    }, 8000)
  }

  // WebSocket alerts
  useEffect(() => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}${API_BASE}/ws/alerts`;
    let ws;
    let reconnectInterval;
    let disposed = false   // set by the cleanup so a late onclose does not schedule a reconnect for a dead effect
    // ADR-0008 #8: browsers cannot set headers on a WebSocket, so the Authentik token travels as a subprotocol (see core/auth.py).
    const token = auth.user?.access_token

    const connect = () => {
      ws = new WebSocket(wsUrl, token ? ['centinela.bearer', token] : undefined);

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'new_alert') {
            setAlerts(prev => [payload.data, ...prev].slice(0, 100));
            // Only raise a toast for genuinely critical runtime alerts. Informational/low
            // sensor chatter still lands in the alerts feed and the threat-hunting log, it
            // just doesn't interrupt with a notification (explicit user request).
            if (normSev(payload.data?.priority) === 'CRITICAL') {
              showNotification(payload.data);
            }
          } else if (payload.type === 'asset_status_update') {
            const update = payload.data;
            if (update && update.asset_name) {
              setPingResults(prev => ({
                ...prev,
                [update.asset_name]: {
                  status: update.ping_ok ? 'ONLINE' : 'OFFLINE',
                  ping_ok: update.ping_ok,
                  latency_ms: update.latency_ms,
                  loading: false
                }
              }));
              if (update.ping_ok) {
                setInventory(prev => prev.map(item => 
                  item.asset_name === update.asset_name 
                    ? { ...item, status: 'active', last_seen: update.last_seen || item.last_seen }
                    : item
                ));
              }
            }
          }
        } catch (err) {
          console.error("WS message parse error:", err);
        }
      };

      ws.onclose = () => {
        if (disposed) return
        reconnectInterval = setTimeout(() => {
          connect();
        }, 5000);
      };
    };

    connect();

    return () => {
      disposed = true
      if (ws) ws.close();
      clearTimeout(reconnectInterval);
    };
  }, [auth.user?.access_token]);

  // Real ITDR/UEBA telemetry -- fetched from ClickHouse-backed endpoints (core/itdr_engine.py,
  // core/ueba_engine.py) when the tab is opened. Was previously 100% hardcoded zeros/placeholder
  // text with no API calls at all.
  useEffect(() => {
    if (currentView !== 'itdr') return
    let cancelled = false
    setItdrLoading(true)
    Promise.all([
      axios.get(`${API_BASE}/itdr/telemetry/recent`, { params: { minutes: 1440 } }),
      axios.get(`${API_BASE}/itdr/telemetry/recent`, { params: { minutes: 15 } }),
      axios.get(`${API_BASE}/xdr/ueba/anomalies`),
    ]).then(([res24h, resRecent, resAnomalies]) => {
      if (cancelled) return
      setItdrEvents24h(Array.isArray(res24h.data?.events) ? res24h.data.events : [])
      setItdrEventsRecent(Array.isArray(resRecent.data?.events) ? resRecent.data.events : [])
      setItdrAnomalies(Array.isArray(resAnomalies.data?.anomalies) ? resAnomalies.data.anomalies : [])
    }).catch(err => console.error("Error fetching ITDR telemetry:", err))
      .finally(() => { if (!cancelled) setItdrLoading(false) })
    return () => { cancelled = true }
  }, [currentView]);

  // ADR-0008 #8: reports are fetched with axios (which sends the Authorization header) and handed to the browser as a Blob; plain
  // window.location navigation cannot carry a bearer token and would be rejected once API auth is enforced.
  const fetchReport = async (path, { openInTab = false } = {}) => {
    try {
      const res = await axios.get(`${API_BASE}${path}${path.includes('?') ? '&' : '?'}t=${Date.now()}`, { responseType: 'blob' })
      const blob = new Blob([res.data], { type: res.headers['content-type'] || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      if (openInTab) {
        window.open(url, '_blank')
      } else {
        const m = /filename="?([^";]+)"?/.exec(res.headers['content-disposition'] || '')
        const a = document.createElement('a')
        a.href = url
        a.download = m ? m[1] : 'reporte'
        document.body.appendChild(a)
        a.click()
        a.remove()
      }
      setTimeout(() => URL.revokeObjectURL(url), 60000)
    } catch (err) {
      console.error('Error descargando reporte:', err)
      alert('No se pudo descargar el reporte: ' + (err.response?.status === 401 ? 'sesión no válida, vuelve a iniciar sesión.' : (err.message || 'error')))
    }
  }

  const handleDownloadReport = () => fetchReport('/reports/executive')
  const handleDownloadAssetReport = (assetName) => fetchReport(`/reports/asset/${encodeURIComponent(assetName)}?format=pdf`)
  const handleViewAssetReportHtml = (assetName) => fetchReport(`/reports/asset/${encodeURIComponent(assetName)}?format=html`, { openInTab: true })
  const handleDownloadVulnerabilityReport = (vulnId) => fetchReport(`/reports/vulnerability/${vulnId}`)
  const handleDownloadCmmiFleetReport = () => fetchReport('/reports/cmmi')
  const handleDownloadCmmiAssetReport = (assetName) => fetchReport(`/reports/cmmi/${encodeURIComponent(assetName)}`)
  // Comparativo "último escaneo vs el anterior" (por activo o para varios activos, p. ej. los visibles con el filtro actual)
  const handleDownloadComparison = (assetName) => fetchReport(`/reports/comparison/asset/${encodeURIComponent(assetName)}?format=pdf`)
  const handleViewComparisonHtml = (assetName) => fetchReport(`/reports/comparison/asset/${encodeURIComponent(assetName)}?format=html`, { openInTab: true })
  const handleDownloadGroupComparison = (assetNames, title, format = 'pdf') => {
    const qs = assetNames.map(n => `asset=${encodeURIComponent(n)}`).join('&')
    return fetchReport(`/reports/comparison/group?${qs}&title=${encodeURIComponent(title || '')}&format=${format}`, { openInTab: format === 'html' })
  }

  const handleWazuhAction = async (agentId, action) => {
    setWazuhActionLoading(true);
    try {
      if (action === 'logs') {
        const res = await axios.post(`${API_BASE}/wazuh/agent/${agentId}/action?action=logs`);
        setWazuhLogs(res.data.logs);
        setShowWazuhLogsModal(true);
      } else {
        const res = await axios.post(`${API_BASE}/wazuh/agent/${agentId}/action?action=${action}`);
        alert(`✅ Wazuh Agent ${agentId}: ${res.data.message || 'Comando enviado con éxito.'}`);
      }
    } catch (error) {
      console.error("Wazuh action error:", error);
      alert("Error al ejecutar acción en Wazuh: " + (error.response?.data?.detail || error.message));
    } finally {
      setWazuhActionLoading(false);
    }
  }

  const handleWazuhUninstall = async (agentId, assetName) => {
    const confirmed = window.confirm(
      `¿Desinstalar el agente Wazuh de '${assetName}' (ID: ${agentId})?\n\nEsto detiene y elimina el agente del host y lo desregistra del Manager. Requiere credenciales de Ansible ya configuradas en Vault para este activo. Esta acción no se puede deshacer.`
    );
    if (!confirmed) return;
    setWazuhActionLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/wazuh/agent/${agentId}/uninstall`);
      alert(`🗑️ ${res.data.message || 'Desinstalación en curso.'}`);
    } catch (error) {
      console.error("Wazuh uninstall error:", error);
      alert("Error al desinstalar el agente Wazuh: " + (error.response?.data?.detail || error.message));
    } finally {
      setWazuhActionLoading(false);
    }
  }

  // Hook must run before the early returns below (auth loading/error/disabled), or hook order changes between renders.

  // ADR-0008 #2: polling is owned by TanStack Query. It never starts a round on top of one still in flight (the old hand-made guard existed
  // because overlapping rounds of ~12 heavy requests once piled up until the API answered 504s), pauses while the tab is hidden, and keeps
  // the previous data on screen while a filter change refetches. The views keep reading the same state setters, so none of them changed.
  const POLL_MS = 20000
  const fetchCore = async () => {
    const remediationQuery = (() => {
      const p = new URLSearchParams();
      if (assetFilter) p.set('asset', assetFilter);
      if (soarCategoryFilter && soarCategoryFilter !== 'ALL') p.set('category', soarCategoryFilter);
      // Only ask for RESOLVED rows when the analyst explicitly wants the remediated/history view -- otherwise the queue (and the count
      // the inventory card links into) stays "pending only" so the two never disagree.
      if (soarStatusFilter === 'REMEDIADO') p.set('status_scope', 'all');
      const q = p.toString();
      return q ? `?${q}` : '';
    })()
    const [resStats, resVulns, resMap, resAlerts, resRisk, resInv, resRem] = await Promise.all([
      axios.get(`${API_BASE}/stats/extended`),
      axios.get(`${API_BASE}/stats`),
      axios.get(`${API_BASE}/map`),
      axios.get(`${API_BASE}/alerts/runtime`),
      axios.get(`${API_BASE}/risk-distribution`),
      axios.get(`${API_BASE}/inventory`),
      axios.get(`${API_BASE}/remediation${remediationQuery}`),
    ])
    return { resStats, resVulns, resMap, resAlerts, resRisk, resInv, resRem }
  }
  const fetchSecondary = async () => {
    const [resHealth, resDaily, resTops, resRoi, resCmmi, resIso, resCharts, resSeverityCat] = await Promise.all([
      axios.get(`${API_BASE}/health`),
      axios.get(`${API_BASE}/stats/daily-detections`),
      axios.get(`${API_BASE}/stats/tops`),
      axios.get(`${API_BASE}/stats/soar-roi`),
      axios.get(`${API_BASE}/audit/cmmi-v3-report`),
      axios.get(`${API_BASE}/audit/iso27001-report`),
      axios.get(`${API_BASE}/stats/dashboard-charts`),
      axios.get(`${API_BASE}/stats/severity-by-category`),
    ])
    return { resHealth, resDaily, resTops, resRoi, resCmmi, resIso, resCharts, resSeverityCat }
  }
  const coreQuery = useQuery({
    queryKey: ['dashboard-core', assetFilter, soarCategoryFilter, soarStatusFilter],
    queryFn: fetchCore, enabled: !!auth.isAuthenticated, refetchInterval: POLL_MS, placeholderData: keepPreviousData,
  })
  const secondaryQuery = useQuery({
    queryKey: ['dashboard-secondary'], queryFn: fetchSecondary, enabled: !!auth.isAuthenticated, refetchInterval: POLL_MS,
  })
  useEffect(() => {
    const d = coreQuery.data
    if (!d) return
    setStats(d.resStats.data || { alerts: 0, endpoints: 0, users: 0, private_hosts: 0, public_hosts: 0 })
    setVulnStats(d.resVulns.data || { total: 0, critical: 0, high: 0, pending_ia: 0, pending_approval: 0 })
    setMapData(Array.isArray(d.resMap.data) ? d.resMap.data.filter(m => m.location_lat && m.location_lon) : [])
    setAlerts(Array.isArray(d.resAlerts.data) ? d.resAlerts.data : [])
    setRiskData(Array.isArray(d.resRisk.data) ? d.resRisk.data : [])
    setInventory(Array.isArray(d.resInv.data) ? d.resInv.data : [])
    setRemediationLog(Array.isArray(d.resRem.data) ? d.resRem.data : [])
    setLastSync(new Date())
  }, [coreQuery.dataUpdatedAt])
  useEffect(() => {
    if (coreQuery.error) console.error("Error fetching dashboard data:", coreQuery.error)
    if (coreQuery.data || coreQuery.error) setLoading(false)      // release the full-screen lock once the first round settles (ok or not)
  }, [coreQuery.dataUpdatedAt, coreQuery.errorUpdatedAt])
  useEffect(() => {
    const d = secondaryQuery.data
    if (!d) return
    setHealthStatus(d.resHealth.data && d.resHealth.data.services ? d.resHealth.data : { services: [] })
    setDailyDetections(Array.isArray(d.resDaily.data) ? d.resDaily.data : [])
    setTops(d.resTops.data || { recent_assets: [], most_vulnerable: [], most_remediated: [] })
    setRoiStats(d.resRoi.data || { avg_remediation_time_minutes: 0, effectiveness_rate_percentage: 0, comparison: { ai_resolved: 0, manual_resolved: 0 } })
    setCmmiReport(d.resCmmi.data?.report || { overall_cmmi_compliance_rate: null, assets_audit: [] })
    setIsoReport(d.resIso.data?.report || { overall_iso_compliance_rate: null, assets_audit: [] })
    setDashboardCharts(d.resCharts.data || { cis_grade_distribution: [], top_mitre_techniques: [], crs_distribution: [], sla_compliance_percentage: null })
    setSeverityByCategory(d.resSeverityCat.data || { infra: {}, code: {} })
  }, [secondaryQuery.dataUpdatedAt])
  useEffect(() => {
    if (secondaryQuery.error) console.error("Error fetching secondary dashboard metrics:", secondaryQuery.error)
  }, [secondaryQuery.errorUpdatedAt])
  // Call sites after a mutation ask for fresh data; refetch() on an in-flight query is deduplicated by the library.
  const fetchData = () => Promise.all([coreQuery.refetch(), secondaryQuery.refetch()])

  if (auth.isLoading) {
    return (
      <div className="h-screen bg-[#0F172A] flex flex-col items-center justify-center text-[#06B6D4]">
        <Activity size={48} className="animate-spin mb-4" />
        <p className="font-bold tracking-[0.2em] animate-pulse uppercase text-xs">Cargando Sesión...</p>
      </div>
    )
  }

  if (currentUserRole === 'Disabled') {
    return (
      <div className="h-screen bg-[#0F172A] flex flex-col items-center justify-center text-red-400 p-8 text-center">
        <ShieldAlert size={64} className="mb-6" />
        <h2 className="text-2xl font-black mb-2 uppercase tracking-tighter">Acceso deshabilitado</h2>
        <p className="max-w-md text-slate-500 font-bold text-sm mb-8">Tu cuenta no tiene un rol activo en Centinela. Solicita a un administrador que te habilite.</p>
        <button onClick={handleLogout} className="px-8 py-4 bg-slate-800 text-white font-black uppercase text-xs tracking-widest rounded-2xl hover:bg-slate-700 transition-all">Cerrar sesión</button>
      </div>
    )
  }

  if (auth.error) {
    return (
      <div className="h-screen bg-[#0F172A] flex flex-col items-center justify-center text-red-400 p-8 text-center">
        <ShieldAlert size={64} className="mb-6" />
        <h2 className="text-2xl font-black mb-2 uppercase tracking-tighter">Error de Autenticación</h2>
        <p className="max-w-md text-slate-500 font-bold text-sm mb-8">{auth.error.message}</p>
        <button 
          onClick={() => auth.signinRedirect()}
          className="px-8 py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-xs tracking-widest rounded-2xl hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20"
        >
          Reintentar Acceso
        </button>
      </div>
    )
  }

  if (!auth.isAuthenticated) {
    return (
      <div className="h-screen bg-[#0F172A] flex flex-col items-center justify-center p-8 text-center overflow-hidden relative">
        <div className="absolute top-0 left-0 w-full h-full" style={{ backgroundImage: 'radial-gradient(circle at 50% 50%, rgba(6, 182, 212, 0.06), transparent 50%)' }} />
        <div className="z-10 animate-in fade-in zoom-in duration-700">
            <div className="w-24 h-24 bg-[#06B6D4]/10 rounded-3xl border border-[#06B6D4]/20 flex items-center justify-center text-[#06B6D4] mb-8 mx-auto shadow-2xl shadow-[#06B6D4]/10">
                <ShieldCheck size={48} />
            </div>
            <h1 className="text-white text-5xl font-black tracking-tighter mb-4">Centinela <span className="text-[#06B6D4]">AI</span></h1>
            <p className="text-slate-500 font-bold uppercase tracking-[0.3em] text-[12px] mb-12">Mando de Seguridad Regional</p>
            <button 
                onClick={() => auth.signinRedirect()}
                className="group relative px-12 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-xs tracking-[0.2em] rounded-[24px] hover:bg-white transition-all shadow-[0_20px_50px_rgba(6,182,212,0.3)] hover:shadow-[0_20px_50px_rgba(255,255,255,0.2)] active:scale-95"
            >
                <div className="flex items-center gap-3">
                    Iniciar Sesión con Authentik
                    <ChevronRight size={16} className="group-hover:translate-x-1 transition-transform" />
                </div>
            </button>
            <div className="mt-16 flex items-center justify-center gap-8 text-[11px] font-black text-slate-700 uppercase tracking-widest">
                <div className="flex items-center gap-2"><Globe size={12} /> Vista global</div>
                <div className="w-1 h-1 rounded-full bg-slate-800" />
                <div className="flex items-center gap-2"><Activity size={12} /> Nodo Centralizado</div>
            </div>
        </div>
      </div>
    )
  }

  const handleTestConnection = async () => {
    setConnTest({ loading: true })
    try {
      const res = await axios.post(`${API_BASE}/inventory/test-connection`, {
        endpoint: newAsset.endpoint,
        asset_type: newAsset.asset_type,
        user: newAsset.vault_ansible_user || '',
        auth_type: newAsset.auth_type,
        password: newAsset.vault_sudo_token || '',
        ssh_private_key: newAsset.ssh_private_key || '',
      }, { timeout: 90000 })
      setConnTest(res.data)
    } catch (error) {
      setConnTest({ ok: false, steps: [{ id: 'req', label: 'Prueba de conexión', status: 'fail',
        detail: error.response?.data?.detail || error.message }] })
    }
  }

  const handleDeleteAsset = async (name) => {
    if (!window.confirm(`¿Eliminar el activo "${name}" y TODOS sus hallazgos, remediaciones y alertas asociados?\n\nEsta acción no se puede deshacer.`)) return
    try {
      const res = await axios.delete(`${API_BASE}/inventory`, { params: { asset_name: name, confirm: name } })
      alert(`🗑️ Activo eliminado: ${res.data.findings_deleted} hallazgos, ${res.data.remediations_deleted} remediaciones y ${res.data.alerts_deleted} alertas.` +
            (res.data.note ? `\n\n⚠️ ${res.data.note}` : ''))
      await fetchData()
    } catch (error) {
      console.error("Error deleting asset:", error)
      alert("No se pudo eliminar el activo: " + (error.response?.data?.detail || error.message))
    }
  }

  const handleAddAsset = async (e) => {
    e.preventDefault()
    if (isRootUser(newAsset.vault_ansible_user) && newAsset.agent_mode !== 'PING_ONLY') {
      alert('No se permite registrar el usuario root. Usa un usuario normal con privilegios sudo (p. ej. "centinela" o "ubuntu").')
      return
    }
    if (newAsset.asset_type === 'SOURCE_ZIP') {
      if (!newAssetZip) { alert('Selecciona el archivo .zip con el código.'); return }
      try {
        const form = new FormData()
        form.append('asset_name', newAsset.asset_name)
        form.append('criticality', newAsset.criticality)
        form.append('file', newAssetZip)
        const res = await axios.post(`${API_BASE}/inventory/source-zip`, form, { timeout: 300000 })
        setShowAddModal(false)
        setNewAssetZip(null)
        setNewAsset({ asset_name: '', asset_type: '', endpoint: '', criticality: 'MEDIUM', vault_sudo_token: '', vault_ansible_user: '', auth_type: 'PASSWORD', ssh_private_key: '', gitlab_user: '', gitlab_token: '', agent_mode: 'AGENT', ipv6_endpoint: '' })
        setCurrentView('inventory')
        await fetchData()
        alert(`✅ ${res.data.files} archivos recibidos como "${res.data.asset_name}".\n${res.data.message}`)
      } catch (error) {
        console.error("Error uploading source zip:", error)
        alert("Error al subir el código: " + (error.response?.data?.detail || error.message))
      }
      return
    }
    try {
        const payload = { ...newAsset }
        // If ping-only mode, clear credentials so they are not sent
        if (newAsset.agent_mode === 'PING_ONLY') {
            payload.vault_sudo_token = ''
            payload.vault_ansible_user = ''
            payload.ssh_private_key = ''
        }
        const res = await axios.post(`${API_BASE}/inventory`, payload)
        setShowAddModal(false)
        const addedName = newAsset.asset_name
        const addedType = newAsset.asset_type
        setNewAsset({ asset_name: '', asset_type: '', endpoint: '', criticality: 'MEDIUM', vault_sudo_token: '', vault_ansible_user: '', auth_type: 'PASSWORD', ssh_private_key: '', gitlab_user: '', gitlab_token: '', agent_mode: 'AGENT', ipv6_endpoint: '' })
        setInventorySearch('')
        setInventoryTypeFilter('')
        setAssetStatusFilter('ALL')
        setCurrentView('inventory')
        await fetchData()
        // Offer agent download for agent-capable asset types registered in AGENT mode
        if (payload.agent_mode === 'AGENT' && ['SERVER_LINUX','SERVER_WINDOWS','WORKSTATION'].includes(addedType)) {
            setAgentModalAsset({ name: addedName, type: addedType, endpoint: payload.endpoint })
            setAgentModalTab('guide')
            setShowAgentModal(true)
        }
    } catch (error) {
        console.error("Error adding asset:", error)
        alert("Error al registrar el activo: " + (error.response?.data?.detail || error.message))
    }
  }

  const handleDownloadAgent = async (assetName, platform) => {
    setAgentDownloading(true)
    try {
        const res = await axios.get(`${API_BASE}/inventory/${encodeURIComponent(assetName)}/agent-installer?platform=${platform}`, {
            responseType: 'blob'
        })
        const ext = platform === 'windows' ? '.ps1' : '.sh'
        const filename = `centinela-wazuh-install-${assetName}${ext}`
        const url = window.URL.createObjectURL(new Blob([res.data]))
        const link = document.createElement('a')
        link.href = url
        link.download = filename
        document.body.appendChild(link)
        link.click()
        link.remove()
        window.URL.revokeObjectURL(url)
    } catch (err) {
        alert('Error al generar el script de instalación: ' + (err.response?.data?.detail || err.message))
    } finally {
        setAgentDownloading(false)
    }
  }

  const handleInvestigate = async (alertId) => {
    setIsInvestigating(true)
    setShowInvestigateModal(true)
    setInvestigationData(null)
    try {
        const res = await axios.post(`${API_BASE}/investigate/runtime`, { alert_id: alertId })
        setInvestigationData(res.data)
    } catch (error) {
        console.error("Error investigating alert:", error)
    } finally {
        setIsInvestigating(false)
    }
  }

  const handleLogout = () => {
    auth.signoutRedirect()
  }

  const handleViewScript = async (vulnId) => {
    setScriptLoading(true)
    setShowScriptModal(true)
    setScriptContent('')
    try {
        const res = await axios.get(`${API_BASE}/remediation/script/${vulnId}`)
        setScriptContent(res.data.content)
    } catch (error) {
        console.error("Error fetching script:", error)
        setScriptContent("# Error al cargar el script maestro de la IA.\n# Verifique la conectividad con el servidor de seguridad.")
    } finally {
        setScriptLoading(false)
    }
  }

  const handleDownloadScript = () => {
    const element = document.createElement("a");
    const file = new Blob([scriptContent], {type: 'text/plain'});
    element.href = URL.createObjectURL(file);
    element.download = `remediation_${selectedRemediation?.cve_id || 'script'}_${new Date().getTime()}.sh`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  }

  const handleExecuteRemediation = async (vulnId) => {
    try {
        const res = await axios.post(`${API_BASE}/remediation/approve/${vulnId}`)
        alert("✅ Orden de Remediación enviada con éxito.\n\nEl Agente Aura-Sentinel ha recibido la instrucción y está procediendo con la ejecución remota vía Wazuh/Docker.\n\nEl estatus del activo se actualizará a 'RESOLVED' automáticamente al finalizar.")
        fetchData()
    } catch (error) {
        console.error("Error executing remediation:", error)
        alert("❌ Error crítico: No se pudo contactar con el Agente de Remediación.")
    }
  }

  const handleManualRemediation = async (e) => {
    e.preventDefault()
    if (!manualSolution || !manualReason) {
        alert("Por favor complete todos los campos.")
        return
    }
    
    setManualSaving(true)
    try {
        await axios.post(`${API_BASE}/remediation/manual/${selectedRemediation.id}`, {
            solution: manualSolution,
            reason: manualReason
        })
        setShowManualModal(false)
        setManualSolution('')
        setManualReason('')
        setSelectedRemediation(null)
        fetchData()
        alert("✅ Vulnerabilidad marcada como remediada manualmente.")
    } catch (error) {
        console.error("Error in manual remediation:", error)
        alert("❌ Error al procesar la remediación manual.")
    } finally {
        setManualSaving(false)
    }
  }

  const handleOpenDetailsModal = async (group) => {
    setDetailsTarget(group)
    setAgentInfo(null)
    setShowDetailsModal(true)
    // If the asset has a Wazuh agent, fetch live OS/kernel info from the Manager
    if (group.agent_id) {
      setAgentInfoLoading(true)
      try {
        const res = await axios.get(`${API_BASE}/wazuh/agent/${group.agent_id}/info`)
        setAgentInfo(res.data)
      } catch (err) {
        console.warn('Could not fetch Wazuh agent info:', err.message)
      } finally {
        setAgentInfoLoading(false)
      }
    }
  }

  const handleOpenVaultModal = (assetName) => {
    setVaultTarget(assetName)
    setVaultPassword('')
    setVaultUser('')
    setVaultAuthType('PASSWORD')
    setVaultSshKey('')
    setVaultResult(null)
    setShowVaultModal(true)
  }

  const handleSaveVaultSecret = async (e) => {
    e.preventDefault()
    if (vaultAuthType === 'PASSWORD' && !vaultPassword) return
    if (vaultAuthType === 'SSH_KEY' && !vaultSshKey) return
    setVaultSaving(true)
    setVaultResult(null)
    try {
      await axios.post(`${API_BASE}/inventory/${encodeURIComponent(vaultTarget)}/vault-secret`, {
        sudo_password: vaultAuthType === 'PASSWORD' ? vaultPassword : undefined,
        ssh_private_key: vaultAuthType === 'SSH_KEY' ? vaultSshKey : undefined,
        ansible_user: vaultUser || undefined
      })
      setVaultResult({ ok: true, msg: `Credencial de '${vaultTarget}' almacenada en Vault. Aura-Sentinel la usará automáticamente.` })
      setVaultPassword('')
      setVaultSshKey('')
    } catch (err) {
      const detail = err?.response?.data?.detail || 'Error desconocido al conectar con Vault.'
      setVaultResult({ ok: false, msg: detail })
    } finally {
      setVaultSaving(false)
    }
  }

  const handlePingAsset = async (assetName) => {
    setPingResults(prev => ({ ...prev, [assetName]: { loading: true } }))
    try {
      const res = await axios.post(`${API_BASE}/inventory/${encodeURIComponent(assetName)}/ping`)
      setPingResults(prev => ({ ...prev, [assetName]: res.data }))
    } catch (err) {
      setPingResults(prev => ({
        ...prev,
        [assetName]: { status: 'OFFLINE', ping_ok: false, message: 'Host inalcanzable u offline' }
      }))
    }
  }

  const handleOpenAssetDetails = async (group) => {
    setShowAssetDetailsModal(true)
    setAssetDetailsLoading(true)
    let currentPing = pingResults[group.name] || null
    try {
      if (!currentPing) {
        try {
          const resPing = await axios.post(`${API_BASE}/inventory/${encodeURIComponent(group.name)}/ping`)
          currentPing = resPing.data
        } catch (e) {
          currentPing = { status: group.status === 'active' ? 'ONLINE' : 'OFFLINE', ping_ok: group.status === 'active', latency_ms: 0.2 }
        }
      }
      
      const resDetails = await axios.get(`${API_BASE}/inventory/${encodeURIComponent(group.name)}/details`)
      const deepDetails = resDetails.data || null
      setAssetDetailsData({ group, info: deepDetails, ping: currentPing })
    } catch (err) {
      console.error("Error fetching asset details:", err)
      setAssetDetailsData({ group, info: null, ping: { status: group.status === 'active' ? 'ONLINE' : 'OFFLINE', ping_ok: group.status === 'active' } })
    } finally {
      setAssetDetailsLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="h-screen bg-[#0F172A] flex flex-col items-center justify-center text-[#06B6D4]">
        <Activity size={48} className="animate-spin mb-4" />
        <p className="font-bold tracking-[0.2em] animate-pulse uppercase text-xs">Sincronizando con Repositorio Central...</p>
      </div>
    )
  }

  const handleSelectAsset = (assetName) => {
    setShowReportModal(false)
    setShowInvestigateModal(false)
    setShowScriptModal(false)
    setShowManualModal(false)
    setShowVaultModal(false)
    setSelectedRemediation(null)
    setInvestigationData(null)
    setAssetFilter(assetName)
    // Drill in on the same set the inventory card counted: real vulnerabilities pending
    // remediation. The user can switch CATEGORÍA to INFORMATIVO to also see markers/quality.
    setSoarCategoryFilter('VULNERABILITY')
    setCurrentView('soar')
  }

  const filteredAlerts = Array.isArray(alerts) ? alerts.filter(a => {
    const matchSeverity = severityFilter ? normSev(a.priority) === severityFilter : true;
    const matchAsset = assetFilter ? a.asset_name === assetFilter : true;
    return matchSeverity && matchAsset;
  }) : [];

  // Derived from filteredAlerts (severity/asset filters, also used by the Dashboard's compact
  // "recent alerts" widget) rather than replacing it outright, so free-text search/sort scoped
  // to the Búsqueda de Amenazas panel doesn't leak into that other, unrelated widget.
  const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
  const threatHuntingAlerts = (() => {
    const term = threatSearch.trim().toLowerCase()
    const searched = term ? filteredAlerts.filter(a => (
      (a.rule_name || '').toLowerCase().includes(term) ||
      (a.alert_text || '').toLowerCase().includes(term) ||
      (a.asset_name || '').toLowerCase().includes(term)
    )) : filteredAlerts
    const sorted = [...searched]
    if (threatSortBy === 'oldest') {
      sorted.sort((a, b) => new Date(a.detected_at) - new Date(b.detected_at))
    } else if (threatSortBy === 'severity') {
      sorted.sort((a, b) => (SEVERITY_RANK[normSev(a.priority)] ?? 9) - (SEVERITY_RANK[normSev(b.priority)] ?? 9))
    } else {
      sorted.sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at))
    }
    return sorted
  })()

  const filteredRemediations = Array.isArray(remediationLog) ? remediationLog.filter(r => {
    const targetAsset = assetFilter ? assetFilter.toLowerCase().trim() : '';
    const logAsset = r.asset_name ? r.asset_name.toLowerCase().trim() : '';
    const matchAsset = assetFilter ? (
      logAsset === targetAsset ||
      logAsset.includes(targetAsset) ||
      targetAsset.includes(logAsset)
    ) : true;
    const matchSeverity = soarSeverityFilter && soarSeverityFilter !== 'ALL' ? r.severity === soarSeverityFilter : true;
    const matchStatus = soarStatusFilter && soarStatusFilter !== 'ALL' ? (
      soarStatusFilter === 'REMEDIADO' ? r.executed_bool === true :
      soarStatusFilter === 'CORRELATED' ? r.status === 'CORRELATED' && !r.executed_bool :
      soarStatusFilter === 'PENDIENTE' ? (r.status === 'NEW' || r.status === 'PENDING') && !r.executed_bool :
      soarStatusFilter === 'AI_FAILED' ? r.status === 'AI_FAILED' && !r.executed_bool : true
    ) : true;
    const matchSearch = soarSearch ? (
      r.cve_id?.toLowerCase().includes(soarSearch.toLowerCase()) ||
      r.script_path?.toLowerCase().includes(soarSearch.toLowerCase())
    ) : true;
    const matchCategory = soarCategoryFilter && soarCategoryFilter !== 'ALL' ? r.finding_category === soarCategoryFilter : true;
    const matchAssetCategory = soarAssetCategoryFilter && soarAssetCategoryFilter !== 'ALL' ? r.asset_category === soarAssetCategoryFilter : true;
    return matchAsset && matchSeverity && matchStatus && matchSearch && matchCategory && matchAssetCategory;
  }) : [];

  // CIS Benchmarks (Hardening Level 1) grade badge -- shared by the inventory grid card, the
  // table row, and the asset detail modal so the color/label logic can't drift between them.
  // grade is null both when never audited (checkedAt also null) and when audited but genuinely
  // unreachable via SSH (checkedAt set, grade null) -- mirrors auditor_cis_benchmarks.py's own
  // honest SIN_CONEXION distinction instead of collapsing both into one ambiguous state.
  const getCisGradeBadge = (grade, checkedAt, percentage) => {
    if (!checkedAt) {
      return { label: 'CIS: No Evaluado', className: 'bg-slate-800 text-slate-400 border-slate-700', title: 'Auditoría de hardening CIS Level 1 aún no ejecutada sobre este activo' }
    }
    if (!grade) {
      return { label: 'CIS: Sin Conexión', className: 'bg-slate-700/50 text-slate-400 border-slate-600', title: `Última auditoría CIS (${new Date(checkedAt).toLocaleString('es-MX')}) no pudo conectarse por SSH al activo` }
    }
    const colorByGrade = {
      A: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      B: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      C: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      F: 'bg-red-500/10 text-red-400 border-red-500/20',
    }
    return {
      label: `CIS: Grade ${grade} (${percentage}%)`,
      className: colorByGrade[grade] || 'bg-slate-800 text-slate-400 border-slate-700',
      title: `Auditoría CIS Benchmarks Level 1: ${percentage}% de controles verificados aprobados (${new Date(checkedAt).toLocaleString('es-MX')})`,
    }
  }

  // Plain-language translation for the technical finding text shown in the CMMI/ISO detail
  // breakdown (f.issue, format "CVE_ID: raw description"). Matched by cve_id PREFIX since real
  // cve_ids often carry a file/line/hash suffix. Falls back to the raw technical text unchanged
  // when no known prefix matches -- this never hides or alters what a finding actually says,
  // it only adds a friendlier summary line above it for readers who aren't security engineers.
  const FINDING_PLAIN_LANGUAGE = [
    { prefix: 'CMMI-CAR-SWALLOWED-EXCEPTION', text: 'El código ignora errores en silencio (bloque "except: pass"), lo que dificulta detectar y corregir fallas reales cuando ocurren.' },
    { prefix: 'CMMI-MSR-HARDCODED-SLEEP', text: 'El código tiene una espera fija (sleep) programada directamente, lo que puede volver el sistema lento o impredecible.' },
    { prefix: 'CMMI-PQA-DEBT-TODO', text: 'Hay una nota "TODO" (tarea pendiente sin resolver) dejada en el código que ya está en producción.' },
    { prefix: 'HARDCODED-SECRET', text: 'Se encontró una contraseña o credencial escrita directamente en el código fuente, en vez de guardarla de forma segura.' },
    { prefix: 'SECRETS-', text: 'Se encontró una credencial o llave de acceso expuesta directamente en el código o configuración.' },
    { prefix: 'SCA-CVE', text: 'Una librería externa que usa este proyecto tiene una vulnerabilidad de seguridad conocida y públicamente documentada.' },
    { prefix: 'DOCKER-MISSING-NON-ROOT-USER', text: 'El contenedor Docker se ejecuta como usuario administrador (root), lo que aumenta el riesgo si llegara a ser comprometido.' },
    { prefix: 'DOCKER-ROOT-USER', text: 'El contenedor Docker se ejecuta como usuario administrador (root), lo que aumenta el riesgo si llegara a ser comprometido.' },
    { prefix: 'CODE-INJECTION-EVAL', text: 'El código ejecuta texto como si fuera código (eval), una práctica riesgosa que puede permitir ejecución de comandos no autorizados.' },
    { prefix: 'SQL-INJECTION', text: 'El código construye consultas a la base de datos de forma insegura, lo que podría permitir manipular o robar datos.' },
    { prefix: 'ZAP-', text: 'Vulnerabilidad detectada probando la aplicación en funcionamiento (no en el código fuente), como lo haría un atacante real.' },
    { prefix: 'STD-ISO25010-LONG-METHOD', text: 'Una función del código es demasiado larga, lo que dificulta su mantenimiento y aumenta el riesgo de errores futuros.' },
    { prefix: 'COGNITIVE-COMPLEXITY-EXCEEDED', text: 'Una función del código es demasiado compleja de seguir, lo que dificulta su mantenimiento y aumenta el riesgo de errores futuros.' },
    { prefix: 'CIS-', text: 'Un control de hardening de sistema operativo (CIS Level 1) no está configurado según el estándar.' },
  ]
  const getFindingPlainLanguage = (issueText) => {
    const cveId = String(issueText || '').split(':')[0].trim().toUpperCase()
    const match = FINDING_PLAIN_LANGUAGE.find(m => cveId.startsWith(m.prefix))
    return match ? match.text : null
  }

  // Grouping logic for inventory
  const groupedInventory = inventory.reduce((acc, item) => {
    if (!acc[item.asset_name]) {
      acc[item.asset_name] = {
        name: item.asset_name,
        max_id: item.max_id || item.id || '',
        vulnerability_count: 0,
        resolved_count: 0,
        runtime_alerts_count: 0,
        interfaces: [],
        status: item.status,
        agent_id: item.agent_id,
        has_vault_secret: item.has_vault_secret,
        last_seen: item.last_seen
      }
    }
    {
      // UUIDv7 ids sort lexicographically in creation order, same property the old integer ids
      // had -- string comparison (not Math.max) picks "most recently created" correctly.
      const candidateId = item.max_id || item.id || ''
      if (candidateId > acc[item.asset_name].max_id) acc[item.asset_name].max_id = candidateId
    }
    acc[item.asset_name].vulnerability_count += parseInt(item.vulnerability_count || 0)
    acc[item.asset_name].resolved_count += parseInt(item.resolved_count || 0)
    acc[item.asset_name].runtime_alerts_count += parseInt(item.runtime_alerts_count || 0)
    acc[item.asset_name].interfaces.push(item)
    return acc
  }, {})

  const processedInventory = Array.isArray(Object.values(groupedInventory)) ? Object.values(groupedInventory)
    .filter(group => {
        const matchSearch = inventorySearch ? 
            group.name.toLowerCase().includes(inventorySearch.toLowerCase()) || 
            group.interfaces.some(i => i.endpoint.toLowerCase().includes(inventorySearch.toLowerCase())) : true;
        
        const matchType = inventoryTypeFilter ? 
            group.interfaces.some(i => i.asset_type === inventoryTypeFilter) : true;
            
        const matchStatus = assetStatusFilter === 'VULNERABLE' ? group.vulnerability_count > 0 :
                           assetStatusFilter === 'ATTACKED' ? group.runtime_alerts_count > 0 : true;

        return matchSearch && matchType && matchStatus;
    })
    .sort((a, b) => {
        if (inventorySortBy === 'alpha') return a.name.localeCompare(b.name);
        if (inventorySortBy === 'vulns') return b.vulnerability_count - a.vulnerability_count;
        if (inventorySortBy === 'alerts') return b.runtime_alerts_count - a.runtime_alerts_count;
        return String(b.max_id || '').localeCompare(String(a.max_id || '')) || a.name.localeCompare(b.name);
    }) : [];

  const dashboardCtx = {
    activeCmmiAreaFilter,
    agentDownloading,
    agentInfo,
    agentInfoLoading,
    agentModalAsset,
    agentModalTab,
    assetDetailsData,
    assetDetailsLoading,
    assetFilter,
    assetStatusFilter,
    availableModels,
    cmmiReport,
    configLoading,
    configSaving,
    connTest,
    currentUserRole,
    dailyDetections,
    dashboardCharts,
    detailsTarget,
    fetchModelsForProvider,
    fetchSystemConfig,
    fetchUsers,
    filteredAlerts,
    filteredRemediations,
    getCisGradeBadge,
    getFindingPlainLanguage,
    handleAddAsset,
    handleDeleteAsset,
    handleDownloadAgent,
    handleDownloadAssetReport,
    handleDownloadCmmiAssetReport,
    handleDownloadComparison,
    fetchReport,
    handleViewComparisonHtml,
    handleDownloadGroupComparison,
    handleDownloadScript,
    handleDownloadVulnerabilityReport,
    handleExecuteRemediation,
    handleInvestigate,
    handleManualRemediation,
    handleOpenAssetDetails,
    handleOpenDetailsModal,
    handleOpenVaultModal,
    handlePingAsset,
    handleSaveConfig,
    handleSaveVaultSecret,
    handleSelectAsset,
    handleTestConnection,
    handleUpdateUserRole,
    handleViewAssetReportHtml,
    handleViewScript,
    handleWazuhAction,
    handleWazuhUninstall,
    healthStatus,
    inventory,
    inventorySearch,
    inventorySortBy,
    inventoryTypeFilter,
    inventoryViewMode,
    investigationData,
    isInvestigating,
    isRootUser,
    isoReport,
    itdrAnomalies,
    itdrEvents24h,
    itdrEventsRecent,
    itdrLoading,
    loadingModels,
    manualReason,
    manualSaving,
    manualSolution,
    mapData,
    newAsset,
    pingResults,
    processedInventory,
    remediationLog,
    riskData,
    roiStats,
    scriptContent,
    scriptLoading,
    selectedRemediation,
    setActiveCmmiAreaFilter,
    setAgentModalAsset,
    setAgentModalTab,
    setAssetFilter,
    setAssetStatusFilter,
    setConnTest,
    setCurrentView,
    setInventorySearch,
    setInventorySortBy,
    setInventoryTypeFilter,
    setInventoryViewMode,
    setManualReason,
    setManualSolution,
    setNewAsset,
    setNewAssetZip,
    setSelectedRemediation,
    setSeverityFilter,
    setShowAddModal,
    setShowAgentModal,
    setShowAssetDetailsModal,
    setShowDetailsModal,
    setShowInvestigateModal,
    setShowManualModal,
    setShowReportModal,
    setShowScriptModal,
    setShowVaultModal,
    setSoarAssetCategoryFilter,
    setSoarCategoryFilter,
    setSoarSearch,
    setSoarSeverityFilter,
    setSoarStatusFilter,
    setSystemConfig,
    setThreatSearch,
    setThreatSortBy,
    setVaultAuthType,
    setVaultPassword,
    setVaultSshKey,
    setVaultUser,
    severityByCategory,
    severityFilter,
    soarAssetCategoryFilter,
    soarCategoryFilter,
    soarSearch,
    soarSeverityFilter,
    soarStatusFilter,
    stats,
    systemConfig,
    threatHuntingAlerts,
    threatSearch,
    threatSortBy,
    tops,
    usersList,
    usersLoading,
    vaultAuthType,
    vaultPassword,
    vaultResult,
    vaultSaving,
    vaultSshKey,
    vaultTarget,
    vaultUser,
    vulnStats,
    wazuhActionLoading,
  }

  return (
    <DashboardContext.Provider value={dashboardCtx}>
<div className="flex h-screen bg-[#0F172A] text-slate-300 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-20 lg:w-64 bg-[#1E293B] flex flex-col border-r border-slate-800 transition-all z-30">
        <div className="p-6 flex items-center gap-3 border-b border-slate-800">
          <div className="bg-[#06B6D4]/20 p-2 rounded-xl">
            <ShieldAlert className="text-[#06B6D4]" size={24} />
          </div>
          <div className="hidden lg:block">
            <p className="font-black text-xl tracking-tighter text-white leading-none">CENTINELA</p>
            <p className="text-[12px] text-[#06B6D4] font-black tracking-widest uppercase">Mando Regional</p>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-2 mt-4">
          <NavItem 
            icon={<LayoutDashboard size={20} />} 
            label="Dashboard" 
            active={currentView === 'dashboard'} 
            onClick={() => { setCurrentView('dashboard'); setSeverityFilter(null); setAssetFilter(null); setSoarCategoryFilter('ALL'); }}
          />
          <NavItem 
            icon={<ShieldAlert size={20} />} 
            label="Búsqueda de Amenazas" 
            active={currentView === 'threat-hunting'} 
            onClick={() => setCurrentView('threat-hunting')}
          />
          <NavItem 
            icon={<UserCheck size={20} />} 
            label="Identidad & ITDR" 
            active={currentView === 'itdr'} 
            onClick={() => setCurrentView('itdr')}
          />
          <NavItem 
            icon={<Database size={20} />} 
            label="Inventario de Activos" 
            active={currentView === 'inventory'} 
            onClick={() => setCurrentView('inventory')}
          />
          <NavItem 
            icon={<Zap size={20} />} 
            label="Remediación con IA" 
            active={currentView === 'soar'} 
            onClick={() => setCurrentView('soar')}
          />
          <NavItem 
            icon={<ShieldCheck size={20} />} 
            label="Supresiones IA" 
            active={currentView === 'suppressions'} 
            onClick={() => setCurrentView('suppressions')}
          />
          <NavItem 
            icon={<FlaskConical size={20} />} 
            label="Pruebas funcionales" 
            active={currentView === 'functional-tests'} 
            onClick={() => setCurrentView('functional-tests')}
          />
          <NavItem 
            icon={<Gauge size={20} />} 
            label="Tokens IA" 
            active={currentView === 'ai-tokens'} 
            onClick={() => setCurrentView('ai-tokens')}
          />
          <NavItem 
            icon={<Activity size={20} />} 
            label="Salud del Sistema" 
            active={currentView === 'health'} 
            onClick={() => setCurrentView('health')}
          />
          <NavItem 
            icon={<Users size={20} />} 
            label="Gestión Usuarios" 
            active={currentView === 'users'} 
            onClick={() => { setCurrentView('users'); fetchUsers(); }}
          />
          {currentUserRole === 'Admin' && (
            <NavItem
              icon={<Cpu size={20} />}
              label="Configuración Sistema"
              active={currentView === 'settings'}
              onClick={() => { setCurrentView('settings'); fetchSystemConfig(); }}
            />
          )}
          <NavItem
            icon={<FileText size={20} />}
            label="Manual de Uso"
            onClick={() => window.open('/api/manual', '_blank', 'noopener,noreferrer')}
          />
          <NavItem
            icon={<FileText size={20} />}
            label="Glosario"
            onClick={() => window.open('/api/glosario', '_blank', 'noopener,noreferrer')}
          />
        </nav>

        <div className="p-4 border-t border-slate-800">
          {currentUserRole === 'Admin' && (
            <button 
              onClick={() => setShowAddModal(true)}
              className="w-full hidden lg:flex items-center gap-3 p-3 mb-4 rounded-xl bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20"
            >
              <Plus size={20} />
              Añadir Activo
            </button>
          )}
          <div className="hidden lg:block mb-4 px-3">
            <p className="text-[11px] text-slate-500 font-bold uppercase tracking-widest">Sincronización</p>
            <div className="text-[12px] text-emerald-500 font-bold uppercase tracking-tighter flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                {lastSync.toLocaleTimeString()}
            </div>
          </div>
          <button 
            onClick={handleLogout}
            className="w-full flex items-center justify-center lg:justify-start gap-3 p-3 rounded-xl hover:bg-red-500/10 text-slate-400 hover:text-red-400 transition-all group"
          >
            <LogOut size={20} />
            <span className="hidden lg:inline font-bold text-sm">Cerrar Sesión</span>
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-[#0A0F1D] relative">
        {/* Top Header */}
        <header className="h-16 border-b border-slate-800 flex items-center justify-between px-8 bg-[#1E293B]/50 backdrop-blur-md sticky top-0 z-20">
          <div className="flex items-center gap-4 text-xs font-bold text-slate-500 uppercase tracking-widest">
            <span className="hover:text-white cursor-pointer transition-colors" onClick={() => setCurrentView('dashboard')}>Red</span>
            <ChevronRight size={14} />
            <span className="hover:text-[#06B6D4] cursor-pointer transition-colors" onClick={() => setCurrentView('dashboard')}>Mando Regional</span>
            <ChevronRight size={14} />
            <span className="text-white uppercase">
              {currentView === 'dashboard' ? 'Dashboard' :
               currentView === 'threat-hunting' ? 'Búsqueda de Amenazas' :
               currentView === 'itdr' ? 'Identidad & ITDR' :
               currentView === 'inventory' ? 'Inventario de Activos' :
               currentView === 'soar' ? 'Remediación con IA' :
               currentView === 'suppressions' ? 'Supresiones IA' :
               currentView === 'functional-tests' ? 'Pruebas funcionales' :
               currentView === 'ai-tokens' ? 'Tokens IA' :
               currentView === 'health' ? 'Salud del Sistema' : currentView}
            </span>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="hidden md:flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-lg border border-slate-800">
              <Search size={14} className="text-slate-500" />
              <input type="text" placeholder="Buscar incidentes..." className="bg-transparent border-none text-[12px] focus:ring-0 w-48 text-slate-300 font-bold placeholder:text-slate-600" />
            </div>
            <button
              onClick={handleDownloadReport}
              className="hidden md:flex items-center gap-2 bg-[#06B6D4]/10 text-[#06B6D4] px-4 py-2 rounded-lg border border-[#06B6D4]/30 hover:bg-[#06B6D4]/20 transition-all font-black text-[12px] uppercase tracking-wider"
            >
              <Download size={14} />
              Reporte PDF
            </button>
            <button
              onClick={handleDownloadCmmiFleetReport}
              title="Descargar reporte PDF de cumplimiento CMMI v3.0 de toda la flota de activos"
              className="hidden lg:flex items-center gap-2 bg-indigo-500/10 text-indigo-400 px-4 py-2 rounded-lg border border-indigo-500/30 hover:bg-indigo-500/20 transition-all font-black text-[12px] uppercase tracking-wider"
            >
              <CheckCircle2 size={14} />
              Reporte CMMI
            </button>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-xs font-bold text-white leading-none">{auth.user?.profile?.name || "Operador"}</p>
                <div className="flex items-center gap-1 justify-end mt-1">
                  <span className={`px-2 py-0.5 text-[11px] font-black rounded-md uppercase tracking-wider ${
                    currentUserRole === 'Admin' ? 'bg-[#06B6D4]/20 text-[#06B6D4] border border-[#06B6D4]/40' :
                    currentUserRole === 'Analyst' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40' :
                    currentUserRole === 'Auditor' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                    currentUserRole === 'Disabled' ? 'bg-red-500/15 text-red-400 border border-red-500/40' :
                    'bg-slate-700/50 text-slate-400 border border-slate-700'
                  }`}>
                    {currentUserRole === 'Admin' ? '🛡️ Admin' :
                     currentUserRole === 'Analyst' ? '⚡ Analista' :
                     currentUserRole === 'Auditor' ? '📋 Auditor' :
                     currentUserRole === 'Disabled' ? '⛔ Deshabilitado' : '👁️ Visualizador'}
                  </span>
                </div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-[#06B6D4]/20 border border-[#06B6D4]/30 flex items-center justify-center text-[#06B6D4] font-black">
                {auth.user?.profile?.preferred_username?.[0]?.toUpperCase() || "A"}
              </div>
            </div>
          </div>
        </header>

        <div className="p-8">
          {currentView === 'dashboard' && (
            <OverviewView />
          )}

          {currentView === 'soar' && (
            <SoarView />
          )}

          {currentView === 'threat-hunting' && (
            <ThreatHuntingView />
          )}

        {currentView === 'inventory' && (
            <InventoryView />
          )}

           {currentView === 'itdr' && (
            <ItdrView />
           )}

           {currentView === 'health' && healthStatus && (
            <HealthView />
          )}

          {currentView === 'functional-tests' && (
            <PruebasFuncionalesView />
          )}

          {currentView === 'ai-tokens' && (
            <TokensIAView />
          )}

          {currentView === 'suppressions' && (
            <SupresionesView reviewer={auth.user?.profile?.preferred_username || auth.user?.profile?.name || 'analyst'} />
          )}

          {adminViewPending && (
            <div className="p-10 text-center text-slate-300">
              {roleError ? (
                <>
                  <p className="text-red-400 font-bold mb-2">No se pudo verificar tu rol: {roleError}</p>
                  <p className="text-slate-500 text-sm mb-4">Esta sección es solo para administradores y no puede mostrarse hasta confirmarlo.</p>
                  <button onClick={fetchUsers} className="px-4 py-2 rounded-xl bg-[#06B6D4]/20 text-[#06B6D4] border border-[#06B6D4]/40 font-bold">Reintentar</button>
                </>
              ) : (
                <p className="animate-pulse">Verificando permisos…</p>
              )}
            </div>
          )}

          {currentView === 'users' && roleChecked && (
            <UsersView />
          )}

          {currentView === 'settings' && roleChecked && (
            <SettingsView />
          )}
        </div>

        {showAddModal && (
            <AddModal />
        )}

        {/* Investigate Modal */}
        {showInvestigateModal && (
            <InvestigateModal />
        )}
        {/* Script Viewer Modal */}
        {showScriptModal && (
            <ScriptModal />
        )}
        {showReportModal && (
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-8 bg-black/80 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-4xl rounded-[48px] border border-emerald-500/30 overflow-hidden shadow-2xl flex flex-col max-h-[85vh]">
                    <div className="p-10 border-b border-white/5 bg-gradient-to-br from-emerald-500/10 to-transparent flex justify-between items-center">
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <div className="p-1.5 rounded-md bg-emerald-500/20 text-emerald-500">
                                    <CheckCircle2 size={14} />
                                </div>
                                <span className="text-emerald-400 font-black text-[12px] uppercase tracking-widest">Remediación Satisfactoria</span>
                            </div>
                            <h2 className="text-white font-black text-3xl tracking-tighter">Informe de Ejecución: {selectedRemediation?.cve_id}</h2>
                            <p className="text-slate-400 text-sm mt-1 font-medium">Trazabilidad completa de acciones realizadas por el Agente Aura-Sentinel.</p>
                        </div>
                        <button 
                            onClick={() => setShowReportModal(false)}
                            className="p-4 bg-slate-800 text-white rounded-full hover:bg-red-500/20 hover:text-red-500 transition-all"
                        >
                            <X size={24} />
                        </button>
                    </div>

                    <div className="flex-1 overflow-y-auto p-10 space-y-8 custom-scrollbar">
                        <section className="bg-[#0F172A]/50 p-10 rounded-[32px] border border-slate-800 text-slate-300 leading-relaxed shadow-inner overflow-hidden">
                            <div className="markdown-report prose prose-invert prose-sm max-w-none prose-cyan">
                                <ReactMarkdown>{selectedRemediation?.log_output || "No se encontró un reporte detallado."}</ReactMarkdown>
                            </div>
                        </section>
                    </div>

                    <div className="p-10 bg-[#0F172A] border-t border-white/5 flex justify-end">
                        <button 
                            onClick={() => setShowReportModal(false)}
                            className="px-12 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-xl shadow-[#06B6D4]/10"
                        >
                            Entendido, cerrar informe
                        </button>
                    </div>
                </div>
            </div>
        )}

        {/* Vault Credential Modal */}
        {showVaultModal && (
            <VaultModal />
        )}

        {showDetailsModal && detailsTarget && (
            <DetailsModal />
        )}

        {showWazuhLogsModal && (
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-2xl rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent flex justify-between items-center">
                        <div>
                            <h3 className="text-white font-bold text-xl tracking-tighter">Logs de Wazuh Manager</h3>
                            <p className="text-[12px] text-slate-500 font-black uppercase tracking-widest mt-0.5">Eventos recientes relacionados al Agente</p>
                        </div>
                        <button onClick={() => setShowWazuhLogsModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={28} />
                        </button>
                    </div>
                    <div className="p-8">
                        <div className="bg-[#0F172A] rounded-2xl p-4 font-mono text-xs text-slate-300 max-h-96 overflow-y-auto space-y-2">
                            {wazuhLogs && wazuhLogs.map((line, idx) => (
                                <div key={idx} className="border-b border-slate-900/50 pb-1 last:border-0">{line}</div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        )}

        {showAssetDetailsModal && assetDetailsData && (
            <AssetDetailsModal />
        )}


        {/* Toast Container */}
        <div className="fixed bottom-6 right-6 z-[120] flex flex-col gap-3 max-w-sm w-full pointer-events-none">
          {toasts.map((toast) => (
            <div 
              key={toast.id} 
              className={`pointer-events-auto p-4 rounded-2xl border bg-[#1E293B]/90 backdrop-blur-md shadow-2xl animate-in slide-in-from-bottom duration-300 flex items-start gap-3 ${
                toast.priority === 'CRITICAL' || toast.priority === 'HIGH' ? 'border-red-500/30' : 'border-slate-800'
              }`}
            >
              <div className={`p-2 rounded-xl ${
                toast.priority === 'CRITICAL' || toast.priority === 'HIGH' ? 'bg-red-500/10 text-red-400' : 'bg-[#06B6D4]/10 text-[#06B6D4]'
              }`}>
                <ShieldAlert size={18} />
              </div>
              <div className="flex-1 min-w-0">
                <h4 className="text-white font-bold text-xs truncate">{toast.title}</h4>
                <p className="text-[12px] text-slate-400 mt-1 line-clamp-2">{toast.message}</p>
              </div>
              <button 
                onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))}
                className="text-slate-500 hover:text-white pointer-events-auto"
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>

        {showManualModal && (
            <ManualModal />
        )}
        {/* ─── Agent Installer Modal ─── */}
        {showAgentModal && agentModalAsset && (
            <AgentModal />
        )}

      </main>
    </div>
</DashboardContext.Provider>
  )
}






