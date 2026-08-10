import React, { useState, useEffect } from 'react'
import axios from 'axios'
import ReactMarkdown from 'react-markdown'
import { useAuth } from 'react-oidc-context'
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Database, 
  AlertTriangle, 
  Activity, 
  LogOut,
  PlusCircle,
  Globe,
  Users,
  Server,
  Zap,
  ChevronRight,
  Search,
  Filter,
  ShieldCheck,
  ZapOff,
  CheckCircle2,
  Lock,
  Shield,
  Clock,
  ExternalLink,
  ShieldX,
  FileText,
  Download,
  Info,
  CheckCircle,
  XCircle,
  Cpu,
  Monitor,
  Plus,
  X,
  Eye,
  Microscope,
  Terminal,
  Container,
  Cloud,
  Layers,
  Link,
  KeyRound,
  ClipboardCheck,
  ClipboardList,
  ChevronDown,
  Laptop,
  RefreshCw,
  Radio,
  UserCheck,
  LayoutGrid,
  List
} from 'lucide-react'
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Cell,
  PieChart,
  Pie,
  Legend
} from 'recharts'
import MapChart from './MapChart'

// Using relative path to utilize the Nginx proxy at /centinela/api/
const API_BASE = "/api"

// /api/health reports honest intermediate states for on-demand/idle capabilities (e.g.
// "Available (On-Demand, Not Yet Run)", "No Data Yet") instead of faking "Online" -- these
// are not failures and must not render as red alongside genuine outages ("Unreachable",
// "Not Installed", "Offline").
function healthStatusTier(status) {
  if (status === 'Online' || status === 'Active') return 'ok'
  if (typeof status === 'string' && /^(Available|No Data|No Recent Data)/.test(status)) return 'warn'
  return 'fail'
}

export default function Dashboard() {
  const auth = useAuth()
  const [currentView, setCurrentView] = useState('dashboard')
  const [stats, setStats] = useState({ alerts: 0, endpoints: 0, users: 0, private_hosts: 0, public_hosts: 0 })
  const [vulnStats, setVulnStats] = useState({ total: 0, critical: 0, high: 0, pending_ia: 0, pending_approval: 0 })
  const [mapData, setMapData] = useState([])
  const [alerts, setAlerts] = useState([])
  const [inventory, setInventory] = useState([])
  const [riskData, setRiskData] = useState([])
  const [remediationLog, setRemediationLog] = useState([])
  const [healthStatus, setHealthStatus] = useState({ services: [] })
  const [dailyDetections, setDailyDetections] = useState([])
  const [tops, setTops] = useState({ recent_assets: [], most_vulnerable: [], most_remediated: [] })
  const [loading, setLoading] = useState(true)
  const [toasts, setToasts] = useState([])
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
  const [inventoryViewMode, setInventoryViewMode] = useState('grid') // 'grid' | 'table'
  const [inventorySortBy, setInventorySortBy] = useState('newest')   // 'newest' | 'alpha' | 'vulns' | 'alerts'
  const [inventoryTypeFilter, setInventoryTypeFilter] = useState('')
  
  const [assetStatusFilter, setAssetStatusFilter] = useState('ALL') // NEW: ALL, VULNERABLE, ATTACKED
  const [soarSeverityFilter, setSoarSeverityFilter] = useState('ALL')
  const [soarStatusFilter, setSoarStatusFilter] = useState('ALL')
  const [soarSearch, setSoarSearch] = useState('')
  
  // Modal State
  const [showAddModal, setShowAddModal] = useState(false)
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
  const [assetDetailsLoading, setAssetDetailsLoading] = useState(false)


  // Manual Remediation Modal
  const [showManualModal, setShowManualModal] = useState(false)
  const [manualSolution, setManualSolution] = useState('')
  const [manualReason, setManualReason] = useState('')
  const [manualSaving, setManualSaving] = useState(false)

  const [usersList, setUsersList] = useState([])
  const [usersLoading, setUsersLoading] = useState(false)
  const [currentUserRole, setCurrentUserRole] = useState('Viewer')

  useEffect(() => {
    if (auth.isAuthenticated) {
      fetchData()
      fetchUsers()
      const interval = setInterval(fetchData, 5000)
      return () => clearInterval(interval)
    }
  }, [auth.isAuthenticated, assetFilter])

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
      }
    } catch (e) {
      console.error("Error fetching Authentik users:", e)
    } finally {
      setUsersLoading(false)
    }
  }

  const handleUpdateUserRole = async (username, newRole) => {
    try {
      await axios.post(`${API_BASE}/users/role`, { username, role: newRole })
      alert(`✅ Rol de ${username} actualizado exitosamente a '${newRole}' en Authentik.`)
      fetchUsers()
    } catch (error) {
      console.error("Error updating user role:", error)
      alert("Error al actualizar el rol en Authentik: " + (error.response?.data?.detail || error.message))
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
    const newToast = {
      id: Date.now(),
      title: alertData.rule_name || "Nueva Alerta",
      message: alertData.alert_text || `Detectado en ${alertData.asset_name || 'desconocido'}`,
      priority: alertData.priority
    }
    setToasts(prev => [...prev, newToast])
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

    const connect = () => {
      ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'new_alert') {
            setAlerts(prev => [payload.data, ...prev].slice(0, 100));
            showNotification(payload.data);
          }
        } catch (err) {
          console.error("WS message parse error:", err);
        }
      };

      ws.onclose = () => {
        reconnectInterval = setTimeout(() => {
          connect();
        }, 5000);
      };
    };

    connect();

    return () => {
      if (ws) ws.close();
      clearTimeout(reconnectInterval);
    };
  }, []);

  const handleDownloadReport = () => {
    window.location.href = `${API_BASE}/reports/executive?t=${Date.now()}`;
  }

  const handleDownloadAssetReport = (assetName) => {
    window.location.href = `${API_BASE}/reports/asset/${assetName}?t=${Date.now()}`;
  }

  const handleDownloadVulnerabilityReport = (vulnId) => {
    window.location.href = `${API_BASE}/reports/vulnerability/${vulnId}?t=${Date.now()}`;
  }

  const handleCreateTicket = async (vulnId, target) => {
    try {
      const descriptionPrompt = prompt("Ingrese detalles de la solución o comentarios para el ticket:");
      if (descriptionPrompt === null) return;
      
      const response = await axios.post(`${API_BASE}/remediation/${vulnId}/ticket`, {
        title: `Mitigación de Vulnerabilidad - ${selectedRemediation?.cve_id}`,
        description: descriptionPrompt || "Mitigación requerida manualmente.",
        target: target
      });
      
      if (response.data && response.data.url) {
        alert(`✅ Ticket creado exitosamente en ${target.toUpperCase()}.\nURL: ${response.data.url}`);
        window.open(response.data.url, '_blank');
      } else {
        alert("Error al crear el ticket.");
      }
    } catch (error) {
      console.error("Error creating ticket:", error);
      alert("Error al conectar con el servicio SOAR: " + (error.response?.data?.detail || error.message));
    }
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

  if (auth.isLoading) {
    return (
      <div className="h-screen bg-[#0F172A] flex flex-col items-center justify-center text-[#06B6D4]">
        <Activity size={48} className="animate-spin mb-4" />
        <p className="font-bold tracking-[0.2em] animate-pulse uppercase text-xs">Cargando Sesión...</p>
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
            <p className="text-slate-500 font-bold uppercase tracking-[0.3em] text-[10px] mb-12">Mando de Seguridad Regional</p>
            <button 
                onClick={() => auth.signinRedirect()}
                className="group relative px-12 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-xs tracking-[0.2em] rounded-[24px] hover:bg-white transition-all shadow-[0_20px_50px_rgba(6,182,212,0.3)] hover:shadow-[0_20px_50px_rgba(255,255,255,0.2)] active:scale-95"
            >
                <div className="flex items-center gap-3">
                    Iniciar Sesión con Authentik
                    <ChevronRight size={16} className="group-hover:translate-x-1 transition-transform" />
                </div>
            </button>
            <div className="mt-16 flex items-center justify-center gap-8 text-[9px] font-black text-slate-700 uppercase tracking-widest">
                <div className="flex items-center gap-2"><Globe size={12} /> Casmarts Global</div>
                <div className="w-1 h-1 rounded-full bg-slate-800" />
                <div className="flex items-center gap-2"><Activity size={12} /> Nodo Centralizado</div>
            </div>
        </div>
      </div>
    )
  }

  const fetchData = async () => {
    try {
      // 1. Fetch essential data to render the dashboard immediately
      const [resStats, resVulns, resMap, resAlerts, resRisk, resInv, resRem] = await Promise.all([
        axios.get(`${API_BASE}/stats/extended`),
        axios.get(`${API_BASE}/stats`),
        axios.get(`${API_BASE}/map`),
        axios.get(`${API_BASE}/alerts/runtime`),
        axios.get(`${API_BASE}/risk-distribution`),
        axios.get(`${API_BASE}/inventory`),
        axios.get(`${API_BASE}/remediation${assetFilter ? `?asset=${assetFilter}` : ''}`)
      ])
      
      setStats(resStats.data || { alerts: 0, endpoints: 0, users: 0, private_hosts: 0, public_hosts: 0 })
      setVulnStats(resVulns.data || { total: 0, critical: 0, high: 0, pending_ia: 0, pending_approval: 0 })
      setMapData(Array.isArray(resMap.data) ? resMap.data.filter(m => m.location_lat && m.location_lon) : [])
      setAlerts(Array.isArray(resAlerts.data) ? resAlerts.data : [])
      setRiskData(Array.isArray(resRisk.data) ? resRisk.data : [])
      setInventory(Array.isArray(resInv.data) ? resInv.data : [])
      setRemediationLog(Array.isArray(resRem.data) ? resRem.data : [])
      setLastSync(new Date())
      setLoading(false)

      // 2. Fetch secondary metrics asynchronously in background without blocking UI
      Promise.all([
        axios.get(`${API_BASE}/health`),
        axios.get(`${API_BASE}/stats/daily-detections`),
        axios.get(`${API_BASE}/stats/tops`),
        axios.get(`${API_BASE}/stats/soar-roi`)
      ]).then(([resHealth, resDaily, resTops, resRoi]) => {
        setHealthStatus(resHealth.data && resHealth.data.services ? resHealth.data : { services: [] })
        setDailyDetections(Array.isArray(resDaily.data) ? resDaily.data : [])
        setTops(resTops.data || { recent_assets: [], most_vulnerable: [], most_remediated: [] })
        setRoiStats(resRoi.data || { avg_remediation_time_minutes: 0, effectiveness_rate_percentage: 0, comparison: { ai_resolved: 0, manual_resolved: 0 } })
      }).catch(err => console.error("Error fetching secondary dashboard metrics:", err))
    } catch (error) {
      console.error("Error fetching dashboard data:", error)
    } finally {
      setLoading(false)
    }
  }

  const handleAddAsset = async (e) => {
    e.preventDefault()
    try {
        await axios.post(`${API_BASE}/inventory`, newAsset)
        setShowAddModal(false)
        setNewAsset({ asset_name: '', asset_type: '', endpoint: '', criticality: 'MEDIUM', vault_sudo_token: '', vault_ansible_user: '', auth_type: 'PASSWORD', ssh_private_key: '', gitlab_user: '', gitlab_token: '' })
        setInventorySearch('')
        setInventoryTypeFilter('')
        setAssetStatusFilter('ALL')
        setCurrentView('inventory')
        await fetchData()
    } catch (error) {
        console.error("Error adding asset:", error)
        alert("Error al registrar el activo")
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
      
      let infoData = null
      if (group.agent_id) {
        const res = await axios.get(`${API_BASE}/wazuh/agent/${encodeURIComponent(group.agent_id)}/info`)
        infoData = res.data?.parsed || null
      }
      setAssetDetailsData({ group, info: infoData, ping: currentPing })
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
    setCurrentView('soar')
  }

  const filteredAlerts = Array.isArray(alerts) ? alerts.filter(a => {
    const matchSeverity = severityFilter ? a.priority === severityFilter : true;
    const matchAsset = assetFilter ? a.asset_name === assetFilter : true;
    return matchSeverity && matchAsset;
  }) : [];

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
    return matchAsset && matchSeverity && matchStatus && matchSearch;
  }) : [];

  // Grouping logic for inventory
  const groupedInventory = inventory.reduce((acc, item) => {
    if (!acc[item.asset_name]) {
      acc[item.asset_name] = {
        name: item.asset_name,
        max_id: parseInt(item.max_id || item.id || 0),
        vulnerability_count: 0,
        resolved_count: 0,
        runtime_alerts_count: 0,
        interfaces: [],
        status: item.status,
        agent_id: item.agent_id,
        has_vault_secret: item.has_vault_secret
      }
    }
    acc[item.asset_name].max_id = Math.max(acc[item.asset_name].max_id, parseInt(item.max_id || item.id || 0))
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
        return (b.max_id || 0) - (a.max_id || 0) || a.name.localeCompare(b.name);
    }) : [];

  return (
    <div className="flex h-screen bg-[#0F172A] text-slate-300 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-20 lg:w-64 bg-[#1E293B] flex flex-col border-r border-slate-800 transition-all z-30">
        <div className="p-6 flex items-center gap-3 border-b border-slate-800">
          <div className="bg-[#06B6D4]/20 p-2 rounded-xl">
            <ShieldAlert className="text-[#06B6D4]" size={24} />
          </div>
          <div className="hidden lg:block">
            <p className="font-black text-xl tracking-tighter text-white leading-none">CENTINELA</p>
            <p className="text-[10px] text-[#06B6D4] font-black tracking-widest uppercase">Mando Regional</p>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-2 mt-4">
          <NavItem 
            icon={<LayoutDashboard size={20} />} 
            label="Dashboard" 
            active={currentView === 'dashboard'} 
            onClick={() => { setCurrentView('dashboard'); setSeverityFilter(null); setAssetFilter(null); }}
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
            label="Manual Técnico"
            onClick={() => window.open('/api/manual', '_blank', 'noopener,noreferrer')}
          />
        </nav>

        <div className="p-4 border-t border-slate-800">
          {currentUserRole === 'Admin' && (
            <button 
              onClick={() => setShowAddModal(true)}
              className="w-full hidden lg:flex items-center gap-3 p-3 mb-4 rounded-xl bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20"
            >
              <Plus size={20} />
              Añadir Activo
            </button>
          )}
          <div className="hidden lg:block mb-4 px-3">
            <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Sincronización</p>
            <div className="text-[10px] text-emerald-500 font-bold uppercase tracking-tighter flex items-center gap-2">
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
            <span className="hover:text-white cursor-pointer transition-colors" onClick={() => setCurrentView('dashboard')}>Red Casmarts</span>
            <ChevronRight size={14} />
            <span className="hover:text-[#06B6D4] cursor-pointer transition-colors" onClick={() => setCurrentView('dashboard')}>Mando Regional</span>
            <ChevronRight size={14} />
            <span className="text-white uppercase">
              {currentView === 'dashboard' ? 'Dashboard' :
               currentView === 'threat-hunting' ? 'Búsqueda de Amenazas' :
               currentView === 'itdr' ? 'Identidad & ITDR' :
               currentView === 'inventory' ? 'Inventario de Activos' :
               currentView === 'soar' ? 'Remediación con IA' :
               currentView === 'health' ? 'Salud del Sistema' : currentView}
            </span>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="hidden md:flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-lg border border-slate-800">
              <Search size={14} className="text-slate-500" />
              <input type="text" placeholder="Buscar incidentes..." className="bg-transparent border-none text-[10px] focus:ring-0 w-48 text-slate-300 font-bold placeholder:text-slate-600" />
            </div>
            <button 
              onClick={handleDownloadReport}
              className="hidden md:flex items-center gap-2 bg-[#06B6D4]/10 text-[#06B6D4] px-4 py-2 rounded-lg border border-[#06B6D4]/30 hover:bg-[#06B6D4]/20 transition-all font-black text-[10px] uppercase tracking-wider"
            >
              <Download size={14} />
              Reporte PDF
            </button>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-xs font-bold text-white leading-none">{auth.user?.profile?.name || "Operador"}</p>
                <div className="flex items-center gap-1 justify-end mt-1">
                  <span className={`px-2 py-0.5 text-[9px] font-black rounded-md uppercase tracking-wider ${
                    currentUserRole === 'Admin' ? 'bg-[#06B6D4]/20 text-[#06B6D4] border border-[#06B6D4]/40' :
                    currentUserRole === 'Analyst' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40' :
                    currentUserRole === 'Auditor' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                    'bg-slate-700/50 text-slate-400 border border-slate-700'
                  }`}>
                    {currentUserRole === 'Admin' ? '🛡️ Admin' :
                     currentUserRole === 'Analyst' ? '⚡ Analista' :
                     currentUserRole === 'Auditor' ? '📋 Auditor' : '👁️ Visualizador'}
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
            <>
              {/* Top Metric Grid */}
              <div className="grid grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
                <MetricCard 
                    label="Usuarios Activos" 
                    value={stats?.users || 0} 
                    icon={<Users size={20} />} 
                    color="text-[#06B6D4]" 
                    sub="Sincronizado CDMX"
                    onClick={() => setCurrentView('itdr')}
                    title="Ver gestión de identidades y telemetría ITDR (Haz clic para ir)"
                />
                <MetricCard 
                    label="Activos / Endpoints" 
                    value={stats?.endpoints || 0} 
                    icon={<Server size={20} />} 
                    color="text-emerald-400" 
                    sub={`${stats?.online_endpoints || 0} En línea • ${stats?.offline_endpoints || 0} Sin conexión`}
                    onClick={() => setCurrentView('inventory')}
                    title={`Total de Activos: ${stats?.endpoints || 0} (${stats?.online_endpoints || 0} En línea / Sincronizados, ${stats?.offline_endpoints || 0} Offline / Pendientes). Haz clic para ir.`}
                />
                <MetricCard 
                    label="Alertas en Tiempo Real" 
                    value={stats?.alerts || 0} 
                    icon={<AlertTriangle size={20} />} 
                    color="text-red-400" 
                    sub={`${vulnStats?.critical || 0} Críticas activas`}
                    highlight
                    onClick={() => setCurrentView('threat-hunting')}
                    title="Ver búsqueda de amenazas y log maestro en tiempo real (Haz clic para ir)"
                />
                <MetricCard 
                    label="Vulnerabilidades" 
                    value={vulnStats?.total || 0} 
                    icon={<ShieldAlert size={20} />} 
                    color="text-orange-400" 
                    sub="Pendientes de Remediar"
                    onClick={() => setCurrentView('soar')}
                    title="Ver hallazgos de seguridad y parches de remediación (Haz clic para ir)"
                />
                <MetricCard 
                    label="Remediación con IA" 
                    value={vulnStats?.pending_ia || 0} 
                    icon={<Zap size={20} />} 
                    color="text-[#06B6D4]" 
                    sub="En cola de análisis"
                    onClick={() => setCurrentView('soar')}
                    title="Ver parches automáticos e IA SOAR (Haz clic para ir)"
                />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-8 space-y-8">
                  {/* Map Section */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 relative overflow-hidden group">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <h3 className="text-white font-bold text-xl mb-1 flex items-center gap-2">
                          <Globe className="text-[#06B6D4]" size={20} />
                          Despliegue de Infraestructura Nacional
                        </h3>
                        <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Activos Detectados y Monitoreados por Nuclei</p>
                      </div>
                    </div>
                    <div className="h-[400px] w-full bg-[#0F172A]/50 rounded-2xl border border-white/5 flex items-center justify-center overflow-hidden">
                      <MapChart markers={mapData} />
                    </div>
                  </div>

                  {/* Alerts Table */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                    <div className="flex items-center justify-between mb-8">
                      <h3 className="text-white font-bold text-xl flex items-center gap-2">
                        <Activity className="text-[#06B6D4]" size={20} />
                        {severityFilter ? `Alertas ${severityFilter}` : 'Alertas Recientes en Tiempo Real'}
                      </h3>
                      {severityFilter && (
                        <button onClick={() => setSeverityFilter(null)} className="text-slate-500 text-[10px] font-black uppercase tracking-widest hover:text-white">Limpiar Filtro</button>
                      )}
                      <button onClick={() => setCurrentView('threat-hunting')} className="text-[#06B6D4] text-[10px] font-black uppercase tracking-widest hover:underline">Ver Todo el Registro</button>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left">
                        <thead>
                          <tr className="text-slate-500 text-[10px] font-black uppercase tracking-widest border-b border-slate-800">
                            <th className="pb-4">Severidad</th>
                            <th className="pb-4">Fecha</th>
                            <th className="pb-4">Entidad</th>
                            <th className="pb-4">Mensaje</th>
                            <th className="pb-4" title="Nivel de severidad de la alerta (CRÍTICA, ALTA, MEDIA, INFO)">Severidad</th>
                            <th className="pb-4" title="Fecha y hora exacta en que se detectó la alerta">Fecha</th>
                            <th className="pb-4" title="Activo o equipo donde se originó la alerta">Activo / Entidad</th>
                            <th className="pb-4" title="Regla o firma de detección que disparó la alerta">Regla / Mensaje</th>
                            <th className="pb-4 text-right" title="Acciones disponibles sobre la alerta">Acción</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {filteredAlerts.length > 0 ? (
                            filteredAlerts.slice(0, 5).map((alert) => (
                                <tr key={alert.id} className="group hover:bg-white/5 transition-all">
                                  <td className="py-4">
                                    <span 
                                      title={alert.priority === 'CRITICAL' ? 'CRÍTICA: Requiere acción inmediata, impacto severo' : alert.priority === 'HIGH' ? 'ALTA: Acción urgente requerida en menos de 4 horas' : alert.priority === 'MEDIUM' ? 'MEDIA: Gestionar en las próximas 24 horas' : 'INFORMATIVA: Sin impacto crítico, requiere monitoreo'}
                                      className={`px-2 py-1 rounded text-[9px] font-black ${
                                      alert.priority === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 
                                      alert.priority === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
                                    }`}>
                                      {alert.priority === 'CRITICAL' ? 'CRÍTICA' : alert.priority === 'HIGH' ? 'ALTA' : alert.priority === 'MEDIUM' ? 'MEDIA' : 'INFO'}
                                    </span>
                                  </td>
                                  <td className="py-4 text-[10px] font-bold text-slate-500">{new Date(alert.detected_at).toLocaleString()}</td>
                                  <td className="py-4 text-[10px] font-bold text-white" title={`Ver alertas del activo: ${alert.asset_name || 'Sistema'}`}>{alert.asset_name || "Sistema"}</td>
                                  <td className="py-4 text-[10px] text-slate-400" title={alert.rule_name}>{alert.rule_name}</td>
                                  <td className="py-4 text-right">
                                    <button 
                                        onClick={() => handleInvestigate(alert.id)}
                                        title="Abrir panel de investigación forense de esta alerta"
                                        className="px-3 py-1.5 rounded-lg bg-[#06B6D4]/10 text-[#06B6D4] text-[10px] font-black uppercase tracking-widest hover:bg-[#06B6D4] hover:text-[#0F172A] transition-all"
                                    >
                                      Investigar
                                    </button>
                                  </td>
                                </tr>
                              ))
                          ) : (
                              <tr>
                                  <td colSpan="5" className="py-8 text-center text-slate-600 text-xs font-bold uppercase tracking-widest italic">
                                      No se detectaron amenazas en runtime actualmente.
                                  </td>
                              </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Daily Detections Chart */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 mt-8">
                    <div>
                      <h3 className="text-white font-bold text-xl mb-1 flex items-center gap-2">
                        <Activity className="text-[#06B6D4]" size={20} />
                        Detecciones Diarias de Vulnerabilidades
                      </h3>
                      <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-6">Tendencia de hallazgos identificados por día</p>
                    </div>
                    <div className="h-[250px] w-full bg-[#0F172A]/50 rounded-2xl border border-white/5 p-4">
                      {dailyDetections.length > 0 ? (
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={dailyDetections}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                            <XAxis dataKey="date" stroke="#64748B" fontSize={10} tickLine={false} />
                            <YAxis stroke="#64748B" fontSize={10} tickLine={false} />
                            <Tooltip 
                              contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px' }}
                              labelStyle={{ color: '#fff', fontWeight: 'bold' }}
                            />
                            <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                      ) : (
                        <div className="flex h-full items-center justify-center text-slate-500 font-bold text-xs uppercase">No hay suficientes datos de tendencia</div>
                      )}
                    </div>
                  </div>

                  {/* Tops Section */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
                    {/* Top 5 Recent Assets */}
                    <div className="bg-[#1E293B] rounded-[24px] border border-slate-800 p-6" title="Últimos activos registrados en el inventario de infraestructura">
                      <h4 className="text-white font-bold text-sm mb-4 flex items-center gap-2 uppercase tracking-wide">
                        <Server className="text-[#06B6D4]" size={16} />
                        Activos Recientes
                      </h4>
                      <ul className="space-y-3">
                        {tops.recent_assets?.map((a, i) => (
                          <li key={i} className="flex justify-between items-center text-xs bg-slate-900/40 p-2.5 rounded-xl border border-white/5" title={`Activo: ${a.asset_name}, Tipo: ${a.asset_type}`}>
                            <span className="font-bold text-slate-300 truncate max-w-[120px]">{a.asset_name}</span>
                            <span className="text-[10px] text-slate-500 font-mono">{a.asset_type}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Top 5 Most Vulnerable Assets */}
                    <div className="bg-[#1E293B] rounded-[24px] border border-slate-800 p-6" title="Activos con mayor número de vulnerabilidades CVE pendientes de remediar">
                      <h4 className="text-white font-bold text-sm mb-4 flex items-center gap-2 uppercase tracking-wide">
                        <ShieldAlert className="text-orange-400" size={16} />
                        Más Vulnerables
                      </h4>
                      <ul className="space-y-3">
                        {tops.most_vulnerable?.map((a, i) => (
                          <li key={i} className="flex justify-between items-center text-xs bg-slate-900/40 p-2.5 rounded-xl border border-white/5" title={`${a.asset_name}: ${a.count} vulnerabilidades pendientes`}>
                            <span className="font-bold text-slate-300 truncate max-w-[120px]">{a.asset_name}</span>
                            <span className="text-xs font-black text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded" title={`${a.count} CVEs sin remediar`}>{a.count} vulns</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Top 5 Most Remediated Assets */}
                    <div className="bg-[#1E293B] rounded-[24px] border border-slate-800 p-6" title="Activos donde el motor SOAR/IA ha ejecutado más remediaciones exitosas">
                      <h4 className="text-white font-bold text-sm mb-4 flex items-center gap-2 uppercase tracking-wide">
                        <CheckCircle2 className="text-emerald-400" size={16} />
                        Más Remediados
                      </h4>
                      <ul className="space-y-3">
                        {tops.most_remediated?.map((a, i) => (
                          <li key={i} className="flex justify-between items-center text-xs bg-slate-900/40 p-2.5 rounded-xl border border-white/5" title={`${a.asset_name}: ${a.count} vulnerabilidades resueltas`}>
                            <span className="font-bold text-slate-300 truncate max-w-[120px]">{a.asset_name}</span>
                            <span className="text-xs font-black text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded" title={`${a.count} CVEs resueltos`}>{a.count} ✓</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* SOAR ROI Metrics Section */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 mt-8">
                    <div>
                      <h3 className="text-white font-bold text-xl mb-1 flex items-center gap-2">
                        <Zap className="text-[#06B6D4]" size={20} />
                        Métricas de Retorno de Inversión (ROI) SOAR & IA
                      </h3>
                      <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-6">Impacto y eficiencia en remediación de incidentes</p>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div className="bg-[#0F172A]/50 border border-slate-800 p-6 rounded-2xl flex flex-col justify-center" title="Tiempo promedio que tarda Centinela-AI en detectar y aplicar un parche desde el momento en que se identifica la vulnerabilidad">
                        <p className="text-[10px] text-slate-500 font-black uppercase tracking-wider mb-2">Tiempo Promedio de Remediación</p>
                        <h4 className="text-[#06B6D4] font-black text-4xl">{roiStats.avg_remediation_time_minutes} min</h4>
                        <p className="text-[10px] text-slate-400 mt-2">vs ~48 hrs en mitigación manual promedio</p>
                      </div>
                      
                      <div className="bg-[#0F172A]/50 border border-slate-800 p-6 rounded-2xl flex flex-col justify-center" title="Porcentaje de remediaciones ejecutadas exitosamente por el motor SOAR/IA sin necesidad de intervención humana manual">
                        <p className="text-[10px] text-slate-500 font-black uppercase tracking-wider mb-2">Tasa de Efectividad IA</p>
                        <h4 className="text-emerald-400 font-black text-4xl">{roiStats.effectiveness_rate_percentage}%</h4>
                        <p className="text-[10px] text-slate-400 mt-2">Ejecución exitosa sin intervención humana</p>
                      </div>

                      <div className="bg-[#0F172A]/50 border border-slate-800 p-6 rounded-2xl">
                        <p className="text-[10px] text-slate-500 font-black uppercase tracking-wider mb-4">Resoluciones IA vs Manuales</p>
                        <div className="flex items-center justify-between text-xs font-bold mb-2">
                          <span className="text-slate-300">Resuelto por IA ({roiStats.comparison?.ai_resolved})</span>
                          <span className="text-slate-500">Manual ({roiStats.comparison?.manual_resolved})</span>
                        </div>
                        <div className="w-full bg-slate-800 h-3.5 rounded-full overflow-hidden flex border border-white/5">
                          <div 
                            style={{ width: `${(roiStats.comparison?.ai_resolved / (roiStats.comparison?.ai_resolved + roiStats.comparison?.manual_resolved || 1)) * 100}%` }} 
                            className="bg-[#06B6D4] h-full"
                          />
                          <div 
                            style={{ width: `${(roiStats.comparison?.manual_resolved / (roiStats.comparison?.ai_resolved + roiStats.comparison?.manual_resolved || 1)) * 100}%` }} 
                            className="bg-slate-700 h-full"
                          />
                        </div>
                        <div className="flex gap-4 mt-3 text-[9px] font-bold uppercase tracking-wider">
                          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-[#06B6D4]" /> IA</div>
                          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-slate-700" /> Manual</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                {/* Right Sidebar */}
                <div className="lg:col-span-4 space-y-8">
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                    <h3 className="text-white font-bold text-lg mb-6">Distribución de Riesgo</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={Array.isArray(riskData) ? riskData : []}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                            nameKey="severity"
                            onClick={(data) => {
                                if (data && data.severity) {
                                    if (severityFilter === data.severity) {
                                        setSeverityFilter(null);
                                    } else {
                                        setSeverityFilter(data.severity);
                                        window.scrollTo({ top: 1000, behavior: 'smooth' });
                                    }
                                }
                            }}
                            className="cursor-pointer"
                          >
                            {(Array.isArray(riskData) ? riskData : []).map((entry, index) => (
                              <Cell 
                                key={`cell-${index}`} 
                                fill={
                                    entry.severity === 'CRITICAL' ? '#EF4444' : 
                                    entry.severity === 'HIGH' ? '#F97316' : 
                                    entry.severity === 'MEDIUM' ? '#EAB308' : '#10B981'
                                } 
                              />
                            ))}
                          </Pie>
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px', fontWeight: 'bold' }}
                            itemStyle={{ color: '#fff' }}
                          />
                          <Legend 
                            verticalAlign="bottom" 
                            height={36} 
                            iconType="circle"
                            formatter={(value, entry) => {
                              const payload = entry.payload;
                              return <span className="text-[10px] font-bold text-slate-300 uppercase">{payload.severity}: {payload.value}</span>
                            }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <p className="text-[10px] text-slate-500 font-bold text-center uppercase tracking-widest mt-4">Haz clic en un segmento para filtrar alertas</p>
                  </div>

                  <div className="bg-gradient-to-br from-[#06B6D4]/20 to-blue-900/20 rounded-[32px] border border-[#06B6D4]/20 p-8">
                    <div className="flex items-center gap-3 mb-4">
                      <Zap className="text-[#06B6D4]" size={24} />
                      <h3 className="text-white font-bold text-lg" title="Sistema de Respuesta Automatizada de Seguridad impulsado por Gemini 1.5 Flash">Remediación con IA</h3>
                    </div>
                    <p className="text-xs text-slate-400 mb-6 leading-relaxed font-medium">
                      El motor <strong>Gemini 1.5 Flash</strong> está analizando <strong>{vulnStats.pending_ia}</strong> hallazgos detectados recientemente.
                    </p>
                    <button
                      onClick={() => setCurrentView('soar')}
                      title="Ir al panel SOAR para revisar, aprobar y gestionar los parches generados por IA"
                      className="w-full py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all active:scale-95"
                    >
                      Gestionar Remediaciones
                    </button>
                  </div>
                </div>
              </div>
            </>
          )}

          {currentView === 'soar' && (
            <div className="space-y-8">
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                            <Zap className="text-[#06B6D4]" size={28} />
                            SOAR Engine - Orquestación de IA
                        </h2>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">Gestión de Remedios y Automatización</p>
                    </div>
                    <div className="flex gap-3 items-center">
                        {assetFilter && (
                            <div className="flex items-center gap-3 bg-[#06B6D4]/10 px-4 py-2 rounded-xl border border-[#06B6D4]/20 animate-in fade-in zoom-in duration-300" title="Solo se muestran remediaciones relacionadas con este activo">
                                <span className="text-[10px] font-black text-[#06B6D4] uppercase tracking-widest">Filtro Activo: {assetFilter}</span>
                                <X size={14} className="text-[#06B6D4] cursor-pointer hover:text-white transition-colors" onClick={() => setAssetFilter(null)} />
                            </div>
                        )}
                        <div className="bg-emerald-500/10 text-emerald-500 px-4 py-2 rounded-xl border border-emerald-500/20 text-[10px] font-black uppercase">
                            Motor Activo
                        </div>
                    </div>
                </div>
 
                {/* FILTERS TOOLBAR */}
                <div className="flex flex-wrap items-center justify-between gap-4 bg-[#1E293B] p-4 rounded-2xl border border-slate-800">
                    <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
                        {/* Search Input */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-xl border border-slate-800 focus-within:border-[#06B6D4] transition-all w-full sm:w-64">
                            <Search size={14} className="text-slate-500" />
                            <input 
                                type="text" 
                                placeholder="Buscar CVE o Script..." 
                                value={soarSearch}
                                onChange={(e) => setSoarSearch(e.target.value)}
                                className="bg-transparent border-none text-[10px] focus:ring-0 text-slate-300 font-bold placeholder:text-slate-600 outline-none w-full" 
                            />
                        </div>

                        {/* Severity Select */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-3 py-2 rounded-xl border border-slate-800" title="Filtrar remediaciones por nivel de severidad">
                            <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Severidad:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={soarSeverityFilter}
                                    onChange={(e) => setSoarSeverityFilter(e.target.value)}
                                    className="bg-transparent border-none text-[10px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="ALL">TODAS</option>
                                    <option value="CRITICAL">CRÍTICA</option>
                                    <option value="HIGH">ALTA</option>
                                    <option value="MEDIUM">MEDIA</option>
                                    <option value="LOW">BAJA</option>
                                </select>
                                <ChevronDown size={11} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>

                        {/* Status Select */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-3 py-2 rounded-xl border border-slate-800" title="Filtrar remediaciones por estado de ejecución">
                            <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Estado:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={soarStatusFilter}
                                    onChange={(e) => setSoarStatusFilter(e.target.value)}
                                    className="bg-transparent border-none text-[10px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="ALL">TODOS</option>
                                    <option value="REMEDIADO">REMEDIADOS</option>
                                    <option value="CORRELATED">LISTO PARA APROBAR</option>
                                    <option value="PENDIENTE">PENDIENTE IA</option>
                                    <option value="AI_FAILED">FALLÓ IA</option>
                                </select>
                                <ChevronDown size={11} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>
                    </div>

                    <div className="flex gap-2">
                        {(soarSearch || soarSeverityFilter !== 'ALL' || soarStatusFilter !== 'ALL') && (
                            <button 
                                onClick={() => { setSoarSearch(''); setSoarSeverityFilter('ALL'); setSoarStatusFilter('ALL'); }}
                                className="px-4 py-2 rounded-xl bg-slate-850 hover:bg-slate-700 text-slate-400 hover:text-white text-[9px] font-black uppercase tracking-widest transition-all"
                            >
                                Limpiar Filtros
                            </button>
                        )}
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    <div className={`${selectedRemediation ? 'lg:col-span-7' : 'lg:col-span-12'} space-y-6 transition-all duration-500`}>
                        {remediationLog.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-32 bg-[#1E293B] rounded-[48px] border border-slate-800 border-dashed">
                                <ZapOff size={64} className="text-slate-700 mb-6" />
                                <h3 className="text-white font-bold text-2xl mb-2">Sin Orquestaciones Pendientes</h3>
                                <p className="text-slate-500 text-sm max-w-md text-center font-medium">
                                    No se han generado planes de remediación automáticos en las últimas 24 horas.
                                </p>
                            </div>
                        ) : (
                            <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 overflow-hidden">
                                <table className="w-full text-left">
                                    <thead className="bg-[#0F172A]">
                                        <tr className="text-slate-500 text-[10px] font-black uppercase tracking-widest border-b border-slate-800">
                                            <th className="p-6">Hallazgo</th>
                                            <th className="p-6">Asset</th>
                                            <th className="p-6">Severidad</th>
                                            <th className="p-6">Estado</th>
                                            <th className="p-6 text-right">Detalle</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-800">
                                        {filteredRemediations.map((log) => (
                                            <tr 
                                                key={log.id} 
                                                onClick={() => setSelectedRemediation(log)}
                                                className={`group hover:bg-white/5 transition-all cursor-pointer ${selectedRemediation?.id === log.id ? 'bg-white/5' : ''}`}
                                            >
                                                <td className="p-6">
                                                    <div className="flex items-center gap-3">
                                                        <div className={`p-2 rounded-lg ${
                                                            log.cve_id === 'SCAN-AUDIT' ? 'bg-blue-500/10 text-blue-400' :
                                                            log.executed_bool ? 'bg-emerald-500/10 text-emerald-500' : 'bg-slate-800 text-[#06B6D4]'
                                                        }`}>
                                                            {log.cve_id === 'SCAN-AUDIT' ? <ClipboardCheck size={16} /> :
                                                             log.executed_bool ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}
                                                        </div>
                                                        <div>
                                                            <div className="flex items-center gap-2">
                                                                <p className="text-white font-bold text-sm">
                                                                    {log.cve_id === 'SCAN-AUDIT' ? 'Auditoría de Activo' : log.cve_id}
                                                                </p>
                                                            </div>
                                                            <div className="flex items-center gap-2 mt-1">
                                                                <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                                                                    CRS {log.risk_score ? log.risk_score : '—'}
                                                                </span>
                                                                {log.is_cisa_kev && (
                                                                    <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                                                                        🚨 CISA KEV
                                                                    </span>
                                                                )}
                                                                {log.reachability_status === 'UNREACHABLE' && (
                                                                    <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-slate-800 text-slate-500 border border-slate-700" title="Dependencia declarada pero nunca importada en el código">
                                                                        SIN USO REAL
                                                                    </span>
                                                                )}
                                                                {log.mitre_technique && (
                                                                    <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20" title={log.mitre_technique}>
                                                                        {log.mitre_technique.match(/T\d+(\.\d+)?/)?.[0] || 'ATT&CK'}
                                                                    </span>
                                                                )}
                                                                {log.is_sla_breached ? (
                                                                    <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                                                                        SLA VENCIDO
                                                                    </span>
                                                                ) : (
                                                                    <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                                                                        SLA OK
                                                                    </span>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="p-6 text-xs font-bold text-slate-400">{log.asset_name}</td>
                                                <td className="p-6">
                                                     <span className={`px-2 py-1 rounded text-[9px] font-black uppercase ${log.severity_badge_class || 'bg-slate-500/20 text-slate-400 border border-slate-500/30'}`}>
                                                         {log.severity_label || log.severity || 'INFO'}
                                                     </span>
                                                 </td>
                                                 <td className="p-6">
                                                     <div className="flex items-center gap-2">
                                                         <span className={`text-[9px] font-black uppercase ${log.status_text_class || 'text-orange-500'}`}>
                                                             {log.status_label || log.status}
                                                         </span>
                                                     </div>
                                                 </td>
                                                <td className="p-6 text-right">
                                                    <ChevronRight size={16} className={`text-slate-700 transition-all ${selectedRemediation?.id === log.id ? 'translate-x-1 text-white' : ''}`} />
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    {selectedRemediation && (
                        <div className="lg:col-span-5 animate-in slide-in-from-right-8 duration-500">
                            <div className="bg-[#1E293B] rounded-[32px] border border-[#06B6D4]/30 overflow-hidden sticky top-24 flex flex-col max-h-[calc(100vh-120px)]">
                                <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent shrink-0">
                                    <div className="flex justify-between items-start mb-6">
                                        <div>
                                            <p className="text-[10px] text-[#06B6D4] font-black uppercase tracking-widest mb-1">Informe Ejecutivo IA</p>
                                            <h3 className="text-white font-bold text-2xl">{selectedRemediation.cve_id}</h3>
                                        </div>
                                        <button onClick={() => setSelectedRemediation(null)} className="text-slate-500 hover:text-white">
                                            <XCircle size={24} />
                                        </button>
                                    </div>
                                    
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                        <div className="flex items-center gap-3 p-4 bg-[#0F172A] rounded-2xl border border-slate-800">
                                            <Server size={18} className="text-slate-500" />
                                            <div>
                                                <p className="text-[9px] text-slate-500 font-bold uppercase">Asset Afectado</p>
                                                <p className="text-xs font-bold text-white">{selectedRemediation.asset_name}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-3 p-4 bg-[#0F172A] rounded-2xl border border-slate-800">
                                            <Cpu size={18} className="text-[#06B6D4]" />
                                            <div>
                                                <p className="text-[9px] text-slate-500 font-bold uppercase">Motor Detector</p>
                                                <p className="text-xs font-bold text-white">{selectedRemediation.detection_engine || "Externo / API"}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-3 p-4 bg-[#0F172A] rounded-2xl border border-slate-800">
                                            <Clock size={18} className="text-slate-500" />
                                            <div>
                                                <p className="text-[9px] text-slate-500 font-bold uppercase">Detección</p>
                                                <p className="text-xs font-bold text-white">
                                                    {selectedRemediation.detected_at ? new Date(selectedRemediation.detected_at).toLocaleString() : "Sin fecha"}
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="p-8 space-y-8 flex-1 overflow-y-auto">
                                    <section>
                                        <h4 className="text-white font-bold text-xs uppercase tracking-widest mb-3 flex items-center gap-2">
                                            <Info size={14} className="text-[#06B6D4]" />
                                            {selectedRemediation.cve_id === 'SCAN-AUDIT' ? 'Resumen de Verificación' : '¿Qué encontramos?'}
                                        </h4>
                                        <div className="p-4 bg-slate-800/50 rounded-2xl text-xs text-slate-300 leading-relaxed italic whitespace-pre-wrap">
                                            {selectedRemediation.executive_summary || selectedRemediation.description || "Análisis de IA generado por el motor de seguridad SOAR."}
                                        </div>
                                    </section>

                                    <section>
                                        <h4 className="text-white font-bold text-xs uppercase tracking-widest mb-3 flex items-center gap-2">
                                            <AlertTriangle size={14} className="text-orange-400" />
                                            Riesgo al Negocio
                                        </h4>
                                        <div className="p-4 bg-orange-500/5 rounded-2xl text-xs text-slate-300 leading-relaxed border border-orange-500/10">
                                            {selectedRemediation.business_impact || "Evaluando impacto financiero y operativo..."}
                                        </div>
                                    </section>

                                    <section>
                                        <h4 className="text-white font-bold text-xs uppercase tracking-widest mb-3 flex items-center gap-2">
                                            <PlusCircle size={14} className="text-emerald-400" />
                                            Pasos de Resolución
                                        </h4>
                                        <div className="space-y-2">
                                            {(selectedRemediation.developer_steps || "Consultando base de conocimientos técnica...").split('\n').map((step, idx) => (
                                                <div key={idx} className="flex gap-3 text-xs text-slate-400">
                                                    <span className="text-[#06B6D4] font-bold">{idx + 1}.</span>
                                                    <span>{step}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </section>

                                    {selectedRemediation.log_output && (
                                        <section className="mt-4 pt-8 border-t border-slate-800">
                                            <h4 className="text-[#06B6D4] font-black text-[10px] uppercase tracking-widest mb-4 flex items-center gap-2">
                                                <Activity size={14} />
                                                Log de Ejecución Remota (Aura-Sentinel)
                                            </h4>
                                            <div className="p-5 bg-black/40 rounded-2xl border border-slate-800 text-[11px] text-slate-400 overflow-x-auto leading-relaxed shadow-inner">
                                                <div className="prose prose-invert prose-xs max-w-none">
                                                    <ReactMarkdown>{selectedRemediation.log_output}</ReactMarkdown>
                                                </div>
                                            </div>
                                        </section>
                                    )}
                                </div>

                                <div className="p-8 bg-[#0F172A] border-t border-slate-800 flex gap-3 shrink-0 flex-wrap">
                                    {selectedRemediation.status === 'RESOLVED' || selectedRemediation.executed_bool ? (
                                        <div className="flex-grow py-4 bg-emerald-500/10 text-emerald-500 font-black uppercase text-[10px] tracking-widest rounded-2xl border border-emerald-500/20 flex items-center justify-center gap-2 cursor-default">
                                            <CheckCircle2 size={16} />
                                            Activo Remediado
                                        </div>
                                    ) : (
                                        <>
                                            {selectedRemediation.status === 'NEW' || selectedRemediation.status === 'PENDING' ? (
                                                <div className="flex-grow py-4 bg-orange-500/10 text-orange-500 font-black uppercase text-[10px] tracking-widest rounded-2xl border border-orange-500/20 flex items-center justify-center gap-2 cursor-default animate-pulse">
                                                    <Activity size={16} className="animate-spin" />
                                                    Procesando IA...
                                                </div>
                                            ) : (
                                                <button 
                                                    onClick={() => handleExecuteRemediation(selectedRemediation.id)}
                                                    className="flex-grow py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all active:scale-95 flex items-center justify-center gap-2 shadow-lg shadow-[#06B6D4]/10"
                                                >
                                                    <Zap size={16} />
                                                    Ejecutar Remedio AI
                                                </button>
                                            )}
                                            {!(selectedRemediation.status === 'RESOLVED' || selectedRemediation.executed_bool) && (
                                                <>
                                                    <button 
                                                        onClick={() => setShowManualModal(true)}
                                                        className="flex-grow py-4 bg-slate-800 text-slate-300 font-black uppercase text-[10px] tracking-widest rounded-2xl border border-slate-700 hover:bg-slate-700 transition-all active:scale-95 flex items-center justify-center gap-2"
                                                    >
                                                        <CheckCircle size={16} />
                                                        Remediar Manual
                                                    </button>
                                                    <button 
                                                        onClick={() => handleCreateTicket(selectedRemediation.id, 'redmine')}
                                                        className="py-4 px-4 bg-red-950/40 text-red-400 font-black uppercase text-[10px] tracking-widest rounded-2xl border border-red-900/40 hover:bg-red-900/30 transition-all active:scale-95 flex items-center justify-center gap-1.5"
                                                        title="Crear ticket en Redmine"
                                                    >
                                                        <ExternalLink size={12} />
                                                        Redmine
                                                    </button>
                                                    <button 
                                                        onClick={() => handleCreateTicket(selectedRemediation.id, 'gitea')}
                                                        className="py-4 px-4 bg-emerald-950/40 text-emerald-400 font-black uppercase text-[10px] tracking-widest rounded-2xl border border-emerald-900/40 hover:bg-emerald-900/30 transition-all active:scale-95 flex items-center justify-center gap-1.5"
                                                        title="Crear issue en Gitea"
                                                    >
                                                        <ExternalLink size={12} />
                                                        Gitea
                                                    </button>
                                                </>
                                            )}
                                        </>
                                    )}
                                    {(selectedRemediation.status === 'RESOLVED' || selectedRemediation.executed_bool) && (
                                        <button 
                                            onClick={() => setShowReportModal(true)}
                                            className="p-4 bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 rounded-2xl hover:bg-emerald-500/20 transition-all flex items-center justify-center"
                                            title="Ver Reporte de Ejecución"
                                        >
                                            <FileText size={20} />
                                        </button>
                                    )}
                                    <button 
                                        onClick={() => handleViewScript(selectedRemediation.id)}
                                        className="p-4 bg-slate-800 text-[#06B6D4] border border-[#06B6D4]/20 rounded-2xl hover:bg-[#06B6D4]/10 transition-all flex items-center justify-center"
                                        title="Auditar Script"
                                    >
                                        <FileText size={20} />
                                    </button>
                                    <button 
                                        onClick={() => {
                                            handleViewScript(selectedRemediation.id);
                                        }}
                                        className="p-4 bg-slate-800 text-slate-400 border border-slate-700 rounded-2xl hover:bg-slate-700 transition-all flex items-center justify-center"
                                        title="Descargar Script (.sh)"
                                    >
                                        <Download size={20} />
                                    </button>
                                    <button 
                                        onClick={() => handleDownloadVulnerabilityReport(selectedRemediation.id)}
                                        className="p-4 bg-cyan-500/10 text-cyan-400 border border-cyan-400/20 rounded-2xl hover:bg-cyan-500/20 transition-all flex items-center justify-center"
                                        title="Descargar Reporte PDF de la Vulnerabilidad"
                                    >
                                        <FileText size={20} className="text-cyan-400" />
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
          )}

          {currentView === 'threat-hunting' && (
            <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                <div className="flex items-center justify-between mb-8">
                    <h3 className="text-white font-bold text-xl flex items-center gap-2">
                        <ShieldAlert className="text-[#06B6D4]" size={24} />
                        Búsqueda de Amenazas en Tiempo Real - Log Maestro
                    </h3>
                    {assetFilter && (
                        <div className="flex items-center gap-3 bg-[#06B6D4]/10 px-4 py-2 rounded-xl border border-[#06B6D4]/20">
                            <span className="text-[10px] font-black text-[#06B6D4] uppercase tracking-widest">Filtro Activo: {assetFilter}</span>
                            <X size={14} className="text-[#06B6D4] cursor-pointer" onClick={() => setAssetFilter(null)} />
                        </div>
                    )}
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="text-slate-500 text-[10px] font-black uppercase tracking-widest border-b border-slate-800">
                                <th className="pb-4">Severidad</th>
                                <th className="pb-4">Marca de Tiempo</th>
                                <th className="pb-4">Activo Afectado</th>
                                <th className="pb-4">Regla / Firma</th>
                                <th className="pb-4">Detalle de Alerta</th>
                                <th className="pb-4 text-right">Acción</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                            {filteredAlerts.length > 0 ? (
                                filteredAlerts.map((alert) => (
                                    <tr key={alert.id} className="group hover:bg-white/5 transition-all">
                                        <td className="py-6">
                                            <span className={`px-2 py-1 rounded text-[9px] font-black ${
                                                alert.priority === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 
                                                alert.priority === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 
                                                alert.priority === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'
                                            }`}>
                                                {alert.priority === 'CRITICAL' ? 'CRÍTICA' :
                                                 alert.priority === 'HIGH' ? 'ALTA' :
                                                 alert.priority === 'MEDIUM' ? 'MEDIA' :
                                                 alert.priority === 'LOW' ? 'BAJA' : 'INFORMATIVA'}
                                            </span>
                                        </td>
                                        <td className="py-6 text-[11px] font-bold text-slate-500">{new Date(alert.detected_at).toLocaleString()}</td>
                                        <td className="py-6 text-[11px] font-bold text-white">{alert.asset_name || "Servidor Centinela-AI (10.4.3.34)"}</td>
                                        <td className="py-6 text-[11px] text-[#06B6D4] font-bold">{alert.rule_name}</td>
                                        <td className="py-6 text-[11px] text-slate-400 max-w-xs truncate">{alert.alert_text}</td>
                                        <td className="py-6 text-right">
                                            <button 
                                                onClick={() => handleInvestigate(alert.id)}
                                                className="px-4 py-2 rounded-xl bg-emerald-500/10 text-emerald-400 font-black text-[10px] uppercase tracking-widest hover:bg-emerald-500 hover:text-white transition-all"
                                            >
                                                Investigar
                                            </button>
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="6" className="py-12 text-center text-slate-600 font-bold uppercase tracking-widest italic text-xs">
                                        No se encontraron logs de seguridad para los filtros seleccionados.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
          )}

        {currentView === 'inventory' && (
            <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between mb-10 gap-6">
                    <div>
                        <h3 className="text-white font-bold text-2xl flex items-center gap-3">
                            <Database className="text-[#06B6D4]" size={28} />
                            Inventario de Activos Unificado
                        </h3>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-widest mt-1">Gestión consolidada de infraestructura y endpoints</p>
                    </div>
                    <div className="flex flex-wrap gap-3">
                        {/* Selector de Ordenamiento */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-2xl border border-slate-800 focus-within:border-[#06B6D4] transition-all" title="Ordenar lista de activos por fecha, nombre o vulnerabilidades">
                            <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest hidden sm:inline">Orden:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={inventorySortBy}
                                    onChange={(e) => setInventorySortBy(e.target.value)}
                                    className="bg-transparent border-none text-[10px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="newest" className="bg-[#0F172A] text-slate-300">Más Recientes Primero</option>
                                    <option value="alpha" className="bg-[#0F172A] text-[#06B6D4]">Alfabético (A-Z)</option>
                                    <option value="vulns" className="bg-[#0F172A] text-orange-400">Más Vulnerables</option>
                                    <option value="alerts" className="bg-[#0F172A] text-red-400">Alertas Runtime</option>
                                </select>
                                <ChevronDown size={12} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>

                        {/* Filtro por Tipo de Activo */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-2xl border border-slate-800 focus-within:border-[#06B6D4] transition-all" title="Filtrar por categoría de activo (Servidor Linux, Windows, Contenedor, etc.)">
                            <Filter size={14} className="text-[#06B6D4]" />
                            <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest hidden sm:inline">Tipo:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={inventoryTypeFilter}
                                    onChange={(e) => setInventoryTypeFilter(e.target.value)}
                                    className="bg-transparent border-none text-[10px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="" className="bg-[#0F172A] text-slate-300">TODOS LOS TIPOS</option>
                                    {Array.from(new Set(inventory.map(i => i.asset_type).filter(Boolean))).sort().map(type => (
                                        <option key={type} value={type} className="bg-[#0F172A] text-[#06B6D4]">
                                            {type}
                                        </option>
                                    ))}
                                </select>
                                <ChevronDown size={12} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>

                        <div className="flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-2xl border border-slate-800 focus-within:border-[#06B6D4] transition-all">
                            <Search size={16} className="text-slate-500" />
                            <input 
                                type="text" 
                                placeholder="Buscar Nombre/IP..." 
                                value={inventorySearch}
                                onChange={(e) => setInventorySearch(e.target.value)}
                                className="bg-transparent border-none text-[10px] focus:ring-0 w-32 md:w-48 text-slate-300 font-bold placeholder:text-slate-600 outline-none" 
                            />
                        </div>

                        {/* Conmutador de Vista (Tarjetas vs Tabla) */}
                        <div className="flex gap-1 p-1 bg-[#0F172A] rounded-2xl border border-slate-800" title="Cambiar modo de visualización del inventario">
                            <button
                                onClick={() => setInventoryViewMode('grid')}
                                className={`p-2 rounded-xl transition-all ${inventoryViewMode === 'grid' ? 'bg-[#06B6D4] text-[#0F172A]' : 'text-slate-500 hover:text-white'}`}
                                title="Vista en cuadrícula de Tarjetas"
                            >
                                <LayoutGrid size={16} />
                            </button>
                            <button
                                onClick={() => setInventoryViewMode('table')}
                                className={`p-2 rounded-xl transition-all ${inventoryViewMode === 'table' ? 'bg-[#06B6D4] text-[#0F172A]' : 'text-slate-500 hover:text-white'}`}
                                title="Vista en Lista / Tabla detallada"
                            >
                                <List size={16} />
                            </button>
                        </div>

                        <div className="flex gap-2 p-1 bg-[#0F172A] rounded-2xl border border-slate-800">
                            {['ALL', 'VULNERABLE', 'ATTACKED'].map(f => (
                                <button 
                                    key={f}
                                    onClick={() => setAssetStatusFilter(f)}
                                    className={`px-4 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all ${assetStatusFilter === f ? 'bg-[#06B6D4] text-[#0F172A]' : 'text-slate-500 hover:text-white'}`}
                                >
                                    {f === 'ALL' ? 'Todos' : f === 'VULNERABLE' ? 'Vulnerables' : 'Bajo Ataque'}
                                </button>
                            ))}
                        </div>
                        <button 
                            onClick={() => setShowAddModal(true)}
                            className="flex items-center gap-2 px-6 py-3 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20"
                            title="Registrar un nuevo servidor, equipo institucional o recurso"
                        >
                            <Plus size={18} />
                            Añadir
                        </button>
                    </div>
                </div>

                {inventoryViewMode === 'grid' ? (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                    {processedInventory.map((group, idx) => (
                        <div key={idx} className="bg-[#0F172A]/50 backdrop-blur-sm p-1 rounded-[32px] border border-slate-800 group hover:border-[#06B6D4]/30 transition-all relative">
                            {group.runtime_alerts_count > 0 && (
                                <div className="absolute -top-2 -right-2 bg-red-600 text-white text-[10px] font-black px-3 py-1 rounded-full animate-bounce shadow-lg shadow-red-600/50 z-10 uppercase tracking-tighter" title="Se han detectado alertas de seguridad en tiempo real en este activo">
                                    🚨 Alerta en Tiempo Real Activa
                                </div>
                            )}
                            
                            <div className="bg-[#0F172A] p-6 rounded-[30px]">
                                <div className="flex justify-between items-start mb-6">
                                    <div className="flex gap-3">
                                        {group.interfaces.map((inf, i) => (
                                            <div key={i} className="p-3 bg-slate-800 rounded-2xl text-[#06B6D4] border border-white/5 shadow-inner" title={`Tipo de activo: ${inf.asset_type_label || inf.asset_type}`}>
                                                <AssetIcon type={inf.asset_type} />
                                            </div>
                                        ))}
                                    </div>
                                    <div className="text-right flex flex-col items-end gap-2">
                                        <button
                                            onClick={() => handleOpenDetailsModal(group)}
                                            title="Ver detalles del activo"
                                            className="p-2 -m-2 rounded-xl text-slate-500 hover:text-[#06B6D4] hover:bg-[#06B6D4]/10 transition-all"
                                        >
                                            <Eye size={16} />
                                        </button>
                                        {pingResults[group.name] ? (
                                            pingResults[group.name].loading ? (
                                                <p className="text-[10px] font-black text-cyan-400 uppercase tracking-tighter flex items-center gap-1">
                                                    <RefreshCw size={10} className="animate-spin" /> Verificando Ping...
                                                </p>
                                            ) : pingResults[group.name].ping_ok ? (
                                                <p className="text-[10px] font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-1" title="Host responde a ICMP Ping en vivo">
                                                    <CheckCircle size={10} /> En línea ({pingResults[group.name].latency_ms}ms)
                                                </p>
                                            ) : (
                                                <p className="text-[10px] font-black text-slate-400 uppercase tracking-tighter flex items-center gap-1" title={pingResults[group.name].message || "Host sin respuesta de ICMP Ping"}>
                                                    <ZapOff size={10} className="text-slate-500" /> Offline (Sin respuesta ICMP)
                                                </p>
                                            )
                                        ) : (group.status === 'active' || group.agent_id) ? (
                                            <p className="text-[10px] font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-1" title="Activo sincronizado y monitoreado por agente o sondeo">
                                                <CheckCircle size={10} /> Sincronizado
                                            </p>
                                        ) : (
                                            <p className="text-[10px] font-black text-slate-400 uppercase tracking-tighter flex items-center gap-1" title="Activo sin agente Wazuh conectado y sin ping verificado">
                                                <Clock size={10} className="text-slate-500" /> Offline / Pendiente
                                            </p>
                                        )}

                                    </div>
                                </div>
                                
                                <h4 className="text-white font-bold text-xl mb-1 tracking-tight">{group.name}</h4>
                                <div className="flex items-center gap-2 mb-3">
                                   <span className={`text-[10px] font-extrabold px-2.5 py-0.5 rounded-full uppercase tracking-widest ${group.interfaces[0]?.asset_type_badge_class || 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'}`}>
                                     {group.interfaces[0]?.asset_type_label || group.interfaces[0]?.asset_type || 'SERVER'}
                                   </span>
                                   <span className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em]" title="Activo consolidado que agrupa sus distintas interfaces, IP y servicios de red">Activo Unificado</span>

                                </div>
                                
                                {/* Wazuh, Vault & Ping status badges */}
                                <div className="flex flex-wrap gap-2 mb-6">
                                  {/* Render Wazuh badge ONLY for server/workstation hosts or if agent_id exists */}
                                  {(group.agent_id || ['SERVER', 'SERVER_LINUX', 'SERVER_WINDOWS', 'WORKSTATION'].includes(group.interfaces[0]?.asset_type)) && (
                                    group.agent_id ? (
                                      <span 
                                        title={`Agente Wazuh EDR instalado y activo en este servidor (ID Agente: ${group.agent_id})`}
                                        className={`text-[8px] font-black px-2 py-0.5 rounded border uppercase tracking-wider ${
                                        group.status === 'active' 
                                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                                          : 'bg-red-500/10 text-red-400 border-red-500/20'
                                      }`}>
                                        Wazuh EDR: {group.status === 'active' ? 'Activo' : group.status} (ID: {group.agent_id})
                                      </span>
                                    ) : (
                                      <span 
                                        title="Agente Wazuh EDR no instalado en este servidor"
                                        className="text-[8px] bg-slate-800 text-slate-400 font-black px-2 py-0.5 rounded border border-slate-700 uppercase tracking-wider"
                                      >
                                        Wazuh EDR: No instalado
                                      </span>
                                    )
                                  )}
                                  
                                  {group.has_vault_secret ? (
                                    <span 
                                      title="Credenciales de conexión Sudo/SSH almacenadas y encriptadas de forma segura en HashiCorp Vault"
                                      className="text-[8px] bg-amber-500/10 text-amber-400 font-black px-2 py-0.5 rounded border border-amber-400/20 uppercase tracking-wider"
                                    >
                                      Credenciales Vault: Configurada
                                    </span>
                                  ) : (
                                    <span 
                                      title="Sin credenciales configuradas en Vault. Haz clic en el botón Vault para asignar un secreto"
                                      className="text-[8px] bg-red-500/10 text-red-400 font-black px-2 py-0.5 rounded border border-red-500/20 uppercase tracking-wider"
                                    >
                                      Credenciales Vault: No asignada
                                    </span>
                                  )}

                                  <button 
                                    onClick={(e) => { e.stopPropagation(); handlePingAsset(group.name); }}
                                    disabled={pingResults[group.name]?.loading}
                                    className={`text-[8px] font-black px-2 py-0.5 rounded border uppercase tracking-wider transition-all flex items-center gap-1 cursor-pointer ${
                                      pingResults[group.name]?.loading 
                                        ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' 
                                        : pingResults[group.name]?.ping_ok === true 
                                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                                        : pingResults[group.name]?.ping_ok === false 
                                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' 
                                        : 'bg-slate-800 text-slate-300 hover:bg-slate-700 border-slate-700'
                                    }`}
                                    title="Comprobar alcanzabilidad por red en tiempo real mediante ICMP Ping"
                                  >
                                    <Activity size={10} className={pingResults[group.name]?.loading ? "animate-spin text-cyan-400" : "text-cyan-400"} />
                                    {pingResults[group.name]?.loading ? "Probando..." : pingResults[group.name]?.ping_ok === true ? `Ping: ${pingResults[group.name]?.latency_ms}ms` : pingResults[group.name]?.ping_ok === false ? "Ping: Sin respuesta" : "Validar Ping"}
                                  </button>
                                </div>
                                
                                {group.agent_id && (
                                  <div className="flex gap-2 mt-2 w-full mb-4">
                                    <button 
                                      onClick={() => handleWazuhAction(group.agent_id, 'restart')}
                                      className="text-[8px] bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-2 py-1 rounded border border-slate-700 transition-all flex-1"
                                      disabled={wazuhActionLoading}
                                      title="Solicitar reinicio remoto del servicio del agente Wazuh"
                                    >
                                      Reiniciar Agente
                                    </button>
                                    <button 
                                      onClick={() => handleWazuhAction(group.agent_id, 'scan')}
                                      className="text-[8px] bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-2 py-1 rounded border border-slate-700 transition-all flex-1"
                                      disabled={wazuhActionLoading}
                                      title="Disparar escaneo de integridad de archivos FIM inmediatamente"
                                    >
                                      Escanear FIM
                                    </button>
                                    <button 
                                      onClick={() => handleWazuhAction(group.agent_id, 'logs')}
                                      className="text-[8px] bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-2 py-1 rounded border border-slate-700 transition-all flex-1"
                                      disabled={wazuhActionLoading}
                                      title="Ver registro de logs recientes del agente en el manager"
                                    >
                                      Ver Logs
                                    </button>
                                  </div>
                                )}

                                {group.agent_id && (
                                  <div className="mt-2 w-full">
                                    <button
                                      onClick={() => handleWazuhUninstall(group.agent_id, group.name)}
                                      className="text-[8px] bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 font-bold px-2 py-1 rounded transition-all w-full"
                                      disabled={wazuhActionLoading}
                                    >
                                      Desinstalar Agente
                                    </button>
                                  </div>
                                )}

                                <div className="grid grid-cols-2 gap-4 mb-6">
                                    <div 
                                      className={`p-4 rounded-2xl border transition-all ${group.vulnerability_count > 0 ? 'bg-orange-500/5 border-orange-500/20' : 'bg-slate-800/20 border-slate-800'}`}
                                      title="Cantidad de vulnerabilidades de seguridad detectadas y pendientes de remediar en este activo"
                                    >
                                        <p className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1">Vulnerabilidades</p>
                                        <div className="flex items-center gap-2">
                                            <ShieldAlert size={14} className={group.vulnerability_count > 0 ? 'text-orange-400' : 'text-slate-600'} />
                                            <span className={`text-lg font-black ${group.vulnerability_count > 0 ? 'text-orange-400' : 'text-slate-400'} flex items-center`}>
                                                {group.vulnerability_count}
                                                {group.resolved_count > 0 && (
                                                    <span className="text-[10px] text-emerald-400 font-black tracking-tighter bg-emerald-500/10 px-2 py-0.5 rounded-md ml-2 border border-emerald-500/20" title={`${group.resolved_count} vulnerabilidades resueltas`}>
                                                        ✓ {group.resolved_count}
                                                    </span>
                                                )}
                                            </span>
                                        </div>
                                    </div>
                                    <div 
                                      className={`p-4 rounded-2xl border transition-all ${group.runtime_alerts_count > 0 ? 'bg-red-500/5 border-red-500/20' : 'bg-slate-800/20 border-slate-800'}`}
                                      title="Alertas de seguridad en tiempo real (Falco/Wazuh/Zeek) asociadas a este activo"
                                    >
                                        <p className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1">Alertas en Tiempo Real</p>
                                        <div className="flex items-center gap-2">
                                            <Zap size={14} className={group.runtime_alerts_count > 0 ? 'text-red-400' : 'text-slate-600'} />
                                            <span className={`text-lg font-black ${group.runtime_alerts_count > 0 ? 'text-red-400' : 'text-slate-400'}`}>
                                                {group.runtime_alerts_count}
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-2 mb-6">
                                    {group.interfaces.map((inf, i) => (
                                        <div key={i} className="flex items-center justify-between text-[10px] bg-slate-800/30 p-2 rounded-xl border border-white/5 group/inf hover:bg-[#06B6D4]/10 transition-all cursor-pointer" onClick={() => handleSelectAsset(inf.asset_name)} title={`Interfaz: ${inf.asset_type_label || inf.asset_type} - ${inf.endpoint}`}>
                                            <div className="flex items-center gap-2">
                                                <div className="w-1.5 h-1.5 rounded-full bg-[#06B6D4]" />
                                                <span className="text-slate-400 font-bold uppercase tracking-tighter">{inf.asset_type}</span>
                                            </div>
                                            <code className="text-[#06B6D4] font-bold truncate max-w-[120px]">{inf.endpoint}</code>
                                            <ChevronRight size={12} className="text-slate-600 group-hover/inf:translate-x-1 transition-all" />
                                        </div>
                                    ))}
                                </div>

                                <div className="flex gap-2">
                                    <button 
                                        onClick={() => handleSelectAsset(group.name)}
                                        title="Ver matriz completa de hallazgos, parches y auditorías de este activo"
                                        className="flex-1 py-3 bg-slate-800 hover:bg-[#06B6D4] text-slate-400 hover:text-[#0F172A] font-black uppercase text-[9px] tracking-[0.2em] rounded-xl transition-all flex items-center justify-center gap-2"
                                    >
                                        Ver Análisis Completo
                                        <ExternalLink size={12} />
                                    </button>
                                    <button
                                        onClick={() => handleDownloadAssetReport(group.name)}
                                        title="Descargar Reporte PDF de seguridad de este activo"
                                        className="py-3 px-4 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-400/20 font-black uppercase text-[9px] tracking-[0.15em] rounded-xl transition-all flex items-center justify-center gap-2 shrink-0"
                                    >
                                        <Download size={13} />
                                        PDF
                                    </button>
                                    <button
                                        onClick={() => handleOpenVaultModal(group.name)}
                                        title="Configurar credenciales Sudo o llaves SSH en HashiCorp Vault"
                                        className="py-3 px-3 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-400/20 font-black uppercase text-[9px] tracking-[0.15em] rounded-xl transition-all flex items-center justify-center gap-1.5 shrink-0"
                                    >
                                        <KeyRound size={13} />
                                        Vault
                                    </button>
                                    <button
                                        onClick={() => handleOpenAssetDetails(group)}
                                        title="Ver características generales del sistema (SO, Kernel, versión EDR)"
                                        className="py-3 px-3 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-400/20 font-black uppercase text-[9px] tracking-[0.15em] rounded-xl transition-all flex items-center justify-center gap-1.5 shrink-0"
                                    >
                                        <Info size={13} />
                                        Detalles
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
                ) : (
                <div className="bg-[#0F172A] rounded-3xl border border-slate-800 overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-[#1E293B] text-slate-400 text-[10px] font-black uppercase tracking-widest border-b border-slate-800">
                                    <th className="p-4">Activo Unificado</th>
                                    <th className="p-4">Tipo</th>
                                    <th className="p-4">Endpoint / IP</th>
                                    <th className="p-4">Estado EDR / Ping</th>
                                    <th className="p-4">Vulnerabilidades</th>
                                    <th className="p-4">Alertas Runtime</th>
                                    <th className="p-4 text-right">Acciones</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800">
                                {processedInventory.map((group, idx) => (
                                    <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                                        <td className="p-4 font-bold text-white text-sm">
                                            <div className="flex items-center gap-2">
                                                <span>{group.name}</span>
                                                {group.runtime_alerts_count > 0 && (
                                                    <span className="text-[9px] bg-red-500/20 text-red-400 font-bold px-2 py-0.5 rounded-full border border-red-500/30 animate-pulse">
                                                        🚨 Runtime
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="p-4">
                                            <span className={`text-[9px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wider ${group.interfaces[0]?.asset_type_badge_class || 'bg-cyan-500/10 text-cyan-400'}`}>
                                                {group.interfaces[0]?.asset_type_label || group.interfaces[0]?.asset_type || 'SERVER'}
                                            </span>
                                        </td>
                                        <td className="p-4 font-mono text-xs text-[#06B6D4]">
                                            {group.interfaces[0]?.endpoint || '10.4.3.34'}
                                        </td>
                                        <td className="p-4 text-xs font-bold">
                                            {pingResults[group.name]?.ping_ok || group.status === 'active' || group.agent_id ? (
                                                <span className="text-emerald-400 flex items-center gap-1">
                                                    <CheckCircle size={12} /> Sincronizado (Online)
                                                </span>
                                            ) : (
                                                <span className="text-slate-400 flex items-center gap-1">
                                                    <Clock size={12} className="text-slate-500" /> Offline / Pendiente
                                                </span>
                                            )}
                                        </td>
                                        <td className="p-4">
                                            <span className={`font-bold ${group.vulnerability_count > 0 ? 'text-orange-400' : 'text-slate-500'}`}>
                                                {group.vulnerability_count}
                                            </span>
                                        </td>
                                        <td className="p-4">
                                            <span className={`font-bold ${group.runtime_alerts_count > 0 ? 'text-red-400' : 'text-slate-500'}`}>
                                                {group.runtime_alerts_count}
                                            </span>
                                        </td>
                                        <td className="p-4 text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                <button
                                                    onClick={() => handleOpenAssetDetails(group)}
                                                    className="px-3 py-1.5 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500 hover:text-white rounded-xl font-bold text-[10px] transition-all"
                                                    title="Ver características del sistema (SO, Kernel, EDR)"
                                                >
                                                    Detalles
                                                </button>
                                                <button
                                                    onClick={() => handleSelectAsset(group.name)}
                                                    className="px-3 py-1.5 bg-[#06B6D4]/10 text-[#06B6D4] hover:bg-[#06B6D4] hover:text-[#0F172A] rounded-xl font-bold text-[10px] transition-all"
                                                >
                                                    Análisis
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
                )}
            </div>
          )}

           {currentView === 'itdr' && (
            <div className="space-y-8">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                    <UserCheck className="text-indigo-400" size={28} />
                    Detección & Respuesta ante Amenazas de Identidad (ITDR)
                  </h2>
                  <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">
                    Monitoreo en Tiempo Real de Autenticación, MFA y Sesiones Authentik
                  </p>
                </div>
                <div className="flex gap-3">
                  <span className="text-[10px] bg-indigo-500/10 text-indigo-400 font-bold px-3 py-1.5 rounded-xl border border-indigo-500/20 uppercase tracking-widest flex items-center gap-2">
                    <Radio size={12} className="animate-pulse text-indigo-400" />
                    Webhook Authentik: Activo
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div className="bg-[#1E293B] p-6 rounded-3xl border border-slate-800">
                  <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-1">Intentos de Fuerza Bruta (24h)</p>
                  <h3 className="text-3xl font-black text-white tracking-tight">0</h3>
                  <p className="text-[9px] text-emerald-400 font-bold mt-2">Protección Autónoma Activada (SLA &lt;500ms)</p>
                </div>
                <div className="bg-[#1E293B] p-6 rounded-3xl border border-slate-800">
                  <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-1">Alertas MFA / Alteraciones</p>
                  <h3 className="text-3xl font-black text-amber-400 tracking-tight">0</h3>
                  <p className="text-[9px] text-slate-500 font-bold mt-2">Dispositivos TOTP Auditados</p>
                </div>
                <div className="bg-[#1E293B] p-6 rounded-3xl border border-slate-800">
                  <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-1">Sesiones Revocadas por IA</p>
                  <h3 className="text-3xl font-black text-indigo-400 tracking-tight">0</h3>
                  <p className="text-[9px] text-indigo-400 font-bold mt-2">Revocación Automática en Authentik</p>
                </div>
              </div>

              <div className="bg-[#1E293B] rounded-3xl border border-slate-800 p-8">
                <h3 className="text-white font-bold text-lg mb-4 flex items-center gap-2">
                  <Activity size={18} className="text-indigo-400" />
                  Registro de Telemetría ITDR & Eventos de Sesión
                </h3>
                <div className="bg-[#0F172A] rounded-2xl p-6 font-mono text-xs text-slate-300 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-slate-500 font-black text-[10px] uppercase tracking-widest">
                    <span>Marca de Tiempo</span>
                    <span>Evento / Regla</span>
                    <span>Usuario</span>
                    <span>IP Origen</span>
                    <span>Confianza</span>
                    <span>Acción Autónoma</span>
                  </div>
                  <div className="text-center py-8 text-slate-500 italic">
                    Sin eventos de amenaza de identidad detectados en los últimos 15 minutos. Escuchando webhooks de Authentik en tiempo real...
                  </div>
                </div>
              </div>
            </div>
           )}

           {currentView === 'health' && healthStatus && (
            <div className="space-y-8">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                            <Activity className="text-[#06B6D4]" size={28} />
                            Salud del Ecosistema Centinela
                        </h2>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">Monitoreo de Servicios y Latencia de IA</p>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {Array.isArray(healthStatus?.services) && healthStatus.services.map((service, idx) => {
                        const tier = healthStatusTier(service.status)
                        const dotClass = tier === 'ok' ? 'bg-emerald-500' : tier === 'warn' ? 'bg-amber-500' : 'bg-red-500'
                        const textClass = tier === 'ok' ? 'text-emerald-400' : tier === 'warn' ? 'text-amber-400' : 'text-red-400'
                        return (
                        <div key={idx} className="bg-[#1E293B] p-8 rounded-[32px] border border-slate-800 relative overflow-hidden group">
                            <div className="absolute top-0 right-0 p-6 opacity-10 group-hover:opacity-20 transition-all">
                                <Cpu size={64} className="text-[#06B6D4]" />
                            </div>
                            <div className="flex items-center gap-4 mb-6">
                                <div className={`w-3 h-3 rounded-full animate-pulse ${dotClass}`} />
                                <h4 className="text-white font-bold text-lg">{service.name}</h4>
                            </div>
                            <div className="flex justify-between items-end">
                                <div>
                                    <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-1">Estado</p>
                                    <p className={`${textClass} font-bold text-sm`}>{service.status}</p>
                                </div>
                                <div className="text-right">
                                    <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-1">Latencia</p>
                                    <p className="text-white font-bold text-sm">{service.latency}</p>
                                </div>
                            </div>
                        </div>
                        )
                    })}
                </div>
            </div>
          )}

          {currentView === 'users' && (
            <div className="space-y-8 animate-in fade-in duration-300">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                            <Users className="text-[#06B6D4]" size={28} />
                            Gestión de Usuarios y Roles (Authentik IDP)
                        </h2>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">
                            Control de Acceso Basado en Roles (RBAC) sincronizado con Authentik Central
                        </p>
                    </div>
                    <button 
                        onClick={fetchUsers} 
                        className="bg-[#0F172A] border border-slate-800 text-slate-300 hover:text-white px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2"
                    >
                        <Activity size={14} className={usersLoading ? "animate-spin text-[#06B6D4]" : ""} />
                        Refrescar desde Authentik
                    </button>
                </div>

                <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="border-b border-slate-800 text-[10px] font-black text-slate-500 uppercase tracking-widest">
                                    <th className="pb-4">Usuario</th>
                                    <th className="pb-4">Nombre Completo</th>
                                    <th className="pb-4">Correo Electrónico</th>
                                    <th className="pb-4">Rol en Centinela</th>
                                    <th className="pb-4 text-right">Acción / Permisos</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/50">
                                {usersList.map((usr, idx) => (
                                    <tr key={idx} className="hover:bg-white/5 transition-colors">
                                        <td className="py-4 text-sm font-bold text-white flex items-center gap-3">
                                            <div className="w-8 h-8 rounded-lg bg-[#06B6D4]/10 border border-[#06B6D4]/30 flex items-center justify-center text-[#06B6D4] font-black text-xs">
                                                {usr.username?.[0]?.toUpperCase()}
                                            </div>
                                            {usr.username}
                                        </td>
                                        <td className="py-4 text-xs font-bold text-slate-300">{usr.name ||usr.username}</td>
                                        <td className="py-4 text-xs font-bold text-slate-400">{usr.email || 'N/A'}</td>
                                        <td className="py-4">
                                             <span className={`px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-wider ${
                                                 usr.role === 'Admin' ? 'bg-[#06B6D4]/20 text-[#06B6D4] border border-[#06B6D4]/30' :
                                                 usr.role === 'Analyst' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' :
                                                 usr.role === 'Auditor' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                                 'bg-slate-800 text-slate-400 border border-slate-700'
                                             }`}>
                                                 {usr.role === 'Admin' ? '🛡️ Administrador' :
                                                  usr.role === 'Analyst' ? '⚡ Analista SOC' :
                                                  usr.role === 'Auditor' ? '📋 Auditor Seg' : '👁️ Visualizador'}
                                             </span>
                                         </td>
                                         <td className="py-4 text-right">
                                             {currentUserRole === 'Admin' ? (
                                                 <div className="relative inline-block">
                                                     <select 
                                                         value={usr.role}
                                                         onChange={(e) => handleUpdateUserRole(usr.username, e.target.value)}
                                                         className="bg-[#0F172A] border border-slate-700 text-white font-bold text-xs rounded-xl px-3 py-2 pr-8 focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                     >
                                                         <option value="Admin">🛡️ Administrador (Acceso Total)</option>
                                                         <option value="Analyst">⚡ Analista SOC (Operación / Remediar)</option>
                                                         <option value="Auditor">📋 Auditor (Auditoría / Reportes)</option>
                                                         <option value="Viewer">👁️ Visualizador (Sólo Lectura)</option>
                                                     </select>
                                                     <ChevronDown size={14} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                                 </div>
                                             ) : (
                                                 <span className="text-[10px] font-bold text-slate-600 uppercase">Sin Privilegios</span>
                                             )}
                                         </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
          )}

          {currentView === 'settings' && (
            <div className="space-y-8 animate-in fade-in duration-300">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                            <Cpu className="text-[#06B6D4]" size={28} />
                            Configuración del Sistema & Agentes
                        </h2>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">
                            Administración centralizada de API Keys, Endpoints de Agentes, Integraciones y Políticas
                        </p>
                    </div>
                    <div className="flex items-center gap-3">
                        <button 
                            onClick={fetchSystemConfig} 
                            className="bg-[#0F172A] border border-slate-800 text-slate-300 hover:text-white px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2"
                        >
                            <Activity size={14} className={configLoading ? "animate-spin text-[#06B6D4]" : ""} />
                            Recargar
                        </button>
                        <button 
                            onClick={handleSaveConfig} 
                            disabled={configSaving}
                            className="bg-[#06B6D4] text-[#0F172A] hover:bg-white px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-wider transition-all shadow-lg shadow-[#06B6D4]/20 flex items-center gap-2"
                        >
                            <ShieldCheck size={16} />
                            {configSaving ? 'Guardando...' : 'Guardar Cambios'}
                        </button>
                    </div>
                </div>

                <div className="grid grid-cols-1 gap-6">
                    {['LLM_AGENTS', 'SECURITY_AGENTS', 'INTEGRATIONS', 'POLICY_RULES'].map((cat, cIdx) => {
                        const items = systemConfig.filter(s => s.category === cat)
                        const categoryTitles = {
                            LLM_AGENTS: '🧠 Agentes de Inteligencia Artificial (LLM & Inference)',
                            SECURITY_AGENTS: '🛡️ Agentes de Seguridad (Wazuh EDR, Zeek NIDS, Falco)',
                            INTEGRATIONS: '🔌 Integraciones Externas (Authentik, GitLab, HashiCorp Vault)',
                            POLICY_RULES: '⚙️ Políticas de Autonomía & SLAs de Seguridad'
                        }
                        if (items.length === 0) return null
                        return (
                            <div key={cIdx} className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 space-y-6">
                                <h3 className="text-white font-bold text-lg border-b border-slate-800 pb-4">
                                    {categoryTitles[cat] || cat}
                                </h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    {items.map((item, idx) => (
                                        <div key={idx} className="space-y-2">
                                            <div className="flex justify-between items-center">
                                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block flex items-center gap-2">
                                                    {item.key}
                                                </label>
                                                {item.key === 'AI_MODEL' && (
                                                    <button 
                                                        type="button" 
                                                        onClick={() => {
                                                            const currentProv = systemConfig.find(s => s.key === 'AI_PROVIDER')?.value || 'nvidia_nim'
                                                            fetchModelsForProvider(currentProv)
                                                        }}
                                                        className="text-[9px] font-black text-[#06B6D4] hover:underline uppercase tracking-wider flex items-center gap-1"
                                                    >
                                                        <Zap size={10} />
                                                        {loadingModels ? 'Cargando...' : 'Cargar Modelos Disponibles'}
                                                    </button>
                                                )}
                                            </div>

                                            {item.key === 'AI_PROVIDER' ? (
                                                <div className="relative">
                                                    <select 
                                                        className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 pr-12 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                        value={item.value || 'nvidia_nim'}
                                                        onChange={(e) => {
                                                            const updated = systemConfig.map(s => s.key === item.key ? { ...s, value: e.target.value } : s)
                                                            setSystemConfig(updated)
                                                            fetchModelsForProvider(e.target.value)
                                                        }}
                                                        title="Seleccionar proveedor de LLM para el motor de análisis SOAR e IA"
                                                    >
                                                        <option value="smart_router">Smart Router Global (Automático con Fallback)</option>
                                                        <option value="nvidia_nim">NVIDIA NIM Cloud / Inference</option>
                                                        <option value="google_genai">Google AI Studio (Gemini)</option>
                                                        <option value="groq">Groq Cloud (Llama / Mixtral)</option>
                                                        <option value="openai">OpenAI (GPT-4o / GPT-4)</option>
                                                        <option value="anthropic">Anthropic (Claude 3.5)</option>
                                                        <option value="ollama">Ollama / Servidor Local / On-Premise</option>
                                                    </select>
                                                    <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                                </div>
                                            ) : item.key === 'AI_MODEL' && availableModels.length > 0 ? (
                                                <div className="relative">
                                                    <select 
                                                        className="w-full bg-[#0F172A] border border-[#06B6D4]/50 rounded-2xl p-4 pr-12 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                        value={item.value || ''}
                                                        onChange={(e) => {
                                                            const updated = systemConfig.map(s => s.key === item.key ? { ...s, value: e.target.value } : s)
                                                            setSystemConfig(updated)
                                                        }}
                                                        title="Seleccionar modelo específico del proveedor de IA"
                                                    >
                                                        {availableModels.map((m, mIdx) => (
                                                            <option key={mIdx} value={m}>{m}</option>
                                                        ))}
                                                    </select>
                                                    <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-[#06B6D4]/50 pointer-events-none" />
                                                </div>
                                            ) : (
                                                <input 
                                                    type={item.key.includes('KEY') || item.key.includes('SECRET') || item.key.includes('TOKEN') ? 'password' : 'text'} 
                                                    className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                                    value={item.value || ''}
                                                    onChange={(e) => {
                                                        const updated = systemConfig.map(s => s.key === item.key ? { ...s, value: e.target.value } : s)
                                                        setSystemConfig(updated)
                                                    }}
                                                />
                                            )}
                                            <p className="text-[9px] text-slate-500 font-medium">{item.description}</p>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )
                    })}
                </div>
            </div>
          )}
        </div>

        {showAddModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0F172A]/80 backdrop-blur-sm animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-lg rounded-[40px] border border-white/10 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-300 max-h-[90vh] overflow-y-auto">
                    <div className="p-8 border-b border-white/5 flex items-center justify-between sticky top-0 bg-[#1E293B] z-10">
                        <h3 className="text-white font-bold text-xl flex items-center gap-3">
                            <PlusCircle className="text-[#06B6D4]" />
                            Registrar Nuevo Activo
                        </h3>
                        <button onClick={() => setShowAddModal(false)} className="text-slate-500 hover:text-white transition-all" title="Cerrar">
                            <X size={24} />
                        </button>
                    </div>
                    <form onSubmit={handleAddAsset} className="p-8 space-y-6">
                        <div className="space-y-4">

                            {/* ── Nombre ── */}
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Nombre del Activo <span className="text-red-400">*</span></label>
                                <input
                                    type="text"
                                    required
                                    className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                    placeholder="ej. Laptop-Dev-Juan o Servidor-Prod-01"
                                    value={newAsset.asset_name}
                                    onChange={(e) => setNewAsset({...newAsset, asset_name: e.target.value})}
                                />
                            </div>

                            {/* ── Tipo de Activo ── */}
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Tipo de Activo <span className="text-red-400">*</span></label>
                                <div className="relative">
                                    <select
                                        required
                                        className={`w-full bg-[#0F172A] border rounded-2xl p-4 pr-10 font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer transition-all ${
                                            newAsset.asset_type ? 'border-slate-800 text-white' : 'border-amber-500/50 text-slate-500'
                                        }`}
                                        value={newAsset.asset_type}
                                        onChange={(e) => setNewAsset({...newAsset, asset_type: e.target.value, vault_ansible_user: '', vault_sudo_token: '', ssh_private_key: '', gitlab_user: '', gitlab_token: '', auth_type: 'PASSWORD'})}
                                    >
                                        <option value="" disabled>— Seleccione tipo de activo —</option>
                                        <optgroup label="Servidores y Equipos">
                                            <option value="WORKSTATION">Estación de Trabajo / Equipo Institucional</option>
                                            <option value="SERVER_LINUX">Servidor Linux</option>
                                            <option value="SERVER_WINDOWS">Servidor Windows</option>
                                        </optgroup>
                                        <optgroup label="Infraestructura de Red">
                                            <option value="CISCO_NETWORK">Switch / Router Cisco (SNMP / SSH)</option>
                                            <option value="VMWARE_ESXI">Hipervisor VMware ESXi (vSphere API / SSH)</option>
                                        </optgroup>
                                        <optgroup label="Cloud y Contenedores">
                                            <option value="CONTAINER">Docker Container</option>
                                            <option value="KUBERNETES">Kubernetes Cluster</option>
                                            <option value="CLOUD">Recurso Cloud (AWS/GCP)</option>
                                        </optgroup>
                                        <optgroup label="Repositorios y Servicios">
                                            <option value="GITLAB">GitLab / Gitea Repository</option>
                                            <option value="IP">Dirección IP / Puerto</option>
                                            <option value="URL">URL / Aplicación Web</option>
                                            <option value="DATABASE">Base de Datos</option>
                                        </optgroup>
                                    </select>
                                    <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                </div>
                                {!newAsset.asset_type && (
                                    <p className="text-[9px] text-amber-400 mt-1.5 flex items-center gap-1 font-medium">
                                        <AlertTriangle size={10} /> Selecciona un tipo para continuar configurando el activo
                                    </p>
                                )}
                            </div>

                            {/* ── Campos que sólo aparecen cuando hay tipo seleccionado ── */}
                            {newAsset.asset_type && (
                                <>
                                    {/* Criticidad */}
                                    <div>
                                        <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2" title="Nivel de criticidad del activo según NIST SP 800-60 y CSF 2.0">Criticidad (NIST SP 800-60 / CSF 2.0)</label>
                                        <div className="relative">
                                            <select
                                                className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 pr-10 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                value={newAsset.criticality}
                                                onChange={(e) => setNewAsset({...newAsset, criticality: e.target.value})}
                                            >
                                                <option value="CRITICAL">Muy Alta / Crítica — Impacto Severo (SLA: 1 hora)</option>
                                                <option value="HIGH">Alta — Impacto Alto (SLA: 4 horas)</option>
                                                <option value="MEDIUM">Moderada / Media — Impacto Moderado (SLA: 24 horas)</option>
                                                <option value="LOW">Baja — Impacto Bajo (SLA: 72 horas)</option>
                                                <option value="INFORMATIONAL">Informativa — Monitoreo (SLA: 7 días)</option>
                                            </select>
                                            <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                        </div>
                                    </div>

                                    {/* Endpoint / Dirección */}
                                    <div>
                                        <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                            {newAsset.asset_type === 'GITLAB' ? 'URL del Repositorio GitLab / Gitea' : 'Dirección / Endpoint (IP / FQDN / URL)'}
                                        </label>
                                        <input
                                            type="text"
                                            required
                                            className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                            placeholder={
                                                newAsset.asset_type === 'GITLAB'
                                                    ? 'ej. http://10.4.3.10 o https://gitlab.casmart.internal'
                                                    : newAsset.asset_type === 'WORKSTATION'
                                                    ? 'ej. 10.4.3.105, 192.168.1.15 o mi-laptop.local'
                                                    : newAsset.asset_type === 'CISCO_NETWORK'
                                                    ? 'ej. 192.168.1.1 (IP del Switch / Router)'
                                                    : newAsset.asset_type === 'VMWARE_ESXI'
                                                    ? 'ej. 10.4.2.17 (IP del host ESXi)'
                                                    : 'ej. 192.168.1.50, postgresql://db..., https://api...'
                                            }
                                            value={newAsset.endpoint}
                                            onChange={(e) => setNewAsset({...newAsset, endpoint: e.target.value})}
                                        />
                                    </div>

                                    {/* ── Credenciales según tipo ── */}
                                    {newAsset.asset_type === 'GITLAB' ? (
                                        <>
                                            <div>
                                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                    <Users size={12} className="text-[#06B6D4]" />
                                                    Usuario de GitLab / Gitea
                                                </label>
                                                <input
                                                    type="text"
                                                    className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700 mb-4"
                                                    placeholder="ej. root o gitlab-admin"
                                                    value={newAsset.gitlab_user || ''}
                                                    onChange={(e) => setNewAsset({...newAsset, gitlab_user: e.target.value})}
                                                />
                                            </div>
                                            <div>
                                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                    <Lock size={12} className="text-[#06B6D4]" />
                                                    Personal Access Token (PAT)
                                                </label>
                                                <div className="relative">
                                                    <input
                                                        type="password"
                                                        required
                                                        className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none pr-12 placeholder-slate-700"
                                                        placeholder="glpat-xxxxxxxxxxxxxxxxxxxx"
                                                        value={newAsset.gitlab_token || ''}
                                                        onChange={(e) => setNewAsset({...newAsset, gitlab_token: e.target.value})}
                                                    />
                                                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2 text-[#06B6D4]/50">
                                                        <Shield size={16} />
                                                    </div>
                                                </div>
                                                <p className="text-[9px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                    <CheckCircle2 size={10} />
                                                    El Token PAT permite auditar repositorios y generar Merge Requests automáticos. Se encripta en Vault.
                                                </p>
                                            </div>
                                        </>
                                    ) : ['SERVER_LINUX', 'SERVER_WINDOWS', 'WORKSTATION', 'CISCO_NETWORK', 'VMWARE_ESXI'].includes(newAsset.asset_type) ? (
                                        <>
                                            {/* Usuario de conexión: sólo si el tipo requiere agente/SSH */}
                                            <div>
                                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2" title="Usuario con privilegios para instalar el agente Wazuh o ejecutar comandos Ansible">
                                                    <Users size={12} className="text-[#06B6D4]" />
                                                    {newAsset.asset_type === 'CISCO_NETWORK' ? 'Usuario SNMP / SSH del Dispositivo' :
                                                     newAsset.asset_type === 'VMWARE_ESXI' ? 'Usuario Administrador vSphere / SSH' :
                                                     'Usuario de Conexión SSH / Ansible'}
                                                </label>
                                                <input
                                                    type="text"
                                                    className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700"
                                                    placeholder={
                                                        newAsset.asset_type === 'CISCO_NETWORK' ? 'ej. admin o cisco-ro' :
                                                        newAsset.asset_type === 'VMWARE_ESXI' ? 'ej. root o administrator@vsphere.local' :
                                                        'ej. ubuntu, centinela, root'
                                                    }
                                                    value={newAsset.vault_ansible_user || ''}
                                                    onChange={(e) => setNewAsset({...newAsset, vault_ansible_user: e.target.value})}
                                                />
                                                <p className="text-[9px] text-slate-500 mt-1.5 font-medium">
                                                    Credencial almacenada de forma encriptada en HashiCorp Vault. Nunca se guarda en texto plano.
                                                </p>
                                            </div>

                                            {/* Método de autenticación — sólo para servidores Linux/Windows/Workstation */}
                                            {['SERVER_LINUX', 'SERVER_WINDOWS', 'WORKSTATION'].includes(newAsset.asset_type) && (
                                                <div className="space-y-4">
                                                    <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2" title="Selecciona cómo Ansible autenticará la conexión SSH al servidor">
                                                        Método de Autenticación SSH
                                                    </label>
                                                    <div className="flex gap-3 mb-4">
                                                        <button
                                                            type="button"
                                                            title="Usar contraseña sudo para autenticación"
                                                            onClick={() => setNewAsset({...newAsset, auth_type: 'PASSWORD'})}
                                                            className={`flex-1 py-3 px-4 rounded-xl text-xs font-bold transition-all border ${newAsset.auth_type !== 'SSH_KEY' ? 'bg-[#06B6D4]/20 border-[#06B6D4] text-[#06B6D4]' : 'bg-[#0F172A] border-slate-800 text-slate-400'}`}
                                                        >
                                                            🔑 Contraseña Sudo
                                                        </button>
                                                        <button
                                                            type="button"
                                                            title="Usar llave privada SSH (.pem / RSA) para autenticación sin contraseña"
                                                            onClick={() => setNewAsset({...newAsset, auth_type: 'SSH_KEY'})}
                                                            className={`flex-1 py-3 px-4 rounded-xl text-xs font-bold transition-all border ${newAsset.auth_type === 'SSH_KEY' ? 'bg-[#06B6D4]/20 border-[#06B6D4] text-[#06B6D4]' : 'bg-[#0F172A] border-slate-800 text-slate-400'}`}
                                                        >
                                                            📜 Llave SSH (.pem / RSA)
                                                        </button>
                                                    </div>

                                                    {newAsset.auth_type === 'SSH_KEY' ? (
                                                        <div>
                                                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                                <KeyRound size={12} className="text-[#06B6D4]" />
                                                                Llave Privada SSH (RSA / OpenSSH / PEM)
                                                            </label>
                                                            <textarea
                                                                rows={4}
                                                                className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-mono text-xs focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700 resize-none"
                                                                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEowIBAAKCAQEA...&#10;-----END RSA PRIVATE KEY-----"
                                                                value={newAsset.ssh_private_key || ''}
                                                                onChange={(e) => setNewAsset({...newAsset, ssh_private_key: e.target.value})}
                                                            />
                                                            <p className="text-[9px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                                <CheckCircle2 size={10} />
                                                                La llave privada se cifra con AES-256 y se almacena exclusivamente en HashiCorp Vault.
                                                            </p>
                                                        </div>
                                                    ) : (
                                                        <div>
                                                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2" title="Contraseña de superusuario (sudo) del servidor Linux/Windows">
                                                                <Lock size={12} className="text-[#06B6D4]" />
                                                                Contraseña Sudo del Servidor
                                                            </label>
                                                            <div className="relative">
                                                                <input
                                                                    type="password"
                                                                    className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none pr-12 placeholder-slate-700"
                                                                    placeholder="••••••••••••"
                                                                    value={newAsset.vault_sudo_token || ''}
                                                                    onChange={(e) => setNewAsset({...newAsset, vault_sudo_token: e.target.value})}
                                                                />
                                                                <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2 text-[#06B6D4]/50">
                                                                    <Shield size={16} />
                                                                </div>
                                                            </div>
                                                            <p className="text-[9px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                                <CheckCircle2 size={10} />
                                                                Almacenada encriptada en Vault. No se expone al frontend ni se guarda en la BD.
                                                            </p>
                                                        </div>
                                                    )}
                                                </div>
                                            )}

                                            {/* Para Cisco/VMware: contraseña/token en lugar de sudo */}
                                            {['CISCO_NETWORK', 'VMWARE_ESXI'].includes(newAsset.asset_type) && (
                                                <div>
                                                    <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2" title="Contraseña o token API del dispositivo de red">
                                                        <Lock size={12} className="text-[#06B6D4]" />
                                                        {newAsset.asset_type === 'CISCO_NETWORK' ? 'Contraseña SSH / Comunidad SNMP' : 'Contraseña / Token API vSphere'}
                                                    </label>
                                                    <div className="relative">
                                                        <input
                                                            type="password"
                                                            className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none pr-12 placeholder-slate-700"
                                                            placeholder="••••••••••••"
                                                            value={newAsset.vault_sudo_token || ''}
                                                            onChange={(e) => setNewAsset({...newAsset, vault_sudo_token: e.target.value})}
                                                        />
                                                        <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2 text-[#06B6D4]/50">
                                                            <Shield size={16} />
                                                        </div>
                                                    </div>
                                                    <p className="text-[9px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                        <CheckCircle2 size={10} />
                                                        Credencial cifrada en Vault. Las sondas de red no requieren instalar agente en el dispositivo.
                                                    </p>
                                                </div>
                                            )}
                                        </>
                                    ) : (
                                        /* Para tipos sin agente (URL, IP, DB, Cloud, Container, K8s) */
                                        <div className="flex items-start gap-3 p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-2xl">
                                            <CheckCircle2 size={16} className="text-emerald-400 mt-0.5 shrink-0" />
                                            <div>
                                                <p className="text-[10px] font-black text-emerald-400 uppercase tracking-widest mb-1">Monitoreo Agentless</p>
                                                <p className="text-[9px] text-slate-400 font-medium leading-relaxed">
                                                    Este tipo de activo se monitorea mediante sondas de red externas (Nuclei, Zeek, SNMP) sin necesidad de instalar software en el destino.
                                                </p>
                                            </div>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>

                        <div className="pt-2">
                            <button
                                type="submit"
                                disabled={!newAsset.asset_type}
                                title={!newAsset.asset_type ? 'Selecciona un tipo de activo para continuar' : 'Registrar el activo y activar monitoreo'}
                                className={`w-full py-4 font-black uppercase text-[10px] tracking-widest rounded-2xl transition-all shadow-lg ${
                                    newAsset.asset_type
                                        ? 'bg-[#06B6D4] text-[#0F172A] hover:bg-white shadow-[#06B6D4]/10 cursor-pointer'
                                        : 'bg-slate-800 text-slate-600 cursor-not-allowed shadow-none'
                                }`}
                            >
                                {newAsset.asset_type ? 'Registrar y Activar Monitoreo' : '— Seleccione tipo de activo —'}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        )}

        {/* Investigate Modal */}
        {showInvestigateModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-2xl rounded-[48px] border border-[#06B6D4]/30 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-10 border-b border-white/5 flex items-center justify-between bg-gradient-to-br from-[#06B6D4]/10 to-transparent">
                        <div className="flex items-center gap-4">
                            <div className="p-3 bg-[#06B6D4] text-[#0F172A] rounded-2xl">
                                <Microscope size={28} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-2xl tracking-tighter">Investigación IA en Tiempo Real</h3>
                                <p className="text-[10px] text-[#06B6D4] font-black uppercase tracking-widest">Motor: Gemini 1.5 Flash</p>
                            </div>
                        </div>
                        <button onClick={() => setShowInvestigateModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={32} />
                        </button>
                    </div>
                    
                    <div className="p-10 min-h-[400px]">
                        {isInvestigating ? (
                            <div className="flex flex-col items-center justify-center py-20 space-y-6">
                                <Activity size={64} className="text-[#06B6D4] animate-spin" />
                                <div className="text-center">
                                    <p className="text-white font-bold text-xl mb-2 animate-pulse">Correlacionando Telemetría...</p>
                                    <p className="text-slate-500 text-xs font-medium max-w-xs">La IA está analizando el contexto del activo y el comportamiento sospechoso.</p>
                                </div>
                            </div>
                        ) : investigationData ? (
                            <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
                                <section>
                                    <h4 className="text-[#06B6D4] font-black text-[10px] uppercase tracking-widest mb-3 flex items-center gap-2">
                                        <Info size={14} />
                                        Contexto Técnico
                                    </h4>
                                    <p className="text-slate-300 text-sm leading-relaxed bg-white/5 p-6 rounded-[24px] border border-white/5 italic">
                                        {investigationData.contexto}
                                    </p>
                                </section>

                                <section>
                                    <h4 className="text-orange-400 font-black text-[10px] uppercase tracking-widest mb-3 flex items-center gap-2">
                                        <AlertTriangle size={14} />
                                        Evaluación de Riesgo Real
                                    </h4>
                                    <div className="p-6 bg-orange-500/10 border border-orange-500/20 rounded-[24px]">
                                        <p className="text-orange-100 font-bold text-sm uppercase tracking-tighter mb-2">{investigationData.riesgo}</p>
                                        <p className="text-orange-200/70 text-xs leading-relaxed font-medium">Impacto directo en la continuidad del servicio detectado.</p>
                                    </div>
                                </section>

                                <section>
                                    <h4 className="text-emerald-400 font-black text-[10px] uppercase tracking-widest mb-3 flex items-center gap-2">
                                        <ShieldCheck size={14} />
                                        Acción Inmediata (SLA 5min)
                                    </h4>
                                    <div className="grid grid-cols-1 gap-3">
                                        {investigationData.accion_inmediata.map((action, i) => (
                                            <div key={i} className="flex items-center gap-4 p-4 bg-[#0F172A] border border-slate-800 rounded-2xl group hover:border-emerald-500/50 transition-all">
                                                <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-500 flex items-center justify-center text-[10px] font-black">
                                                    {i + 1}
                                                </div>
                                                <p className="text-xs font-bold text-slate-300">{action}</p>
                                            </div>
                                        ))}
                                    </div>
                                </section>
                            </div>
                        ) : (
                            <div className="text-center py-20 text-slate-500">No se pudo obtener el análisis.</div>
                        )}
                    </div>

                    <div className="p-10 bg-[#0F172A] border-t border-white/5 flex gap-4">
                        <button 
                            onClick={() => { setShowInvestigateModal(false); setCurrentView('soar'); }}
                            className="flex-1 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-xl shadow-[#06B6D4]/10"
                        >
                            Generar Plan SOAR Completo
                        </button>
                        <button 
                            onClick={() => setShowInvestigateModal(false)}
                            className="px-8 py-5 bg-slate-800 text-white font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                        >
                            Cerrar
                        </button>
                    </div>
                </div>
            </div>
        )}
        {/* Script Viewer Modal */}
        {showScriptModal && (
            <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-[#0F172A]/95 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-4xl rounded-[48px] border border-[#06B6D4]/30 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-10 border-b border-white/5 flex items-center justify-between bg-gradient-to-br from-[#06B6D4]/10 to-transparent">
                        <div className="flex items-center gap-4">
                            <div className="p-3 bg-slate-800 text-[#06B6D4] rounded-2xl shadow-inner border border-white/5">
                                <Terminal size={28} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-2xl tracking-tighter">Auditoría de Script de Remediación</h3>
                                <p className="text-[10px] text-[#06B6D4] font-black uppercase tracking-widest">Procedimiento Validado por Inteligencia Artificial</p>
                            </div>
                        </div>
                        <button onClick={() => setShowScriptModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={32} />
                        </button>
                    </div>
                    
                    <div className="p-10">
                        {scriptLoading ? (
                             <div className="flex flex-col items-center justify-center py-20">
                                <Activity size={48} className="text-[#06B6D4] animate-spin mb-4" />
                                <p className="text-slate-500 text-xs font-bold uppercase tracking-widest animate-pulse">Sincronizando con repositorio de remedios...</p>
                             </div>
                        ) : (
                            <div className="relative group">
                                <div className="absolute -inset-1 bg-gradient-to-r from-[#06B6D4]/20 to-blue-500/20 rounded-[34px] blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                                <pre className="relative bg-[#0F172A] p-8 rounded-[32px] border border-slate-800 text-emerald-400 font-mono text-xs overflow-auto max-h-[450px] leading-relaxed custom-scrollbar shadow-inner">
                                    <div className="flex gap-2 mb-4 border-b border-white/5 pb-2">
                                        <div className="w-2.5 h-2.5 rounded-full bg-red-500/50"></div>
                                        <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50"></div>
                                        <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/50"></div>
                                    </div>
                                    {scriptContent}
                                </pre>
                            </div>
                        )}
                    </div>

                    <div className="p-10 bg-[#0F172A] border-t border-white/5 flex gap-4">
                        <button 
                            onClick={handleDownloadScript}
                            disabled={scriptLoading}
                            className="flex-1 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-xl shadow-[#06B6D4]/10 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            <PlusCircle size={18} />
                            Descargar Script Maestro (.sh)
                        </button>
                        <button 
                            onClick={() => { navigator.clipboard.writeText(scriptContent); alert("Script copiado al portapapeles de seguridad."); }}
                            disabled={scriptLoading}
                            className="px-10 py-5 bg-slate-800 text-white font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all disabled:opacity-50"
                        >
                            Copiar Código
                        </button>
                    </div>
                </div>
            </div>
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
                                <span className="text-emerald-400 font-black text-[10px] uppercase tracking-widest">Remediación Satisfactoria</span>
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
                            className="px-12 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-xl shadow-[#06B6D4]/10"
                        >
                            Entendido, cerrar informe
                        </button>
                    </div>
                </div>
            </div>
        )}

        {/* Vault Credential Modal */}
        {showVaultModal && (
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-lg rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-amber-400/10 to-transparent flex justify-between items-center">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-amber-400/10 border border-amber-400/20 flex items-center justify-center text-amber-400">
                                <Lock size={24} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tighter">Credencial Sudo — Vault</h3>
                                <p className="text-[10px] text-amber-400/70 font-black uppercase tracking-widest mt-0.5">
                                    {vaultTarget}
                                </p>
                            </div>
                        </div>
                        <button onClick={() => setShowVaultModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={28} />
                        </button>
                    </div>

                    <form onSubmit={handleSaveVaultSecret} className="p-8 space-y-5">
                        <div>
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                Usuario SSH / Ansible
                            </label>
                            <input
                                type="text"
                                className="w-full bg-[#0F172A] border border-slate-700 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-amber-400 outline-none placeholder-slate-600"
                                placeholder="ej. ia, root, ansible_user"
                                value={vaultUser}
                                onChange={(e) => setVaultUser(e.target.value)}
                            />
                        </div>
                        <div>
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                Método de Credencial
                            </label>
                            <div className="flex gap-3 mb-4">
                                <button
                                    type="button"
                                    onClick={() => setVaultAuthType('PASSWORD')}
                                    className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-bold transition-all border ${vaultAuthType === 'PASSWORD' ? 'bg-amber-400/20 border-amber-400 text-amber-300' : 'bg-[#0F172A] border-slate-700 text-slate-400'}`}
                                >
                                    🔑 Contraseña Sudo
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setVaultAuthType('SSH_KEY')}
                                    className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-bold transition-all border ${vaultAuthType === 'SSH_KEY' ? 'bg-amber-400/20 border-amber-400 text-amber-300' : 'bg-[#0F172A] border-slate-700 text-slate-400'}`}
                                >
                                    📜 Llave Privada SSH (.pem / RSA)
                                </button>
                            </div>
                        </div>

                        {vaultAuthType === 'SSH_KEY' ? (
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                    Llave Privada SSH (PEM / RSA / OpenSSH) *
                                </label>
                                <textarea
                                    rows={5}
                                    required
                                    className="w-full bg-[#0F172A] border border-amber-400/30 rounded-2xl p-4 text-amber-300 font-mono text-xs focus:ring-2 focus:ring-amber-400 outline-none placeholder-slate-700 resize-none"
                                    placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEowIBAAKCAQEA...&#10;-----END RSA PRIVATE KEY-----"
                                    value={vaultSshKey}
                                    onChange={(e) => setVaultSshKey(e.target.value)}
                                    autoFocus
                                />
                                <p className="text-[9px] text-amber-400/60 mt-2 flex items-center gap-1 font-medium">
                                    <CheckCircle2 size={10} />
                                    Cifrado AES-256 en HashiCorp Vault. La llave privada se guarda de forma totalmente confidencial.
                                </p>
                            </div>
                        ) : (
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                    Contraseña Sudo *
                                </label>
                                <div className="relative">
                                    <input
                                        type="password"
                                        required
                                        className="w-full bg-[#0F172A] border border-amber-400/30 rounded-2xl p-4 text-amber-300 font-bold text-sm focus:ring-2 focus:ring-amber-400 outline-none pr-12 placeholder-slate-700"
                                        placeholder="••••••••••••"
                                        value={vaultPassword}
                                        onChange={(e) => setVaultPassword(e.target.value)}
                                        autoFocus
                                    />
                                    <div className="absolute right-4 top-1/2 -translate-y-1/2 text-amber-400/40">
                                        <Shield size={16} />
                                    </div>
                                </div>
                                <p className="text-[9px] text-amber-400/60 mt-2 flex items-center gap-1 font-medium">
                                    <CheckCircle2 size={10} />
                                    Cifrado AES-256 en HashiCorp Vault. No se almacena en la BD ni en el frontend.
                                </p>
                            </div>
                        )}

                        {vaultResult && (
                            <div className={`p-4 rounded-2xl text-xs font-bold flex items-center gap-2 ${vaultResult.ok ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                                {vaultResult.ok ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                                {vaultResult.msg}
                            </div>
                        )}

                        <div className="pt-2 flex gap-3">
                            <button
                                type="submit"
                                disabled={vaultSaving || (vaultAuthType === 'PASSWORD' ? !vaultPassword : !vaultSshKey)}
                                className="flex-1 py-4 bg-amber-500 text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-amber-400 transition-all shadow-lg shadow-amber-500/20 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {vaultSaving ? (
                                    <><Activity size={14} className="animate-spin" /> Guardando...</>
                                ) : (
                                    <><KeyRound size={14} /> Guardar en Vault</>
                                )}
                            </button>
                            <button
                                type="button"
                                onClick={() => setShowVaultModal(false)}
                                className="px-6 py-4 bg-slate-800 text-white font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                            >
                                Cancelar
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        )}

        {showDetailsModal && detailsTarget && (
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-xl rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500 max-h-[85vh] flex flex-col">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent flex justify-between items-center shrink-0">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-[#06B6D4]/10 border border-[#06B6D4]/20 flex items-center justify-center text-[#06B6D4]">
                                <Eye size={24} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tighter">{detailsTarget.name}</h3>
                                <p className="text-[10px] text-[#06B6D4]/70 font-black uppercase tracking-widest mt-0.5">
                                    Detalles del Activo
                                </p>
                            </div>
                        </div>
                        <button onClick={() => setShowDetailsModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={28} />
                        </button>
                    </div>

                    <div className="p-8 space-y-6 overflow-y-auto">
                        <div className="grid grid-cols-3 gap-3">
                            <div className="p-4 rounded-2xl border bg-slate-800/20 border-slate-800">
                                <p className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1">Vulnerabilidades</p>
                                <p className="text-lg font-black text-orange-400">{detailsTarget.vulnerability_count}</p>
                            </div>
                            <div className="p-4 rounded-2xl border bg-slate-800/20 border-slate-800">
                                <p className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1">Resueltas</p>
                                <p className="text-lg font-black text-emerald-400">{detailsTarget.resolved_count}</p>
                            </div>
                            <div className="p-4 rounded-2xl border bg-slate-800/20 border-slate-800">
                                <p className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1">Alertas Runtime</p>
                                <p className="text-lg font-black text-red-400">{detailsTarget.runtime_alerts_count}</p>
                            </div>
                        </div>

                        <div>
                            <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">Estado General</p>
                            <div className="flex flex-wrap gap-2">
                                {detailsTarget.agent_id ? (
                                    <span className={`text-[9px] font-black px-2.5 py-1 rounded border uppercase tracking-wider ${detailsTarget.status === 'active' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                                        Wazuh: {detailsTarget.status} (ID: {detailsTarget.agent_id})
                                    </span>
                                ) : (
                                    <span className="text-[9px] bg-slate-800 text-slate-400 font-black px-2.5 py-1 rounded border border-slate-700 uppercase tracking-wider">
                                        Wazuh: No instalado
                                    </span>
                                )}
                                <span className={`text-[9px] font-black px-2.5 py-1 rounded border uppercase tracking-wider ${detailsTarget.has_vault_secret ? 'bg-amber-500/10 text-amber-400 border-amber-400/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                                    Vault Creds: {detailsTarget.has_vault_secret ? 'Sí' : 'No'}
                                </span>
                            </div>
                        </div>

                        <div>
                            <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">
                                Interfaces ({detailsTarget.interfaces.length})
                            </p>
                            <div className="space-y-2">
                                {detailsTarget.interfaces.map((inf, i) => (
                                    <div key={i} className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800 text-xs">
                                        <div className="flex items-center justify-between mb-2">
                                            <span className={`text-[9px] font-extrabold px-2 py-0.5 rounded-full uppercase tracking-widest ${inf.asset_type_badge_class || 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'}`}>
                                                {inf.asset_type_label || inf.asset_type}
                                            </span>
                                            <code className="text-[#06B6D4] font-bold">{inf.endpoint}</code>
                                        </div>
                                        <div className="grid grid-cols-3 gap-2 text-[10px] text-slate-400">
                                            <div>
                                                <span className="text-slate-600 uppercase tracking-wider block mb-0.5">Criticidad</span>
                                                <span className="font-bold text-slate-300">{inf.criticality || '—'}</span>
                                            </div>
                                            <div>
                                                <span className="text-slate-600 uppercase tracking-wider block mb-0.5">Último Escaneo</span>
                                                <span className="font-bold text-slate-300">{inf.last_scanned ? new Date(inf.last_scanned).toLocaleString('es-MX') : 'Nunca'}</span>
                                            </div>
                                            <div>
                                                <span className="text-slate-600 uppercase tracking-wider block mb-0.5">Última Auditoría</span>
                                                <span className="font-bold text-slate-300">{inf.last_audit || '—'}</span>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Wazuh Live System Info */}
                        {detailsTarget.agent_id && (
                          <div>
                            <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                              <Cpu size={12} className="text-[#06B6D4]" />
                              Información del Sistema (Wazuh Live)
                            </p>
                            {agentInfoLoading ? (
                              <div className="flex items-center gap-2 text-[10px] text-slate-500 font-bold p-3">
                                <Activity size={14} className="animate-spin text-[#06B6D4]" />
                                Consultando agente en tiempo real...
                              </div>
                            ) : agentInfo ? (
                              <div className="bg-[#0F172A] rounded-2xl border border-slate-800 divide-y divide-slate-800 overflow-hidden text-[11px]">
                                {[
                                  { label: 'Sistema Operativo', value: agentInfo.os_name },
                                  { label: 'Hostname (Agente)', value: agentInfo.hostname },
                                  { label: 'Kernel', value: agentInfo.kernel },
                                  { label: 'Arquitectura', value: agentInfo.arch },
                                  { label: 'Versión Wazuh', value: agentInfo.wazuh_version },
                                  { label: 'Último Keep-Alive', value: agentInfo.last_keepalive },
                                  { label: 'Syscheck', value: agentInfo.syscheck_time },
                                ].map(({ label, value }) => (
                                  <div key={label} className="flex items-start justify-between px-4 py-2.5 hover:bg-slate-800/30 transition-all">
                                    <span className="text-slate-500 font-bold uppercase tracking-wider shrink-0 w-40">{label}</span>
                                    <span className="text-slate-200 font-mono text-right break-all">{value || '—'}</span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-[10px] text-slate-600 font-bold p-3">No se pudo obtener información del sistema del agente.</p>
                            )}
                          </div>
                        )}
                    </div>

                    <div className="p-6 border-t border-slate-800 shrink-0">
                        <button
                            onClick={() => setShowDetailsModal(false)}
                            className="w-full py-3 bg-slate-800 text-white font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                        >
                            Cerrar
                        </button>
                    </div>
                </div>
            </div>
        )}

        {showWazuhLogsModal && (
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-2xl rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent flex justify-between items-center">
                        <div>
                            <h3 className="text-white font-bold text-xl tracking-tighter">Logs de Wazuh Manager</h3>
                            <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mt-0.5">Eventos recientes relacionados al Agente</p>
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
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-2xl rounded-[48px] border border-indigo-500/20 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-indigo-500/10 to-transparent flex justify-between items-center">
                        <div className="flex items-center gap-3">
                            <div className="p-3 bg-indigo-500/10 rounded-2xl text-indigo-400 border border-indigo-500/20">
                                <Laptop size={24} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tight">{assetDetailsData.group.name}</h3>
                                <p className="text-[10px] text-indigo-400 font-black uppercase tracking-widest mt-0.5">Características del Sistema Operativo & Hardware</p>
                            </div>
                        </div>
                        <button onClick={() => setShowAssetDetailsModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={28} />
                        </button>
                    </div>

                    <div className="p-8 space-y-6">
                        {assetDetailsLoading ? (
                            <div className="flex items-center justify-center py-12 text-indigo-400 gap-3">
                                <Activity size={24} className="animate-spin" />
                                <span className="text-xs font-bold uppercase tracking-widest">Consultando telemetría del sistema...</span>
                            </div>
                        ) : (
                            <div className="grid grid-cols-2 gap-4 text-xs">
                                <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                    <span className="text-[9px] text-slate-500 font-black uppercase block mb-1">Nombre del Activo</span>
                                    <span className="text-white font-bold">{assetDetailsData.group.name}</span>
                                </div>
                                <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                    <span className="text-[9px] text-slate-500 font-black uppercase block mb-1">Tipo de Activo</span>
                                    <span className="text-indigo-400 font-bold">{assetDetailsData.group.interfaces[0]?.asset_type_label || assetDetailsData.group.interfaces[0]?.asset_type}</span>
                                </div>
                                <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                    <span className="text-[9px] text-slate-500 font-black uppercase block mb-1">Dirección / Endpoint</span>
                                    <code className="text-[#06B6D4] font-bold">{assetDetailsData.group.interfaces[0]?.endpoint}</code>
                                </div>
                                <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                    <span className="text-[9px] text-slate-500 font-black uppercase block mb-1">Estado de Conectividad</span>
                                    <span className={`font-bold ${(assetDetailsData.ping?.ping_ok || assetDetailsData.group.status === 'active') ? 'text-emerald-400' : 'text-amber-400'}`}>
                                        {(assetDetailsData.ping?.ping_ok || assetDetailsData.group.status === 'active') 
                                            ? `En Línea (Sincronizado ${assetDetailsData.ping?.latency_ms ? `- ${assetDetailsData.ping?.latency_ms}ms` : ''})` 
                                            : 'Offline / Pendiente'}
                                    </span>
                                </div>

                                {assetDetailsData.info ? (
                                    <>
                                        <div className="col-span-2 bg-[#0F172A] p-4 rounded-2xl border border-slate-800 space-y-1">
                                            <span className="text-[9px] text-slate-500 font-black uppercase block">Sistema Operativo & Kernel</span>
                                            <p className="text-slate-200 font-mono text-xs">{assetDetailsData.info.operating_system || 'N/A'}</p>
                                        </div>
                                        <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                            <span className="text-[9px] text-slate-500 font-black uppercase block mb-1">Versión Cliente EDR</span>
                                            <span className="text-emerald-400 font-bold">{assetDetailsData.info.client_version || 'Wazuh EDR'}</span>
                                        </div>
                                        <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                            <span className="text-[9px] text-slate-500 font-black uppercase block mb-1">Último Análisis FIM (Syscheck)</span>
                                            <span className="text-slate-300 font-bold">{assetDetailsData.info.syscheck_last_ended_at || assetDetailsData.info.syscheck_last_started_at || 'N/A'}</span>
                                        </div>
                                    </>
                                ) : (
                                    <div className="col-span-2 bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                        <span className="text-[9px] text-slate-500 font-black uppercase block mb-1">Telemetría de Agente EDR</span>
                                        <p className="text-slate-400 italic text-xs">Agente EDR no instalado o sin reporte remoto activo.</p>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </div>
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
                <p className="text-[10px] text-slate-400 mt-1 line-clamp-2">{toast.message}</p>
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
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-xl rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent flex justify-between items-center">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-[#06B6D4]/10 border border-[#06B6D4]/20 flex items-center justify-center text-[#06B6D4]">
                                <CheckCircle size={24} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tighter">Remediación Manual</h3>
                                <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mt-0.5">
                                    {selectedRemediation?.cve_id} — {selectedRemediation?.asset_name}
                                </p>
                            </div>
                        </div>
                        <button onClick={() => setShowManualModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={28} />
                        </button>
                    </div>

                    <form onSubmit={handleManualRemediation} className="p-8 space-y-6">
                        <div>
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                Descripción de la Solución
                            </label>
                            <textarea
                                required
                                className="w-full bg-[#0F172A] border border-slate-700 rounded-2xl p-4 text-white font-medium text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700 h-32 resize-none"
                                placeholder="Explique qué acciones se realizaron para mitigar este hallazgo..."
                                value={manualSolution}
                                onChange={(e) => setManualSolution(e.target.value)}
                            />
                        </div>
                        
                        <div>
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                Motivo de la Intervención Manual
                            </label>
                            <textarea
                                required
                                className="w-full bg-[#0F172A] border border-slate-700 rounded-2xl p-4 text-white font-medium text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700 h-24 resize-none"
                                placeholder="¿Por qué no se usó la remediación automática? (ej. Configuración personalizada, política interna, etc.)"
                                value={manualReason}
                                onChange={(e) => setManualReason(e.target.value)}
                            />
                        </div>

                        <div className="pt-2 flex gap-3">
                            <button
                                type="submit"
                                disabled={manualSaving || !manualSolution || !manualReason}
                                className="flex-1 py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {manualSaving ? (
                                    <><Activity size={14} className="animate-spin" /> Procesando...</>
                                ) : (
                                    <><ShieldCheck size={16} /> Confirmar Remediación</>
                                )}
                            </button>
                            <button
                                type="button"
                                onClick={() => setShowManualModal(false)}
                                className="px-6 py-4 bg-slate-800 text-white font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                            >
                                Cancelar
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        )}
      </main>
    </div>
  )
}

function AssetIcon({ type }) {
    switch (type) {
        case 'WORKSTATION':
        case 'LAPTOP': return <Laptop size={20} />;
        case 'SERVER_LINUX':
        case 'SERVER': return <Server size={20} />;
        case 'SERVER_WINDOWS': return <Monitor size={20} />;
        case 'CONTAINER': return <Container size={20} />;
        case 'KUBERNETES': return <Layers size={20} />;
        case 'IP': return <Terminal size={20} />;
        case 'URL': return <Link size={20} />;
        case 'DATABASE': return <Database size={20} />;
        case 'CLOUD': return <Cloud size={20} />;
        default: return <Server size={20} />;
    }
}

function NavItem({ icon, label, active = false, onClick }) {
  return (
    <div 
      onClick={onClick}
      className={`flex items-center gap-3 p-3 rounded-xl cursor-pointer transition-all group ${active ? 'bg-[#06B6D4]/10 text-[#06B6D4] border border-[#06B6D4]/20' : 'text-slate-500 hover:text-white hover:bg-white/5'}`}
    >
      <div className={`${active ? 'text-[#06B6D4]' : 'text-slate-500 group-hover:text-[#06B6D4]'}`}>
        {icon}
      </div>
      <span className="hidden lg:inline font-bold text-sm tracking-tight">{label}</span>
    </div>
  )
}

function MetricCard({ label, value, icon, color, sub, highlight = false, onClick, title }) {
  return (
    <div 
      onClick={onClick}
      title={title || `Ir a ${label}`}
      className={`bg-[#1E293B] p-6 rounded-[24px] border ${highlight ? 'border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.15)]' : 'border-slate-800'} ${onClick ? 'cursor-pointer hover:border-[#06B6D4]/60 hover:bg-[#1E293B]/80 hover:scale-[1.02]' : ''} group transition-all`}
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-2 rounded-xl bg-slate-800 text-slate-400 group-hover:text-[#06B6D4] transition-all`}>
          {icon}
        </div>
        <div className="w-1.5 h-1.5 rounded-full bg-[#06B6D4] animate-pulse" />
      </div>
      <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.15em] mb-1">{label}</p>
      <p className={`text-3xl font-black ${color} mb-1 tracking-tighter`}>{value}</p>
      <p className="text-[10px] font-bold text-slate-600 tracking-tight">{sub}</p>
    </div>
  )
}
