import React, { useState, useEffect } from 'react'
import { useAuth } from 'react-oidc-context'
import axios from 'axios'
import ReactMarkdown from 'react-markdown'
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
  KeyRound
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
  Pie
} from 'recharts'
import MapChart from './MapChart'

// Using relative path to utilize the Nginx proxy at /centinela/api/
const API_BASE = "/centinela/api"

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
  const [healthStatus, setHealthStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [lastSync, setLastSync] = useState(new Date())
  const [selectedRemediation, setSelectedRemediation] = useState(null)
  const [severityFilter, setSeverityFilter] = useState(null)
  const [assetFilter, setAssetFilter] = useState(null)
  const [inventorySearch, setInventorySearch] = useState('')
  const [inventoryTypeFilter, setInventoryTypeFilter] = useState('')
  
  const [assetStatusFilter, setAssetStatusFilter] = useState('ALL') // NEW: ALL, VULNERABLE, ATTACKED
  
  // Modal State
  const [showAddModal, setShowAddModal] = useState(false)
  const [newAsset, setNewAsset] = useState({ asset_name: '', asset_type: 'CONTAINER', endpoint: '', criticality: 'MEDIUM' })
  
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
  const [vaultSaving, setVaultSaving] = useState(false)
  const [vaultResult, setVaultResult] = useState(null)     // { ok: bool, msg: string }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => clearInterval(interval)
  }, [assetFilter])

  const fetchData = async () => {
    try {
      const [resStats, resVulns, resMap, resAlerts, resRisk, resInv, resRem, resHealth] = await Promise.all([
        axios.get(`${API_BASE}/stats/extended`),
        axios.get(`${API_BASE}/stats`),
        axios.get(`${API_BASE}/map`),
        axios.get(`${API_BASE}/alerts/runtime`),
        axios.get(`${API_BASE}/risk-distribution`),
        axios.get(`${API_BASE}/inventory`),
        axios.get(`${API_BASE}/remediation${assetFilter ? `?asset=${assetFilter}` : ''}`),
        axios.get(`${API_BASE}/health`)
      ])
      
      setStats(resStats.data)
      setVulnStats(resVulns.data)
      setMapData(resMap.data)
      setAlerts(resAlerts.data)
      setRiskData(resRisk.data)
      setInventory(resInv.data)
      setRemediationLog(resRem.data)
      setHealthStatus(resHealth.data)
      setLastSync(new Date())
      setLoading(false)
    } catch (error) {
      console.error("Error fetching dashboard data:", error)
    }
  }

  const handleAddAsset = async (e) => {
    e.preventDefault()
    try {
        await axios.post(`${API_BASE}/inventory`, newAsset)
        setShowAddModal(false)
        setNewAsset({ asset_name: '', asset_type: 'CONTAINER', endpoint: '', criticality: 'MEDIUM' })
        fetchData()
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

  const handleOpenVaultModal = (assetName) => {
    setVaultTarget(assetName)
    setVaultPassword('')
    setVaultUser('')
    setVaultResult(null)
    setShowVaultModal(true)
  }

  const handleSaveVaultSecret = async (e) => {
    e.preventDefault()
    if (!vaultPassword) return
    setVaultSaving(true)
    setVaultResult(null)
    try {
      await axios.post(`${API_BASE}/inventory/${encodeURIComponent(vaultTarget)}/vault-secret`, {
        sudo_password: vaultPassword,
        ansible_user: vaultUser || undefined
      })
      setVaultResult({ ok: true, msg: `Credencial de '${vaultTarget}' almacenada en Vault. Aura-Sentinel la usará automáticamente.` })
      setVaultPassword('')
    } catch (err) {
      const detail = err?.response?.data?.detail || 'Error desconocido al conectar con Vault.'
      setVaultResult({ ok: false, msg: detail })
    } finally {
      setVaultSaving(false)
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

  const filteredAlerts = alerts.filter(a => {
    const matchSeverity = severityFilter ? a.priority === severityFilter : true;
    const matchAsset = assetFilter ? a.asset_name === assetFilter : true;
    return matchSeverity && matchAsset;
  });

  const filteredRemediations = remediationLog.filter(r => {
    const matchAsset = assetFilter ? r.asset_name?.toLowerCase().trim() === assetFilter.toLowerCase().trim() : true;
    return matchAsset;
  });

  // Grouping logic for inventory
  const groupedInventory = inventory.reduce((acc, item) => {
    if (!acc[item.asset_name]) {
      acc[item.asset_name] = {
        name: item.asset_name,
        vulnerability_count: 0,
        runtime_alerts_count: 0,
        interfaces: []
      }
    }
    acc[item.asset_name].vulnerability_count += parseInt(item.vulnerability_count || 0)
    acc[item.asset_name].runtime_alerts_count += parseInt(item.runtime_alerts_count || 0)
    acc[item.asset_name].interfaces.push(item)
    return acc
  }, {})

  const processedInventory = Object.values(groupedInventory)
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
        const scoreA = (a.runtime_alerts_count * 10) + a.vulnerability_count
        const scoreB = (b.runtime_alerts_count * 10) + b.vulnerability_count
        return scoreB - scoreA || a.name.localeCompare(b.name)
    });

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
            label="Threat Hunting" 
            active={currentView === 'threat-hunting'} 
            onClick={() => setCurrentView('threat-hunting')}
          />
          <NavItem 
            icon={<Database size={20} />} 
            label="Inventario Assets" 
            active={currentView === 'inventory'} 
            onClick={() => setCurrentView('inventory')}
          />
          <NavItem 
            icon={<Zap size={20} />} 
            label="IA Remediation" 
            active={currentView === 'soar'} 
            onClick={() => setCurrentView('soar')}
          />
          <NavItem 
            icon={<Activity size={20} />} 
            label="Salud del Sistema" 
            active={currentView === 'health'} 
            onClick={() => setCurrentView('health')}
          />
        </nav>

        <div className="p-4 border-t border-slate-800">
          <button 
            onClick={() => setShowAddModal(true)}
            className="w-full hidden lg:flex items-center gap-3 p-3 mb-4 rounded-xl bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20"
          >
            <Plus size={20} />
            Añadir Activo
          </button>
          <div className="hidden lg:block mb-4 px-3">
            <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Sincronización</p>
            <p className="text-[10px] text-emerald-500 font-bold uppercase tracking-tighter flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                {lastSync.toLocaleTimeString()}
            </p>
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
            <span className="text-white">{currentView.replace('-', ' ')}</span>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="hidden md:flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-lg border border-slate-800">
              <Search size={14} className="text-slate-500" />
              <input type="text" placeholder="Buscar incidentes..." className="bg-transparent border-none text-[10px] focus:ring-0 w-48 text-slate-300 font-bold placeholder:text-slate-600" />
            </div>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-xs font-bold text-white leading-none">{auth.user?.profile?.name || "Operador"}</p>
                <p className="text-[10px] text-[#06B6D4] uppercase font-black tracking-tighter">Mando de Seguridad</p>
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
                    value={stats.users} 
                    icon={<Users size={20} />} 
                    color="text-[#06B6D4]" 
                    sub="Sincronizado CDMX"
                />
                <MetricCard 
                    label="Endpoints" 
                    value={stats.endpoints} 
                    icon={<Server size={20} />} 
                    color="text-emerald-400" 
                    sub="Infraestructura Local"
                />
                <MetricCard 
                    label="Alertas Runtime" 
                    value={stats.alerts} 
                    icon={<AlertTriangle size={20} />} 
                    color="text-red-400" 
                    sub={`${vulnStats.critical} Críticas activas`}
                    highlight
                />
                <MetricCard 
                    label="Vulnerabilidades" 
                    value={vulnStats.total} 
                    icon={<ShieldAlert size={20} />} 
                    color="text-orange-400" 
                    sub="Pendientes de Remediar"
                />
                <MetricCard 
                    label="IA Remediation" 
                    value={vulnStats.pending_ia} 
                    icon={<Zap size={20} />} 
                    color="text-[#06B6D4]" 
                    sub="En cola de análisis"
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
                        {severityFilter ? `Alertas ${severityFilter}` : 'Alertas Recientes (Runtime)'}
                      </h3>
                      {severityFilter && (
                        <button onClick={() => setSeverityFilter(null)} className="text-slate-500 text-[10px] font-black uppercase tracking-widest hover:text-white">Limpiar Filtro</button>
                      )}
                      <button onClick={() => setCurrentView('threat-hunting')} className="text-[#06B6D4] text-[10px] font-black uppercase tracking-widest hover:underline">Ver Todo el Log</button>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left">
                        <thead>
                          <tr className="text-slate-500 text-[10px] font-black uppercase tracking-widest border-b border-slate-800">
                            <th className="pb-4">Severidad</th>
                            <th className="pb-4">Fecha</th>
                            <th className="pb-4">Entidad</th>
                            <th className="pb-4">Mensaje</th>
                            <th className="pb-4 text-right">Acción</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {filteredAlerts.length > 0 ? (
                            filteredAlerts.slice(0, 5).map((alert) => (
                                <tr key={alert.id} className="group hover:bg-white/5 transition-all">
                                  <td className="py-4">
                                    <span className={`px-2 py-1 rounded text-[9px] font-black ${
                                      alert.priority === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 
                                      alert.priority === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
                                    }`}>
                                      {alert.priority}
                                    </span>
                                  </td>
                                  <td className="py-4 text-[10px] font-bold text-slate-500">{new Date(alert.detected_at).toLocaleString()}</td>
                                  <td className="py-4 text-[10px] font-bold text-white">{alert.asset_name || "System"}</td>
                                  <td className="py-4 text-[10px] text-slate-400">{alert.rule_name}</td>
                                  <td className="py-4 text-right">
                                    <button 
                                        onClick={() => handleInvestigate(alert.id)}
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
                </div>

                {/* Right Sidebar */}
                <div className="lg:col-span-4 space-y-8">
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                    <h3 className="text-white font-bold text-lg mb-6">Distribución de Riesgo</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={riskData}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                            onClick={(data) => {
                                setSeverityFilter(data.severity);
                                window.scrollTo({ top: 1000, behavior: 'smooth' });
                            }}
                            className="cursor-pointer"
                          >
                            {riskData.map((entry, index) => (
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
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <p className="text-[10px] text-slate-500 font-bold text-center uppercase tracking-widest mt-4">Haz clic en un segmento para filtrar alertas</p>
                  </div>

                  <div className="bg-gradient-to-br from-[#06B6D4]/20 to-blue-900/20 rounded-[32px] border border-[#06B6D4]/20 p-8">
                    <div className="flex items-center gap-3 mb-4">
                      <Zap className="text-[#06B6D4]" size={24} />
                      <h3 className="text-white font-bold text-lg">IA Remediation</h3>
                    </div>
                    <p className="text-xs text-slate-400 mb-6 leading-relaxed font-medium">
                      El motor **Gemini 1.5 Flash** está analizando {vulnStats.pending_ia} hallazgos detectados recientemente.
                    </p>
                    <button onClick={() => setCurrentView('soar')} className="w-full py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all active:scale-95">
                      Gestionar Remedios
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
                            <div className="flex items-center gap-3 bg-[#06B6D4]/10 px-4 py-2 rounded-xl border border-[#06B6D4]/20 animate-in fade-in zoom-in duration-300">
                                <span className="text-[10px] font-black text-[#06B6D4] uppercase tracking-widest">Filtro Asset: {assetFilter}</span>
                                <X size={14} className="text-[#06B6D4] cursor-pointer hover:text-white transition-colors" onClick={() => setAssetFilter(null)} />
                            </div>
                        )}
                        <div className="bg-emerald-500/10 text-emerald-500 px-4 py-2 rounded-xl border border-emerald-500/20 text-[10px] font-black uppercase">
                            Motor Activo
                        </div>
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
                                                        <div className={`p-2 rounded-lg ${log.executed_bool ? 'bg-emerald-500/10 text-emerald-500' : 'bg-slate-800 text-[#06B6D4]'}`}>
                                                            {log.executed_bool ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}
                                                        </div>
                                                        <div>
                                                            <p className="text-white font-bold text-sm">{log.cve_id}</p>
                                                            <p className="text-[9px] text-slate-500 font-bold truncate max-w-[150px]">{log.script_path}</p>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="p-6 text-xs font-bold text-slate-400">{log.asset_name}</td>
                                                <td className="p-6">
                                                    <span className={`px-2 py-1 rounded text-[9px] font-black ${
                                                        log.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 
                                                        log.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
                                                    }`}>
                                                        {log.severity}
                                                    </span>
                                                </td>
                                                <td className="p-6">
                                                    <div className="flex items-center gap-2">
                                                        {log.executed_bool ? (
                                                            <span className="text-[9px] font-black text-emerald-500 uppercase">REMEDIADO</span>
                                                        ) : (
                                                            <span className={`text-[9px] font-black uppercase ${
                                                                log.status === 'CORRELATED' ? 'text-[#06B6D4]' : 
                                                                log.status === 'AI_FAILED' ? 'text-red-400' : 'text-orange-500 animate-pulse'
                                                            }`}>
                                                                {log.status === 'CORRELATED' ? 'LISTO PARA APROBAR' : 
                                                                 log.status === 'AI_FAILED' ? 'FALLO IA (REINTENTANDO)' : 
                                                                 log.status === 'NEW' || log.status === 'PENDING' ? 'PENDIENTE IA' : log.status}
                                                            </span>
                                                        )}
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
                            <div className="bg-[#1E293B] rounded-[32px] border border-[#06B6D4]/30 overflow-hidden sticky top-24">
                                <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent">
                                    <div className="flex justify-between items-start mb-6">
                                        <div>
                                            <p className="text-[10px] text-[#06B6D4] font-black uppercase tracking-widest mb-1">Informe Ejecutivo IA</p>
                                            <h3 className="text-white font-bold text-2xl">{selectedRemediation.cve_id}</h3>
                                        </div>
                                        <button onClick={() => setSelectedRemediation(null)} className="text-slate-500 hover:text-white">
                                            <XCircle size={24} />
                                        </button>
                                    </div>
                                    
                                    <div className="space-y-4">
                                        <div className="flex items-center gap-3 p-4 bg-[#0F172A] rounded-2xl border border-slate-800">
                                            <Server size={18} className="text-slate-500" />
                                            <div>
                                                <p className="text-[9px] text-slate-500 font-bold uppercase">Asset Afectado</p>
                                                <p className="text-xs font-bold text-white">{selectedRemediation.asset_name}</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="p-8 space-y-8 max-h-[60vh] overflow-y-auto">
                                    <section>
                                        <h4 className="text-white font-bold text-xs uppercase tracking-widest mb-3 flex items-center gap-2">
                                            <Info size={14} className="text-[#06B6D4]" />
                                            ¿Qué encontramos?
                                        </h4>
                                        <div className="p-4 bg-slate-800/50 rounded-2xl text-xs text-slate-400 leading-relaxed italic">
                                            {selectedRemediation.executive_summary || "Análisis de IA pendiente de generación detallada..."}
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

                                <div className="p-8 bg-[#0F172A] border-t border-slate-800 flex gap-3">
                                    {selectedRemediation.status === 'RESOLVED' || selectedRemediation.executed_bool ? (
                                        <div className="flex-grow py-4 bg-emerald-500/10 text-emerald-500 font-black uppercase text-[10px] tracking-widest rounded-2xl border border-emerald-500/20 flex items-center justify-center gap-2 cursor-default">
                                            <CheckCircle2 size={16} />
                                            Activo Remediado
                                        </div>
                                    ) : selectedRemediation.approval_token === 'APPROVED' || selectedRemediation.approval_token === 'EXECUTING' ? (
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
                        Runtime Threat Hunting - Log Maestro
                    </h3>
                    {assetFilter && (
                        <div className="flex items-center gap-3 bg-[#06B6D4]/10 px-4 py-2 rounded-xl border border-[#06B6D4]/20">
                            <span className="text-[10px] font-black text-[#06B6D4] uppercase tracking-widest">Filtro Asset: {assetFilter}</span>
                            <X size={14} className="text-[#06B6D4] cursor-pointer" onClick={() => setAssetFilter(null)} />
                        </div>
                    )}
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="text-slate-500 text-[10px] font-black uppercase tracking-widest border-b border-slate-800">
                                <th className="pb-4">Severidad</th>
                                <th className="pb-4">Timestamp</th>
                                <th className="pb-4">Asset</th>
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
                                                alert.priority === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
                                            }`}>
                                                {alert.priority}
                                            </span>
                                        </td>
                                        <td className="py-6 text-[11px] font-bold text-slate-500">{new Date(alert.detected_at).toLocaleString()}</td>
                                        <td className="py-6 text-[11px] font-bold text-white">{alert.asset_name || "Internal"}</td>
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
                        >
                            <Plus size={18} />
                            Añadir
                        </button>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                    {processedInventory.map((group, idx) => (
                        <div key={idx} className="bg-[#0F172A]/50 backdrop-blur-sm p-1 rounded-[32px] border border-slate-800 group hover:border-[#06B6D4]/30 transition-all relative">
                            {group.runtime_alerts_count > 0 && (
                                <div className="absolute -top-2 -right-2 bg-red-600 text-white text-[10px] font-black px-3 py-1 rounded-full animate-bounce shadow-lg shadow-red-600/50 z-10 uppercase tracking-tighter">
                                    Ataque en Vivo
                                </div>
                            )}
                            
                            <div className="bg-[#0F172A] p-6 rounded-[30px]">
                                <div className="flex justify-between items-start mb-6">
                                    <div className="flex gap-3">
                                        {group.interfaces.map((inf, i) => (
                                            <div key={i} className="p-3 bg-slate-800 rounded-2xl text-[#06B6D4] border border-white/5 shadow-inner" title={inf.asset_type}>
                                                <AssetIcon type={inf.asset_type} />
                                            </div>
                                        ))}
                                    </div>
                                    <div className="text-right">
                                        <p className="text-[10px] font-black text-emerald-500 uppercase tracking-tighter">Sincronizado</p>
                                        <p className="text-[9px] text-slate-500 font-bold">Health: 100%</p>
                                    </div>
                                </div>
                                
                                <h4 className="text-white font-bold text-xl mb-1 tracking-tight">{group.name}</h4>
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] mb-6">Identidad Consolidada</p>
                                
                                <div className="grid grid-cols-2 gap-4 mb-6">
                                    <div className={`p-4 rounded-2xl border transition-all ${group.vulnerability_count > 0 ? 'bg-orange-500/5 border-orange-500/20' : 'bg-slate-800/20 border-slate-800'}`}>
                                        <p className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1">Vulnerabilidades</p>
                                        <div className="flex items-center gap-2">
                                            <ShieldAlert size={14} className={group.vulnerability_count > 0 ? 'text-orange-400' : 'text-slate-600'} />
                                            <span className={`text-lg font-black ${group.vulnerability_count > 0 ? 'text-orange-400' : 'text-slate-400'}`}>
                                                {group.vulnerability_count}
                                            </span>
                                        </div>
                                    </div>
                                    <div className={`p-4 rounded-2xl border transition-all ${group.runtime_alerts_count > 0 ? 'bg-red-500/5 border-red-500/20' : 'bg-slate-800/20 border-slate-800'}`}>
                                        <p className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1">Alertas Runtime</p>
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
                                        <div key={i} className="flex items-center justify-between text-[10px] bg-slate-800/30 p-2 rounded-xl border border-white/5 group/inf hover:bg-[#06B6D4]/10 transition-all cursor-pointer" onClick={() => { setAssetFilter(inf.asset_name); setCurrentView('soar'); }}>
                                            <div className="flex items-center gap-2">
                                                <div className="w-1.5 h-1.5 rounded-full bg-[#06B6D4]" />
                                                <span className="text-slate-400 font-bold uppercase tracking-tighter">{inf.asset_type}</span>
                                            </div>
                                            <code className="text-[#06B6D4] font-bold truncate max-w-[120px]">{inf.endpoint}</code>
                                            <ChevronRight size={12} className="text-slate-600 group-hover/inf:translate-x-1 transition-all" />
                                        </div>
                                    ))}
                                </div>

                                <button 
                                    onClick={() => { setAssetFilter(group.name); setCurrentView('soar'); }}
                                    className="flex-1 py-3 bg-slate-800 hover:bg-[#06B6D4] text-slate-400 hover:text-[#0F172A] font-black uppercase text-[9px] tracking-[0.2em] rounded-xl transition-all flex items-center justify-center gap-2"
                                >
                                    Ver Análisis Completo
                                    <ExternalLink size={12} />
                                </button>
                                <button
                                    onClick={() => handleOpenVaultModal(group.name)}
                                    title="Configurar credencial sudo en Vault"
                                    className="py-3 px-4 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-400/20 font-black uppercase text-[9px] tracking-[0.15em] rounded-xl transition-all flex items-center justify-center gap-2"
                                >
                                    <KeyRound size={13} />
                                    Vault
                                </button>
                            </div>
                        </div>
                    ))}
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
                    {healthStatus.services.map((service, idx) => (
                        <div key={idx} className="bg-[#1E293B] p-8 rounded-[32px] border border-slate-800 relative overflow-hidden group">
                            <div className="absolute top-0 right-0 p-6 opacity-10 group-hover:opacity-20 transition-all">
                                <Cpu size={64} className="text-[#06B6D4]" />
                            </div>
                            <div className="flex items-center gap-4 mb-6">
                                <div className={`w-3 h-3 rounded-full animate-pulse ${service.status === 'Online' || service.status === 'Active' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                                <h4 className="text-white font-bold text-lg">{service.name}</h4>
                            </div>
                            <div className="flex justify-between items-end">
                                <div>
                                    <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-1">Estado</p>
                                    <p className="text-emerald-400 font-bold text-sm">{service.status}</p>
                                </div>
                                <div className="text-right">
                                    <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-1">Latencia</p>
                                    <p className="text-white font-bold text-sm">{service.latency}</p>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>

                <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                    <h3 className="text-white font-bold text-lg mb-6 flex items-center gap-2">
                        <Monitor size={20} className="text-[#06B6D4]" />
                        Estado de los Nodos Regionales
                    </h3>
                    <div className="space-y-4">
                        <div className="p-4 bg-[#0F172A] rounded-2xl border border-slate-800 flex items-center justify-between">
                            <span className="text-xs font-bold text-white">Nodo Central - CDMX</span>
                            <span className="px-3 py-1 bg-emerald-500/10 text-emerald-500 text-[10px] font-black rounded-lg">MAESTRO</span>
                        </div>
                        <div className="p-4 bg-[#0F172A] rounded-2xl border border-slate-800 flex items-center justify-between">
                            <span className="text-xs font-bold text-white">Nodos Quintana Roo (Chetumal, Cancún, Playa)</span>
                            <span className="px-3 py-1 bg-[#06B6D4]/10 text-[#06B6D4] text-[10px] font-black rounded-lg">CONECTADO</span>
                        </div>
                    </div>
                </div>
            </div>
          )}
        </div>

        {/* Add Asset Modal */}
        {showAddModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0F172A]/80 backdrop-blur-sm animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-lg rounded-[40px] border border-white/10 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-300">
                    <div className="p-8 border-b border-white/5 flex items-center justify-between">
                        <h3 className="text-white font-bold text-xl flex items-center gap-3">
                            <PlusCircle className="text-[#06B6D4]" />
                            Registrar Nuevo Activo
                        </h3>
                        <button onClick={() => setShowAddModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <X size={24} />
                        </button>
                    </div>
                    <form onSubmit={handleAddAsset} className="p-8 space-y-6">
                        <div className="space-y-4">
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Nombre del Asset</label>
                                <input 
                                    type="text" 
                                    required
                                    className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                    placeholder="ej. cluster-k8s-prod"
                                    value={newAsset.asset_name}
                                    onChange={(e) => setNewAsset({...newAsset, asset_name: e.target.value})}
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Tipo de Infraestructura</label>
                                    <select 
                                        className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none"
                                        value={newAsset.asset_type}
                                        onChange={(e) => setNewAsset({...newAsset, asset_type: e.target.value})}
                                    >
                                        <option value="CONTAINER">Docker Container</option>
                                        <option value="KUBERNETES">Kubernetes Cluster</option>
                                        <option value="SERVER">Servidor Linux/Windows</option>
                                        <option value="IP">Dirección IP / Puerto</option>
                                        <option value="URL">URL / Aplicación Web</option>
                                        <option value="DATABASE">Base de Datos</option>
                                        <option value="CLOUD">Cloud Resource</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Criticidad</label>
                                    <select 
                                        className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none"
                                        value={newAsset.criticality}
                                        onChange={(e) => setNewAsset({...newAsset, criticality: e.target.value})}
                                    >
                                        <option value="CRITICAL">Crítica (SLA 1h)</option>
                                        <option value="HIGH">Alta (SLA 4h)</option>
                                        <option value="MEDIUM">Media (SLA 24h)</option>
                                        <option value="LOW">Baja (SLA 72h)</option>
                                    </select>
                                </div>
                            </div>
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Endpoint / IP / URI de Conexión</label>
                                <input 
                                    type="text" 
                                    required
                                    className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                    placeholder="ej. 192.168.1.50, postgresql://db..., https://api..."
                                    value={newAsset.endpoint}
                                    onChange={(e) => setNewAsset({...newAsset, endpoint: e.target.value})}
                                />
                            </div>
                        </div>
                        <div>
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                <Lock size={12} className="text-[#06B6D4]" />
                                Contraseña Sudo (Vault Secret)
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
                                Almacenamiento encriptado y gestionado mediante HashiCorp Vault. No se expone al frontend ni a la red.
                            </p>
                        </div>
                        <div className="pt-4">
                            <button 
                                type="submit"
                                className="w-full py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[10px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/10"
                            >
                                Registrar y Activar Monitoreo
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
      </main>
    </div>
  )
}

function AssetIcon({ type }) {
    switch (type) {
        case 'CONTAINER': return <Container size={20} />;
        case 'KUBERNETES': return <Layers size={20} />;
        case 'SERVER': return <Monitor size={20} />;
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

function MetricCard({ label, value, icon, color, sub, highlight = false }) {
  return (
    <div className={`bg-[#1E293B] p-6 rounded-[24px] border ${highlight ? 'border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.15)]' : 'border-slate-800'} group hover:border-[#06B6D4]/30 transition-all`}>
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
