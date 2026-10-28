// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, CheckCircle, CheckCircle2, ChevronDown, ChevronRight, Clock, Code2, Database, Download, ExternalLink, Eye, Filter, FolderTree, GitCompare, Info, KeyRound, LayoutGrid, List, Plus, RefreshCw, Search, ShieldAlert, ShieldCheck, Trash2, Zap, ZapOff } from 'lucide-react'
import { useDashboard } from './DashboardContext'
import { AssetIcon } from './shared'
import BranchScanButton from './BranchScanButton'
import TestCredentialsButton from './TestCredentialsButton'
import GitLabGroupsView from './GitLabGroupsView'

export default function InventoryView() {
  const { assetStatusFilter, cmmiReport, getCisGradeBadge, handleDeleteAsset, handleDownloadAssetReport, handleDownloadComparison, handleDownloadGroupComparison, handleOpenAssetDetails, handleOpenDetailsModal, handleOpenVaultModal, handlePingAsset, handleSelectAsset, handleViewAssetReportHtml, handleViewComparisonHtml, handleWazuhAction, handleWazuhUninstall, inventory, inventorySearch, inventorySortBy, inventoryTypeFilter, inventoryViewMode, isoReport, pingResults, processedInventory, setAssetStatusFilter, setInventorySearch, setInventorySortBy, setInventoryTypeFilter, setInventoryViewMode, setShowAddModal, wazuhActionLoading } = useDashboard()
  return (
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
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest hidden sm:inline">Orden:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={inventorySortBy}
                                    onChange={(e) => setInventorySortBy(e.target.value)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
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
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest hidden sm:inline">Tipo:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={inventoryTypeFilter}
                                    onChange={(e) => setInventoryTypeFilter(e.target.value)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
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
                                className="bg-transparent border-none text-[12px] focus:ring-0 w-32 md:w-48 text-slate-300 font-bold placeholder:text-slate-600 outline-none" 
                            />
                        </div>

                        {inventorySearch.trim() && processedInventory.length > 0 && (
                            <div className="flex gap-1 p-1 bg-[#0F172A] rounded-2xl border border-violet-400/30" title="Comparativo del último escaneo contra el anterior para los activos visibles con este filtro">
                                <button
                                    onClick={() => handleDownloadGroupComparison(processedInventory.slice(0, 200).map(g => g.name), inventorySearch.trim(), 'pdf')}
                                    className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-violet-300 hover:bg-violet-500/20 text-[11px] font-black uppercase tracking-wider transition-all"
                                >
                                    <GitCompare size={14} /> Comparativo ({Math.min(processedInventory.length, 200)})
                                </button>
                                <button
                                    onClick={() => handleDownloadGroupComparison(processedInventory.slice(0, 200).map(g => g.name), inventorySearch.trim(), 'html')}
                                    className="px-2 py-2 rounded-xl text-violet-300 hover:bg-violet-500/20 text-[11px] font-black uppercase transition-all"
                                    title="Abrir el comparativo en HTML"
                                >
                                    HTML
                                </button>
                            </div>
                        )}

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
                            <button
                                onClick={() => setInventoryViewMode('groups')}
                                className={`p-2 rounded-xl transition-all ${inventoryViewMode === 'groups' ? 'bg-[#06B6D4] text-[#0F172A]' : 'text-slate-500 hover:text-white'}`}
                                title="Activos de GitLab agrupados por instancia, grupo y proyecto, con reportes por grupo"
                            >
                                <FolderTree size={16} />
                            </button>
                        </div>

                        <div className="flex gap-2 p-1 bg-[#0F172A] rounded-2xl border border-slate-800">
                            {['ALL', 'VULNERABLE', 'ATTACKED'].map(f => (
                                <button 
                                    key={f}
                                    onClick={() => setAssetStatusFilter(f)}
                                    className={`px-4 py-2 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all ${assetStatusFilter === f ? 'bg-[#06B6D4] text-[#0F172A]' : 'text-slate-500 hover:text-white'}`}
                                >
                                    {f === 'ALL' ? 'Todos' : f === 'VULNERABLE' ? 'Vulnerables' : 'Bajo Ataque'}
                                </button>
                            ))}
                        </div>
                        <button 
                            onClick={() => setShowAddModal(true)}
                            className="flex items-center gap-2 px-6 py-3 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20"
                            title="Registrar un nuevo servidor, equipo institucional o recurso"
                        >
                            <Plus size={18} />
                            Añadir
                        </button>
                    </div>
                </div>

                {inventoryViewMode === 'groups' ? (
                    <GitLabGroupsView />
                ) : inventoryViewMode === 'grid' ? (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                    {processedInventory.map((group, idx) => (
                        <div key={idx} className="bg-[#0F172A]/50 backdrop-blur-sm p-1 rounded-[32px] border border-slate-800 group hover:border-[#06B6D4]/30 transition-all relative">
                            {group.runtime_alerts_count > 0 && (
                                <div className="absolute -top-2 -right-2 bg-red-600 text-white text-[12px] font-black px-3 py-1 rounded-full animate-bounce shadow-lg shadow-red-600/50 z-10 uppercase tracking-tighter" title="Se han detectado alertas de seguridad en tiempo real en este activo">
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
                                        <BranchScanButton assetName={group.name} />
                                        <TestCredentialsButton assetName={group.name} />
                                        <button
                                            onClick={() => handleDeleteAsset(group.name)}
                                            title="Eliminar este activo (inválido o ya no existe) y todos sus hallazgos"
                                            className="px-2.5 py-1.5 rounded-xl text-red-400 bg-red-500/10 border border-red-500/30 hover:bg-red-500 hover:text-white font-black uppercase text-[10px] tracking-widest flex items-center gap-1.5 transition-all"
                                        >
                                            <Trash2 size={12} /> Eliminar
                                        </button>
                                        {String(group.status).toLowerCase() === 'active' ? (
                                            // Real bug fixed 2026-08-14: a Wazuh agent actively reporting IS stronger
                                            // evidence of liveness than a raw ICMP ping (many real hosts -- Windows
                                            // workstations by default, hardened Linux servers -- block inbound ICMP
                                            // Echo while remaining fully reachable), so this trusts group.status
                                            // (kept genuinely fresh by the backend's periodic Wazuh/ping poller) over a
                                            // ping result. A SECOND bug, found live right after the first fix shipped:
                                            // this used to also accept a bare `group.agent_id` as sufficient on its own
                                            // -- but agent_id only proves an agent was EVER enrolled, not that it's
                                            // connected NOW. Confirmed live: a genuinely disconnected workstation
                                            // (status='disconnected' in the DB, Wazuh's own agent_control reporting
                                            // "Disconnected") still showed "Sincronizado" purely because agent_id was
                                            // still set (agent_id is never cleared just because a host went offline).
                                            // Dropped the agent_id fallback entirely -- group.status alone decides.
                                            <p className="text-[12px] font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-1" title="Activo sincronizado y monitoreado por agente o sondeo">
                                                <CheckCircle size={10} /> Sincronizado{Number.isFinite(pingResults[group.name]?.latency_ms) ? ` (${pingResults[group.name].latency_ms}ms)` : ''}
                                            </p>
                                        ) : pingResults[group.name] ? (
                                            pingResults[group.name].loading ? (
                                                <p className="text-[12px] font-black text-cyan-400 uppercase tracking-tighter flex items-center gap-1">
                                                    <RefreshCw size={10} className="animate-spin" /> Verificando...
                                                </p>
                                            ) : pingResults[group.name].ping_ok ? (
                                                <p className="text-[12px] font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-1" title={pingResults[group.name].message || "Host responde"}>
                                                    <CheckCircle size={10} /> En línea{Number.isFinite(pingResults[group.name].latency_ms) ? ` (${pingResults[group.name].latency_ms}ms)` : ''}
                                                </p>
                                            ) : pingResults[group.name].method === 'wazuh_agent' ? (
                                                // Real gap fixed 2026-08-14, per direct user question: assets enrolled
                                                // remotely/via VPN have no fixed IP (endpoint="remote-agent"), so a
                                                // network ping is structurally undeliverable, not "no response" --
                                                // confirmed live, pinging such an agent's real VPN IP got an explicit
                                                // "Destination Host Unreachable" from the gateway itself, not a
                                                // timeout. The backend now checks Wazuh's own live agent status
                                                // instead (method='wazuh_agent') and this shows that real result
                                                // honestly, distinct from a genuine network ping failure below.
                                                <p className="text-[12px] font-black text-amber-400 uppercase tracking-tighter flex items-center gap-1" title={pingResults[group.name].message}>
                                                    <ZapOff size={10} className="text-amber-400" /> Agente: Desconectado
                                                </p>
                                            ) : (
                                                <p className="text-[12px] font-black text-slate-400 uppercase tracking-tighter flex items-center gap-1" title={pingResults[group.name].message || "Host sin respuesta de ICMP Ping"}>
                                                    <ZapOff size={10} className="text-slate-500" /> Offline (Sin respuesta ICMP)
                                                </p>
                                            )
                                        ) : group.last_seen ? (
                                            <p className="text-[12px] font-black text-amber-400 uppercase tracking-tighter flex items-center gap-1" title={`Desconectado. Última conexión: ${new Date(group.last_seen).toLocaleString('es-MX')}`}>
                                                <ZapOff size={10} className="text-amber-400" /> Offline (Desconectado)
                                            </p>
                                        ) : (
                                            <p className="text-[12px] font-black text-slate-400 uppercase tracking-tighter flex items-center gap-1" title="Activo registrado pero nunca se ha conectado ni sincronizado">
                                                <Clock size={10} className="text-slate-500" /> Offline (Sin Conexión Previa)
                                            </p>
                                        )}

                                    </div>
                                </div>
                                
                                <h4 className="text-white font-bold text-xl mb-1 tracking-tight">{group.name}</h4>
                                <div className="flex items-center gap-2 mb-3">
                                   <span className={`text-[12px] font-extrabold px-2.5 py-0.5 rounded-full uppercase tracking-widest ${group.interfaces[0]?.asset_type_badge_class || 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'}`}>
                                     {group.interfaces[0]?.asset_type_label || group.interfaces[0]?.asset_type || 'SERVER'}
                                   </span>
                                   <span className="text-[12px] text-slate-500 font-bold uppercase tracking-[0.2em]" title="Activo consolidado que agrupa sus distintas interfaces, IP y servicios de red">Activo Unificado</span>

                                </div>
                                
                                {/* Wazuh, Vault & Ping status badges -- Vault SSH/sudo credentials and ICMP ping only
                                    make sense for real network-reachable infrastructure. A GitLab-Repo asset has no
                                    IP to ping and is remediated via git apply/Merge Request, never SSH, so showing
                                    "Credenciales Vault: No asignada" / "Ping: Sin respuesta" on a code repository
                                    card is pure noise, not a real gap -- confirmed by inspecting the actual rendered
                                    dashboard against the 67/83 assets that are GitLab-Repo type. */}
                                {!['GITLAB-REPO', 'GITLAB'].includes(String(group.interfaces[0]?.asset_type || '').toUpperCase()) && (
                                <div className="flex flex-wrap gap-2 mb-6">
                                  {/* Render Wazuh badge ONLY for server/workstation hosts or if agent_id exists */}
                                  {(group.agent_id || ['SERVER', 'SERVER_LINUX', 'SERVER_WINDOWS', 'WORKSTATION'].includes(group.interfaces[0]?.asset_type)) && (
                                    group.agent_id ? (
                                      <span 
                                        title={`Agente Wazuh EDR instalado y activo en este servidor (ID Agente: ${group.agent_id})`}
                                        className={`text-[10px] font-black px-2 py-0.5 rounded border uppercase tracking-wider ${
                                        group.status === 'active' 
                                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                                          : 'bg-red-500/10 text-red-400 border-red-500/20'
                                      }`}>
                                        Wazuh EDR: {group.status === 'active' ? 'Activo' : group.status} (ID: {group.agent_id})
                                      </span>
                                    ) : (
                                      <span 
                                        title="Agente Wazuh EDR no instalado en este servidor"
                                        className="text-[10px] bg-slate-800 text-slate-400 font-black px-2 py-0.5 rounded border border-slate-700 uppercase tracking-wider"
                                      >
                                        Wazuh EDR: No instalado
                                      </span>
                                    )
                                  )}
                                  
                                  {group.has_vault_secret ? (
                                    <span 
                                      title="Credenciales de conexión Sudo/SSH almacenadas y encriptadas de forma segura en HashiCorp Vault"
                                      className="text-[10px] bg-amber-500/10 text-amber-400 font-black px-2 py-0.5 rounded border border-amber-400/20 uppercase tracking-wider"
                                    >
                                      Credenciales Vault: Configurada
                                    </span>
                                  ) : (
                                    <span 
                                      title="Sin credenciales configuradas en Vault. Haz clic en el botón Vault para asignar un secreto"
                                      className="text-[10px] bg-red-500/10 text-red-400 font-black px-2 py-0.5 rounded border border-red-500/20 uppercase tracking-wider"
                                    >
                                      Credenciales Vault: No asignada
                                    </span>
                                  )}

                                  <button 
                                    onClick={(e) => { e.stopPropagation(); handlePingAsset(group.name); }}
                                    disabled={pingResults[group.name]?.loading}
                                    className={`text-[10px] font-black px-2 py-0.5 rounded border uppercase tracking-wider transition-all flex items-center gap-1 cursor-pointer ${
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

                                  {(() => {
                                    const badge = getCisGradeBadge(group.interfaces[0]?.cis_grade, group.interfaces[0]?.cis_checked_at, group.interfaces[0]?.cis_percentage)
                                    return (
                                      <span title={badge.title} className={`text-[10px] font-black px-2 py-0.5 rounded border uppercase tracking-wider ${badge.className}`}>
                                        {badge.label}
                                      </span>
                                    )
                                  })()}
                                </div>
                                )}

                                {group.agent_id && (
                                  <div className="flex gap-2 mt-2 w-full mb-4">
                                    <button 
                                      onClick={() => handleWazuhAction(group.agent_id, 'restart')}
                                      className="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-2 py-1 rounded border border-slate-700 transition-all flex-1"
                                      disabled={wazuhActionLoading}
                                      title="Solicitar reinicio remoto del servicio del agente Wazuh"
                                    >
                                      Reiniciar Agente
                                    </button>
                                    <button 
                                      onClick={() => handleWazuhAction(group.agent_id, 'scan')}
                                      className="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-2 py-1 rounded border border-slate-700 transition-all flex-1"
                                      disabled={wazuhActionLoading}
                                      title="Disparar escaneo de integridad de archivos FIM inmediatamente"
                                    >
                                      Escanear FIM
                                    </button>
                                    <button 
                                      onClick={() => handleWazuhAction(group.agent_id, 'logs')}
                                      className="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-2 py-1 rounded border border-slate-700 transition-all flex-1"
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
                                      className="text-[10px] bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 font-bold px-2 py-1 rounded transition-all w-full"
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
                                        <p className="text-[11px] text-slate-500 font-black uppercase tracking-widest mb-1">Vulnerabilidades</p>
                                        <div className="flex items-center gap-2">
                                            <ShieldAlert size={14} className={group.vulnerability_count > 0 ? 'text-orange-400' : 'text-slate-600'} />
                                            <span className={`text-lg font-black ${group.vulnerability_count > 0 ? 'text-orange-400' : 'text-slate-400'} flex items-center`}>
                                                {group.vulnerability_count}
                                                {group.resolved_count > 0 && (
                                                    <span className="text-[12px] text-emerald-400 font-black tracking-tighter bg-emerald-500/10 px-2 py-0.5 rounded-md ml-2 border border-emerald-500/20" title={`${group.resolved_count} vulnerabilidades resueltas`}>
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
                                        <p className="text-[11px] text-slate-500 font-black uppercase tracking-widest mb-1">Alertas en Tiempo Real</p>
                                        <div className="flex items-center gap-2">
                                            <Zap size={14} className={group.runtime_alerts_count > 0 ? 'text-red-400' : 'text-slate-600'} />
                                            <span className={`text-lg font-black ${group.runtime_alerts_count > 0 ? 'text-red-400' : 'text-slate-400'}`}>
                                                {group.runtime_alerts_count}
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                {/* Porcentaje de Cumplimiento ISO y CMMI v3.0 en Card Principal -- ambos usan el dato
                                    real (isoReport.assets_audit / cmmiReport.assets_audit), no una fórmula estimada.
                                    ISO usaba antes `100 - vulnerability_count*12`, que saturaba en 0% para cualquier
                                    activo con más de ~8 hallazgos (la inmensa mayoría de la flota real). */}
                                <div className="grid grid-cols-2 gap-2 mb-4">
                                    <div className="bg-[#0F172A] p-2.5 rounded-xl border border-emerald-500/20 flex items-center justify-between" title="Cumplimiento ISO 27001 / ISO 25010 real (cobertura de controles sin violaciones activas)">
                                        <div>
                                            <span className="text-[10px] font-black text-slate-500 uppercase block">ISO 27001 / 25010</span>
                                            <span className="text-xs font-black text-emerald-400">
                                                {(() => {
                                                    // is_verified=false means no engine capable of an ISO-relevant audit
                                                    // (CIS hardening, SAST/SCA) has actually reached this asset yet -- an
                                                    // EDR agent connecting is not enough on its own (see
                                                    // evaluate_iso27001_for_asset()'s 2026-08-14 fix). Absence of findings
                                                    // on a never-audited asset is not evidence of compliance.
                                                    const real = isoReport.assets_audit?.find(a => a.asset_name === group.name)
                                                    if (!real) return '—'
                                                    return real.is_verified ? `${real.iso_compliance_percentage}%` : 'Sin Verificar'
                                                })()}
                                            </span>
                                        </div>
                                        <ShieldCheck size={16} className="text-emerald-400/60" />
                                    </div>
                                    <div className="bg-[#0F172A] p-2.5 rounded-xl border border-indigo-500/20 flex items-center justify-between" title="Cumplimiento CMMI v3.0 real (CAR/PQA/CM/MC/VV)">
                                        <div>
                                            <span className="text-[10px] font-black text-slate-500 uppercase block">CMMI v3.0 (Real)</span>
                                            <span className="text-xs font-black text-indigo-400">
                                                {(() => {
                                                    const real = cmmiReport.assets_audit?.find(a => a.asset_name === group.name)
                                                    if (!real) return '—'
                                                    return real.is_verified ? `${real.cmmi_compliance_percentage}%` : 'Sin Verificar'
                                                })()}
                                            </span>
                                        </div>
                                        <CheckCircle2 size={16} className="text-indigo-400/60" />
                                    </div>
                                </div>

                                <div className="space-y-2 mb-6">
                                    {group.interfaces.map((inf, i) => (
                                        <div key={i} className="flex items-center justify-between text-[12px] bg-slate-800/30 p-2 rounded-xl border border-white/5 group/inf hover:bg-[#06B6D4]/10 transition-all cursor-pointer" onClick={() => handleSelectAsset(inf.asset_name)} title={`Interfaz: ${inf.asset_type_label || inf.asset_type} - ${inf.endpoint}`}>
                                            <div className="flex items-center gap-2">
                                                <div className="w-1.5 h-1.5 rounded-full bg-[#06B6D4]" />
                                                <span className="text-slate-400 font-bold uppercase tracking-tighter">{inf.asset_type}</span>
                                            </div>
                                            <code className="text-[#06B6D4] font-bold truncate max-w-[120px]">{inf.endpoint}</code>
                                            <ChevronRight size={12} className="text-slate-600 group-hover/inf:translate-x-1 transition-all" />
                                        </div>
                                    ))}
                                </div>

                                <div className="flex flex-col gap-2">
                                    <button 
                                        onClick={() => handleSelectAsset(group.name)}
                                        title="Ver matriz completa de hallazgos, parches y auditorías de este activo"
                                        className="w-full py-3 bg-slate-800 hover:bg-[#06B6D4] text-slate-400 hover:text-[#0F172A] font-black uppercase text-[11px] tracking-[0.2em] rounded-xl transition-all flex items-center justify-center gap-2"
                                    >
                                        Ver Análisis Completo
                                        <ExternalLink size={12} />
                                    </button>
                                    <div className="grid grid-cols-[1fr_auto] gap-2">
                                        <button
                                            onClick={() => handleDownloadComparison(group.name)}
                                            title="Descargar el comparativo del último escaneo contra el anterior: qué se solventó, qué persiste y qué es nuevo"
                                            className="py-2.5 bg-violet-500/10 hover:bg-violet-500/20 text-violet-300 border border-violet-400/20 font-black uppercase text-[11px] tracking-[0.05em] rounded-xl transition-all flex items-center justify-center gap-1.5"
                                        >
                                            <GitCompare size={13} />
                                            Comparativo vs anterior
                                        </button>
                                        <button
                                            onClick={() => handleViewComparisonHtml(group.name)}
                                            title="Abrir el comparativo en HTML"
                                            className="py-2.5 px-3 bg-violet-500/10 hover:bg-violet-500/20 text-violet-300 border border-violet-400/20 font-black uppercase text-[11px] rounded-xl transition-all"
                                        >
                                            HTML
                                        </button>
                                    </div>
                                    <div className="grid grid-cols-4 gap-2">
                                    <button
                                        onClick={() => handleViewAssetReportHtml(group.name)}
                                        title="Reporte general del activo (HTML): todos los hallazgos abiertos actuales"
                                        className="py-3 px-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-400/20 font-black uppercase text-[11px] tracking-[0.05em] rounded-xl transition-all flex items-center justify-center gap-1 min-w-0"
                                    >
                                        <Code2 size={13} />
                                        HTML
                                    </button>
                                    <button
                                        onClick={() => handleDownloadAssetReport(group.name)}
                                        title="Reporte general del activo (PDF): todos los hallazgos abiertos actuales"
                                        className="py-3 px-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-400/20 font-black uppercase text-[11px] tracking-[0.05em] rounded-xl transition-all flex items-center justify-center gap-1 min-w-0"
                                    >
                                        <Download size={13} />
                                        PDF
                                    </button>
                                    <button
                                        onClick={() => handleOpenVaultModal(group.name)}
                                        title="Configurar credenciales Sudo o llaves SSH en HashiCorp Vault"
                                        className="py-3 px-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-400/20 font-black uppercase text-[11px] tracking-[0.05em] rounded-xl transition-all flex items-center justify-center gap-1 min-w-0"
                                    >
                                        <KeyRound size={13} />
                                        Vault
                                    </button>
                                    <button
                                        onClick={() => handleOpenAssetDetails(group)}
                                        title="Ver características generales del sistema (SO, Kernel, versión EDR)"
                                        className="py-3 px-1 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-400/20 font-black uppercase text-[11px] tracking-[0.05em] rounded-xl transition-all flex items-center justify-center gap-1 min-w-0"
                                    >
                                        <Info size={13} />
                                        Detalles
                                    </button>
                                    </div>
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
                                <tr className="bg-[#1E293B] text-slate-400 text-[12px] font-black uppercase tracking-widest border-b border-slate-800">
                                    <th className="p-4">Activo Unificado</th>
                                    <th className="p-4">Tipo</th>
                                    <th className="p-4">Endpoint / IP</th>
                                    <th className="p-4">Estado EDR / Ping</th>
                                    <th className="p-4">Vulnerabilidades</th>
                                    <th className="p-4">Alertas Runtime</th>
                                    <th className="p-4">CIS Hardening</th>
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
                                                    <span className="text-[11px] bg-red-500/20 text-red-400 font-bold px-2 py-0.5 rounded-full border border-red-500/30 animate-pulse">
                                                        🚨 Runtime
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="p-4">
                                            <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wider ${group.interfaces[0]?.asset_type_badge_class || 'bg-cyan-500/10 text-cyan-400'}`}>
                                                {group.interfaces[0]?.asset_type_label || group.interfaces[0]?.asset_type || 'SERVER'}
                                            </span>
                                        </td>
                                        <td className="p-4 font-mono text-xs text-[#06B6D4]">
                                            {group.interfaces[0]?.endpoint || '192.0.2.15'}
                                        </td>
                                        <td className="p-4 text-xs font-bold">
                                            {String(group.status).toLowerCase() === 'active' || pingResults[group.name]?.ping_ok ? (
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
                                        <td className="p-4">
                                            {(() => {
                                                const badge = getCisGradeBadge(group.interfaces[0]?.cis_grade, group.interfaces[0]?.cis_checked_at, group.interfaces[0]?.cis_percentage)
                                                return (
                                                    <span title={badge.title} className={`text-[10px] font-black px-2 py-0.5 rounded border uppercase tracking-wider ${badge.className}`}>
                                                        {badge.label}
                                                    </span>
                                                )
                                            })()}
                                        </td>
                                        <td className="p-4 text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                <button
                                                    onClick={() => handleOpenAssetDetails(group)}
                                                    className="px-3 py-1.5 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500 hover:text-white rounded-xl font-bold text-[12px] transition-all"
                                                    title="Ver características del sistema (SO, Kernel, EDR)"
                                                >
                                                    Detalles
                                                </button>
                                                <button
                                                    onClick={() => handleSelectAsset(group.name)}
                                                    className="px-3 py-1.5 bg-[#06B6D4]/10 text-[#06B6D4] hover:bg-[#06B6D4] hover:text-[#0F172A] rounded-xl font-bold text-[12px] transition-all"
                                                >
                                                    Análisis
                                                </button>
                                                <button
                                                    onClick={() => handleDownloadComparison(group.name)}
                                                    className="px-3 py-1.5 bg-violet-500/10 text-violet-300 hover:bg-violet-500 hover:text-white rounded-xl font-bold text-[12px] flex items-center gap-1.5 transition-all"
                                                    title="Comparativo del último escaneo contra el anterior (PDF)"
                                                >
                                                    <GitCompare size={13} /> Comparativo
                                                </button>
                                                <BranchScanButton assetName={group.name} compact />
                                                <TestCredentialsButton assetName={group.name} compact />
                                                <button
                                                    onClick={() => handleDeleteAsset(group.name)}
                                                    className="px-3 py-1.5 bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500 hover:text-white rounded-xl font-bold text-[12px] flex items-center gap-1.5 transition-all"
                                                    title="Eliminar este activo (inválido o ya no existe) y todos sus hallazgos"
                                                >
                                                    <Trash2 size={13} /> Eliminar
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
  )
}
