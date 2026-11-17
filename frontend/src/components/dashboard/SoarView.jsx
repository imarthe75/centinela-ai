// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import GitLabIssueButton from './GitLabIssueButton'
import { Activity, AlertTriangle, CheckCircle, CheckCircle2, ChevronDown, ChevronRight, ClipboardCheck, Clock, Cpu, Download, FileText, Info, PlusCircle, Search, Server, ShieldAlert, X, XCircle, Zap, ZapOff } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { useDashboard } from './DashboardContext'

export default function SoarView() {
  const { assetFilter, filteredRemediations, handleDownloadVulnerabilityReport, handleExecuteRemediation, handleViewScript, remediationLog, selectedRemediation, setAssetFilter, setSelectedRemediation, setShowManualModal, setShowReportModal, setSoarAssetCategoryFilter, setSoarCategoryFilter, setSoarSearch, setSoarSeverityFilter, setSoarStatusFilter, soarAssetCategoryFilter, soarCategoryFilter, soarSearch, soarSeverityFilter, soarStatusFilter } = useDashboard()
  return (
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
                                <span className="text-[12px] font-black text-[#06B6D4] uppercase tracking-widest">Filtro Activo: {assetFilter}</span>
                                <X size={14} className="text-[#06B6D4] cursor-pointer hover:text-white transition-colors" onClick={() => { setAssetFilter(null); setSoarCategoryFilter('ALL'); }} />
                            </div>
                        )}
                        <div className="bg-emerald-500/10 text-emerald-500 px-4 py-2 rounded-xl border border-emerald-500/20 text-[12px] font-black uppercase">
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
                                className="bg-transparent border-none text-[12px] focus:ring-0 text-slate-300 font-bold placeholder:text-slate-600 outline-none w-full" 
                            />
                        </div>

                        {/* Severity Select */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-3 py-2 rounded-xl border border-slate-800" title="Filtrar remediaciones por nivel de severidad">
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Severidad:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={soarSeverityFilter}
                                    onChange={(e) => setSoarSeverityFilter(e.target.value)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
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
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Estado:</span>
                            <div className="relative flex items-center">
                                <select 
                                    value={soarStatusFilter}
                                    onChange={(e) => setSoarStatusFilter(e.target.value)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
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

                        {/* Category Select: real vulnerability vs. informational/quality marker */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-3 py-2 rounded-xl border border-slate-800" title="Vulnerabilidad: hallazgo de seguridad real y accionable. Informativo: métricas de calidad de código, deuda técnica o marcadores de auditoría (no son vulnerabilidades)">
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Categoría:</span>
                            <div className="relative flex items-center">
                                <select
                                    value={soarCategoryFilter}
                                    onChange={(e) => setSoarCategoryFilter(e.target.value)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="ALL">TODAS</option>
                                    <option value="VULNERABILITY">VULNERABILIDAD REAL</option>
                                    <option value="COMPLIANCE">CUMPLIMIENTO (ACCESIBILIDAD)</option>
                                    <option value="INFORMATIONAL">INFORMATIVO / CALIDAD</option>
                                </select>
                                <ChevronDown size={11} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>

                        {/* Asset Category Select: infrastructure vs. code repos */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-3 py-2 rounded-xl border border-slate-800" title="Infraestructura: servidores, bases de datos. Código: repositorios GitLab (SAST/SCA/calidad de código)">
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Activo:</span>
                            <div className="relative flex items-center">
                                <select
                                    value={soarAssetCategoryFilter}
                                    onChange={(e) => setSoarAssetCategoryFilter(e.target.value)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="ALL">TODOS</option>
                                    <option value="INFRA">INFRAESTRUCTURA</option>
                                    <option value="CODE">CÓDIGO</option>
                                </select>
                                <ChevronDown size={11} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>
                    </div>

                    <div className="flex gap-2">
                        {(soarSearch || soarSeverityFilter !== 'ALL' || soarStatusFilter !== 'ALL' || soarCategoryFilter !== 'ALL' || soarAssetCategoryFilter !== 'ALL') && (
                            <button
                                onClick={() => { setSoarSearch(''); setSoarSeverityFilter('ALL'); setSoarStatusFilter('ALL'); setSoarCategoryFilter('ALL'); setSoarAssetCategoryFilter('ALL'); }}
                                className="px-4 py-2 rounded-xl bg-slate-850 hover:bg-slate-700 text-slate-400 hover:text-white text-[11px] font-black uppercase tracking-widest transition-all"
                            >
                                Limpiar Filtros
                            </button>
                        )}
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    <div className={`${selectedRemediation ? 'lg:col-span-7' : 'lg:col-span-12'} space-y-6 transition-all duration-500`}>
                        {filteredRemediations.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-32 bg-[#1E293B] rounded-[48px] border border-slate-800 border-dashed">
                                <ZapOff size={64} className="text-slate-700 mb-6" />
                                <h3 className="text-white font-bold text-2xl mb-2">Sin Orquestaciones Pendientes</h3>
                                <p className="text-slate-500 text-sm max-w-md text-center font-medium">
                                    {remediationLog.length === 0
                                        ? 'No se han generado planes de remediación automáticos en las últimas 24 horas.'
                                        : 'Ningún hallazgo coincide con los filtros seleccionados.'}
                                </p>
                            </div>
                        ) : (
                            <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 overflow-hidden">
                                <table className="w-full text-left">
                                    <thead className="bg-[#0F172A]">
                                        <tr className="text-slate-500 text-[12px] font-black uppercase tracking-widest border-b border-slate-800">
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
                                                                <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                                                                    CRS {log.risk_score ? log.risk_score : '—'}
                                                                </span>
                                                                {log.is_cisa_kev && (
                                                                    <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                                                                        🚨 CISA KEV
                                                                    </span>
                                                                )}
                                                                {log.reachability_status === 'UNREACHABLE' && (
                                                                    <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-slate-800 text-slate-500 border border-slate-700" title="Dependencia declarada pero nunca importada en el código">
                                                                        SIN USO REAL
                                                                    </span>
                                                                )}
                                                                {log.mitre_technique && (
                                                                    <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20" title={log.mitre_technique}>
                                                                        {log.mitre_technique.match(/T\d+(\.\d+)?/)?.[0] || 'ATT&CK'}
                                                                    </span>
                                                                )}
                                                                {log.is_sla_breached ? (
                                                                    <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                                                                        SLA VENCIDO
                                                                    </span>
                                                                ) : (
                                                                    <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                                                                        SLA OK
                                                                    </span>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="p-6 text-xs font-bold text-slate-400">{log.asset_name}</td>
                                                <td className="p-6">
                                                     <span className={`px-2 py-1 rounded text-[11px] font-black uppercase ${log.severity_badge_class || 'bg-slate-500/20 text-slate-400 border border-slate-500/30'}`}>
                                                         {log.severity_label || log.severity || 'INFO'}
                                                     </span>
                                                 </td>
                                                 <td className="p-6">
                                                     <div className="flex items-center gap-2">
                                                         <span className={`text-[11px] font-black uppercase ${log.status_text_class || 'text-orange-500'}`}>
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
                                            <p className="text-[12px] text-[#06B6D4] font-black uppercase tracking-widest mb-1">Informe Ejecutivo IA</p>
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
                                                <p className="text-[11px] text-slate-500 font-bold uppercase">Asset Afectado</p>
                                                <p className="text-xs font-bold text-white">{selectedRemediation.asset_name}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-3 p-4 bg-[#0F172A] rounded-2xl border border-slate-800">
                                            <Cpu size={18} className="text-[#06B6D4]" />
                                            <div>
                                                <p className="text-[11px] text-slate-500 font-bold uppercase">Motor Detector</p>
                                                <p className="text-xs font-bold text-white">{selectedRemediation.detection_engine || "Externo / API"}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-3 p-4 bg-[#0F172A] rounded-2xl border border-slate-800">
                                            <Clock size={18} className="text-slate-500" />
                                            <div>
                                                <p className="text-[11px] text-slate-500 font-bold uppercase">Detección</p>
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
                                            <h4 className="text-[#06B6D4] font-black text-[12px] uppercase tracking-widest mb-4 flex items-center gap-2">
                                                <Activity size={14} />
                                                Log de Ejecución Remota (Aura-Sentinel)
                                            </h4>
                                            <div className="p-5 bg-black/40 rounded-2xl border border-slate-800 text-[13px] text-slate-400 overflow-x-auto leading-relaxed shadow-inner">
                                                <div className="prose prose-invert prose-xs max-w-none">
                                                    <ReactMarkdown>{selectedRemediation.log_output}</ReactMarkdown>
                                                </div>
                                            </div>
                                        </section>
                                    )}
                                </div>

                                <div className="p-8 bg-[#0F172A] border-t border-slate-800 flex gap-3 shrink-0 flex-wrap">
                                    {selectedRemediation.status === 'RESOLVED' || selectedRemediation.executed_bool ? (
                                        <div className="flex-grow py-4 bg-emerald-500/10 text-emerald-500 font-black uppercase text-[12px] tracking-widest rounded-2xl border border-emerald-500/20 flex items-center justify-center gap-2 cursor-default">
                                            <CheckCircle2 size={16} />
                                            Activo Remediado
                                        </div>
                                    ) : (
                                        <>
                                            {selectedRemediation.status === 'NEW' || selectedRemediation.status === 'PENDING' ? (
                                                <div className="flex-grow py-4 bg-orange-500/10 text-orange-500 font-black uppercase text-[12px] tracking-widest rounded-2xl border border-orange-500/20 flex items-center justify-center gap-2 cursor-default animate-pulse">
                                                    <Activity size={16} className="animate-spin" />
                                                    Procesando IA...
                                                </div>
                                            ) : (
                                                <button 
                                                    onClick={() => handleExecuteRemediation(selectedRemediation.id)}
                                                    className="flex-grow py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all active:scale-95 flex items-center justify-center gap-2 shadow-lg shadow-[#06B6D4]/10"
                                                >
                                                    <Zap size={16} />
                                                    Ejecutar Remedio AI
                                                </button>
                                            )}
                                            {/* Code findings: an issue in the finding's own GitLab project (Redmine/Gitea are not deployed here). */}
                                            {!(selectedRemediation.status === 'RESOLVED' || selectedRemediation.executed_bool) && (
                                                <GitLabIssueButton key={selectedRemediation.id} vulnId={selectedRemediation.id} assetName={selectedRemediation.asset_name} />
                                            )}
                                            {!(selectedRemediation.status === 'RESOLVED' || selectedRemediation.executed_bool) && (
                                                <button
                                                    onClick={() => setShowManualModal(true)}
                                                    className="flex-grow py-4 bg-slate-800 text-slate-300 font-black uppercase text-[12px] tracking-widest rounded-2xl border border-slate-700 hover:bg-slate-700 transition-all active:scale-95 flex items-center justify-center gap-2"
                                                >
                                                    <CheckCircle size={16} />
                                                    Remediar Manual
                                                </button>
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
  )
}
