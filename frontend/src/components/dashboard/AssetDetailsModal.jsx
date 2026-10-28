// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, AlertTriangle, CheckCircle2, Download, Globe, ShieldCheck, XCircle } from 'lucide-react'
import { useDashboard } from './DashboardContext'
import { AssetIcon } from './shared'

export default function AssetDetailsModal() {
  const { activeCmmiAreaFilter, assetDetailsData, assetDetailsLoading, getCisGradeBadge, getFindingPlainLanguage, handleDownloadCmmiAssetReport, setActiveCmmiAreaFilter, setAgentModalAsset, setAgentModalTab, setShowAgentModal, setShowAssetDetailsModal } = useDashboard()
  return (
<div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-2xl rounded-[48px] border border-indigo-500/20 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500 flex flex-col max-h-[85vh]">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-indigo-500/10 to-transparent flex justify-between items-center shrink-0">
                        <div className="flex items-center gap-3">
                            <div className="p-3 bg-indigo-500/10 rounded-2xl text-indigo-400 border border-indigo-500/20">
                                <AssetIcon type={assetDetailsData.group.interfaces[0]?.asset_type} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tight">{assetDetailsData.group.name}</h3>
                                <p className="text-[12px] text-indigo-400 font-black uppercase tracking-widest mt-0.5">
                                    {assetDetailsData.group.interfaces[0]?.asset_type_label || assetDetailsData.group.interfaces[0]?.asset_type} — Telemetría del Sistema
                                </p>
                            </div>
                        </div>
                        <button onClick={() => setShowAssetDetailsModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={28} />
                        </button>
                    </div>

                    <div className="flex-1 overflow-y-auto p-8 space-y-6 custom-scrollbar">
                        {assetDetailsLoading ? (
                            <div className="flex items-center justify-center py-12 text-indigo-400 gap-3">
                                <Activity size={24} className="animate-spin" />
                                <span className="text-xs font-bold uppercase tracking-widest">Consultando telemetría del sistema...</span>
                            </div>
                        ) : (
                            <>
                                {/* Base info grid */}
                                <div className="grid grid-cols-2 gap-4 text-xs">
                                    <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                        <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Nombre del Activo</span>
                                        <span className="text-white font-bold">{assetDetailsData.group.name}</span>
                                    </div>
                                    <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                        <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Tipo de Activo</span>
                                        <span className="text-indigo-400 font-bold">{assetDetailsData.group.interfaces[0]?.asset_type_label || assetDetailsData.group.interfaces[0]?.asset_type}</span>
                                    </div>
                                    <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                        <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Dirección / Endpoint</span>
                                        <code className="text-[#06B6D4] font-bold break-all">{assetDetailsData.group.interfaces[0]?.endpoint}</code>
                                    </div>
                                    <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                        <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Estado de Conectividad</span>
                                        <span className={`font-bold ${(assetDetailsData.ping?.ping_ok || assetDetailsData.group.status === 'active') ? 'text-emerald-400' : 'text-amber-400'}`}>
                                            {(assetDetailsData.ping?.ping_ok || assetDetailsData.group.status === 'active')
                                                ? `En Línea${assetDetailsData.ping?.latency_ms ? ` — ${assetDetailsData.ping?.latency_ms}ms` : ''}`
                                                : 'Offline / Pendiente'}
                                        </span>
                                    </div>
                                    <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                        <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Criticidad</span>
                                        <span className={`font-bold text-xs ${
                                            assetDetailsData.info?.criticality === 'CRITICAL' ? 'text-red-400' :
                                            assetDetailsData.info?.criticality === 'HIGH' ? 'text-orange-400' :
                                            assetDetailsData.info?.criticality === 'MEDIUM' ? 'text-amber-400' : 'text-slate-400'
                                        }`}>{assetDetailsData.info?.criticality || assetDetailsData.group.interfaces[0]?.criticality || 'N/A'}</span>
                                    </div>
                                    <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                        <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Último Escaneo</span>
                                        <span className="text-slate-400 font-bold text-[12px]">
                                            {assetDetailsData.info?.last_scanned
                                                ? new Date(assetDetailsData.info.last_scanned).toLocaleString('es-MX')
                                                : 'Pendiente de escaneo'}
                                        </span>
                                    </div>
                                </div>

                                {/* OS & System Details */}
                                {assetDetailsData.info && (
                                    <div className="space-y-3">
                                        <p className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Sistema Operativo & Plataforma</p>
                                        <div className="grid grid-cols-2 gap-3 text-xs">
                                            <div className="col-span-2 bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                                <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Sistema Operativo / Motor</span>
                                                <p className="text-white font-bold">{assetDetailsData.info.os_info || 'Linux Enterprise'}</p>
                                            </div>
                                            <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                                <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Kernel / Build</span>
                                                <span className="text-slate-300 font-mono font-bold text-[13px]">{assetDetailsData.info.kernel || 'N/A'}</span>
                                            </div>
                                            <div className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                                <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Arquitectura</span>
                                                <span className="text-indigo-400 font-bold">{assetDetailsData.info.architecture || 'x86_64'}</span>
                                            </div>
                                            {assetDetailsData.info.engine_version && assetDetailsData.info.engine_version !== 'N/A' && (
                                                <div className="col-span-2 bg-[#0F172A] p-4 rounded-2xl border border-slate-800">
                                                    <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">Versión de Motor / EDR</span>
                                                    <span className="text-emerald-400 font-bold">{assetDetailsData.info.engine_version}</span>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                )}

                                {/* Bloque de Cumplimiento ISO por Separado -- iso_score/cmmi_score llegan como null desde
                                    el backend cuando is_verified es false (activo nunca alcanzado por ningún motor real:
                                    sin agente EDR, sin auditoría CIS exitosa, no es GitLab-Repo, cero hallazgos reales).
                                    Mostrar "Sin Verificar" en vez de un número -- la ausencia de hallazgos en un activo
                                    nunca contactado no es evidencia de cumplimiento real. */}
                                <div className="space-y-2">
                                    <div className="flex items-center justify-between">
                                        <p className="text-[11px] font-black text-emerald-400 uppercase tracking-widest flex items-center gap-1.5">
                                            <ShieldCheck size={12} /> Cumplimiento Estándares ISO (Seguridad & Calidad ISO 27001 / 25010 / 25001)
                                        </p>
                                        <span className={`text-xs font-black px-2.5 py-0.5 rounded-full border ${
                                            assetDetailsData.info?.compliance?.iso_score != null
                                                ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                                                : 'text-slate-400 bg-slate-500/10 border-slate-500/30'
                                        }`}>
                                            {assetDetailsData.info?.compliance?.iso_score != null ? `${assetDetailsData.info.compliance.iso_score}%` : 'Sin Verificar'}
                                        </span>
                                    </div>
                                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden mb-2">
                                        <div
                                            className="h-full bg-emerald-400 rounded-full transition-all duration-500"
                                            style={{ width: `${assetDetailsData.info?.compliance?.iso_score ?? 0}%` }}
                                        />
                                    </div>
                                    <div className="grid grid-cols-3 gap-2">
                                        <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-500/30 text-center">
                                            <span className="text-[10px] text-slate-400 font-black uppercase block">ISO/IEC 27001:2022</span>
                                            <span className="text-emerald-400 font-bold text-xs">A.8.8 & A.8.16</span>
                                            <span className="text-[10px] text-slate-400 block mt-0.5">Gestión de Vulnerabilidades y Monitoreo</span>
                                        </div>
                                        <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-500/30 text-center">
                                            <span className="text-[10px] text-slate-400 font-black uppercase block">ISO/IEC 25010 / 25001</span>
                                            <span className="text-emerald-400 font-bold text-xs">SQuaRE Calidad</span>
                                            <span className="text-[10px] text-slate-400 block mt-0.5">Mantenibilidad & Cero Deuda Técnica</span>
                                        </div>
                                        <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-500/30 text-center">
                                            <span className="text-[10px] text-slate-400 font-black uppercase block">ISO/IEC 27017</span>
                                            <span className="text-emerald-400 font-bold text-xs">Seguridad Cloud</span>
                                            <span className="text-[10px] text-slate-400 block mt-0.5">Protección de Cargas & Aislamiento</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Bloque de Cumplimiento CMMI v3.0 -- 5 áreas de práctica reales evaluables por código (CAR/PQA/CM/MC/VV),
                                    evaluadas en vivo contra los hallazgos reales de este activo (evaluate_cmmi_v3_for_asset). */}
                                <div className="space-y-2">
                                    <div className="flex items-center justify-between">
                                        <p className="text-[11px] font-black text-indigo-400 uppercase tracking-widest flex items-center gap-1.5">
                                            <CheckCircle2 size={12} /> Modelo CMMI v3.0 — Auditoría Real por Activo
                                        </p>
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={() => handleDownloadCmmiAssetReport(assetDetailsData.group.name)}
                                                title="Descargar reporte PDF de cumplimiento CMMI v3.0 de este activo"
                                                className="flex items-center gap-1 text-[10px] font-black text-indigo-300 bg-indigo-500/10 px-2 py-0.5 rounded-full border border-indigo-500/20 hover:bg-indigo-500/20 transition-all uppercase tracking-wider"
                                            >
                                                <Download size={10} /> PDF
                                            </button>
                                            {assetDetailsData.info?.compliance?.cmmi_maturity_level && (
                                                <span className="text-[10px] font-black text-indigo-300 bg-indigo-500/10 px-2 py-0.5 rounded-full border border-indigo-500/20">
                                                    {assetDetailsData.info.compliance.cmmi_maturity_level}
                                                </span>
                                            )}
                                            <span className={`text-xs font-black px-2.5 py-0.5 rounded-full border ${
                                                assetDetailsData.info?.compliance?.cmmi_score != null
                                                    ? 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30'
                                                    : 'text-slate-400 bg-slate-500/10 border-slate-500/30'
                                            }`}>
                                                {assetDetailsData.info?.compliance?.cmmi_score != null ? `${assetDetailsData.info.compliance.cmmi_score}%` : 'Sin Verificar'}
                                            </span>
                                        </div>
                                    </div>
                                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden mb-2">
                                        <div
                                            className="h-full bg-indigo-400 rounded-full transition-all duration-500"
                                            style={{ width: `${assetDetailsData.info?.compliance?.cmmi_score ?? 0}%` }}
                                        />
                                    </div>
                                    {Array.isArray(assetDetailsData.info?.compliance?.cmmi_practice_areas) && assetDetailsData.info.compliance.cmmi_practice_areas.length > 0 ? (
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                            {assetDetailsData.info.compliance.cmmi_practice_areas.map((pa, idx) => {
                                                // Same keyword patterns evaluate_cmmi_v3_for_asset() (backend) uses per area, so a
                                                // click here filters the real findings list below to the ones actually behind
                                                // this specific area's pass/fail result -- not just a generic list.
                                                const areaCode = (pa.area.match(/^([A-Z]+)/) || [])[1]
                                                const isActive = activeCmmiAreaFilter === areaCode
                                                return (
                                                <div
                                                    key={idx}
                                                    onClick={() => !pa.passed && setActiveCmmiAreaFilter(isActive ? null : areaCode)}
                                                    className={`bg-[#0F172A] p-3 rounded-xl border text-left transition-all ${pa.passed ? 'border-emerald-500/30' : 'border-red-500/30 cursor-pointer hover:bg-red-500/5'} ${isActive ? 'ring-2 ring-red-400' : ''}`}
                                                    title={pa.passed ? undefined : 'Haz clic para ver los hallazgos reales detrás de esta área'}
                                                >
                                                    <div className="flex items-center justify-between mb-1">
                                                        <span className="text-[11px] text-slate-300 font-black uppercase">{pa.area}</span>
                                                        <span className={`text-[10px] font-black px-1.5 py-0.5 rounded-md ${pa.passed ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                                                            {pa.status}
                                                        </span>
                                                    </div>
                                                    <span className="text-[11px] text-slate-400 leading-snug block">{pa.evidence}</span>
                                                </div>
                                                )
                                            })}
                                        </div>
                                    ) : (
                                        <span className="text-[12px] text-slate-500 italic">Cargando evaluación CMMI real...</span>
                                    )}
                                </div>

                                {/* Bloque de CIS Benchmarks (Hardening Level 1) -- checks reales de solo lectura vía
                                    SSH (auditors/auditor_cis_benchmarks.py). grade es null tanto si nunca se auditó
                                    como si la última auditoría no pudo conectarse por SSH; checked_at distingue
                                    ambos casos, igual que el estado SIN_CONEXION honesto del backend. */}
                                <div className="space-y-2">
                                    {(() => {
                                        const cis = assetDetailsData.info?.compliance?.cis_benchmark
                                        const badge = getCisGradeBadge(cis?.grade, cis?.checked_at, cis?.percentage)
                                        const barColorByGrade = { A: 'bg-emerald-400', B: 'bg-cyan-400', C: 'bg-amber-400', F: 'bg-red-400' }
                                        const barColor = barColorByGrade[cis?.grade] || 'bg-slate-600'
                                        return (
                                            <>
                                                <div className="flex items-center justify-between">
                                                    <p className="text-[11px] font-black text-cyan-400 uppercase tracking-widest flex items-center gap-1.5">
                                                        <ShieldCheck size={12} /> CIS Benchmarks (Hardening Level 1 — SSH Real)
                                                    </p>
                                                    <span title={badge.title} className={`text-xs font-black px-2.5 py-0.5 rounded-full border ${badge.className}`}>
                                                        {badge.label}
                                                    </span>
                                                </div>
                                                {cis?.checked_at ? (
                                                    <>
                                                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden mb-2">
                                                            <div className={`h-full rounded-full transition-all duration-500 ${barColor}`} style={{ width: `${cis.percentage ?? 0}%` }} />
                                                        </div>
                                                        <span className="text-[10px] text-slate-500 block">
                                                            Última verificación: {new Date(cis.checked_at).toLocaleString('es-MX')}
                                                            {!cis.grade && ' — no se pudo establecer conexión SSH con el activo.'}
                                                        </span>
                                                    </>
                                                ) : (
                                                    <span className="text-[12px] text-slate-500 italic block">Aún no se ha ejecutado una auditoría CIS Benchmarks sobre este activo.</span>
                                                )}
                                                {cis?.findings?.length > 0 && (
                                                    <div className="space-y-1.5 mt-2">
                                                        {cis.findings.map((f, idx) => (
                                                            <div key={idx} className="flex items-center justify-between bg-[#0F172A] p-2.5 rounded-xl border border-slate-800 text-[12px]">
                                                                <div>
                                                                    <span className="text-cyan-400 font-bold block">{f.check}</span>
                                                                    <span className="text-slate-300">{f.issue}</span>
                                                                </div>
                                                                <span className={`px-2 py-0.5 rounded-md font-bold text-[10px] ${
                                                                    f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                                                                    f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                                                                    f.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' :
                                                                    f.severity === 'LOW' ? 'bg-blue-500/20 text-blue-400' :
                                                                    'bg-slate-500/20 text-slate-400'
                                                                }`}>
                                                                    {f.severity}
                                                                </span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </>
                                        )
                                    })()}
                                </div>

                                {/* Desglose de Fallos Reales que Afectan el Cumplimiento */}
                                {assetDetailsData.info?.compliance?.iso_findings?.length > 0 && (() => {
                                    // Realigned 2026-08-25 to match compliance_mapper.py's evaluate_cmmi_v3_for_asset():
                                    // SAM/MSR removed (not real CMMI V3.0 codes under the tailored, ISACA-verified 19-area
                                    // model -- see the manual citation in that file), PQA broadened to absorb the former
                                    // MSR keywords (no honest per-finding CMMI area exists for a hardcoded sleep). CM/MC/VV
                                    // are boolean/evidence-based, not finding-keyword-based, so they have no entry here
                                    // (same as EST/PLAN/VV before this change) -- clicking them shows all findings.
                                    const CMMI_AREA_KEYWORDS = {
                                        CAR: ['INJECTION', 'SWALLOWED', 'CAR'],
                                        PQA: ['HARDCODED', 'SECRET', 'TODO', 'SLEEP', 'DEBT', 'COMPLEXITY'],
                                    }
                                    const keywords = activeCmmiAreaFilter ? CMMI_AREA_KEYWORDS[activeCmmiAreaFilter] || [] : null
                                    const findings = keywords
                                        ? assetDetailsData.info.compliance.iso_findings.filter(f => keywords.some(k => f.issue?.toUpperCase().includes(k)))
                                        : assetDetailsData.info.compliance.iso_findings
                                    return (
                                    <div className="space-y-2 bg-red-500/5 p-4 rounded-2xl border border-red-500/20">
                                        <div className="flex items-center justify-between">
                                            <p className="text-[11px] font-black text-red-400 uppercase tracking-widest flex items-center gap-1.5">
                                                <AlertTriangle size={12} /> Hallazgos Reales de Código que Afectan el Cumplimiento ({findings.length}{activeCmmiAreaFilter ? ` de ${assetDetailsData.info.compliance.open_vulnerabilities_count}` : ''})
                                            </p>
                                            {activeCmmiAreaFilter && (
                                                <button onClick={() => setActiveCmmiAreaFilter(null)} className="text-[10px] font-black text-slate-400 hover:text-white uppercase tracking-wider bg-slate-800 px-2 py-1 rounded-md">
                                                    Filtro: {activeCmmiAreaFilter} ✕
                                                </button>
                                            )}
                                        </div>
                                        <div className="space-y-1.5">
                                            {findings.map((f, idx) => {
                                                const plainLanguage = getFindingPlainLanguage(f.issue)
                                                return (
                                                <div key={idx} className="flex items-center justify-between bg-[#0F172A] p-2.5 rounded-xl border border-slate-800 text-[12px]">
                                                    <div>
                                                        <span className="text-amber-400 font-bold block">{f.control}</span>
                                                        {plainLanguage && <span className="text-slate-300 block mb-0.5">{plainLanguage}</span>}
                                                        <span className={`font-mono ${plainLanguage ? 'text-slate-500 text-[10px]' : 'text-slate-300'}`}>{f.issue}</span>
                                                    </div>
                                                    <span className={`px-2 py-0.5 rounded-md font-bold text-[10px] ${
                                                        f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                                                        f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                                                        f.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' :
                                                        f.severity === 'LOW' ? 'bg-blue-500/20 text-blue-400' :
                                                        'bg-slate-500/20 text-slate-400'
                                                    }`}>
                                                        {f.severity}
                                                    </span>
                                                </div>
                                                )
                                            })}
                                        </div>
                                    </div>
                                    )
                                })()}

                                {/* Specific Details (type-specific) */}
                                {assetDetailsData.info && Array.isArray(assetDetailsData.info.specific_details) && assetDetailsData.info.specific_details.length > 0 && (
                                    <div className="space-y-3">
                                        <p className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Detalles Específicos del Activo</p>
                                        <div className="grid grid-cols-2 gap-3 text-xs">
                                            {assetDetailsData.info.specific_details.map((item, i) => (
                                                <div key={i} className={`bg-[#0F172A] p-4 rounded-2xl border border-slate-800 ${item.key?.length > 20 ? 'col-span-2' : ''}`}>
                                                    <span className="text-[11px] text-slate-500 font-black uppercase block mb-1">{item.key}</span>
                                                    <span className="text-slate-200 font-bold">{item.value}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Multiple interfaces (multi-IP) */}
                                {assetDetailsData.group.interfaces?.length > 1 && (
                                    <div className="space-y-3">
                                        <p className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Interfaces y Endpoints Registrados</p>
                                        <div className="space-y-2">
                                            {assetDetailsData.group.interfaces.map((iface, i) => (
                                                <div key={i} className="flex items-center justify-between bg-[#0F172A] p-3 rounded-xl border border-slate-800">
                                                    <div className="flex items-center gap-2">
                                                        <Globe size={12} className="text-[#06B6D4]" />
                                                        <code className="text-[#06B6D4] text-[13px] font-bold">{iface.endpoint}</code>
                                                    </div>
                                                    <span className="text-[11px] text-slate-500 font-black uppercase">{iface.asset_type}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Agent download action for agent-capable types */}
                                {['SERVER_LINUX', 'SERVER_WINDOWS', 'WORKSTATION', 'SERVER'].includes(assetDetailsData.group.interfaces[0]?.asset_type) && (
                                    <div className="flex items-center gap-3 p-4 bg-indigo-500/5 border border-indigo-500/20 rounded-2xl">
                                        <Download size={16} className="text-indigo-400 shrink-0" />
                                        <div className="flex-1">
                                            <p className="text-[12px] font-black text-indigo-400 uppercase tracking-widest mb-0.5">Agente Wazuh EDR</p>
                                            <p className="text-[11px] text-slate-500 font-medium">
                                                {assetDetailsData.group.agent_id
                                                    ? `Agente instalado y activo (ID: ${assetDetailsData.group.agent_id})`
                                                    : 'Instala el agente para habilitar monitoreo EDR completo.'}
                                            </p>
                                        </div>
                                        {!assetDetailsData.group.agent_id && (
                                            <button
                                                onClick={() => {
                                                    setShowAssetDetailsModal(false)
                                                    setAgentModalAsset({
                                                        name: assetDetailsData.group.name,
                                                        type: assetDetailsData.group.interfaces[0]?.asset_type,
                                                        endpoint: assetDetailsData.group.interfaces[0]?.endpoint
                                                    })
                                                    setAgentModalTab('guide')
                                                    setShowAgentModal(true)
                                                }}
                                                className="shrink-0 py-2 px-4 bg-indigo-500 text-white font-black uppercase text-[11px] tracking-widest rounded-xl hover:bg-indigo-400 transition-all flex items-center gap-1.5"
                                            >
                                                <Download size={12} /> Instalar Agente
                                            </button>
                                        )}
                                    </div>
                                )}
                            </>
                        )}
                    </div>

                    <div className="p-6 bg-[#0F172A] border-t border-white/5 flex justify-end shrink-0">
                        <button
                            onClick={() => setShowAssetDetailsModal(false)}
                            className="px-10 py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all"
                        >
                            Cerrar
                        </button>
                    </div>
                </div>
            </div>
  )
}
