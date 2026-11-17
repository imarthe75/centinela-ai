// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { ChevronDown, Filter, Search, ShieldAlert, X } from 'lucide-react'
import { useDashboard } from './DashboardContext'
import { SEV_BADGE_CLS, SEV_LABEL_ES, normSev } from './shared'

export default function ThreatHuntingView() {
  const { assetFilter, handleInvestigate, setAssetFilter, setSeverityFilter, setSoarCategoryFilter, setThreatSearch, setThreatSortBy, severityFilter, threatHuntingAlerts, threatSearch, threatSortBy } = useDashboard()
  return (
<div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between mb-8 gap-6">
                    <h3 className="text-white font-bold text-xl flex items-center gap-2">
                        <ShieldAlert className="text-[#06B6D4]" size={24} />
                        Búsqueda de Amenazas en Tiempo Real - Log Maestro
                    </h3>
                    <div className="flex flex-wrap items-center gap-3">
                        {assetFilter && (
                            <div className="flex items-center gap-3 bg-[#06B6D4]/10 px-4 py-2 rounded-xl border border-[#06B6D4]/20">
                                <span className="text-[12px] font-black text-[#06B6D4] uppercase tracking-widest">Filtro Activo: {assetFilter}</span>
                                <X size={14} className="text-[#06B6D4] cursor-pointer" onClick={() => { setAssetFilter(null); setSoarCategoryFilter('ALL'); }} />
                            </div>
                        )}

                        {/* Selector de Ordenamiento -- mismo patrón visual que Inventario de Activos */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-2xl border border-slate-800 focus-within:border-[#06B6D4] transition-all" title="Ordenar alertas por fecha o severidad">
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest hidden sm:inline">Orden:</span>
                            <div className="relative flex items-center">
                                <select
                                    value={threatSortBy}
                                    onChange={(e) => setThreatSortBy(e.target.value)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="newest" className="bg-[#0F172A] text-slate-300">Más Recientes Primero</option>
                                    <option value="oldest" className="bg-[#0F172A] text-slate-300">Más Antiguas Primero</option>
                                    <option value="severity" className="bg-[#0F172A] text-red-400">Por Severidad</option>
                                </select>
                                <ChevronDown size={12} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>

                        {/* Filtro por Severidad */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-2xl border border-slate-800 focus-within:border-[#06B6D4] transition-all" title="Filtrar por severidad de la alerta">
                            <Filter size={14} className="text-[#06B6D4]" />
                            <span className="text-[11px] font-black text-slate-500 uppercase tracking-widest hidden sm:inline">Severidad:</span>
                            <div className="relative flex items-center">
                                <select
                                    value={severityFilter || ''}
                                    onChange={(e) => setSeverityFilter(e.target.value || null)}
                                    className="bg-transparent border-none text-[12px] font-black text-[#06B6D4] uppercase focus:ring-0 cursor-pointer outline-none p-0 pr-5 appearance-none"
                                >
                                    <option value="" className="bg-[#0F172A] text-slate-300">TODAS</option>
                                    <option value="CRITICAL" className="bg-[#0F172A] text-red-400">CRÍTICA</option>
                                    <option value="HIGH" className="bg-[#0F172A] text-orange-400">ALTA</option>
                                    <option value="MEDIUM" className="bg-[#0F172A] text-amber-400">MEDIA</option>
                                    <option value="LOW" className="bg-[#0F172A] text-blue-400">BAJA</option>
                                    <option value="INFO" className="bg-[#0F172A] text-slate-400">INFORMATIVA</option>
                                </select>
                                <ChevronDown size={12} className="absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                            </div>
                        </div>

                        {/* Búsqueda de texto libre */}
                        <div className="flex items-center gap-2 bg-[#0F172A] px-4 py-2 rounded-2xl border border-slate-800 focus-within:border-[#06B6D4] transition-all">
                            <Search size={16} className="text-slate-500" />
                            <input
                                type="text"
                                placeholder="Buscar regla/activo/detalle..."
                                value={threatSearch}
                                onChange={(e) => setThreatSearch(e.target.value)}
                                className="bg-transparent border-none text-[12px] focus:ring-0 w-32 md:w-48 text-slate-300 font-bold placeholder:text-slate-600 outline-none"
                            />
                        </div>
                    </div>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="text-slate-500 text-[12px] font-black uppercase tracking-widest border-b border-slate-800">
                                <th className="pb-4">Severidad</th>
                                <th className="pb-4">Marca de Tiempo</th>
                                <th className="pb-4">Activo Afectado</th>
                                <th className="pb-4">Regla / Firma</th>
                                <th className="pb-4">Detalle de Alerta</th>
                                <th className="pb-4 text-right">Acción</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                            {threatHuntingAlerts.length > 0 ? (
                                threatHuntingAlerts.map((alert) => (
                                    <tr key={alert.id} className="group hover:bg-white/5 transition-all">
                                        <td className="py-6">
                                            <span className={`px-2 py-1 rounded text-[11px] font-black ${SEV_BADGE_CLS[normSev(alert.priority)]}`}>
                                                {SEV_LABEL_ES[normSev(alert.priority)]}
                                            </span>
                                        </td>
                                        <td className="py-6 text-[13px] font-bold text-slate-500">{new Date(alert.detected_at).toLocaleString()}</td>
                                        <td className="py-6 text-[13px] font-bold text-white">{alert.asset_name || "Servidor Centinela-AI (192.0.2.17)"}</td>
                                        <td className="py-6 text-[13px] text-[#06B6D4] font-bold">{alert.rule_name}</td>
                                        <td className="py-6 text-[13px] text-slate-400 max-w-xs truncate">{alert.alert_text}</td>
                                        <td className="py-6 text-right">
                                            <button 
                                                onClick={() => handleInvestigate(alert.id)}
                                                className="px-4 py-2 rounded-xl bg-emerald-500/10 text-emerald-400 font-black text-[12px] uppercase tracking-widest hover:bg-emerald-500 hover:text-white transition-all"
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
  )
}
