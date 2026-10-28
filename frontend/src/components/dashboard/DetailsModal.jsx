// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, Cpu, Eye, XCircle } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function DetailsModal() {
  const { agentInfo, agentInfoLoading, detailsTarget, setShowDetailsModal } = useDashboard()
  return (
<div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-xl rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500 max-h-[85vh] flex flex-col">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent flex justify-between items-center shrink-0">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-[#06B6D4]/10 border border-[#06B6D4]/20 flex items-center justify-center text-[#06B6D4]">
                                <Eye size={24} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tighter">{detailsTarget.name}</h3>
                                <p className="text-[12px] text-[#06B6D4]/70 font-black uppercase tracking-widest mt-0.5">
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
                                <p className="text-[11px] text-slate-500 font-black uppercase tracking-widest mb-1">Vulnerabilidades</p>
                                <p className="text-lg font-black text-orange-400">{detailsTarget.vulnerability_count}</p>
                            </div>
                            <div className="p-4 rounded-2xl border bg-slate-800/20 border-slate-800">
                                <p className="text-[11px] text-slate-500 font-black uppercase tracking-widest mb-1">Resueltas</p>
                                <p className="text-lg font-black text-emerald-400">{detailsTarget.resolved_count}</p>
                            </div>
                            <div className="p-4 rounded-2xl border bg-slate-800/20 border-slate-800">
                                <p className="text-[11px] text-slate-500 font-black uppercase tracking-widest mb-1">Alertas Runtime</p>
                                <p className="text-lg font-black text-red-400">{detailsTarget.runtime_alerts_count}</p>
                            </div>
                        </div>

                        <div>
                            <p className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2">Estado General</p>
                            <div className="flex flex-wrap gap-2">
                                {detailsTarget.agent_id ? (
                                    <span className={`text-[11px] font-black px-2.5 py-1 rounded border uppercase tracking-wider ${detailsTarget.status === 'active' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                                        Wazuh: {detailsTarget.status} (ID: {detailsTarget.agent_id})
                                    </span>
                                ) : (
                                    <span className="text-[11px] bg-slate-800 text-slate-400 font-black px-2.5 py-1 rounded border border-slate-700 uppercase tracking-wider">
                                        Wazuh: No instalado
                                    </span>
                                )}
                                <span className={`text-[11px] font-black px-2.5 py-1 rounded border uppercase tracking-wider ${detailsTarget.has_vault_secret ? 'bg-amber-500/10 text-amber-400 border-amber-400/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                                    Vault Creds: {detailsTarget.has_vault_secret ? 'Sí' : 'No'}
                                </span>
                            </div>
                        </div>

                        <div>
                            <p className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2">
                                Interfaces ({detailsTarget.interfaces.length})
                            </p>
                            <div className="space-y-2">
                                {detailsTarget.interfaces.map((inf, i) => (
                                    <div key={i} className="bg-[#0F172A] p-4 rounded-2xl border border-slate-800 text-xs">
                                        <div className="flex items-center justify-between mb-2">
                                            <span className={`text-[11px] font-extrabold px-2 py-0.5 rounded-full uppercase tracking-widest ${inf.asset_type_badge_class || 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'}`}>
                                                {inf.asset_type_label || inf.asset_type}
                                            </span>
                                            <code className="text-[#06B6D4] font-bold">{inf.endpoint}</code>
                                        </div>
                                        <div className="grid grid-cols-3 gap-2 text-[12px] text-slate-400">
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
                            <p className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                              <Cpu size={12} className="text-[#06B6D4]" />
                              Información del Sistema (Wazuh Live)
                            </p>
                            {agentInfoLoading ? (
                              <div className="flex items-center gap-2 text-[12px] text-slate-500 font-bold p-3">
                                <Activity size={14} className="animate-spin text-[#06B6D4]" />
                                Consultando agente en tiempo real...
                              </div>
                            ) : agentInfo ? (
                              <div className="bg-[#0F172A] rounded-2xl border border-slate-800 divide-y divide-slate-800 overflow-hidden text-[13px]">
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
                              <p className="text-[12px] text-slate-600 font-bold p-3">No se pudo obtener información del sistema del agente.</p>
                            )}
                          </div>
                        )}
                    </div>

                    <div className="p-6 border-t border-slate-800 shrink-0">
                        <button
                            onClick={() => setShowDetailsModal(false)}
                            className="w-full py-3 bg-slate-800 text-white font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                        >
                            Cerrar
                        </button>
                    </div>
                </div>
            </div>
  )
}
