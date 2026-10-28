// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, AlertTriangle, Info, Microscope, ShieldCheck, XCircle } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function InvestigateModal() {
  const { investigationData, isInvestigating, setCurrentView, setShowInvestigateModal } = useDashboard()
  return (
<div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-2xl rounded-[48px] border border-[#06B6D4]/30 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-10 border-b border-white/5 flex items-center justify-between bg-gradient-to-br from-[#06B6D4]/10 to-transparent">
                        <div className="flex items-center gap-4">
                            <div className="p-3 bg-[#06B6D4] text-[#0F172A] rounded-2xl">
                                <Microscope size={28} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-2xl tracking-tighter">Investigación IA en Tiempo Real</h3>
                                <p className="text-[12px] text-[#06B6D4] font-black uppercase tracking-widest">Motor: cascada de IA</p>
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
                                    <h4 className="text-[#06B6D4] font-black text-[12px] uppercase tracking-widest mb-3 flex items-center gap-2">
                                        <Info size={14} />
                                        Contexto Técnico
                                    </h4>
                                    <p className="text-slate-300 text-sm leading-relaxed bg-white/5 p-6 rounded-[24px] border border-white/5 italic">
                                        {investigationData.contexto}
                                    </p>
                                </section>

                                <section>
                                    <h4 className="text-orange-400 font-black text-[12px] uppercase tracking-widest mb-3 flex items-center gap-2">
                                        <AlertTriangle size={14} />
                                        Evaluación de Riesgo Real
                                    </h4>
                                    <div className="p-6 bg-orange-500/10 border border-orange-500/20 rounded-[24px]">
                                        <p className="text-orange-100 font-bold text-sm uppercase tracking-tighter mb-2">{investigationData.riesgo}</p>
                                        <p className="text-orange-200/70 text-xs leading-relaxed font-medium">Impacto directo en la continuidad del servicio detectado.</p>
                                    </div>
                                </section>

                                <section>
                                    <h4 className="text-emerald-400 font-black text-[12px] uppercase tracking-widest mb-3 flex items-center gap-2">
                                        <ShieldCheck size={14} />
                                        Acción Inmediata (SLA 5min)
                                    </h4>
                                    <div className="grid grid-cols-1 gap-3">
                                        {investigationData.accion_inmediata.map((action, i) => (
                                            <div key={i} className="flex items-center gap-4 p-4 bg-[#0F172A] border border-slate-800 rounded-2xl group hover:border-emerald-500/50 transition-all">
                                                <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-500 flex items-center justify-center text-[12px] font-black">
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
                            className="flex-1 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-xl shadow-[#06B6D4]/10"
                        >
                            Generar Plan SOAR Completo
                        </button>
                        <button 
                            onClick={() => setShowInvestigateModal(false)}
                            className="px-8 py-5 bg-slate-800 text-white font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                        >
                            Cerrar
                        </button>
                    </div>
                </div>
            </div>
  )
}
