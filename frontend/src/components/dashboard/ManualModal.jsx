// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, CheckCircle, ShieldCheck, XCircle } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function ManualModal() {
  const { handleManualRemediation, manualReason, manualSaving, manualSolution, selectedRemediation, setManualReason, setManualSolution, setShowManualModal } = useDashboard()
  return (
<div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-xl rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-[#06B6D4]/10 to-transparent flex justify-between items-center">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-[#06B6D4]/10 border border-[#06B6D4]/20 flex items-center justify-center text-[#06B6D4]">
                                <CheckCircle size={24} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tighter">Remediación Manual</h3>
                                <p className="text-[12px] text-slate-500 font-black uppercase tracking-widest mt-0.5">
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
                            <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">
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
                            <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">
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
                                className="flex-1 py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-lg shadow-[#06B6D4]/20 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
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
                                className="px-6 py-4 bg-slate-800 text-white font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                            >
                                Cancelar
                            </button>
                        </div>
                    </form>
                </div>
            </div>
  )
}
