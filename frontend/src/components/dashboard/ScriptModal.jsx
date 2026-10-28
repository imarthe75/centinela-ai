// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, PlusCircle, Terminal, XCircle } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function ScriptModal() {
  const { handleDownloadScript, scriptContent, scriptLoading, setShowScriptModal } = useDashboard()
  return (
<div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-[#0F172A]/95 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-4xl rounded-[48px] border border-[#06B6D4]/30 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-10 border-b border-white/5 flex items-center justify-between bg-gradient-to-br from-[#06B6D4]/10 to-transparent">
                        <div className="flex items-center gap-4">
                            <div className="p-3 bg-slate-800 text-[#06B6D4] rounded-2xl shadow-inner border border-white/5">
                                <Terminal size={28} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-2xl tracking-tighter">Auditoría de Script de Remediación</h3>
                                <p className="text-[12px] text-[#06B6D4] font-black uppercase tracking-widest">Procedimiento Validado por Inteligencia Artificial</p>
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
                            className="flex-1 py-5 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all shadow-xl shadow-[#06B6D4]/10 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            <PlusCircle size={18} />
                            Descargar Script Maestro (.sh)
                        </button>
                        <button 
                            onClick={() => { navigator.clipboard.writeText(scriptContent); alert("Script copiado al portapapeles de seguridad."); }}
                            disabled={scriptLoading}
                            className="px-10 py-5 bg-slate-800 text-white font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all disabled:opacity-50"
                        >
                            Copiar Código
                        </button>
                    </div>
                </div>
            </div>
  )
}
