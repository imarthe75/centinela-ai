// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, Cpu } from 'lucide-react'
import { useDashboard } from './DashboardContext'
import { healthStatusTier } from './shared'

export default function HealthView() {
  const { healthStatus } = useDashboard()
  return (
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
                                    <p className="text-[12px] text-slate-500 font-black uppercase tracking-widest mb-1">Estado</p>
                                    <p className={`${textClass} font-bold text-sm`}>{service.status}</p>
                                </div>
                                <div className="text-right">
                                    <p className="text-[12px] text-slate-500 font-black uppercase tracking-widest mb-1">Latencia</p>
                                    <p className="text-white font-bold text-sm">{service.latency}</p>
                                </div>
                            </div>
                        </div>
                        )
                    })}
                </div>
            </div>
  )
}
