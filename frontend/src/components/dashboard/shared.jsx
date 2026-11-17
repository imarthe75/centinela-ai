// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Cloud, Container, Database, Laptop, Layers, Link, Monitor, Server, Terminal } from 'lucide-react'

export const API_BASE = "/api"

export const normSev = (p) => {
  const s = String(p || '').trim().toUpperCase()
  const map = {
    EMERGENCY: 'CRITICAL', ALERT: 'CRITICAL', CRITICAL: 'CRITICAL',
    ERROR: 'HIGH', HIGH: 'HIGH',
    WARNING: 'MEDIUM', MEDIUM: 'MEDIUM',
    NOTICE: 'LOW', LOW: 'LOW',
    INFORMATIONAL: 'INFO', INFO: 'INFO', DEBUG: 'INFO',
  }
  return map[s] || 'INFO'
}

export const SEV_LABEL_ES = { CRITICAL: 'CRÍTICA', HIGH: 'ALTA', MEDIUM: 'MEDIA', LOW: 'BAJA', INFO: 'INFORMATIVA' }

export const SEV_BADGE_CLS = {
  CRITICAL: 'bg-red-500/20 text-red-400',
  HIGH: 'bg-orange-500/20 text-orange-400',
  MEDIUM: 'bg-amber-500/20 text-amber-400',
  LOW: 'bg-blue-500/20 text-blue-400',
  INFO: 'bg-slate-500/20 text-slate-400',
}

export function healthStatusTier(status) {
  if (status === 'Online' || status === 'Active') return 'ok'
  if (typeof status === 'string' && /^Autonomous/.test(status)) return 'ok'
  if (typeof status === 'string' && /^(Available|No Data|No Recent Data|Observation|Manual only|Stale|Module Off|Online \(Warning)/.test(status)) return 'warn'
  return 'fail'
}

export function AssetIcon({ type }) {
    switch (type) {
        case 'WORKSTATION':
        case 'LAPTOP': return <Laptop size={20} />;
        case 'SERVER_LINUX':
        case 'SERVER': return <Server size={20} />;
        case 'SERVER_WINDOWS': return <Monitor size={20} />;
        case 'CONTAINER': return <Container size={20} />;
        case 'KUBERNETES': return <Layers size={20} />;
        case 'IP': return <Terminal size={20} />;
        case 'URL': return <Link size={20} />;
        case 'DATABASE': return <Database size={20} />;
        case 'CLOUD': return <Cloud size={20} />;
        default: return <Server size={20} />;
    }
}

export function NavItem({ icon, label, active = false, onClick }) {
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

export function MetricCard({ label, value, icon, color, sub, highlight = false, onClick, title }) {
  return (
    <div 
      onClick={onClick}
      title={title || `Ir a ${label}`}
      className={`bg-[#1E293B] p-6 rounded-[24px] border ${highlight ? 'border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.15)]' : 'border-slate-800'} ${onClick ? 'cursor-pointer hover:border-[#06B6D4]/60 hover:bg-[#1E293B]/80 hover:scale-[1.02]' : ''} group transition-all`}
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-2 rounded-xl bg-slate-800 text-slate-400 group-hover:text-[#06B6D4] transition-all`}>
          {icon}
        </div>
        <div className="w-1.5 h-1.5 rounded-full bg-[#06B6D4] animate-pulse" />
      </div>
      <p className="text-[12px] font-black text-slate-500 uppercase tracking-[0.15em] mb-1">{label}</p>
      <p className={`text-3xl font-black ${color} mb-1 tracking-tighter`}>{value}</p>
      <p className="text-[12px] font-bold text-slate-600 tracking-tight">{sub}</p>
    </div>
  )
}

