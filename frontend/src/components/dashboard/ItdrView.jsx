// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, AlertTriangle, Radio, UserCheck } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function ItdrView() {
  const { itdrAnomalies, itdrEvents24h, itdrEventsRecent, itdrLoading } = useDashboard()
  return (
<div className="space-y-8">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                    <UserCheck className="text-indigo-400" size={28} />
                    Detección & Respuesta ante Amenazas de Identidad (ITDR)
                  </h2>
                  <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">
                    Monitoreo en Tiempo Real de Autenticación, MFA y Sesiones Authentik
                  </p>
                </div>
                <div className="flex gap-3">
                  {/* This used to unconditionally read "Webhook Authentik: Activo" once loading
                      finished -- true of the receiver endpoint itself, but misleading as a
                      status badge: it never reflected whether Authentik has actually ever sent
                      a real event. Now honestly distinguishes "receiving real telemetry" from
                      "endpoint is up but has never received a real Authentik event" using the
                      real fetched event counts instead of a static label. */}
                  <span
                    title={itdrLoading ? undefined : (itdrEvents24h.length > 0
                      ? 'El webhook receptor está recibiendo eventos reales de Authentik'
                      : 'El endpoint receptor del webhook está activo, pero no ha recibido ningún evento real de Authentik todavía -- verifica que Authentik tenga un Notification Transport configurado apuntando a este endpoint')}
                    className={`text-[12px] font-bold px-3 py-1.5 rounded-xl border uppercase tracking-widest flex items-center gap-2 ${
                      itdrLoading
                        ? 'bg-slate-800 text-slate-500 border-slate-700'
                        : itdrEvents24h.length > 0
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                    }`}
                  >
                    <Radio size={12} className={itdrLoading ? "animate-pulse text-slate-500" : itdrEvents24h.length > 0 ? "animate-pulse text-emerald-400" : "text-amber-400"} />
                    {itdrLoading ? "Cargando telemetría..." : itdrEvents24h.length > 0 ? "Webhook Authentik: Recibiendo Eventos" : "Webhook Authentik: Sin Eventos Reales Aún"}
                  </span>
                </div>
              </div>

              {(() => {
                const bruteForceCount = itdrEvents24h.filter(e => e.event_type === 'ITDR-AUTHENTIK-BRUTE-FORCE').length
                const mfaCount = itdrEvents24h.filter(e => e.event_type === 'ITDR-AUTHENTIK-MFA-BYPASS').length
                const revokedCount = itdrEvents24h.filter(e => {
                  try { return JSON.parse(e.details || '{}').autonomous_action_executed === true } catch { return false }
                }).length
                return (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div className="bg-[#1E293B] p-6 rounded-3xl border border-slate-800">
                  <p className="text-[12px] text-slate-500 font-black uppercase tracking-widest mb-1">Intentos de Fuerza Bruta (24h)</p>
                  <h3 className="text-3xl font-black text-white tracking-tight">{bruteForceCount}</h3>
                  <p className="text-[11px] text-emerald-400 font-bold mt-2">Detección activa · la respuesta autónoma depende de la política (ver Salud del Sistema)</p>
                </div>
                <div className="bg-[#1E293B] p-6 rounded-3xl border border-slate-800">
                  <p className="text-[12px] text-slate-500 font-black uppercase tracking-widest mb-1">Alertas MFA / Alteraciones (24h)</p>
                  <h3 className="text-3xl font-black text-amber-400 tracking-tight">{mfaCount}</h3>
                  <p className="text-[11px] text-slate-500 font-bold mt-2">Dispositivos TOTP Auditados</p>
                </div>
                <div className="bg-[#1E293B] p-6 rounded-3xl border border-slate-800">
                  <p className="text-[12px] text-slate-500 font-black uppercase tracking-widest mb-1">Sesiones Revocadas por IA (24h)</p>
                  <h3 className="text-3xl font-black text-indigo-400 tracking-tight">{revokedCount}</h3>
                  <p className="text-[11px] text-indigo-400 font-bold mt-2">Revocación de sesiones sujeta a política y token de Authentik</p>
                </div>
              </div>
                )
              })()}

              {itdrAnomalies.length > 0 && (
                <div className="bg-[#1E293B] rounded-3xl border border-amber-500/30 p-8 mb-8">
                  <h3 className="text-white font-bold text-lg mb-4 flex items-center gap-2">
                    <AlertTriangle size={18} className="text-amber-400" />
                    Anomalías de Comportamiento (UEBA) — {itdrAnomalies.length}
                  </h3>
                  <div className="space-y-2">
                    {itdrAnomalies.map((a, idx) => (
                      <div key={idx} className="bg-[#0F172A] p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                        <div>
                          <span className="text-amber-400 font-bold text-xs block">{a.anomaly_type}</span>
                          <span className="text-slate-400 text-[13px]">{a.description}</span>
                          <span className="text-slate-500 text-[12px] block mt-1">{a.entity}</span>
                        </div>
                        <span className="text-amber-400 font-black text-sm">{a.risk_score}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="bg-[#1E293B] rounded-3xl border border-slate-800 p-8">
                <h3 className="text-white font-bold text-lg mb-4 flex items-center gap-2">
                  <Activity size={18} className="text-indigo-400" />
                  Registro de Telemetría ITDR & Eventos de Sesión (últimos 15 min)
                </h3>
                <div className="bg-[#0F172A] rounded-2xl p-6 font-mono text-xs text-slate-300 space-y-3">
                  <div className="grid grid-cols-6 gap-2 border-b border-slate-800 pb-2 text-slate-500 font-black text-[12px] uppercase tracking-widest">
                    <span>Marca de Tiempo</span>
                    <span>Evento / Regla</span>
                    <span>Usuario</span>
                    <span>IP Origen</span>
                    <span>Confianza</span>
                    <span>Acción Autónoma</span>
                  </div>
                  {itdrEventsRecent.length > 0 ? itdrEventsRecent.map((e, idx) => {
                    let autonomous = false
                    try { autonomous = JSON.parse(e.details || '{}').autonomous_action_executed === true } catch {}
                    return (
                      <div key={idx} className="grid grid-cols-6 gap-2 py-2 border-b border-slate-800/50 text-[13px]">
                        <span className="text-slate-500">{e.timestamp}</span>
                        <span className={e.severity === 'CRITICAL' ? 'text-red-400 font-bold' : e.severity === 'HIGH' ? 'text-orange-400 font-bold' : 'text-slate-300'}>{e.event_type}</span>
                        <span>{e.username}</span>
                        <span className="text-slate-400">{e.client_ip}</span>
                        <span>{Math.round((e.confidence_score || 0) * 100)}%</span>
                        <span className={autonomous ? 'text-emerald-400 font-bold' : 'text-slate-500'}>{autonomous ? 'Ejecutada' : '—'}</span>
                      </div>
                    )
                  }) : (
                    <div className="text-center py-8 text-slate-500 italic">
                      {itdrLoading ? 'Cargando telemetría real...' : 'Sin eventos de amenaza de identidad detectados en los últimos 15 minutos. Escuchando webhooks de Authentik en tiempo real...'}
                    </div>
                  )}
                </div>
              </div>
            </div>
  )
}
