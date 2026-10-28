import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { Gauge, RefreshCw, Zap, AlertTriangle, CheckCircle2, XCircle, KeyRound, Clock, Info } from 'lucide-react'

const API_BASE = '/api'

const STATE = {
  disponible: { label: 'Disponible', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', Icon: CheckCircle2 },
  agotado: { label: 'Cuota agotada', cls: 'bg-red-500/15 text-red-400 border-red-500/30', Icon: XCircle },
  en_pausa: { label: 'En pausa', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30', Icon: Clock },
  revisar: { label: 'Revisar', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30', Icon: AlertTriangle },
  sin_llave: { label: 'Sin llave', cls: 'bg-slate-700/40 text-slate-400 border-slate-700', Icon: KeyRound },
  sin_uso: { label: 'Sin uso reciente', cls: 'bg-sky-500/10 text-sky-400 border-sky-500/30', Icon: Info },
}

const fmt = (n) => (n ?? 0).toLocaleString('es-MX')
const when = (iso) => (iso ? new Date(iso).toLocaleString('es-MX', { hour12: false }) : '—')

export default function TokensIAView() {
  const [probe, setProbe] = useState(null)
  const [probing, setProbing] = useState(false)

  // ADR-0008 #2: server state via TanStack Query (cache, dedupe, background refresh) instead of hand-rolled state + setInterval.
  const query = useQuery({
    queryKey: ['ai-tokens'],
    queryFn: async () => (await axios.get(`${API_BASE}/ai-tokens`)).data,
    refetchInterval: 30000,
  })
  const data = query.data ?? null
  const loading = query.isFetching
  const error = query.error ? (query.error.response?.data?.detail || query.error.message) : null
  const load = () => query.refetch()

  const runProbe = async () => {
    setProbing(true)
    try {
      const res = await axios.post(`${API_BASE}/ai-tokens/probe`, null, { timeout: 120000 })
      setProbe(res.data)
    } catch (e) {
      console.error('Error probing AI quota:', e)
      alert('No se pudo sondear la cuota: ' + (e.response?.data?.detail || e.message))
    } finally {
      setProbing(false)
    }
  }

  const tiers = data?.tiers || []
  const usable = tiers.filter((t) => t.configured && ['disponible', 'sin_uso'].includes(t.state))
  const configured = tiers.filter((t) => t.configured)
  const tokensToday = tiers.reduce((a, t) => a + t.prompt_tokens_today + t.completion_tokens_today, 0)
  const callsToday = tiers.reduce((a, t) => a + t.ok_today, 0)

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-white font-bold text-2xl flex items-center gap-3">
            <Gauge className="text-[#06B6D4]" size={28} /> Tokens de IA
          </h2>
          <p className="text-slate-500 text-sm mt-1 max-w-3xl">
            Proveedores de la cascada de análisis (se prueban en orden; si uno se queda sin cuota, se pasa al siguiente).
            Si todos se agotan, los hallazgos quedan pendientes hasta que la cuota se reinicie.
          </p>
        </div>
        <div className="flex gap-3">
          <button onClick={load} disabled={loading}
            className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 font-black uppercase text-[11px] tracking-widest rounded-xl flex items-center gap-2 transition-all">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Actualizar
          </button>
          <button onClick={runProbe} disabled={probing}
            title="Consulta a Groq y OpenRouter cuánta cuota real les queda (consume ~1 token por modelo de Groq)"
            className="px-4 py-3 bg-[#06B6D4]/15 hover:bg-[#06B6D4]/25 text-[#06B6D4] border border-[#06B6D4]/30 font-black uppercase text-[11px] tracking-widest rounded-xl flex items-center gap-2 transition-all">
            <Zap size={14} className={probing ? 'animate-pulse' : ''} /> {probing ? 'Sondeando…' : 'Verificar cuota real'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-2xl border border-red-500/30 bg-red-500/10 text-red-300 text-sm font-bold">
          No se pudo leer el estado: {error}
        </div>
      )}

      {data && (
        <>
          <div className={`p-5 rounded-2xl border flex items-center gap-4 ${
            usable.length > 0 ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/10'}`}>
            {usable.length > 0 ? <CheckCircle2 className="text-emerald-400" size={28} /> : <XCircle className="text-red-400" size={28} />}
            <div>
              <p className="text-white font-black">
                {usable.length > 0
                  ? `${usable.length} de ${configured.length} proveedores con cuota aparente`
                  : 'Ningún proveedor con cuota disponible ahora'}
              </p>
              <p className="text-slate-400 text-xs mt-0.5">
                Hoy (UTC): {fmt(callsToday)} llamadas correctas · {fmt(tokensToday)} tokens reportados por los proveedores.
                {usable.length === 0 && ' Los hallazgos con análisis profundo esperan a que se reinicie alguna cuota.'}
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {tiers.map((t, idx) => {
              const st = STATE[t.state] || STATE.revisar
              const pr = probe?.results?.[t.label]
              const h = pr?.headers || {}
              return (
                <div key={t.label} className="bg-[#0F172A] border border-white/5 rounded-2xl p-5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex items-start gap-4">
                      <div className="w-8 h-8 rounded-lg bg-slate-800 text-slate-400 flex items-center justify-center font-black text-xs" title="Orden en la cascada">{idx + 1}</div>
                      <div>
                        <p className="text-white font-bold">{t.provider} <span className="text-slate-500 font-medium text-sm">· {t.model}</span></p>
                        <p className="text-slate-500 text-xs mt-0.5">{t.detail}</p>
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded-lg text-[11px] font-black uppercase tracking-wider border flex items-center gap-1.5 ${st.cls}`}>
                      <st.Icon size={12} /> {st.label}
                    </span>
                  </div>

                  {t.configured && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4 text-xs">
                      <Metric label="Llamadas hoy (OK / fallo)" value={`${fmt(t.ok_today)} / ${fmt(t.fail_today)}`} />
                      <Metric label="Tokens hoy (entrada + salida)"
                        value={`${fmt(t.prompt_tokens_today)} + ${fmt(t.completion_tokens_today)}`}
                        hint={t.ok_calls_without_token_data_today > 0 ? `${t.ok_calls_without_token_data_today} llamadas no reportaron tokens` : null} />
                      <Metric label="Última respuesta correcta" value={when(t.last_ok)} />
                      <Metric label={t.resumes_at ? 'Se reanuda' : 'Último error de cuota'} value={when(t.resumes_at || t.last_quota_error_at)} />
                    </div>
                  )}

                  {t.reference_limit && (
                    <p className="text-[11px] text-slate-500 mt-3">Tope gratuito de referencia (publicado/observado, no medido en la cuenta): {t.reference_limit}</p>
                  )}

                  {pr && (
                    <div className="mt-3 p-3 rounded-xl bg-[#06B6D4]/5 border border-[#06B6D4]/20 text-xs text-slate-300">
                      <p className="font-black text-[#06B6D4] uppercase tracking-widest text-[10px] mb-1">Cuota real (sondeo del proveedor)</p>
                      {pr.error && !h['x-ratelimit-limit-requests'] ? <span className="text-red-300">{pr.error}</span> : null}
                      {h['x-ratelimit-limit-requests'] && (
                        <p>Solicitudes (diarias): quedan <b>{fmt(+h['x-ratelimit-remaining-requests'])}</b> de {fmt(+h['x-ratelimit-limit-requests'])} (reinicia en {h['x-ratelimit-reset-requests']}) ·
                          Tokens/min: quedan <b>{fmt(+h['x-ratelimit-remaining-tokens'])}</b> de {fmt(+h['x-ratelimit-limit-tokens'])}</p>
                      )}
                      {pr.http === 429 && pr.error && <p className="text-red-300 mt-1">{pr.error}</p>}
                      {pr.data?.free_model_daily_requests && (
                        <p>Modelos gratuitos hoy: usadas <b>{fmt(pr.data.free_model_daily_requests.used)}</b> de {fmt(pr.data.free_model_daily_requests.limit)} ·
                          quedan <b>{fmt(pr.data.free_model_daily_requests.remaining)}</b></p>
                      )}
                      {pr.data && (
                        <p>Uso acumulado: {String(pr.data.usage ?? '—')} · Límite: {String(pr.data.limit ?? 'sin límite de créditos')} · Plan gratuito: {String(pr.data.is_free_tier ?? '—')}
                          {pr.data.rate_limit ? ` · Rate limit: ${JSON.stringify(pr.data.rate_limit)}` : ''}</p>
                      )}
                    </div>
                  )}

                  {t.last_error && t.state !== 'disponible' && (
                    <p className="text-[11px] text-red-300/80 mt-3 break-words">Último error ({when(t.last_error.at)}): {t.last_error.text}</p>
                  )}
                </div>
              )
            })}
          </div>

          <div className="text-[11px] text-slate-500 leading-relaxed">
            <p>• <b>Medido por Centinela</b>: llamadas y tokens salen de cada intento real de la cascada. Los días se cuentan en {data.day_basis}</p>
            <p>• <b>Cuota real</b> solo se puede consultar en Groq y OpenRouter. {probe?.not_probeable || 'Gemini, Cloudflare, NVIDIA, Mistral, Cerebras y SambaNova no la exponen por API: ahí se ve lo medido por Centinela y el último error de cuota.'}</p>
            <p>• El historial empieza cuando se desplegó este monitor; antes no se registraba el consumo.</p>
          </div>
        </>
      )}
    </div>
  )
}

function Metric({ label, value, hint }) {
  return (
    <div className="bg-slate-800/40 rounded-xl p-3 border border-white/5">
      <p className="text-slate-500 uppercase tracking-wider text-[10px] font-black mb-1">{label}</p>
      <p className="text-white font-bold">{value}</p>
      {hint && <p className="text-amber-400/80 text-[10px] mt-1">{hint}</p>}
    </div>
  )
}
