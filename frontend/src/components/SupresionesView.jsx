import React, { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { ShieldCheck, CheckCircle2, XCircle, RefreshCw, Info, AlertTriangle } from 'lucide-react'

const API_BASE = '/api'

const SEV_STYLE = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
}

const TABS = [
  { key: 'PENDING', label: 'Pendientes de revisión' },
  { key: 'APPROVED', label: 'Aprobadas' },
  { key: 'REJECTED', label: 'Rechazadas' },
  { key: 'CONDITIONAL', label: 'Condicionadas (verificar supuesto)' },
]

export default function SupresionesView({ reviewer = 'analyst' }) {
  const [tab, setTab] = useState('PENDING')
  const [busyId, setBusyId] = useState(null)
  const [actionError, setActionError] = useState(null)
  const [notes, setNotes] = useState({})
  const queryClient = useQueryClient()

  // ADR-0008 #2: TanStack Query. The list depends on the tab; the pending counter is its own query so it stays correct on every tab.
  const list = useQuery({
    queryKey: ['suppressions', tab],
    queryFn: async () => {
      if (tab === 'CONDITIONAL') return (await axios.get(`${API_BASE}/risk-verdicts/conditional`)).data.conditional || []
      return (await axios.get(`${API_BASE}/suppression-proposals`, { params: { status: tab } })).data.proposals || []
    },
  })
  const pending = useQuery({
    queryKey: ['suppressions', 'PENDING'],
    queryFn: async () => (await axios.get(`${API_BASE}/suppression-proposals`, { params: { status: 'PENDING' } })).data.proposals || [],
  })
  const items = list.data ?? []
  const counts = { PENDING: (pending.data ?? []).length }
  const loading = list.isFetching
  const error = actionError || (list.error ? (list.error.response?.data?.detail || list.error.message) : null)
  const load = () => queryClient.invalidateQueries({ queryKey: ['suppressions'] })

  const review = async (id, action) => {
    setBusyId(id)
    setActionError(null)
    try {
      await axios.post(`${API_BASE}/suppression-proposals/${id}/${action}`, {
        reviewer,
        note: notes[id] || null,
      })
      await load()
    } catch (e) {
      setActionError(e?.response?.data?.detail || e.message)
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
            <ShieldCheck className="text-[#06B6D4]" size={28} />
            Revisión de Supresiones Propuestas por IA
          </h2>
          <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">
            Centinela propone descartar hallazgos que revisó y concluyó que no se pueden explotar. Nada se descarta sin tu aprobación.
          </p>
        </div>
        <button
          onClick={load}
          className="bg-[#0F172A] border border-slate-800 text-slate-300 hover:text-white px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin text-[#06B6D4]' : ''} />
          Refrescar
        </button>
      </div>

      <div className="bg-[#1E293B] border border-slate-800 rounded-2xl p-4 flex gap-3 text-xs text-slate-400">
        <Info size={16} className="text-[#06B6D4] shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-slate-200">Aprobar</strong> = estás de acuerdo en que no hay riesgo real: los hallazgos se marcan como suprimidos y
          dejan de contar en dashboard, SLA y reportes. <strong className="text-slate-200">Rechazar</strong> = no estás de acuerdo: los hallazgos vuelven
          a la severidad original de la herramienta y su plazo de SLA se recalcula. Ambas decisiones quedan registradas con tu nombre.
        </p>
      </div>

      <div className="flex gap-2 flex-wrap">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 rounded-xl text-xs font-bold border transition-all ${
              tab === t.key
                ? 'bg-[#06B6D4] text-[#0F172A] border-[#06B6D4]'
                : 'bg-[#0F172A] text-slate-400 border-slate-800 hover:text-white'
            }`}
          >
            {t.label}{t.key === 'PENDING' && counts.PENDING != null ? ` (${counts.PENDING})` : ''}
          </button>
        ))}
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 rounded-xl p-3 text-xs flex items-center gap-2">
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {!loading && items.length === 0 && (
        <div className="bg-[#1E293B] border border-slate-800 rounded-2xl p-10 text-center text-slate-500 text-sm">
          No hay elementos en esta pestaña.
        </div>
      )}

      <div className="space-y-4">
        {items.map((it, idx) => {
          const id = it.id
          const sev = String(it.tool_severity || '').toUpperCase()
          return (
            <div key={id || `${it.asset_name}-${it.cve_id}-${idx}`} className="bg-[#1E293B] border border-slate-800 rounded-2xl p-6">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="space-y-1">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className={`text-[10px] font-black px-2 py-1 rounded border ${SEV_STYLE[sev] || 'bg-slate-500/20 text-slate-400 border-slate-500/30'}`}>
                      Herramienta: {sev || 'N/D'}
                    </span>
                    <span className="text-white font-bold">{it.cve_id}</span>
                    <span className="text-xs text-slate-500">({it.affected_count ?? it.occurrences ?? 1} ocurrencia(s))</span>
                  </div>
                  <p className="text-xs text-slate-400">{it.asset_name}</p>
                </div>
                {it.review_status && it.review_status !== 'PENDING' && (
                  <span className={`text-[10px] font-black px-2 py-1 rounded border ${
                    it.review_status === 'APPROVED'
                      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                      : 'bg-slate-500/20 text-slate-300 border-slate-500/30'
                  }`}>
                    {it.review_status === 'APPROVED' ? 'APROBADA' : 'RECHAZADA'} por {it.reviewed_by}
                  </span>
                )}
              </div>

              <p className="text-sm text-slate-300 mt-4 leading-relaxed whitespace-pre-line">
                <strong className="text-slate-100">Por qué la IA propone descartarlo: </strong>
                {String(it.explanation || it.reason || '').replace(/^Propuesta automática:\s*/, '')}
              </p>

              {Array.isArray(it.sample_locations) && it.sample_locations.filter(Boolean).length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {it.sample_locations.filter(Boolean).map((l) => (
                    <code key={l} className="text-[11px] bg-[#0F172A] border border-slate-800 text-slate-400 px-2 py-1 rounded">{l}</code>
                  ))}
                </div>
              )}

              {it.review_note && (
                <p className="text-xs text-slate-500 mt-3">Nota del revisor: {it.review_note}</p>
              )}

              {tab === 'PENDING' && id && (
                <div className="mt-5 flex items-center gap-3 flex-wrap">
                  <input
                    value={notes[id] || ''}
                    onChange={(e) => setNotes((n) => ({ ...n, [id]: e.target.value }))}
                    placeholder="Nota opcional (por qué apruebas o rechazas)"
                    className="flex-1 min-w-[220px] bg-[#0F172A] border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-[#06B6D4]"
                  />
                  <button
                    disabled={busyId === id}
                    onClick={() => review(id, 'approve')}
                    className="flex items-center gap-2 bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 px-4 py-2 rounded-xl text-xs font-bold disabled:opacity-50"
                  >
                    <CheckCircle2 size={14} /> Aprobar (sin riesgo real)
                  </button>
                  <button
                    disabled={busyId === id}
                    onClick={() => review(id, 'reject')}
                    className="flex items-center gap-2 bg-red-500/20 border border-red-500/40 text-red-300 hover:bg-red-500/30 px-4 py-2 rounded-xl text-xs font-bold disabled:opacity-50"
                  >
                    <XCircle size={14} /> Rechazar (sí hay riesgo)
                  </button>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
