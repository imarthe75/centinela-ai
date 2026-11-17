import React, { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { GitBranch, X, RefreshCw } from 'lucide-react'
import { CHANGE_LABELS, rulesHint, short } from './changeState'

// Asset names of GitLab projects: "GitLab/<path>", "GitLab2/<path>", ... and "<that>@<branch>" for a branch audited on its own.
export function parseGitlabAsset(name) {
  const m = /^GitLab(\d*)\/(.+)$/.exec(String(name || ''))
  if (!m) return null
  return { instance: m[1] ? `gitlab${m[1]}` : 'primary', path: m[2].split('@')[0] }
}

export default function BranchScanButton({ assetName, compact = false }) {
  const ref = parseGitlabAsset(assetName)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(null)
  const [msg, setMsg] = useState(null)

  const qc = useQueryClient()
  const branches = useQuery({
    queryKey: ['gitlab-branches', ref?.instance, ref?.path],
    enabled: open && !!ref,
    queryFn: async () => (await axios.get(`/api/gitlab/projects/${ref.path}/branches`, { params: { instance: ref.instance } })).data,
  })

  if (!ref) return null

  const scan = async (branch) => {
    setBusy(branch)
    setMsg(null)
    try {
      const r = (await axios.post(`/api/gitlab/projects/${ref.path}/scan-branch`, null, { params: { branch, instance: ref.instance } })).data
      setMsg({ ok: true, text: r.already_queued
        ? `La rama ya estaba en cola. Resultados en el activo ${r.asset_name}.`
        : `Rama en cola. Cuando termine, sus hallazgos aparecerán como el activo ${r.asset_name}.` })
      qc.invalidateQueries({ queryKey: ['gitlab-branches', ref.instance, ref.path] })
      qc.invalidateQueries({ queryKey: ['gitlab-changes'] })
    } catch (e) {
      setMsg({ ok: false, text: e?.response?.data?.detail || e.message })
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <button
        onClick={() => { setMsg(null); setOpen(true) }}
        title="Elegir una rama de este proyecto GitLab y analizarla como un activo propio"
        className={compact
          ? 'px-3 py-1.5 bg-violet-500/10 text-violet-300 border border-violet-500/30 hover:bg-violet-500 hover:text-white rounded-xl font-bold text-[12px] flex items-center gap-1.5 transition-all'
          : 'px-2.5 py-1.5 rounded-xl text-violet-300 bg-violet-500/10 border border-violet-500/30 hover:bg-violet-500 hover:text-white font-black uppercase text-[10px] tracking-widest flex items-center gap-1.5 transition-all'}
      >
        <GitBranch size={compact ? 13 : 12} /> Ramas
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setOpen(false)}>
          <div className="bg-[#0F172A] border border-slate-700 rounded-2xl w-full max-w-xl max-h-[80vh] overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-1">
              <h3 className="text-white font-bold text-lg">Analizar una rama</h3>
              <button onClick={() => setOpen(false)} className="text-slate-400 hover:text-white"><X size={18} /></button>
            </div>
            <p className="text-slate-400 text-sm mb-4 break-all">{ref.path}</p>
            <p className="text-slate-500 text-xs mb-4">
              Cada rama se analiza como un activo independiente (<span className="font-mono">{ref.path}@rama</span>): sus hallazgos no se mezclan con los del proyecto principal ni con los de otras ramas.
              No se repiten las revisiones del proyecto en sí (configuración de GitLab, evidencia CMMI).
              Solo se puede analizar una rama si su último commit no es el que ya se analizó.
            </p>
            {branches.isLoading && <div className="text-slate-400 text-sm flex items-center gap-2"><RefreshCw size={14} className="animate-spin" /> Consultando ramas en GitLab…</div>}
            {branches.error && <div className="text-red-400 text-sm">{branches.error.response?.data?.detail || branches.error.message}</div>}
            <ul className="space-y-2">
              {(branches.data?.branches || []).map((b) => {
                const lab = CHANGE_LABELS[b.change_state] || CHANGE_LABELS.SIN_VERIFICAR
                const allowed = b.rescan_allowed !== false
                const hint = b.change_state === 'REGLAS_NUEVAS' ? rulesHint(b) : lab.hint
                return (
                  <li key={b.name} className="flex items-center justify-between gap-3 bg-slate-800/50 border border-slate-700 rounded-xl px-3 py-2">
                    <div className="min-w-0">
                      <div className="text-white text-sm font-mono truncate">{b.name}
                        {b.default && <span className="ml-2 text-[10px] text-cyan-300 uppercase">por defecto</span>}
                        {b.protected && <span className="ml-2 text-[10px] text-amber-300 uppercase">protegida</span>}
                        <span className={`ml-2 text-[10px] font-bold px-1.5 py-0.5 rounded border ${lab.cls}`} title={hint}>{lab.text}</span>
                      </div>
                      <div className="text-slate-500 text-[11px]">
                        {b.last_commit_at ? `Último commit: ${new Date(b.last_commit_at).toLocaleString()} (${short(b.commit_sha)})` : ''}
                        {b.last_audit ? ` · Analizado: ${short(b.analyzed_commit)}, ${new Date(b.last_audit).toLocaleString()}` : ' · Sin auditar'}
                      </div>
                    </div>
                    <button
                      disabled={busy !== null || !allowed}
                      onClick={() => scan(b.name)}
                      title={allowed ? 'Analizar el último commit de esta rama' : hint}
                      className="shrink-0 px-3 py-1.5 bg-violet-500/20 text-violet-200 hover:bg-violet-500 hover:text-white rounded-lg text-xs font-bold disabled:opacity-40 disabled:hover:bg-violet-500/20 disabled:hover:text-violet-200 disabled:cursor-not-allowed"
                    >
                      {busy === b.name ? 'Encolando…' : !allowed ? (b.change_state === 'EN_COLA' ? 'En análisis' : 'Sin cambios') : b.last_audit ? 'Re-analizar' : 'Analizar'}
                    </button>
                  </li>
                )
              })}
            </ul>
            {msg && <div className={`mt-4 text-sm ${msg.ok ? 'text-emerald-400' : 'text-red-400'}`}>{msg.text}</div>}
          </div>
        </div>
      )}
    </>
  )
}
