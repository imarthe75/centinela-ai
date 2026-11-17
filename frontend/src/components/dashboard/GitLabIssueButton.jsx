// Creates (or reuses) an issue for a code finding in its own GitLab project: POST /api/remediation/{id}/ticket {target:'gitlab'}.
import { useState } from 'react'
import axios from 'axios'
import { ExternalLink, GitBranch } from 'lucide-react'
import { API_BASE } from './shared'

export default function GitLabIssueButton({ vulnId, assetName }) {
  const [state, setState] = useState({ busy: false })
  if (!/^GitLab\d*\//.test(assetName || '')) return null
  const create = async () => {
    setState({ busy: true })
    try {
      const r = await axios.post(`${API_BASE}/remediation/${vulnId}/ticket`, { target: 'gitlab', title: '', description: '' })
      setState({ url: r.data.url, existed: r.data.status === 'exists' })
    } catch (e) {
      setState({ error: e.response?.data?.detail || e.message })
    }
  }
  if (state.url) {
    return (
      <a href={state.url} target="_blank" rel="noopener noreferrer"
        className="flex-grow py-4 bg-slate-800 text-emerald-400 font-black uppercase text-[12px] tracking-widest rounded-2xl border border-emerald-500/30 flex items-center justify-center gap-2">
        <ExternalLink size={16} /> {state.existed ? 'Ver issue existente' : 'Issue creado'}
      </a>
    )
  }
  return (
    <button onClick={create} disabled={state.busy} title={state.error || 'Crear un issue en el proyecto de GitLab de este hallazgo'}
      className="flex-grow py-4 bg-slate-800 text-slate-300 font-black uppercase text-[12px] tracking-widest rounded-2xl border border-slate-700 hover:bg-slate-700 transition-all flex items-center justify-center gap-2 disabled:opacity-50">
      <GitBranch size={16} /> {state.busy ? 'Creando…' : state.error ? 'Reintentar issue' : 'Crear issue en GitLab'}
      {state.error && <span className="sr-only">Error: {state.error}</span>}
    </button>
  )
}
