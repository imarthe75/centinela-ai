// Per-project data access (ADR-0019): which assets each user or Authentik group may see. Admins only.
import { useEffect, useState } from 'react'
import axios from 'axios'
import { Lock, Plus, Trash2 } from 'lucide-react'
import { API_BASE } from './shared'

const EMPTY = { subject_type: 'group', subject: '', asset_prefix: '', note: '' }

export default function AccessScopesPanel() {
  const [data, setData] = useState({ scopes: [], default_policy: 'all' })
  const [form, setForm] = useState(EMPTY)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => axios.get(`${API_BASE}/access-scopes`)
    .then((r) => setData({ scopes: Array.isArray(r.data?.scopes) ? r.data.scopes : [], default_policy: r.data?.default_policy || 'all' }))
    .catch((e) => setMsg({ ok: false, text: e.response?.data?.detail || e.message }))
  useEffect(() => { load() }, [])

  const add = async (e) => {
    e.preventDefault()
    setBusy(true)
    try {
      const r = await axios.post(`${API_BASE}/access-scopes`, form)
      setMsg({ ok: true, text: `Alcance otorgado: ${r.data.asset_prefix} (${r.data.matching_assets} activos hoy).` })
      setForm(EMPTY)
      await load()
    } catch (err) {
      setMsg({ ok: false, text: err.response?.data?.detail?.toString?.() || err.message })
    } finally {
      setBusy(false)
    }
  }
  const remove = async (s) => {
    if (!window.confirm(`¿Retirar a ${s.subject} el acceso a ${s.asset_prefix}?`)) return
    try {
      await axios.delete(`${API_BASE}/access-scopes/${s.id}`)
      await load()
    } catch (err) {
      setMsg({ ok: false, text: err.response?.data?.detail || err.message })
    }
  }

  return (
    <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 mt-8">
      <h3 className="text-white font-bold text-xl mb-1 flex items-center gap-2"><Lock size={18} className="text-[#06B6D4]" /> Alcance de datos por proyecto</h3>
      <p className="text-xs text-slate-400 mb-4 leading-relaxed">
        Limita qué activos ve un usuario o un grupo de Authentik. Un prefijo cubre sus subproyectos y ramas
        (<code>GitLab2/grupo-a/proyecto-a</code> incluye <code>GitLab2/grupo-a/proyecto-a/backend/…@rama</code>). Los administradores ven todo.
        Quien no tiene ningún alcance asignado {data.default_policy === 'all' ? 've todos los proyectos (política actual: sin restricción por omisión)' : 'no ve ningún proyecto'}.
      </p>
      <form onSubmit={add} className="grid grid-cols-1 md:grid-cols-5 gap-3 mb-4">
        <select value={form.subject_type} onChange={(e) => setForm({ ...form, subject_type: e.target.value })}
          className="bg-[#0F172A] border border-slate-700 rounded-xl px-3 py-2 text-sm text-white" aria-label="Tipo de sujeto">
          <option value="group">Grupo de Authentik</option>
          <option value="user">Usuario</option>
        </select>
        <input required value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })}
          placeholder={form.subject_type === 'group' ? 'Nombre del grupo' : 'Usuario o correo'} aria-label="Sujeto"
          className="bg-[#0F172A] border border-slate-700 rounded-xl px-3 py-2 text-sm text-white" />
        <input required value={form.asset_prefix} onChange={(e) => setForm({ ...form, asset_prefix: e.target.value })}
          placeholder="Prefijo de activo (GitLab2/grupo-a/proyecto-a)" aria-label="Prefijo de activo"
          className="md:col-span-2 bg-[#0F172A] border border-slate-700 rounded-xl px-3 py-2 text-sm text-white" />
        <button type="submit" disabled={busy}
          className="flex items-center justify-center gap-2 bg-[#06B6D4] text-white font-bold text-sm rounded-xl px-3 py-2 disabled:opacity-50">
          <Plus size={14} /> Otorgar
        </button>
      </form>
      {msg && <p className={`text-sm mb-3 ${msg.ok ? 'text-emerald-400' : 'text-red-400'}`} role="status">{msg.text}</p>}
      <table className="w-full text-sm">
        <thead><tr className="text-left text-[11px] uppercase tracking-widest text-slate-500">
          <th className="py-2">Sujeto</th><th>Prefijo</th><th>Otorgó</th><th>Fecha</th><th className="sr-only">Acciones</th>
        </tr></thead>
        <tbody>
          {data.scopes.length === 0 && <tr><td colSpan={5} className="py-3 text-slate-500">Sin alcances asignados: nadie está restringido.</td></tr>}
          {data.scopes.map((s) => (
            <tr key={s.id} className="border-t border-slate-800 text-slate-300">
              <td className="py-2">{s.subject_type === 'group' ? 'Grupo' : 'Usuario'}: <b className="text-white">{s.subject}</b></td>
              <td><code>{s.asset_prefix}</code></td>
              <td>{s.created_by || '—'}</td>
              <td>{(s.created_at || '').slice(0, 10)}</td>
              <td className="text-right">
                <button onClick={() => remove(s)} className="text-red-400 hover:text-red-300 p-1" aria-label={`Retirar alcance ${s.asset_prefix} de ${s.subject}`}>
                  <Trash2 size={14} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
