import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { KeyRound, Trash2, X, Plus, Lock } from 'lucide-react'

const KINDS = [['user', 'Usuario'], ['admin', 'Administrador'], ['readonly', 'Solo lectura']]
const OTHER = '__other__'
const input = 'w-full bg-[#0F172A] border border-slate-700 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-indigo-400'
const label = 'text-[11px] text-slate-500 font-black uppercase tracking-wider block mb-1'

function originOf(u) {
  try { return new URL(u).origin } catch { return '' }
}

function errText(e) {
  return e?.response?.data?.detail || e?.message || 'Error desconocido'
}

function Modal({ assetName, onClose }) {
  const q = useQuery({
    queryKey: ['test-credentials', assetName],
    queryFn: async () => (await axios.get('/api/test-credentials', { params: { asset_name: assetName } })).data,
  })
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)
  const [cfg, setCfg] = useState(null)       // editable copy of the application config
  const [sourceQ, setSourceQ] = useState('')
  const candidates = useQuery({
    queryKey: ['test-credentials-candidates', sourceQ],
    queryFn: async () => (await axios.get('/api/test-credentials/candidates', { params: { q: sourceQ, limit: 12 } })).data,
  })
  const [form, setForm] = useState({ profile: '', other: '', kind: 'user', username: '', password: '' })
  const [extra, setExtra] = useState([])        // profiles read from the OpenAPI document

  const data = q.data
  const editable = cfg || (data && {
    base_url: data.config.base_url || (data.asset_type === 'URL' ? originOf(assetName) : ''),
    login: { url: '', method: 'POST', body: 'json', username_field: 'username', password_field: 'password', token_json_path: 'access_token', ...(data.config.app_login || {}) },
    sources: data.config.source_assets || [],
    ui: { url: /login/i.test(assetName) && /^https?:/.test(assetName) ? assetName : '', routes: [], ...(data.config.login_ui || {}) },
    authz: { endpoints: [], openapi_url: '', admin_only: [], ...(data.config.authz || {}) },
  })

  const run = async (fn, ok) => {
    setBusy(true); setMsg(null)
    try { await fn(); setMsg({ ok: true, text: ok }); await q.refetch() }
    catch (e) { setMsg({ ok: false, text: errText(e) }) }
    finally { setBusy(false) }
  }

  const saveConfig = () => run(() => axios.put('/api/test-credentials/config', {
    asset_name: assetName, base_url: editable.base_url, app_login: editable.login, source_assets: editable.sources,
    login_ui: editable.ui, authz: editable.authz,
  }), 'Configuración guardada')

  const saveRole = () => {
    const role = form.profile === OTHER ? form.other.trim() : form.profile
    return run(async () => {
      await axios.put('/api/test-credentials/role', { asset_name: assetName, role, username: form.username, password: form.password, kind: form.kind })
      setForm({ profile: '', other: '', kind: 'user', username: '', password: '' })
    }, `Credencial del perfil «${role}» guardada en Vault`)
  }

  const readOpenapi = () => run(async () => {
    const r = (await axios.get('/api/test-credentials/openapi-profiles', { params: { asset_name: assetName, url: editable.authz.openapi_url || undefined } })).data
    setExtra(r.profiles)
  }, 'Perfiles leídos del documento OpenAPI')

  const removeRole = (role) => run(() => axios.delete('/api/test-credentials/role', { params: { asset_name: assetName, role } }), `Perfil «${role}» eliminado`)
  const editRole = (r) => setForm({ profile: (data.profiles || []).some(p => p.role.toLowerCase() === r.name.toLowerCase()) ? data.profiles.find(p => p.role.toLowerCase() === r.name.toLowerCase()).role : OTHER, other: r.name, kind: r.kind, username: r.username, password: '' })

  const lines = (v) => (v || '').split('\n')
  const setUi = (k, v) => setCfg({ ...editable, ui: { ...editable.ui, [k]: v } })
  const setAuthz = (k, v) => setCfg({ ...editable, authz: { ...editable.authz, [k]: v } })
  const testLogin = (role) => run(async () => {
    const r = (await axios.post('/api/test-credentials/test-login', null, { params: { asset_name: assetName, role } })).data
    if (!r.ok) throw new Error(r.detail)
  }, `Inicio de sesión del perfil «${role}»: se obtuvo un token`)
  const setLogin = (k, v) => setCfg({ ...editable, login: { ...editable.login, [k]: v } })
  const addSource = (name) => !editable.sources.includes(name) && setCfg({ ...editable, sources: [...editable.sources, name] })
  const dropSource = (name) => setCfg({ ...editable, sources: editable.sources.filter(s => s !== name) })

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md">
      <div className="bg-[#1E293B] w-full max-w-3xl max-h-[92vh] rounded-[32px] border border-slate-800 shadow-2xl overflow-hidden flex flex-col">
        <div className="p-6 border-b border-slate-800 flex justify-between items-center shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-2xl bg-amber-400/10 border border-amber-400/20 flex items-center justify-center text-amber-400"><Lock size={20} /></div>
            <div>
              <h3 className="text-white font-bold text-lg">Credenciales de prueba por perfil</h3>
              <p className="text-[11px] text-amber-400/70 font-black uppercase tracking-widest break-all">{assetName}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white"><X size={26} /></button>
        </div>

        <div className="p-6 overflow-y-auto space-y-6 text-xs">
          {q.isLoading && <p className="text-slate-400">Cargando…</p>}
          {q.isError && <p className="text-red-400">No se pudo leer la configuración: {errText(q.error)}</p>}
          {data && editable && (<>
            <p className="text-slate-400 leading-relaxed">
              Con estas credenciales Centinela inicia sesión como cada perfil y comprueba qué puede ver o hacer cada uno (control de acceso y datos personales expuestos).
              Usa cuentas <b className="text-white">de pruebas</b> del ambiente de QA. Las contraseñas se guardan <b className="text-white">solo en Vault</b> y no se vuelven a mostrar.
            </p>

            <section className="space-y-3">
              <h4 className="text-white font-black uppercase tracking-wider text-[11px]">1. Aplicativo</h4>
              <div className="grid grid-cols-2 gap-3">
                <div className="col-span-2"><span className={label}>URL base del aplicativo o de su API</span>
                  <input className={input} value={editable.base_url} onChange={e => setCfg({ ...editable, base_url: e.target.value })} placeholder="http://servidor/api" /></div>
                <div className="col-span-2"><span className={label}>URL del inicio de sesión (API)</span>
                  <input className={input} value={editable.login.url || ''} onChange={e => setLogin('url', e.target.value)} placeholder="http://servidor/api/auth/login" /></div>
                <div><span className={label}>Método</span>
                  <select className={input} value={editable.login.method} onChange={e => setLogin('method', e.target.value)}><option>POST</option><option>PUT</option></select></div>
                <div><span className={label}>Formato del cuerpo</span>
                  <select className={input} value={editable.login.body} onChange={e => setLogin('body', e.target.value)}><option value="json">JSON</option><option value="form">Formulario</option></select></div>
                <div><span className={label}>Campo del usuario</span><input className={input} value={editable.login.username_field} onChange={e => setLogin('username_field', e.target.value)} /></div>
                <div><span className={label}>Campo de la contraseña</span><input className={input} value={editable.login.password_field} onChange={e => setLogin('password_field', e.target.value)} /></div>
                <div><span className={label}>Encabezado de la respuesta con el token (si no viene en el cuerpo)</span>
                  <input className={input} value={editable.login.token_header || ''} onChange={e => setLogin('token_header', e.target.value)} placeholder="Authorization" /></div>
                <div><span className={label}>O bien, ruta JSON del token en el cuerpo</span>
                  <input className={input} value={editable.login.token_json_path} onChange={e => setLogin('token_json_path', e.target.value)} placeholder="access_token  ·  data.token" /></div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="col-span-2"><span className={label}>Pantalla de inicio de sesión (la que ve el usuario en el navegador)</span>
                  <input className={input} value={editable.ui.url || ''} onChange={e => setUi('url', e.target.value)} placeholder="http://servidor/app/auth/login" /></div>
                <div className="col-span-2"><span className={label}>Rutas a visitar después de entrar (una URL por línea)</span>
                  <textarea rows={3} className={input} value={(editable.ui.routes || []).join('\n')} onChange={e => setUi('routes', lines(e.target.value))} placeholder="http://servidor/app/bandeja" /></div>
                <div className="col-span-2"><span className={label}>Endpoints de la API a comparar entre perfiles (una ruta por línea, relativa a la URL base)</span>
                  <textarea rows={3} className={input} value={(editable.authz.endpoints || []).join('\n')} onChange={e => setAuthz('endpoints', lines(e.target.value))} placeholder="/usuario/servidor-publico/1" /></div>
                <div><span className={label}>URL de OpenAPI/Swagger (opcional)</span>
                  <input className={input} value={editable.authz.openapi_url || ''} onChange={e => setAuthz('openapi_url', e.target.value)} placeholder="http://servidor/v3/api-docs" />
                  <button disabled={busy || !editable.authz.openapi_url} onClick={readOpenapi} className="mt-2 px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:text-white disabled:opacity-40">Leer perfiles del OpenAPI</button></div>
                <div><span className={label}>Rutas solo para administradores (una por línea)</span>
                  <textarea rows={2} className={input} value={(editable.authz.admin_only || []).join('\n')} onChange={e => setAuthz('admin_only', lines(e.target.value))} placeholder="*/admin/*" /></div>
              </div>

              <div>
                <span className={label}>Repositorios relacionados de donde obtener la lista de perfiles (opcional: un aplicativo sin código en el inventario no los necesita)</span>
                <div className="flex flex-wrap gap-2 mb-2">
                  {editable.sources.map(s => (
                    <span key={s} className="px-2 py-1 rounded-lg bg-indigo-500/10 border border-indigo-400/20 text-indigo-300 flex items-center gap-1 break-all">
                      {s}<button onClick={() => dropSource(s)} title="Quitar"><X size={12} /></button></span>))}
                  {!editable.sources.length && <span className="text-slate-600">Ninguno. Si este activo es un repositorio, se usa su propio código; si es una URL o un endpoint, puedes escribir los perfiles a mano.</span>}
                </div>
                <input className={input} value={sourceQ} onChange={e => setSourceQ(e.target.value)} placeholder="Buscar un repositorio (por ejemplo, el backend del aplicativo)…" />
                <div className="mt-2 max-h-28 overflow-y-auto space-y-1">
                  {(candidates.data || []).map(c => (
                    <button key={c.asset_name} onClick={() => addSource(c.asset_name)} className="w-full text-left px-2 py-1 rounded-lg hover:bg-slate-700/40 text-slate-300 flex justify-between gap-3">
                      <span className="break-all">{c.asset_name}</span><span className="text-slate-500 shrink-0">{c.profiles} perfiles</span></button>))}
                </div>
              </div>
              <button disabled={busy} onClick={saveConfig} className="px-4 py-2 rounded-xl bg-indigo-500/20 border border-indigo-400/30 text-indigo-200 font-black uppercase tracking-wider text-[11px] disabled:opacity-50">Guardar configuración</button>
            </section>

            <section className="space-y-3">
              <h4 className="text-white font-black uppercase tracking-wider text-[11px]">2. Perfiles con credenciales ({data.config.roles.length})</h4>
              {!data.config.roles.length && <p className="text-slate-600">Aún no hay credenciales guardadas.</p>}
              {data.config.roles.map(r => (
                <div key={r.name} className="flex items-center justify-between gap-3 bg-[#0F172A] border border-slate-800 rounded-xl px-3 py-2">
                  <div className="min-w-0"><span className="text-white font-bold">{r.name}</span> <span className="text-slate-500">· {KINDS.find(k => k[0] === r.kind)?.[1] || r.kind}</span>
                    <div className="text-slate-400 break-all">{r.username} · {r.has_password ? 'contraseña guardada' : 'sin contraseña'}</div></div>
                  <div className="flex gap-2 shrink-0">
                    <button disabled={busy} onClick={() => testLogin(r.name)} title="Intenta el inicio de sesión de la API con esta credencial" className="px-2 py-1 rounded-lg border border-emerald-400/20 text-emerald-300 hover:bg-emerald-500/10">Probar</button>
                    <button onClick={() => editRole(r)} className="px-2 py-1 rounded-lg border border-slate-700 text-slate-300 hover:text-white">Editar</button>
                    <button disabled={busy} onClick={() => removeRole(r.name)} title="Eliminar" className="p-1.5 rounded-lg border border-red-400/20 text-red-400 hover:bg-red-500/10"><Trash2 size={14} /></button>
                  </div>
                </div>))}

              <div className="bg-[#0F172A]/60 border border-slate-800 rounded-2xl p-4 space-y-3">
                <span className="text-white font-black uppercase tracking-wider text-[11px] flex items-center gap-2"><Plus size={13} /> Agregar o editar un perfil</span>
                <div className="grid grid-cols-2 gap-3">
                  <div><span className={label}>Perfil</span>
                    <select className={input} value={form.profile} onChange={e => setForm({ ...form, profile: e.target.value })}>
                      <option value="">Selecciona un perfil…</option>
                      {[...(data.profiles || []), ...extra.filter(x => !(data.profiles || []).some(p => p.role.toLowerCase() === x.role.toLowerCase()))].map(p => <option key={p.role + p.source} value={p.role}>{p.role} · {p.source}</option>)}
                      <option value={OTHER}>Otro (escribir el nombre)…</option>
                    </select>
                    {!data.profiles.length && !extra.length && <p className="text-slate-600 mt-1">No hay perfiles conocidos para este activo (no tiene código en el inventario). Lee el OpenAPI, elige un repositorio relacionado arriba o elige «Otro» y escribe el nombre.</p>}
                  </div>
                  <div><span className={label}>Tipo de cuenta</span>
                    <select className={input} value={form.kind} onChange={e => setForm({ ...form, kind: e.target.value })}>{KINDS.map(k => <option key={k[0]} value={k[0]}>{k[1]}</option>)}</select></div>
                  {form.profile === OTHER && <div className="col-span-2"><span className={label}>Nombre del perfil</span><input className={input} value={form.other} onChange={e => setForm({ ...form, other: e.target.value })} /></div>}
                  <div><span className={label}>Usuario</span><input className={input} autoComplete="off" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} /></div>
                  <div><span className={label}>Contraseña</span><input className={input} type="password" autoComplete="new-password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} placeholder="(sin cambios al editar)" /></div>
                </div>
                <button disabled={busy || !form.profile || !form.username} onClick={saveRole} className="px-4 py-2 rounded-xl bg-amber-500/20 border border-amber-400/30 text-amber-200 font-black uppercase tracking-wider text-[11px] disabled:opacity-40">Guardar en Vault</button>
              </div>
            </section>
          </>)}
          {msg && <p className={msg.ok ? 'text-emerald-400' : 'text-red-400'}>{msg.text}</p>}
        </div>
      </div>
    </div>
  )
}

export default function TestCredentialsButton({ assetName, compact = false }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)} title="Credenciales de prueba por perfil del aplicativo (se guardan en Vault)"
        className={compact ? 'px-2 py-1 rounded-lg text-amber-400 border border-amber-400/20 hover:bg-amber-500/10 flex items-center gap-1 text-[11px] font-black uppercase' : 'p-2 -m-2 rounded-xl text-slate-500 hover:text-amber-400 hover:bg-amber-500/10 transition-all'}>
        <KeyRound size={compact ? 13 : 16} />{compact && 'Perfiles'}
      </button>
      {open && <Modal assetName={assetName} onClose={() => setOpen(false)} />}
    </>
  )
}
