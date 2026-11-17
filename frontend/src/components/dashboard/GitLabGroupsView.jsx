import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react'
import axios from 'axios'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, Download, FileText, Folder, FolderOpen, GitBranch, GitCompare, Loader2, Package, RefreshCw, RotateCcw, X } from 'lucide-react'
import { useDashboard } from './DashboardContext'
import { CHANGE_LABELS, countChanges, folderAssetNames, rulesHint, short } from './changeState'

// Change states + "re-analyze changes" action shared by every row of the tree.
const ChangesContext = createContext({ states: {}, startRescan: () => {}, busy: null })

// GitLab assets are named "GitLab[N]/<group>/<subgroup>/.../<project>[@<branch>]" (core/gitlab_instances.py).
export function parseGitlabName(name) {
  const m = /^(GitLab\d*)\/(.+)$/.exec(String(name || ''))
  if (!m) return null
  const at = m[2].indexOf('@')
  const path = at >= 0 ? m[2].slice(0, at) : m[2]
  const branch = at >= 0 ? m[2].slice(at + 1) : null
  const segs = path.split('/')
  return { instance: m[1], path, branch, project: segs[segs.length - 1], groups: segs.slice(0, -1) }
}

// Main branch of a project: the fleet branch GitLab reports (states[name].is_fleet_branch), else the asset with no branch suffix, else
// the branch with most findings. Counting only it (ADR-0019) stops a project with five branches from showing five times its findings.
export function mainBranchAsset(assets, states = {}) {
  return assets.find(a => states[a.name]?.is_fleet_branch) || assets.find(a => !a.branch)
    || [...assets].sort((x, y) => Number(y.vulnerability_count || 0) - Number(x.vulnerability_count || 0))[0]
}

// Tree: instance -> groups/subgroups -> projects -> branch assets. Each folder keeps the prefix that selects all its assets.
export function buildGitlabTree(items, states = {}) {
  const root = new Map()
  const newFolder = (label, prefix) => ({ label, prefix, folders: new Map(), projects: new Map(), assets: 0, vulns: 0 })
  for (const it of items) {
    const p = parseGitlabName(it.name)
    if (!p) continue
    if (!root.has(p.instance)) root.set(p.instance, newFolder(p.instance, `${p.instance}/`))
    let node = root.get(p.instance)
    const chain = [node]
    let prefix = `${p.instance}/`
    for (const g of p.groups) {
      prefix += `${g}/`
      if (!node.folders.has(g)) node.folders.set(g, newFolder(g, prefix))
      node = node.folders.get(g)
      chain.push(node)
    }
    if (!node.projects.has(p.project)) node.projects.set(p.project, { label: p.project, path: p.path, instance: p.instance, assets: [], vulns: 0, chain })
    const proj = node.projects.get(p.project)
    proj.assets.push({ ...it, branch: p.branch })
    for (const n of chain) n.assets += 1
  }
  const visit = (folder) => {
    for (const proj of folder.projects.values()) {
      const main = mainBranchAsset(proj.assets, states)
      proj.main = main?.name
      proj.vulns = Number(main?.vulnerability_count || 0)
      for (const n of proj.chain) n.vulns += proj.vulns
      delete proj.chain
    }
    for (const f of folder.folders.values()) visit(f)
  }
  for (const inst of root.values()) visit(inst)
  return root
}

const BUNDLES_KEY = 'centinela.reportBundles'
const loadBundles = () => { try { return JSON.parse(localStorage.getItem(BUNDLES_KEY) || '[]') } catch { return [] } }
const saveBundles = (b) => { try { localStorage.setItem(BUNDLES_KEY, JSON.stringify(b.slice(0, 10))) } catch { /* per-viewer convenience only */ } }

function selectionQuery(sel, title, format) {
  const q = new URLSearchParams()
  if (sel.prefix) q.set('prefix', sel.prefix)
  for (const a of sel.assets || []) q.append('asset', a)
  q.set('title', title)
  q.set('format', format)
  return q.toString()
}

function ChangeBadges({ names }) {
  const { states } = useContext(ChangesContext)
  const c = countChanges(names, states)
  return (
    <>
      {c.changed > 0 && <span className="text-[10px] font-black uppercase px-1.5 py-0.5 rounded border bg-amber-500/15 text-amber-300 border-amber-400/30"
        title="Activos con commits nuevos desde su último análisis (o ramas aún sin analizar)">{c.changed} con cambios</span>}
      {c.queued > 0 && <span className="text-[10px] font-black uppercase px-1.5 py-0.5 rounded border bg-cyan-500/15 text-cyan-300 border-cyan-400/30">{c.queued} en análisis</span>}
      {c.rules > 0 && <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-slate-500/10 text-slate-400 border-slate-500/30"
        title="El código no cambió pero los detectores sí: la rama del escaneo diario se reanaliza a las 03:00; las ramas elegidas a mano, con su próximo commit">{c.rules} reglas nuevas</span>}
    </>
  )
}

function RescanButton({ sel, names, title, size = 12 }) {
  const { states, startRescan, busy } = useContext(ChangesContext)
  const c = countChanges(names, states)
  if (!c.changed) return null   // only offered when something changed since the last analysis
  return (
    <button className="px-2 py-1 rounded-lg text-[10px] font-black uppercase tracking-wider flex items-center gap-1 transition-all bg-amber-500/15 text-amber-300 hover:bg-amber-500/30 disabled:opacity-50"
      title={`Reanalizar solo los ${c.changed} activo(s) con cambios desde su último análisis`} disabled={busy === title}
      onClick={(e) => { e.stopPropagation(); startRescan(sel, title) }}>
      {busy === title ? <Loader2 size={size} className="animate-spin" /> : <RotateCcw size={size} />} Reanalizar cambios ({c.changed})
    </button>
  )
}

function GroupActions({ sel, title, onBundle, size = 12 }) {
  const { fetchReport } = useDashboard()
  const btn = 'px-2 py-1 rounded-lg text-[10px] font-black uppercase tracking-wider flex items-center gap-1 transition-all'
  return (
    <div className="flex flex-wrap gap-1.5" onClick={e => e.stopPropagation()}>
      <button className={`${btn} bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/25`} title="Reporte general consolidado del grupo (PDF)"
        onClick={() => fetchReport(`/reports/group/general?${selectionQuery(sel, title, 'pdf')}`)}>
        <FileText size={size} /> General
      </button>
      <button className={`${btn} bg-violet-500/10 text-violet-300 hover:bg-violet-500/25`} title="Comparativo del último escaneo vs el anterior para todo el grupo (PDF)"
        onClick={() => fetchReport(`/reports/comparison/group?${selectionQuery(sel, title, 'pdf')}`)}>
        <GitCompare size={size} /> Comparativo
      </button>
      <button className={`${btn} bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/25`}
        title="Paquete ZIP: reporte general del grupo, comparativo y el reporte individual de cada activo"
        onClick={() => onBundle(sel, title)}>
        <Package size={size} /> Todo (ZIP)
      </button>
    </div>
  )
}

function BranchState({ name }) {
  const { states } = useContext(ChangesContext)
  const st = states[name]
  const lab = CHANGE_LABELS[st?.state || 'SIN_VERIFICAR']
  const detail = st ? ` · analizado ${short(st.analyzed_commit)} · en GitLab ${short(st.remote_commit)}` : ''
  const hint = st?.state === 'REGLAS_NUEVAS' ? rulesHint(st) : lab.hint
  return <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${lab.cls}`} title={hint + detail}>{lab.text}</span>
}

function ProjectRow({ proj, depth, onBundle }) {
  const { handleDownloadAssetReport, handleViewAssetReportHtml, handleDownloadComparison, handleSelectAsset } = useDashboard()
  const [open, setOpen] = useState(false)
  const title = `${proj.instance}/${proj.path}`
  return (
    <div className="border-b border-slate-800/60">
      <div className="flex items-center gap-2 py-2 pr-2 hover:bg-slate-800/30 cursor-pointer" style={{ paddingLeft: depth * 18 + 8 }} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={14} className="text-slate-500" /> : <ChevronRight size={14} className="text-slate-500" />}
        <FileText size={14} className="text-slate-400" />
        <span className="text-[13px] font-bold text-slate-200">{proj.label}</span>
        <span className="text-[11px] text-slate-500" title="Hallazgos de la rama principal; las demás ramas muestran sus diferencias">{proj.assets.length} rama(s) · {proj.vulns} hallazgos en la rama principal</span>
        <ChangeBadges names={proj.assets.map(a => a.name)} />
        <div className="ml-auto flex flex-wrap gap-1.5 justify-end">
          <RescanButton sel={{ assets: proj.assets.map(a => a.name) }} names={proj.assets.map(a => a.name)} title={title} />
          <GroupActions sel={{ assets: proj.assets.map(a => a.name) }} title={title} onBundle={onBundle} />
        </div>
      </div>
      {open && proj.assets.map(a => (
        <div key={a.name} className="flex items-center gap-2 py-1.5 pr-2 text-[12px]" style={{ paddingLeft: depth * 18 + 40 }}>
          <GitBranch size={12} className="text-slate-500" />
          <button className="text-[#06B6D4] hover:underline font-bold" onClick={() => handleSelectAsset(a.name)} title="Ver análisis completo">
            {a.branch || '(rama por defecto)'}
          </button>
          <span className="text-slate-500">{a.vulnerability_count} hallazgos</span>
          {a.name === proj.main ? <span className="text-[10px] font-black uppercase text-amber-300">principal</span> : <BranchDiff asset={a.name} />}
          <BranchState name={a.name} />
          <div className="ml-auto flex gap-1.5">
            <button className="px-2 py-1 rounded-lg bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/25 text-[10px] font-black uppercase" title="Reporte general del activo (PDF)"
              onClick={() => handleDownloadAssetReport(a.name)}>PDF</button>
            <button className="px-2 py-1 rounded-lg bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/25 text-[10px] font-black uppercase" title="Reporte general del activo (HTML)"
              onClick={() => handleViewAssetReportHtml(a.name)}>HTML</button>
            <button className="px-2 py-1 rounded-lg bg-violet-500/10 text-violet-300 hover:bg-violet-500/25 text-[10px] font-black uppercase flex items-center gap-1" title="Comparativo vs el escaneo anterior (PDF)"
              onClick={() => handleDownloadComparison(a.name)}><GitCompare size={11} /> Comparativo</button>
          </div>
        </div>
      ))}
    </div>
  )
}

// What a secondary branch adds or no longer has compared with the main branch (GET /api/gitlab/branch-diff), loaded on demand.
function BranchDiff({ asset }) {
  const [state, setState] = useState(null)
  const load = async (e) => {
    e.stopPropagation()
    if (state?.data) { setState({ ...state, open: !state.open }); return }
    setState({ loading: true })
    try {
      setState({ data: (await axios.get('/api/gitlab/branch-diff', { params: { asset } })).data, open: true })
    } catch (err) {
      setState({ error: err.response?.data?.detail || err.message })
    }
  }
  const d = state?.data
  const added = d ? d.only_in_branch.reduce((n, x) => n + x.count, 0) : 0
  const gone = d ? d.only_in_base.reduce((n, x) => n + x.count, 0) : 0
  return (
    <span className="relative">
      <button onClick={load} className="px-2 py-0.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-[10px] font-black uppercase"
        title={state?.error || 'Comparar con la rama principal (por regla y archivo)'}>
        {state?.loading ? '…' : d ? `+${added} / −${gone} vs principal` : state?.error ? 'sin comparación' : 'Diferencias vs principal'}
      </button>
      {d && state.open && (added + gone > 0) && (
        <div className="absolute z-20 mt-1 left-0 w-[520px] max-h-72 overflow-y-auto bg-[#0F172A] border border-slate-700 rounded-xl p-3 text-[11px] shadow-xl"
          onClick={(e) => e.stopPropagation()}>
          <p className="text-slate-400 mb-2">Comparado con <code>{d.base}</code> · {d.common} en común</p>
          {[['Solo en esta rama', d.only_in_branch, 'text-red-300'], ['Ya no está en esta rama', d.only_in_base, 'text-emerald-300']].map(([label, list, cls]) => list.length > 0 && (
            <div key={label} className="mb-2">
              <p className={`font-black ${cls}`}>{label}</p>
              {list.slice(0, 50).map(x => <p key={x.cve_id + x.file} className="text-slate-300 truncate">{x.count}× {x.cve_id} · {x.file}</p>)}
            </div>
          ))}
        </div>
      )}
    </span>
  )
}

function FolderRow({ node, depth, onBundle, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  const folders = [...node.folders.values()].sort((a, b) => a.label.localeCompare(b.label))
  const projects = [...node.projects.values()].sort((a, b) => a.label.localeCompare(b.label))
  const title = node.prefix.replace(/\/$/, '')
  const names = useMemo(() => folderAssetNames(node), [node])
  return (
    <div>
      <div className="flex items-center gap-2 py-2 pr-2 border-b border-slate-800/60 hover:bg-slate-800/30 cursor-pointer" style={{ paddingLeft: depth * 18 + 8 }} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={14} className="text-slate-500" /> : <ChevronRight size={14} className="text-slate-500" />}
        {open ? <FolderOpen size={15} className="text-amber-400" /> : <Folder size={15} className="text-amber-400" />}
        <span className={`font-black ${depth === 0 ? 'text-[14px] text-white' : 'text-[13px] text-slate-200'}`}>{node.label}</span>
        <span className="text-[11px] text-slate-500">{node.assets} activo(s) · {node.vulns} hallazgos</span>
        <ChangeBadges names={names} />
        {/* Reports and re-analysis per group/subgroup only: a whole GitLab instance is not a useful unit. */}
        {depth > 0 && (
          <div className="ml-auto flex flex-wrap gap-1.5 justify-end">
            <RescanButton sel={{ prefix: node.prefix }} names={names} title={title} />
            <GroupActions sel={{ prefix: node.prefix }} title={title} onBundle={onBundle} />
          </div>
        )}
      </div>
      {open && (
        <div>
          {folders.map(f => <FolderRow key={f.prefix} node={f} depth={depth + 1} onBundle={onBundle} />)}
          {projects.map(p => <ProjectRow key={p.path} proj={p} depth={depth + 1} onBundle={onBundle} />)}
        </div>
      )}
    </div>
  )
}

function BundlePanel({ bundles, setBundles }) {
  const { fetchReport } = useDashboard()
  const timer = useRef(null)
  const active = bundles.some(b => b.status === 'queued' || b.status === 'running')

  useEffect(() => {
    if (!active) return undefined
    const poll = async () => {
      const next = await Promise.all(bundles.map(async b => {
        if (b.status !== 'queued' && b.status !== 'running') return b
        try {
          const st = (await axios.get(`/api/reports/group/bundle/${b.id}`)).data
          return { ...b, status: st.status, done: st.done, total: st.total, current: st.current, failed: st.failed?.length || 0, error: st.error }
        } catch (e) {
          return { ...b, status: e?.response?.status === 404 ? 'expired' : b.status }
        }
      }))
      setBundles(next)
      saveBundles(next)
    }
    timer.current = setTimeout(poll, 3000)
    return () => clearTimeout(timer.current)
  }, [bundles, active, setBundles])

  if (!bundles.length) return null
  const remove = (id) => { const n = bundles.filter(b => b.id !== id); setBundles(n); saveBundles(n) }
  return (
    <div className="mb-4 p-3 rounded-2xl border border-emerald-400/20 bg-emerald-500/5 space-y-2">
      <div className="text-[11px] font-black uppercase tracking-widest text-emerald-300">Paquetes de reportes</div>
      {bundles.map(b => (
        <div key={b.id} className="flex items-center gap-3 text-[12px]">
          {(b.status === 'queued' || b.status === 'running') ? <Loader2 size={14} className="animate-spin text-emerald-300" /> : <Package size={14} className="text-emerald-300" />}
          <span className="font-bold text-slate-200 truncate max-w-[40%]" title={b.title}>{b.title}</span>
          <span className="text-slate-400">
            {b.status === 'queued' && 'en cola (hay otro paquete en curso)…'}
            {b.status === 'running' && `${b.done}/${b.total} reportes${b.current ? ` · ${b.current}` : ''}`}
            {b.status === 'done' && `listo · ${b.total} reportes${b.failed ? ` · ${b.failed} con error (ver INDICE.txt)` : ''}`}
            {b.status === 'failed' && `falló: ${b.error || ''}`}
            {b.status === 'interrupted' && 'interrumpido (se reinició el servicio); vuelva a solicitarlo'}
            {b.status === 'expired' && 'expirado (se conservan 24 h)'}
          </span>
          {b.status === 'running' && (
            <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-emerald-400" style={{ width: `${Math.round(100 * (b.done || 0) / (b.total || 1))}%` }} />
            </div>
          )}
          <div className="ml-auto flex gap-2">
            {b.status === 'done' && (
              <button className="px-3 py-1 rounded-lg bg-emerald-500 text-[#0F172A] text-[11px] font-black uppercase flex items-center gap-1"
                onClick={() => fetchReport(`/reports/group/bundle/${b.id}/download`)}><Download size={12} /> Descargar ZIP</button>
            )}
            <button className="text-slate-500 hover:text-white" title="Quitar de la lista" onClick={() => remove(b.id)}><X size={14} /></button>
          </div>
        </div>
      ))}
    </div>
  )
}

const RESCANS_KEY = 'centinela.rescanBatches'
const loadRescans = () => { try { return JSON.parse(localStorage.getItem(RESCANS_KEY) || '[]') } catch { return [] } }
const saveRescans = (b) => { try { localStorage.setItem(RESCANS_KEY, JSON.stringify(b.slice(0, 10))) } catch { /* per-viewer convenience only */ } }

function RescanPanel({ batches, setBatches, onFinished }) {
  const timer = useRef(null)
  const active = batches.some(b => !b.finished && !b.expired)
  useEffect(() => {
    if (!active) return undefined
    const poll = async () => {
      const next = await Promise.all(batches.map(async b => {
        if (b.finished || b.expired) return b
        try {
          const p = (await axios.get(`/api/gitlab/rescan-batch/${b.id}`)).data
          return { ...b, ...p, id: b.id }
        } catch (e) {
          return e?.response?.status === 404 ? { ...b, expired: true } : b
        }
      }))
      setBatches(next)
      saveRescans(next)
      onFinished()            // states move from "en análisis" to "al día" as each asset finishes
    }
    timer.current = setTimeout(poll, 5000)
    return () => clearTimeout(timer.current)
  }, [batches, active, setBatches, onFinished])

  if (!batches.length) return null
  const remove = (id) => { const n = batches.filter(b => b.id !== id); setBatches(n); saveRescans(n) }
  return (
    <div className="mb-4 p-3 rounded-2xl border border-amber-400/20 bg-amber-500/5 space-y-2">
      <div className="text-[11px] font-black uppercase tracking-widest text-amber-300">Reanálisis de cambios</div>
      {batches.map(b => (
        <div key={b.id} className="flex items-center gap-3 text-[12px]">
          {!b.finished && !b.expired ? <Loader2 size={14} className="animate-spin text-amber-300" /> : <RotateCcw size={14} className="text-amber-300" />}
          <span className="font-bold text-slate-200 truncate max-w-[35%]" title={b.title}>{b.title}</span>
          <span className="text-slate-400">
            {b.expired ? 'sin datos del lote' : `${b.percent ?? 0}% · ${(b.done || 0) + (b.failed || 0)}/${b.total || 0} activos`}
            {!b.finished && b.current ? ` · analizando ${b.current.split(':').slice(1).join(':')}` : ''}
            {!b.finished && !b.current && b.queued ? ' · en cola' : ''}
            {b.failed ? ` · ${b.failed} con error` : ''}
            {b.finished ? ' · terminado: ya puede generar los reportes y comparativos' : ''}
          </span>
          <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div className={`h-full ${b.failed ? 'bg-amber-500' : 'bg-emerald-400'}`} style={{ width: `${b.percent || 0}%` }} />
          </div>
          <button className="ml-auto text-slate-500 hover:text-white" title="Quitar de la lista" onClick={() => remove(b.id)}><X size={14} /></button>
        </div>
      ))}
    </div>
  )
}

export default function GitLabGroupsView() {
  const { processedInventory } = useDashboard()
  const changesForTree = useQuery({ queryKey: ['gitlab-changes'], queryFn: async () => (await axios.get('/api/gitlab/changes')).data, staleTime: 60_000 })
  const treeStates = useMemo(() => Object.fromEntries((changesForTree.data?.assets || []).map(a => [a.asset_name, a])), [changesForTree.data])
  const tree = useMemo(() => buildGitlabTree(processedInventory, treeStates), [processedInventory, treeStates])
  const [bundles, setBundles] = useState(loadBundles)
  const [err, setErr] = useState(null)
  const [info, setInfo] = useState(null)
  const [rescans, setRescans] = useState(loadRescans)
  const [busy, setBusy] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const qc = useQueryClient()
  const changes = useQuery({
    queryKey: ['gitlab-changes'],
    queryFn: async () => (await axios.get('/api/gitlab/changes')).data,
    refetchInterval: 60000,
  })
  const states = useMemo(() => Object.fromEntries((changes.data?.assets || []).map(a => [a.asset_name, a])), [changes.data])
  const lastCheck = useMemo(() => (changes.data?.assets || []).reduce((m, a) => (a.checked_at && a.checked_at > m ? a.checked_at : m), ''), [changes.data])
  const refreshStates = useMemo(() => () => qc.invalidateQueries({ queryKey: ['gitlab-changes'] }), [qc])

  const startRescan = async (sel, title) => {
    setErr(null); setInfo(null); setBusy(title)
    try {
      const r = (await axios.post('/api/gitlab/rescan-changed', { prefix: sel.prefix || null, asset: sel.assets || null })).data
      const n = [{ id: r.batch_id, title, total: r.queued.length + r.already_queued.length, percent: 0, done: 0, failed: 0 }, ...rescans]
      setRescans(n); saveRescans(n)
      setInfo(`${title}: ${r.queued.length} activo(s) en cola${r.already_queued.length ? `, ${r.already_queued.length} ya estaban en análisis` : ''}` +
        `${r.skipped.length ? `; ${r.skipped.length} sin cambios no se reanalizan` : ''}.`)
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message)
    } finally {
      setBusy(null); refreshStates()
    }
  }

  const verifyNow = async () => {
    setErr(null); setVerifying(true)
    try {
      const prefixes = [...tree.keys()].map(k => `${k}/`)
      const failed = []
      for (const prefix of prefixes) failed.push(...((await axios.post('/api/gitlab/changes/refresh', { prefix })).data.refresh_failed || []))
      if (failed.length) setErr(`No se pudo consultar GitLab para ${failed.length} proyecto(s): ${failed.slice(0, 3).map(f => f.project).join(', ')}`)
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message)
    } finally {
      setVerifying(false); refreshStates()
    }
  }

  const startBundle = async (sel, title) => {
    setErr(null)
    try {
      const r = (await axios.post('/api/reports/group/bundle', { asset: sel.assets || [], prefix: sel.prefix || null, title })).data
      const n = [{ id: r.bundle_id, title: r.title, status: 'queued', done: 0, total: r.assets + 2 }, ...bundles]
      setBundles(n)
      saveBundles(n)
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message)
    }
  }

  const instances = [...tree.values()].sort((a, b) => a.label.localeCompare(b.label))
  return (
    <ChangesContext.Provider value={{ states, startRescan, busy }}>
    <div className="bg-[#0F172A]/50 rounded-[32px] border border-slate-800 p-4">
      <RescanPanel batches={rescans} setBatches={setRescans} onFinished={refreshStates} />
      <BundlePanel bundles={bundles} setBundles={setBundles} />
      <div className="mb-3 px-2 flex flex-wrap items-center gap-3 text-[11px]">
        <span className="text-slate-400">
          Cambios desde el último análisis{changes.data ? `: ${changes.data.summary?.rescan_allowed || 0} activo(s) con cambios` : ''}
          {lastCheck ? ` · GitLab consultado ${new Date(lastCheck).toLocaleString()}` : ''}
        </span>
        <button className="px-2 py-1 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 font-bold flex items-center gap-1 disabled:opacity-50"
          title="Consultar ahora en GitLab el último commit de cada rama (se actualiza solo cada 15 minutos)" disabled={verifying} onClick={verifyNow}>
          <RefreshCw size={12} className={verifying ? 'animate-spin' : ''} /> {verifying ? 'Consultando GitLab…' : 'Verificar cambios ahora'}
        </button>
      </div>
      {info && <div className="mb-3 text-[12px] text-emerald-300 px-2">{info}</div>}
      {err && <div className="mb-3 text-[12px] text-red-400">{err}</div>}
      {!instances.length ? (
        <div className="text-slate-500 text-[13px] p-6">No hay activos de GitLab con los filtros actuales.</div>
      ) : (
        <>
          <p className="text-[11px] text-slate-500 mb-2 px-2">
            Activos de GitLab por instancia, grupo y proyecto. El árbol respeta el buscador y los filtros; los reportes de un grupo incluyen todos sus activos. En cada grupo, subgrupo o proyecto: reporte general consolidado,
            comparativo contra el escaneo anterior, o un ZIP con todos los reportes. El ZIP se arma en segundo plano: un grupo grande tarda varios minutos.
            «Reanalizar cambios» aparece solo cuando hay ramas con commits nuevos desde su último análisis, y reanaliza únicamente esas; lo que no cambió no se vuelve a escanear.
          </p>
          {instances.map(n => <FolderRow key={n.prefix} node={n} depth={0} onBundle={startBundle} defaultOpen />)}
        </>
      )}
    </div>
    </ChangesContext.Provider>
  )
}
