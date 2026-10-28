import { useEffect, useMemo, useRef, useState } from 'react'
import axios from 'axios'
import { ChevronDown, ChevronRight, Download, FileText, Folder, FolderOpen, GitBranch, GitCompare, Loader2, Package, X } from 'lucide-react'
import { useDashboard } from './DashboardContext'

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

// Tree: instance -> groups/subgroups -> projects -> branch assets. Each folder keeps the prefix that selects all its assets.
export function buildGitlabTree(items) {
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
    if (!node.projects.has(p.project)) node.projects.set(p.project, { label: p.project, path: p.path, instance: p.instance, assets: [], vulns: 0 })
    const proj = node.projects.get(p.project)
    proj.assets.push({ ...it, branch: p.branch })
    proj.vulns += Number(it.vulnerability_count || 0)
    for (const n of chain) { n.assets += 1; n.vulns += Number(it.vulnerability_count || 0) }
  }
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
        <span className="text-[11px] text-slate-500">{proj.assets.length} rama(s) · {proj.vulns} hallazgos</span>
        <div className="ml-auto"><GroupActions sel={{ assets: proj.assets.map(a => a.name) }} title={title} onBundle={onBundle} /></div>
      </div>
      {open && proj.assets.map(a => (
        <div key={a.name} className="flex items-center gap-2 py-1.5 pr-2 text-[12px]" style={{ paddingLeft: depth * 18 + 40 }}>
          <GitBranch size={12} className="text-slate-500" />
          <button className="text-[#06B6D4] hover:underline font-bold" onClick={() => handleSelectAsset(a.name)} title="Ver análisis completo">
            {a.branch || '(rama por defecto)'}
          </button>
          <span className="text-slate-500">{a.vulnerability_count} hallazgos</span>
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

function FolderRow({ node, depth, onBundle, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  const folders = [...node.folders.values()].sort((a, b) => a.label.localeCompare(b.label))
  const projects = [...node.projects.values()].sort((a, b) => a.label.localeCompare(b.label))
  const title = node.prefix.replace(/\/$/, '')
  return (
    <div>
      <div className="flex items-center gap-2 py-2 pr-2 border-b border-slate-800/60 hover:bg-slate-800/30 cursor-pointer" style={{ paddingLeft: depth * 18 + 8 }} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={14} className="text-slate-500" /> : <ChevronRight size={14} className="text-slate-500" />}
        {open ? <FolderOpen size={15} className="text-amber-400" /> : <Folder size={15} className="text-amber-400" />}
        <span className={`font-black ${depth === 0 ? 'text-[14px] text-white' : 'text-[13px] text-slate-200'}`}>{node.label}</span>
        <span className="text-[11px] text-slate-500">{node.assets} activo(s) · {node.vulns} hallazgos</span>
        {/* Reports per group/subgroup only: a whole GitLab instance is not a useful unit to report on. */}
        {depth > 0 && <div className="ml-auto"><GroupActions sel={{ prefix: node.prefix }} title={title} onBundle={onBundle} /></div>}
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

export default function GitLabGroupsView() {
  const { processedInventory } = useDashboard()
  const tree = useMemo(() => buildGitlabTree(processedInventory), [processedInventory])
  const [bundles, setBundles] = useState(loadBundles)
  const [err, setErr] = useState(null)

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
    <div className="bg-[#0F172A]/50 rounded-[32px] border border-slate-800 p-4">
      <BundlePanel bundles={bundles} setBundles={setBundles} />
      {err && <div className="mb-3 text-[12px] text-red-400">{err}</div>}
      {!instances.length ? (
        <div className="text-slate-500 text-[13px] p-6">No hay activos de GitLab con los filtros actuales.</div>
      ) : (
        <>
          <p className="text-[11px] text-slate-500 mb-2 px-2">
            Activos de GitLab por instancia, grupo y proyecto. El árbol respeta el buscador y los filtros; los reportes de un grupo incluyen todos sus activos. En cada grupo, subgrupo o proyecto: reporte general consolidado,
            comparativo contra el escaneo anterior, o un ZIP con todos los reportes. El ZIP se arma en segundo plano: un grupo grande tarda varios minutos.
          </p>
          {instances.map(n => <FolderRow key={n.prefix} node={n} depth={0} onBundle={startBundle} defaultOpen />)}
        </>
      )}
    </div>
  )
}
