import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, CircleSlash, FlaskConical, Info, PauseCircle, RefreshCw, Search, ShieldAlert, XCircle } from 'lucide-react'

const API_BASE = '/api'

export const STATUS = {
  PASSED: { label: 'Pasó', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', Icon: CheckCircle2 },
  FAILED: { label: 'Falló', cls: 'bg-red-500/15 text-red-400 border-red-500/30', Icon: XCircle },
  BLOCKED: { label: 'Bloqueado', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30', Icon: PauseCircle },
  NOT_EXECUTED: { label: 'No ejecutado', cls: 'bg-slate-700/40 text-slate-400 border-slate-700', Icon: CircleSlash },
}
const ORDER = ['FAILED', 'BLOCKED', 'NOT_EXECUTED', 'PASSED']
const pct = (v) => (v === null || v === undefined ? '—' : `${v}%`)
const when = (iso) => (iso ? new Date(iso).toLocaleString('es-MX', { hour12: false }) : '—')

// Cases matching the status chip and the free-text search (id, criterion, detail or reason).
export function filterCases(cases, status, text) {
  const q = (text || '').trim().toLowerCase()
  return (cases || []).filter(c => (status === 'ALL' || c.status === status) &&
    (!q || [c.case_id, c.criterion, c.detail, c.reason].some(v => String(v || '').toLowerCase().includes(q))))
}

function Badge({ status }) {
  const s = STATUS[status] || STATUS.NOT_EXECUTED
  return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-lg border text-[11px] font-bold ${s.cls}`}><s.Icon size={12} />{s.label}</span>
}

function Kpi({ label, value, sub, tone = 'text-white' }) {
  return (
    <div className="bg-[#0F172A] border border-slate-800 rounded-2xl px-4 py-3 min-w-[130px]">
      <div className="text-[11px] uppercase tracking-wider text-slate-500 font-bold">{label}</div>
      <div className={`text-2xl font-black ${tone}`}>{value}</div>
      {sub && <div className="text-[11px] text-slate-500">{sub}</div>}
    </div>
  )
}

function CaseRow({ c }) {
  const [open, setOpen] = useState(false)
  const text = c.status === 'PASSED' || c.status === 'FAILED' ? c.detail : (c.reason || c.detail)
  return (
    <>
      <tr className="border-b border-slate-800/70 hover:bg-slate-800/30 cursor-pointer align-top" onClick={() => setOpen(!open)}>
        <td className="py-2 px-3 whitespace-nowrap">
          <span className="inline-flex items-center gap-1 text-slate-200 font-bold">
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}{c.case_id}
          </span>
        </td>
        <td className="py-2 px-3 text-slate-400 text-[12px]">{c.criterion || '—'}</td>
        <td className="py-2 px-3"><Badge status={c.status} /></td>
        <td className="py-2 px-3 text-slate-300 text-[12px]">
          {c.security_relevant && (
            <span className="inline-flex items-center gap-1 mr-2 px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 text-[10px] font-black uppercase" title="Fallo con impacto de seguridad: también se registró como hallazgo">
              <ShieldAlert size={11} /> Seguridad{c.category ? ` · ${c.category}` : ''}
            </span>
          )}
          <span className={open ? '' : 'line-clamp-2'}>{text || '—'}</span>
        </td>
      </tr>
      {open && (
        <tr className="border-b border-slate-800/70 bg-slate-900/40">
          <td colSpan={4} className="px-8 py-3 text-[12px] text-slate-300 space-y-2">
            {c.detail && <div><b className="text-slate-400">Observado:</b> {c.detail}</div>}
            {c.reason && <div><b className="text-slate-400">Motivo:</b> {c.reason}</div>}
            {c.substitution && <div><b className="text-slate-400">Sustitución declarada:</b> {c.substitution}</div>}
            {c.finding && <div><b className="text-slate-400">Hallazgo en Centinela:</b> {c.finding.severity} · estado {c.finding.status}</div>}
            {(c.evidence || []).length > 0 && (
              <div>
                <b className="text-slate-400">Evidencia:</b>
                <ul className="list-disc ml-5 mt-1 space-y-0.5">
                  {c.evidence.map((e, i) => (
                    <li key={i}><span className="text-slate-500">{e.kind}:</span> <code className="text-[11px] text-cyan-300 break-all">{e.value}</code>{e.note ? <span className="text-slate-500"> — {e.note}</span> : null}</li>
                  ))}
                </ul>
                {c.evidence.some(e => e.kind === 'screenshot') && (
                  <div className="text-[11px] text-slate-500 mt-1">Las capturas están en el reporte de la corrida de centinela-smart-tests; aquí solo se registra su nombre.</div>
                )}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

function RunDetail({ runId }) {
  const [status, setStatus] = useState('ALL')
  const [text, setText] = useState('')
  const q = useQuery({ queryKey: ['functional-run', runId], queryFn: async () => (await axios.get(`${API_BASE}/functional-tests/runs/${runId}`)).data })
  const run = q.data
  const cases = useMemo(() => filterCases(run?.cases, status, text), [run, status, text])
  if (q.isLoading) return <div className="p-6 text-slate-500 text-[13px]">Cargando corrida…</div>
  if (q.error) return <div className="p-6 text-red-400 text-[13px]">{q.error.response?.data?.detail || q.error.message}</div>
  const s = run.summary || {}
  const counts = s.counts || {}
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3">
        <Kpi label="Planeados" value={s.planned ?? '—'} sub={s.not_reported ? `${s.not_reported} sin resultado` : 'todos con resultado'} />
        <Kpi label="Ejecutados" value={s.executed ?? '—'} sub={`${pct(s.executed_pct)} de lo planeado`} />
        <Kpi label="Éxito" value={pct(s.pass_rate_over_executed_pct)} sub="pasan ÷ ejecutados" tone="text-emerald-400" />
        <Kpi label="Fallan" value={counts.FAILED ?? 0} tone={counts.FAILED ? 'text-red-400' : 'text-white'} sub={s.security_failures ? `${s.security_failures} con impacto de seguridad` : null} />
        <Kpi label="Bloqueados" value={counts.BLOCKED ?? 0} tone={counts.BLOCKED ? 'text-amber-400' : 'text-white'} sub="no se pudieron correr" />
        <Kpi label="No ejecutados" value={counts.NOT_EXECUTED ?? 0} sub="sin automatizar o fuera de alcance" />
      </div>
      {run.meta?.substitution_notice && (
        <div className="text-[12px] text-amber-300/90 bg-amber-500/5 border border-amber-500/20 rounded-xl px-3 py-2">
          <b>Sustituciones declaradas:</b> {run.meta.substitution_notice}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {['ALL', ...ORDER].map(k => (
          <button key={k} onClick={() => setStatus(k)}
            className={`px-3 py-1.5 rounded-xl text-[11px] font-black uppercase tracking-wider border transition-all ${status === k ? 'bg-[#06B6D4] text-[#0F172A] border-[#06B6D4]' : 'border-slate-700 text-slate-400 hover:text-white'}`}>
            {k === 'ALL' ? `Todos (${run.cases.length})` : `${STATUS[k].label} (${counts[k] ?? 0})`}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2 bg-[#0F172A] px-3 py-1.5 rounded-xl border border-slate-800">
          <Search size={14} className="text-slate-500" />
          <input value={text} onChange={e => setText(e.target.value)} placeholder="Caso, criterio o texto…"
            className="bg-transparent outline-none text-[12px] text-slate-300 w-48" />
        </div>
      </div>
      <div className="overflow-x-auto rounded-2xl border border-slate-800">
        <table className="w-full text-left text-[13px]">
          <thead className="bg-slate-900 text-[11px] uppercase tracking-wider text-slate-500">
            <tr><th className="py-2 px-3">Caso</th><th className="py-2 px-3">Criterio</th><th className="py-2 px-3">Estado</th><th className="py-2 px-3">Resultado / motivo</th></tr>
          </thead>
          <tbody>
            {cases.map(c => <CaseRow key={c.case_id} c={c} />)}
            {!cases.length && <tr><td colSpan={4} className="py-6 text-center text-slate-500 text-[12px]">Ningún caso con este filtro.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

const yesNo = (v) => (v === true ? 'Sí' : v === false ? 'No encontradas' : '—')

// CI test reports (JUnit/JaCoCo) of the projects, read by centinela-smart-tests. Read-only: Centinela never runs the project's tests.
export function CiReports({ reports }) {
  if (!reports?.length) return null
  return (
    <div className="bg-[#0F172A]/50 border border-slate-800 rounded-2xl overflow-hidden">
      <div className="px-4 py-3 text-[11px] uppercase tracking-widest font-black text-slate-500 border-b border-slate-800">
        Reportes de CI ({reports.length})
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12px]">
          <thead className="text-slate-500 text-left">
            <tr>{['Activo / rama', 'Pruebas', 'Fallidas', 'Omitidas', 'Cobertura líneas', 'Cobertura ramas', '401', '403', '409', 'Recibido']
              .map(h => <th key={h} className="px-3 py-2 font-bold">{h}</th>)}</tr>
          </thead>
          <tbody>
            {reports.map(r => (
              <tr key={r.id} className="border-t border-slate-800/70 text-slate-300">
                <td className="px-3 py-2"><div className="font-bold text-slate-100">{r.asset_name}</div>
                  <div className="text-[10px] text-slate-500">{r.ref || '—'}{r.commit_sha ? ` · ${r.commit_sha.slice(0, 8)}` : ''}</div></td>
                <td className="px-3 py-2">{r.tests}</td>
                <td className={`px-3 py-2 font-bold ${r.failures + r.errors ? 'text-red-400' : 'text-emerald-400'}`}>{r.failures + r.errors}</td>
                <td className="px-3 py-2">{r.skipped}</td>
                <td className="px-3 py-2">{pct(r.coverage_line_pct)}</td>
                <td className="px-3 py-2">{pct(r.coverage_branch_pct)}</td>
                {['has_401_tests', 'has_403_tests', 'has_409_tests'].map(k => (
                  <td key={k} className={`px-3 py-2 ${r[k] === false ? 'text-amber-400' : ''}`}>{yesNo(r[k])}</td>))}
                <td className="px-3 py-2 text-slate-500">{when(r.received_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-4 py-2 text-[11px] text-slate-500 border-t border-slate-800">
        Las pruebas de 401/403/409 se detectan por el nombre de la prueba: «No encontradas» significa que ningún nombre las menciona, no que no existan.
      </div>
    </div>
  )
}

export default function PruebasFuncionalesView() {
  const [selected, setSelected] = useState(null)
  const status = useQuery({ queryKey: ['functional-status'], queryFn: async () => (await axios.get(`${API_BASE}/functional-tests/status`)).data, refetchInterval: 60000 })
  const runs = useQuery({ queryKey: ['functional-runs'], queryFn: async () => (await axios.get(`${API_BASE}/functional-tests/runs`)).data, refetchInterval: 60000 })
  const ci = useQuery({ queryKey: ['functional-ci'], queryFn: async () => (await axios.get(`${API_BASE}/functional-tests/ci-reports`)).data, refetchInterval: 60000 })
  const list = runs.data || []
  const current = selected || list[0]?.id || null

  return (
    <div className="space-y-6">
      <div className="flex items-start gap-4">
        <div className="p-3 rounded-2xl bg-[#06B6D4]/10 text-[#06B6D4]"><FlaskConical size={26} /></div>
        <div className="flex-1">
          <h2 className="text-2xl font-black text-white">Pruebas funcionales</h2>
          <p className="text-[13px] text-slate-400 max-w-4xl">
            Corridas de <b>centinela-smart-tests</b> sobre los paquetes de casos de prueba. Solo cuentan como ejecutados los casos que pasaron o
            fallaron (ambos con evidencia); un caso bloqueado o no ejecutado lleva su motivo y no se presenta como aprobado. Los fallos con impacto
            de seguridad, usabilidad o accesibilidad también aparecen como hallazgos en el activo. Abajo, los reportes del CI de cada proyecto.
          </p>
        </div>
        <button onClick={() => { status.refetch(); runs.refetch(); ci.refetch() }} className="p-2 rounded-xl border border-slate-700 text-slate-400 hover:text-white" title="Actualizar">
          <RefreshCw size={16} className={runs.isFetching ? 'animate-spin' : ''} />
        </button>
      </div>

      {status.data && !status.data.ingest_enabled && (
        <div className="flex gap-2 items-start text-[12px] text-amber-300 bg-amber-500/5 border border-amber-500/20 rounded-xl px-3 py-2">
          <AlertTriangle size={15} className="mt-0.5" /> La ingesta está deshabilitada: falta <code>SMART_TESTS_INGEST_TOKEN</code> en el servidor de Centinela.
        </div>
      )}

      {runs.error && <div className="text-red-400 text-[13px]">{runs.error.response?.data?.detail || runs.error.message}</div>}

      {!runs.isLoading && !list.length ? (
        <div className="bg-[#0F172A]/50 border border-slate-800 rounded-2xl p-6 text-[13px] text-slate-400 space-y-2">
          <div className="flex items-center gap-2 text-slate-200 font-bold"><Info size={16} /> Aún no hay corridas registradas.</div>
          <div>
            Para que lleguen aquí, el ejecutor de pruebas necesita <code>SMART_TESTS_INGEST_URL=http://centinela-backend:8000/api/ingest/smart-tests</code> y
            el mismo <code>SMART_TESTS_INGEST_TOKEN</code> que tiene Centinela. Cada corrida se envía completa al terminar.
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(320px,420px)_1fr] gap-6">
          <div className="bg-[#0F172A]/50 border border-slate-800 rounded-2xl overflow-hidden h-fit">
            <div className="px-4 py-3 text-[11px] uppercase tracking-widest font-black text-slate-500 border-b border-slate-800">
              Corridas ({list.length})
            </div>
            {list.map(r => {
              const c = r.summary?.counts || {}
              return (
                <button key={r.id} onClick={() => setSelected(r.id)}
                  className={`w-full text-left px-4 py-3 border-b border-slate-800/70 transition-all ${current === r.id ? 'bg-[#06B6D4]/10' : 'hover:bg-slate-800/40'}`}>
                  <div className="flex items-center gap-2">
                    <span className="font-black text-slate-100 text-[13px]">{r.project}</span>
                    <span className="text-[11px] text-slate-500 truncate">{r.package}</span>
                  </div>
                  <div className="text-[11px] text-slate-500">{r.cycle || 'sin ciclo'} · {r.started || '?'} → {r.finished || '?'}</div>
                  <div className="flex gap-2 mt-1.5 text-[11px] font-bold">
                    <span className="text-emerald-400">{c.PASSED ?? 0} pasan</span>
                    <span className="text-red-400">{c.FAILED ?? 0} fallan</span>
                    <span className="text-amber-400">{c.BLOCKED ?? 0} bloq.</span>
                    <span className="text-slate-400">{c.NOT_EXECUTED ?? 0} no ejec.</span>
                    <span className="ml-auto text-slate-300">éxito {pct(r.summary?.pass_rate_over_executed_pct)}</span>
                  </div>
                  <div className="text-[10px] text-slate-600 mt-1">recibida {when(r.updated_at || r.received_at)}{r.asset_name ? ` · ${r.asset_name}` : ''}</div>
                </button>
              )
            })}
          </div>
          <div>{current && <RunDetail runId={current} />}</div>
        </div>
      )}

      <CiReports reports={ci.data} />
    </div>
  )
}
