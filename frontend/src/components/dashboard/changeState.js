// Change state of GitLab assets since their last analysis (backend: core/change_detection.py, GET /api/gitlab/changes).
// A manual re-analysis is only offered for code changes (CAMBIOS) or never-analyzed branches (SIN_ANALISIS): re-scanning code that did
// not change spends scanner time and AI tokens for nothing. New detector rules (REGLAS_NUEVAS) reach the daily branch at 03:00 (see rulesHint).

export const CHANGE_LABELS = {
  CAMBIOS: { text: 'Con cambios', cls: 'bg-amber-500/15 text-amber-300 border-amber-400/30', hint: 'Hay commits nuevos desde el último análisis' },
  SIN_ANALISIS: { text: 'Sin analizar', cls: 'bg-amber-500/15 text-amber-300 border-amber-400/30', hint: 'Esta rama todavía no tiene un análisis con commit registrado' },
  REGLAS_NUEVAS: { text: 'Reglas nuevas', cls: 'bg-slate-500/15 text-slate-300 border-slate-400/30', hint: 'El código no cambió, pero los detectores sí desde su último análisis' },
  AL_DIA: { text: 'Al día', cls: 'bg-emerald-500/10 text-emerald-300 border-emerald-400/30', hint: 'El último commit ya está analizado' },
  EN_COLA: { text: 'En análisis', cls: 'bg-cyan-500/15 text-cyan-300 border-cyan-400/30', hint: 'Hay un análisis de este activo en cola o en curso' },
  RAMA_ELIMINADA: { text: 'Rama eliminada', cls: 'bg-red-500/10 text-red-300 border-red-400/30', hint: 'La rama ya no existe en GitLab' },
  SIN_VERIFICAR: { text: 'Sin verificar', cls: 'bg-slate-700/40 text-slate-400 border-slate-600', hint: 'Todavía no se consultó GitLab para esta rama' },
}

// Where an asset whose code did not change picks up new detector rules: the project's daily branch at 03:00; a branch chosen by hand
// is not part of the daily run, so it is re-analyzed with its next commit.
export const rulesHint = (st) => (st?.is_fleet_branch
  ? 'El código no cambió, pero los detectores sí: esta rama se reanaliza en el escaneo diario de las 03:00'
  : 'El código no cambió, pero los detectores sí. Esta rama no entra al escaneo diario: se reanalizará cuando tenga commits nuevos')

// Assets eligible for a manual re-analysis.
export const isRescannable = (st) => !!st && (st.state === 'CAMBIOS' || st.state === 'SIN_ANALISIS')

// Counts of a set of asset names given the {asset_name: state} map.
export function countChanges(names, states) {
  const c = { changed: 0, queued: 0, rules: 0, unverified: 0, total: 0 }
  for (const n of names) {
    const st = states[n]
    c.total += 1
    if (!st) { c.unverified += 1; continue }
    if (isRescannable(st)) c.changed += 1
    else if (st.state === 'EN_COLA') c.queued += 1
    else if (st.state === 'REGLAS_NUEVAS') c.rules += 1
    else if (st.state === 'SIN_VERIFICAR') c.unverified += 1
  }
  return c
}

// Every asset name below a tree folder (folders + projects, recursively).
export function folderAssetNames(node) {
  const out = []
  for (const p of node.projects.values()) for (const a of p.assets) out.push(a.name)
  for (const f of node.folders.values()) out.push(...folderAssetNames(f))
  return out
}

export const short = (sha) => (sha ? String(sha).slice(0, 8) : '—')
