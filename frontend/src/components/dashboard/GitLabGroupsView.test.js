import { describe, it, expect } from 'vitest'
import { buildGitlabTree, parseGitlabName } from './GitLabGroupsView'

describe('parseGitlabName', () => {
  it('splits instance, groups, project and branch', () => {
    expect(parseGitlabName('GitLab2/grupo-b/proyecto-e/proyecto-e-web@develop-vulneravilidades')).toEqual({
      instance: 'GitLab2', path: 'grupo-b/proyecto-e/proyecto-e-web', branch: 'develop-vulneravilidades', project: 'proyecto-e-web', groups: ['grupo-b', 'proyecto-e'],
    })
    expect(parseGitlabName('GitLab/proyecto-g/backend-proyecto-g').branch).toBeNull()
    expect(parseGitlabName('proyecto-e-Deploy (192.0.2.10)')).toBeNull()
  })
})

describe('buildGitlabTree', () => {
  it('groups branches under their project and keeps a selecting prefix per folder', () => {
    const tree = buildGitlabTree([
      { name: 'GitLab2/grupo-b/proyecto-e/proyecto-e-web@develop', vulnerability_count: 3 },
      { name: 'GitLab2/grupo-b/proyecto-e/proyecto-e-web@develop-vulneravilidades', vulnerability_count: 2 },
      { name: 'GitLab2/grupo-b/proyecto-e/proyecto-e-backend@develop', vulnerability_count: 1 },
      { name: 'GitLab/proyecto-g/backend-proyecto-g', vulnerability_count: 5 },
      { name: 'Servidor X', vulnerability_count: 9 },
    ])
    expect([...tree.keys()].sort()).toEqual(['GitLab', 'GitLab2'])
    const g2 = tree.get('GitLab2')
    expect(g2.assets).toBe(3)
    expect(g2.vulns).toBe(4)   // main branch only: proyecto-e-web counts its biggest branch (3), not both (5)
    const proyecto-e = g2.folders.get('grupo-b').folders.get('proyecto-e')
    expect(proyecto-e.prefix).toBe('GitLab2/grupo-b/proyecto-e/')
    expect(proyecto-e.projects.get('proyecto-e-web').assets.map(a => a.branch)).toEqual(['develop', 'develop-vulneravilidades'])
    expect(tree.get('GitLab').projects.size).toBe(0)
    expect(tree.get('GitLab').folders.get('proyecto-g').projects.get('backend-proyecto-g').vulns).toBe(5)
  })
  it('counts the fleet branch reported by GitLab as the main branch', () => {
    const items = [{ name: 'GitLab2/g/app@develop', vulnerability_count: 9 }, { name: 'GitLab2/g/app@main', vulnerability_count: 2 }]
    const tree = buildGitlabTree(items, { 'GitLab2/g/app@main': { is_fleet_branch: true } })
    const app = tree.get('GitLab2').folders.get('g').projects.get('app')
    expect(app.main).toBe('GitLab2/g/app@main')
    expect(app.vulns).toBe(2)
    expect(tree.get('GitLab2').vulns).toBe(2)
  })
})

describe('change states', async () => {
  const { countChanges, folderAssetNames, isRescannable } = await import('./changeState')
  it('only code changes and never-analyzed branches can be re-analyzed by hand', () => {
    expect(isRescannable({ state: 'CAMBIOS' })).toBe(true)
    expect(isRescannable({ state: 'SIN_ANALISIS' })).toBe(true)
    for (const s of ['AL_DIA', 'REGLAS_NUEVAS', 'EN_COLA', 'RAMA_ELIMINADA', 'SIN_VERIFICAR']) expect(isRescannable({ state: s })).toBe(false)
    expect(isRescannable(undefined)).toBe(false)
  })
  it('counts a folder recursively', () => {
    const tree = buildGitlabTree([
      { name: 'GitLab/g/a@develop' }, { name: 'GitLab/g/a@feature' }, { name: 'GitLab/g/sub/b@main' }, { name: 'GitLab/g/sub/c@main' },
    ])
    const g = tree.get('GitLab').folders.get('g')
    const names = folderAssetNames(g)
    expect(names.sort()).toEqual(['GitLab/g/a@develop', 'GitLab/g/a@feature', 'GitLab/g/sub/b@main', 'GitLab/g/sub/c@main'])
    const c = countChanges(names, {
      'GitLab/g/a@develop': { state: 'CAMBIOS' }, 'GitLab/g/a@feature': { state: 'AL_DIA' },
      'GitLab/g/sub/b@main': { state: 'EN_COLA' }, 'GitLab/g/sub/c@main': { state: 'REGLAS_NUEVAS' },
    })
    expect(c).toEqual({ changed: 1, queued: 1, rules: 1, unverified: 0, total: 4 })
  })
})
