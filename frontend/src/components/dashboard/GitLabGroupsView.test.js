import { describe, it, expect } from 'vitest'
import { buildGitlabTree, parseGitlabName } from './GitLabGroupsView'

describe('parseGitlabName', () => {
  it('splits instance, groups, project and branch', () => {
    expect(parseGitlabName('GitLab2/grupo-b/proyecto-e/proyecto-e-web@develop-vulneravilidades')).toEqual({
      instance: 'GitLab2', path: 'grupo-b/proyecto-e/proyecto-e-web', branch: 'develop-vulneravilidades', project: 'proyecto-e-web', groups: ['grupo-b', 'proyecto-e'],
    })
    expect(parseGitlabName('GitLab/proyecto-g/backend-proyecto-g').branch).toBeNull()
    expect(parseGitlabName('proyecto-e-Deploy (192.0.2.8)')).toBeNull()
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
    expect(g2.vulns).toBe(6)
    const proyecto-e = g2.folders.get('grupo-b').folders.get('proyecto-e')
    expect(proyecto-e.prefix).toBe('GitLab2/grupo-b/proyecto-e/')
    expect(proyecto-e.projects.get('proyecto-e-web').assets.map(a => a.branch)).toEqual(['develop', 'develop-vulneravilidades'])
    expect(tree.get('GitLab').projects.size).toBe(0)
    expect(tree.get('GitLab').folders.get('proyecto-g').projects.get('backend-proyecto-g').vulns).toBe(5)
  })
})
