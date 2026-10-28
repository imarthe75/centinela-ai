import { describe, it, expect } from 'vitest'
import { filterCases, STATUS } from './PruebasFuncionalesView'

const cases = [
  { case_id: 'CI-59', status: 'FAILED', criterion: 'RQ-09 · CA1', detail: 'sin bitácora' },
  { case_id: 'CI-60', status: 'PASSED', criterion: 'RQ-09 · CA2', detail: 'ok' },
  { case_id: 'UAT-3', status: 'BLOCKED', criterion: 'RQ-11', reason: 'falta cuenta SP-02' },
]

describe('filterCases', () => {
  it('filters by status and by text in id, criterion, detail or reason', () => {
    expect(filterCases(cases, 'ALL', '').length).toBe(3)
    expect(filterCases(cases, 'FAILED', '').map(c => c.case_id)).toEqual(['CI-59'])
    expect(filterCases(cases, 'ALL', 'sp-02').map(c => c.case_id)).toEqual(['UAT-3'])
    expect(filterCases(cases, 'ALL', 'rq-09').length).toBe(2)
    expect(filterCases(cases, 'PASSED', 'bitácora')).toEqual([])
  })
  it('has a label for every status the results model allows', () => {
    expect(Object.keys(STATUS).sort()).toEqual(['BLOCKED', 'FAILED', 'NOT_EXECUTED', 'PASSED'])
  })
})
