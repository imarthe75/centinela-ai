// ADR-0008 #2: smoke test of the whole dashboard shell. Renders it as an authenticated Admin with empty API data and walks every nav
// view, so a broken extraction (undefined variable, bad context wiring) fails here instead of in front of a user.
import React from 'react'
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, cleanup, fireEvent, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('react-oidc-context', () => ({
  useAuth: () => ({
    isLoading: false, isAuthenticated: true, error: null, events: { addAccessTokenExpired: () => () => {} }, signinRedirect: () => {}, signoutRedirect: () => {},
    user: { access_token: 't', profile: { preferred_username: 'tester', email: 'tester@example.com', name: 'Tester' } },
  }),
}))
vi.mock('./MapChart', () => ({ default: () => null }))
vi.mock('axios', () => {
  const reply = (url) => {
    if (String(url).endsWith('/users')) return [{ username: 'tester', email: 'tester@example.com', role: 'Admin' }]
    if (/\/(inventory|remediation|alerts|map|incidents|suppressions|suppression-proposals)(\?|$)/.test(String(url))) return []
    return {}
  }
  const ok = (url) => { (globalThis.__apiCalls ||= []).push(String(url)); return Promise.resolve({ data: reply(url), status: 200 }) }
  const api = { get: ok, post: ok, put: ok, delete: ok, patch: ok, create: () => api, defaults: { headers: { common: {} } }, interceptors: { request: { use() {} }, response: { use() {} } } }
  return { default: api, ...api }
})

globalThis.ResizeObserver = globalThis.ResizeObserver || class { observe() {} unobserve() {} disconnect() {} }
globalThis.WebSocket = class { constructor() {} close() {} send() {} }
globalThis.alert = () => {}
globalThis.confirm = () => true
window.matchMedia = window.matchMedia || (() => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }))
window.scrollTo = () => {}

const VIEWS = ['Dashboard', 'Búsqueda de Amenazas', 'Identidad & ITDR', 'Inventario de Activos', 'Remediación con IA', 'Supresiones IA',
  'Tokens IA', 'Salud del Sistema', 'Gestión Usuarios', 'Configuración Sistema']

const settle = () => act(async () => { await new Promise((r) => setTimeout(r, 200)) })

async function walk(Component) {
  const { container, getAllByText } = render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><Component /></MemoryRouter></QueryClientProvider>)
  await settle()
  const out = { initial: container.innerHTML }
  for (const label of VIEWS) {
    const el = getAllByText(label).find((n) => n.closest('nav'))
    fireEvent.click(el)
    await settle()
    out[label] = container.innerHTML
  }
  return out
}

describe('Dashboard shell', () => {
  afterEach(() => cleanup())

  it('renders every view without throwing', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-10-05T12:00:00Z'))
    const { default: Dashboard } = await import('./Dashboard')
    const views = await walk(Dashboard)
    for (const [name, html] of Object.entries(views)) expect(html.length, name).toBeGreaterThan(500)
    // each nav click must really change the view (URL-driven), not just re-render the same one
    expect(new Set(Object.values(views)).size).toBeGreaterThan(8)
    vi.useRealTimers()
  })

  it('polls through TanStack Query: one round on mount, and the same data is not requested twice per round', async () => {
    globalThis.__apiCalls = []
    const { default: Dashboard } = await import('./Dashboard')
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    await settle()
    const hits = (needle) => globalThis.__apiCalls.filter((u) => u.endsWith(needle)).length
    expect(hits('/stats/extended')).toBe(1)
    expect(hits('/inventory')).toBe(1)
    expect(hits('/audit/iso27001-report')).toBe(1)        // secondary round also exactly once
  })
})
