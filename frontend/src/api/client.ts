import {
  ApiError,
  type ApiErrorBody,
  type ApprovalDecisionResponse,
  type ApprovalKind,
  type ApprovalStatus,
  type LlmMode,
  type LlmModeName,
  type LedgerVerify,
  type LoginResponse,
  type User,
} from './types'
import type { Paths, Route } from './generated'
import * as N from './normalize'


// The only module that talks HTTP. Request shapes come from the backend's OpenAPI spec (generated.ts);
// responses pass through normalize.ts. With VITE_API_BASE_URL unset, the in-process mock answers instead.
// Set VITE_API_BASE_URL=/ to call the same origin (e.g. through the Vite dev proxy to localhost:8000).
const RAW_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() ?? ''
export const USING_MOCK = RAW_BASE === ''
const BASE = RAW_BASE.replace(/\/+$/, '')
const demoEnv = import.meta.env.VITE_DEMO_MODE as string | undefined
/** Build-time demo flag. The shell prefers the server's own flag from /health when it reports one. */
export const DEMO_MODE = demoEnv !== undefined ? demoEnv === 'true' : USING_MOCK

let token: string | null = null
export function setToken(t: string | null) {
  token = t
}

type Query = Record<string, string | number | undefined | null>

function qs(q?: Query) {
  if (!q) return ''
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

async function request(method: string, path: string, opts: { body?: unknown; query?: Query } = {}): Promise<unknown> {
  let status: number
  let json: unknown
  // Literal env check so production builds pointed at a backend drop the mock chunk entirely.
  if (!import.meta.env.VITE_API_BASE_URL) {
    const { mockRequest } = await import('../mocks/server')
    const res = await mockRequest(method, path, opts.query ?? {}, opts.body, token)
    status = res.status
    json = res.body
  } else {
    let res: Response
    try {
      res = await fetch(`${BASE}${path}${qs(opts.query)}`, {
        method,
        headers: {
          ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      })
    } catch {
      throw new ApiError(0, 'network.unreachable', 'Cannot reach the Sentinel API.', undefined, undefined, true)
    }
    status = res.status
    json = await res.json().catch(() => null)
  }
  if (status >= 400) {
    const e = (json as ApiErrorBody | null)?.error
    // FastAPI's own 422s use {detail: [...]} instead of the Sentinel envelope
    const detail = (json as { detail?: unknown } | null)?.detail
    const fallback = Array.isArray(detail) ? detail.map((d: { loc?: unknown[]; msg?: string }) => `${(d.loc ?? []).join('.')}: ${d.msg}`).join('; ') : undefined
    throw new ApiError(status, e?.code ?? (status === 422 ? 'validation.failed' : 'http.error'), e?.message ?? fallback ?? `Request failed (${status})`, e?.details, e?.request_id)
  }
  return json
}

type Opts<R extends Route> = ([Paths[R]['path']] extends [never] ? { path?: never } : { path: Paths[R]['path'] }) &
  ([Paths[R]['query']] extends [never] ? { query?: never } : { query?: Paths[R]['query'] }) &
  ([Paths[R]['body']] extends [never] ? { body?: never } : { body: Paths[R]['body'] })

/** Typed call keyed by "METHOD /path/{param}" from the OpenAPI spec. */
function call<R extends Route>(route: R, opts: Opts<R> = {} as Opts<R>): Promise<unknown> {
  const [method, tpl] = (route as string).split(' ') as [string, string]
  const params = (opts.path ?? {}) as Record<string, string | number>
  const path = tpl.replace(/\{(\w+)\}/g, (_, k: string) => encodeURIComponent(String(params[k])))
  return request(method, path, { query: opts.query as Query | undefined, body: opts.body ?? (method === 'POST' ? {} : undefined) })
}

export const api = {
  // auth
  login: (user_id: string, password: string) =>
    call('POST /api/v1/auth/login', { body: { user_id, password } }).then((r) => {
      const o = r as { token: string; user: unknown; expires_in?: number }
      return { token: o.token, user: N.user(o.user), expires_in: o.expires_in ?? 0 } as LoginResponse
    }),
  users: () => call('GET /api/v1/users').then((r) => N.list(r).map(N.user) as User[]),
  health: () => call('GET /health').then(N.health),

  // sessions + sandbox
  createSession: (agent_id = 'supportbot') => call('POST /api/v1/sessions', { body: { agent_id } }).then(N.session),
  getSession: (id: string) => call('GET /api/v1/sessions/{session_id}', { path: { session_id: id } }).then(N.session),
  resetTaint: (id: string, reason: string) => call('POST /api/v1/sessions/{session_id}/taint/reset', { path: { session_id: id }, body: { reason } }) as Promise<{ taint_level: number }>,
  sandboxMessage: (session_id: string, text: string) => call('POST /api/v1/sandbox/message', { body: { session_id, text } }).then((r) => ({ steps: N.steps(r) })),
  loadReview: (session_id: string, review_id: string) => call('POST /api/v1/sandbox/load-review', { body: { session_id, review_id } }).then(N.loadReview),
  replayStart: (script_id = 'demo-v1', reset = true) => call('POST /api/v1/sandbox/replay', { body: { script_id, reset } }).then(N.replayStart),
  replayStep: (session_id: string, step_id: string) => call('POST /api/v1/sandbox/replay/step', { body: { session_id, step_id } }).then(N.replayStep),
  outbox: () => call('GET /api/v1/sandbox/outbox').then(N.outbox),
  sandboxReset: () => call('POST /api/v1/sandbox/reset'),

  // llm
  llmMode: () => call('GET /api/v1/llm/mode') as Promise<LlmMode>,
  setLlmMode: (mode: LlmModeName) => call('POST /api/v1/llm/mode', { body: { mode } }) as Promise<LlmMode>,

  // decisions + ledger
  decisions: (q: Paths['GET /api/v1/decisions']['query']) => call('GET /api/v1/decisions', { query: q }).then(N.decisions),
  ledgerEntry: (seq: number) => call('GET /api/v1/ledger/{seq}', { path: { seq } }).then(N.ledgerEntry),
  verifyLedger: () => call('GET /api/v1/ledger/verify') as Promise<LedgerVerify>,

  // approvals
  approvals: (q: { status?: ApprovalStatus | ''; kind?: ApprovalKind | '' } = {}) => call('GET /api/v1/approvals', { query: q }).then(N.approvals),
  approval: (id: string) => call('GET /api/v1/approvals/{approval_id}', { path: { approval_id: id } }).then(N.approval),
  decideApproval: (id: string, decision: 'approve' | 'reject', comment: string) =>
    call('POST /api/v1/approvals/{approval_id}/decision', { path: { approval_id: id }, body: { decision, comment } }) as Promise<ApprovalDecisionResponse>,
}
