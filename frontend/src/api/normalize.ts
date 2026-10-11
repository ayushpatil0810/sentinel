// Runtime boundary for backend responses. The OpenAPI spec types most responses as plain objects, so these
// mappers only *rename and default* fields the server sent. They never derive an outcome, fingerprint, match
// result or taint level: if the server omitted a value, the UI shows it as missing.
import type {
  ApprovalRecord,
  ApprovalSummary,
  DecisionItem,
  DecisionsResponse,
  Health,
  LedgerEntry,
  Outbox,
  ReplayStartResponse,
  ReplayStepResult,
  SandboxStep,
  Session,
  User,
} from './types'

type O = Record<string, unknown>
const isObj = (v: unknown): v is O => typeof v === 'object' && v !== null && !Array.isArray(v)
const str = (v: unknown) => (typeof v === 'string' ? v : undefined)
const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : undefined)
/** Accepts `[...]` or `{items: [...]}`. */
export function list<T = O>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[]
  if (isObj(v) && Array.isArray(v.items)) return v.items as T[]
  return []
}

export const user = (v: unknown): User => {
  const o = isObj(v) ? v : {}
  return { user_id: String(o.user_id ?? ''), display_name: String(o.display_name ?? o.user_id ?? ''), roles: (strs(o.roles) ?? []) as User['roles'] }
}

export const health = (v: unknown): Health => v as Health

export const session = (v: unknown): Session => v as Session

const STEP_KINDS = new Set(['ingress', 'action', 'reply', 'user', 'system'])
export function step(v: unknown): SandboxStep {
  const o = isObj(v) ? v : {}
  const rawKind = str(o.kind) ?? 'system'
  const kind = (rawKind === 'agent' ? 'reply' : STEP_KINDS.has(rawKind) ? rawKind : 'system') as SandboxStep['kind']
  const sess = isObj(o.session) ? o.session : undefined
  return {
    kind,
    request_id: str(o.request_id),
    outcome: str(o.outcome) as SandboxStep['outcome'],
    // ingress steps carry the screened text the model received; null means withheld (block / escalate)
    text: str(o.text) ?? str(o.text_for_model) ?? str(o.message) ?? (kind === 'ingress' ? '[withheld from the model]' : ''),
    reason: str(o.reason),
    rule_ids: strs(o.rule_ids),
    decision_path: str(o.decision_path) as SandboxStep['decision_path'],
    approval_id: str(o.approval_id) ?? str(o.review_id) ?? null,
    action_id: str(o.action_id) ?? null,
    error_code: str(o.error_code) ?? (isObj(o.error) ? str(o.error.code) : undefined),
    session: sess as SandboxStep['session'],
  }
}
export const steps = (v: unknown): SandboxStep[] => (isObj(v) && Array.isArray(v.steps) ? v.steps.map(step) : [])

/** load-review: api.md says it returns the screened (ingress-shaped) result; also accept `{ingress, steps}`. */
export function loadReview(v: unknown): SandboxStep[] {
  if (!isObj(v)) return []
  if (Array.isArray(v.steps) && v.steps.length) return v.steps.map(step)
  const ing = isObj(v.ingress) ? v.ingress : 'outcome' in v ? v : null
  return ing ? [step({ ...ing, kind: 'ingress' })] : []
}

export function replayStart(v: unknown): ReplayStartResponse {
  const o = isObj(v) ? v : {}
  return {
    session_id: String(o.session_id ?? ''),
    steps: list<O>(o.steps).map((s) => ({
      id: String(s.id ?? s.step_id ?? ''),
      title: String(s.title ?? ''),
      status: (str(s.status) ?? 'pending') as ReplayStartResponse['steps'][number]['status'],
      actor: str(s.actor),
    })),
  }
}

export function replayStep(v: unknown): ReplayStepResult {
  const o = isObj(v) ? v : {}
  return {
    step_id: String(o.step_id ?? ''),
    actor: String(o.actor ?? ''),
    request_ids: strs(o.request_ids) ?? [],
    expected: isObj(o.expected) ? o.expected : {},
    actual: isObj(o.actual) ? o.actual : {},
    match: o.match === true, // only the server's explicit true counts as matched
    steps: Array.isArray(o.steps) ? o.steps.map(step) : undefined,
  }
}

export function outbox(v: unknown): Outbox {
  const o = isObj(v) ? v : {}
  return { emails: list(o.emails) as Outbox['emails'], db_ops: list(o.db_ops) as Outbox['db_ops'] }
}

export function decisions(v: unknown): DecisionsResponse {
  const items = list<DecisionItem>(v).map((d) => ({ ...d, rule_ids: d.rule_ids ?? [] }))
  const next = isObj(v) && typeof v.next_seq === 'number' ? v.next_seq : undefined
  return { items, next_seq: next ?? (items.length ? Math.max(...items.map((i) => i.seq)) + 1 : 0) }
}

export function ledgerEntry(v: unknown): LedgerEntry {
  const o = isObj(v) ? v : {}
  const entry = isObj(o.entry) ? { ...o.entry, ...o } : o
  return { ...(entry as unknown as LedgerEntry), rule_ids: strs(entry.rule_ids) ?? [], payload: entry.payload ?? entry.redacted_payload ?? entry.payload_redacted }
}

export const approvals = (v: unknown): ApprovalSummary[] => list<ApprovalSummary>(v)
export const approval = (v: unknown): ApprovalRecord => {
  const o = isObj(v) ? v : {}
  return { ...(o as unknown as ApprovalRecord), review: (isObj(o.review) ? o.review : {}) as ApprovalRecord['review'] }
}
