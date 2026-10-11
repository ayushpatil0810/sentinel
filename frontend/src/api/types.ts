// Types transcribed from docs/api.md and docs/data-models.md.

export type Role = 'requester' | 'approver' | 'admin'
export type Outcome = 'allow' | 'block' | 'hold' | 'sanitize' | 'escalate' | 'ok' | 'refused' | 'info'
export type DecisionPath = 'rules' | 'rules+llm' | 'fallback' | 'n/a'
export type TaintLevel = 0 | 1 | 2
export type TaintLabel = 'clean' | 'untrusted_present' | 'flagged'
export type LlmModeName = 'ok' | 'down' | 'says_safe_always' | 'timeout' | 'garbage'

export interface User {
  user_id: string
  display_name: string
  roles: Role[]
}

export interface LoginResponse {
  token: string
  user: User
  expires_in: number
}

export interface Health {
  status: string
  policy_version: number
  graph_version: number
  ledger_head: number
  llm_mode: LlmModeName
  /** Not in api.md; honoured if the server sends it. */
  demo_mode?: boolean
}

export interface LedgerVerify {
  valid: boolean
  checked: number
  first_broken_seq: number | null
  reason: string | null
  detail?: string
}

export interface Session {
  session_id: string
  agent_id?: string
  owner_user_id?: string
  taint_level: TaintLevel
  taint_label?: TaintLabel
  taint_reasons?: string[]
}

export interface Finding {
  type: string
  confidence_pct: number
  detector: string
  start: number
  end: number
  evidence: string
  encoding?: string
}

export interface IngressResult {
  request_id: string
  outcome: Outcome
  reason: string
  rule_ids: string[]
  decision_path: DecisionPath
  policy_version: number
  text_for_model: string | null
  findings: Finding[]
  session: { taint_level: TaintLevel; taint_label: TaintLabel }
  review_id: string | null
}

export interface ReviewPreset {
  review_id: string
  style: string
  text: string
}

export interface SandboxStep {
  kind: 'ingress' | 'action' | 'reply' | 'user' | 'system'
  request_id?: string
  outcome?: Outcome
  text: string
  reason?: string
  rule_ids?: string[]
  decision_path?: DecisionPath
  approval_id?: string | null
  action_id?: string | null
  error_code?: string
  session?: { taint_level: TaintLevel; taint_label: TaintLabel }
}

export interface SandboxMessageResponse {
  steps: SandboxStep[]
}

export interface LoadReviewResponse {
  review_id: string
  tool: string
  ingress: IngressResult
  steps: SandboxStep[]
}

export type ReplayStatus = 'pending' | 'running' | 'matched' | 'mismatch'

export interface ReplayStepInfo {
  id: string
  title: string
  status: ReplayStatus
  actor?: string
}

export interface ReplayStartResponse {
  session_id: string
  steps: ReplayStepInfo[]
}

export interface ReplayStepResult {
  step_id: string
  actor: string
  request_ids: string[]
  expected: Record<string, unknown>
  actual: Record<string, unknown>
  match: boolean
  steps?: SandboxStep[]
}

export interface Outbox {
  emails: { outbox_id: number; ts: string; to: string[]; subject: string; body_excerpt: string; simulated: true }[]
  db_ops: { op_id: number; op: string; resource: string; record_count: number }[]
}

export interface LlmMode {
  mode: LlmModeName
  breaker: string
  consecutive_failures: number
}

export interface DecisionItem {
  seq: number
  ts: string
  module: string
  event_type: string
  subject: string
  outcome: Outcome
  reason: string
  rule_ids: string[]
  decision_path: DecisionPath
  session_taint: TaintLevel | TaintLabel | { taint_level: TaintLevel; taint_label?: TaintLabel } | null
}

export interface DecisionsResponse {
  items: DecisionItem[]
  next_seq: number
}

export interface LedgerEntry {
  seq: number
  ts: string
  module: string
  event_type: string
  subject: string
  outcome: Outcome
  reason: string
  rule_ids: string[]
  decision_path: DecisionPath
  policy_version: number
  payload_ref: string | null
  payload_digest: string
  prev_hash: string
  hash: string
  payload?: unknown
}

export type ApprovalKind = 'action' | 'ingress_review' | 'policy.update'
// 'consumed' per the OpenAPI query description; 'used' kept for the mock
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'consumed' | 'used'

export interface ApprovalSummary {
  approval_id: string
  kind: ApprovalKind
  status: ApprovalStatus
  requester: string
  created_at: string
  expires_at: string
  summary: string
}

export interface ApprovalReview {
  action_type?: string
  arguments?: Record<string, unknown>
  llm?: { summary: string; risk_flags: string[]; suggested_outcome: string; label: 'advisory' } | null
  rule_ids?: string[]
  rule_reasons?: Record<string, string>
  taint_level?: TaintLevel
  blast?: { level: string; reason?: string; routes?: number }
  fingerprint?: string
  decision_path?: DecisionPath
  diff?: { op: string; path: string; value?: unknown }[]
  findings?: Finding[]
  text_redacted?: string
}

export interface ApprovalRecord extends ApprovalSummary {
  approver?: string | null
  comment?: string | null
  signature?: string | null
  decided_at?: string | null
  review: ApprovalReview
}

export interface ApprovalDecisionResponse {
  approval_id: string
  status: ApprovalStatus
  approver: string
  signature: string
}

export interface ApiErrorBody {
  error: { code: string; message: string; details?: Record<string, unknown>; request_id?: string }
}

export class ApiError extends Error {
  code: string
  status: number
  details?: Record<string, unknown>
  requestId?: string
  network: boolean
  constructor(status: number, code: string, message: string, details?: Record<string, unknown>, requestId?: string, network = false) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
    this.network = network
  }
}
