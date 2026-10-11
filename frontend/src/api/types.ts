// Types transcribed from docs/api.md and docs/data-models.md.

export type Role = "requester" | "approver" | "admin"
export type Outcome = "allow" | "block" | "hold" | "sanitize" | "escalate" | "ok" | "refused" | "info"
export type DecisionPath = "rules" | "rules+llm" | "fallback" | "n/a"
export type TaintLevel = 0 | 1 | 2
export type TaintLabel = "clean" | "untrusted_present" | "flagged"
export type LlmModeName = "ok" | "down" | "says_safe_always" | "timeout" | "garbage"

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
  kind: "ingress" | "action" | "reply" | "user" | "system"
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

export type ReplayStatus = "pending" | "running" | "matched" | "mismatch"

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
  emails: {
    outbox_id: number
    ts: string
    to: string[]
    subject: string
    body_excerpt: string
    simulated: true
  }[]
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
  session_taint: TaintLevel | TaintLabel | {
    taint_level: TaintLevel
    taint_label?: TaintLabel
  } | null
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

export type ApprovalKind = "action" | "ingress_review" | "policy.update"
// 'consumed' per the OpenAPI query description; 'used' kept for the mock
export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "consumed" | "used"

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
  llm?: {
    summary: string
    risk_flags: string[]
    suggested_outcome: string
    label: "advisory"
  } | null
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
  error: {
    code: string
    message: string
    details?: Record<string, unknown>
    request_id?: string
  }
}

export class ApiError extends Error {
  code: string
  status: number
  details?: Record<string, unknown>
  requestId?: string
  network: boolean
  constructor(
    status: number,
    code: string,
    message: string,
    details?: Record<string, unknown>,
    requestId?: string,
    network = false,
  ) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
    this.network = network
  }
}

// ── BreachPath Graph Types ──
export interface GraphNode {
  id: string
  type: "user" | "role" | "service" | "agent" | "tool" | "asset" | "external"
  name: string
  entry_point?: boolean
  sensitivity?: "none" | "low" | "medium" | "high" | "critical"
  entry_source?: "manual" | "derived" | null
  attrs?: Record<string, unknown>
}

export interface GraphEdge {
  id: string
  src: string
  dst: string
  type: "member_of" | "can_assume" | "can_invoke" | "can_read" | "can_write" | "trusts" | "network_reachable" | "ingests_from" | "calls" | string
  attrs?: Record<string, unknown>
}

export interface GraphModel {
  schema?: string
  name?: string
  settings?: {
    max_depth?: number
    max_paths?: number
    time_budget_ms?: number
    sensitive_min?: string
  }
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface GraphResponse extends GraphModel {
  graph_version: number
  warnings?: string[]
}

export interface GraphRouteStep {
  from: string
  edge_id: string
  edge_type: string
  to: string
  reversed: boolean
  text: string
}

export interface GraphRoute {
  path_id: string
  entry: string
  asset: string
  asset_sensitivity: string
  length: number
  steps: GraphRouteStep[]
  summary: string
  short?: string
}

export interface GraphRoutesResponse {
  graph_version: number
  max_depth: number
  truncated: boolean
  truncation_reason: string | null
  warning: string | null
  routes: GraphRoute[]
}

export interface RemediationSuggestion {
  edge_id: string
  type?: string
  breaks: number
  path_ids: string[]
  rationale: string
  preview: {
    removed: string[]
    remaining: string[]
    new: string[]
  }
}

export interface RemediationsResponse {
  suggestions: RemediationSuggestion[]
  plan?: { edge_id: string; covers: number }[]
}

export interface RemediationPreviewResponse {
  removed: string[]
  remaining: string[]
  new: string[]
  comparison_reliable: boolean
}

export interface GraphDiff {
  from_version: number
  to_version: number
  comparison_reliable: boolean
  removed: string[]
  remaining: string[]
  new: string[]
  routes?: {
    removed: GraphRoute[]
    new: GraphRoute[]
  }
}

export interface GraphVersionItem {
  graph_version: number
  created_by: string
  created_at: string
  change_summary: unknown
}

export interface BlastRadius {
  node_id: string
  on_attack_path: boolean
  paths_count: number
  min_distance_to_sensitive?: number
  max_sensitivity_reachable?: string
  level: "low" | "medium" | "high"
  reason: string | null
}

// ── PromptShield Lab & Benchmark Types ──
export interface LabScanResponse extends IngressResult {
  text_sanitized?: string
}

export interface BenchmarkMetrics {
  run_id: string
  ts: string
  policy_version: number
  split: string
  n: number
  confusion: { tp: number; fp: number; tn: number; fn: number }
  precision: { value: number; ci95?: [number, number] }
  recall: { value: number; ci95?: [number, number] }
  f1: number
  fpr: { value: number; ci95?: [number, number] }
  per_category: Record<string, {
    total: number
    tp?: number
    fn?: number
    recall?: number
  }>
  per_tier: Record<string, {
    total: number
    recall?: number
    tp?: number
    fn?: number
  }>
  sanitize_quality?: {
    cases: number
    preserved_pct: number
    rescan_clean_pct: number
  }
  misses: {
    id: string
    category: string
    tier?: string
    excerpt?: string
    explanation: string
  }[]
  false_positives: {
    id: string
    category?: string
    tier?: string
    excerpt?: string
    explanation: string
  }[]
}

// ── Policy Types ──
export interface PolicyDocument {
  version: number
  name?: string
  action_rules?: unknown[]
  ingress?: unknown
  settings?: unknown
}

export interface PolicyVersionItem {
  version: number
  created_by: string
  approved_by: string | null
  activated_at: string | null
  content_hash: string
}

export interface PolicyProposalResponse {
  proposal_id: string
  approval_id: string
  outcome: Outcome
  rule_ids: string[]
  fingerprint: string
  diff: { op: string; path: string; value?: unknown }[]
}

// ── Test Report Types ──
export interface TestCaseResult {
  test: string
  status: "passed" | "failed" | "skipped"
  duration_ms: number
}

export interface TestReportResponse {
  run_id: string
  ts: string
  totals: { passed: number; failed: number; skipped: number }
  by_requirement: Record<string, TestCaseResult[]>
  untested_requirements: string[]
}
