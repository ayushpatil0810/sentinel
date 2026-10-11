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
  type GraphResponse,
  type GraphRoutesResponse,
  type GraphRoute,
  type RemediationsResponse,
  type RemediationPreviewResponse,
  type GraphDiff,
  type GraphVersionItem,
  type BlastRadius,
  type LabScanResponse,
  type BenchmarkMetrics,
  type PolicyDocument,
  type PolicyVersionItem,
  type PolicyProposalResponse,
  type TestReportResponse,
  type SystemStatus,
  type LlmSettings,
  type LlmSettingsUpdate,
  type LlmTestResult,
} from "./types"
import type { Paths, Route } from "./generated"
import * as N from "./normalize"

// The only module that talks HTTP. Request shapes come from the backend's OpenAPI spec (generated.ts);
// responses pass through normalize.ts. With VITE_API_BASE_URL unset, the in-process mock answers instead.
const RAW_BASE =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() ?? ""
export const USING_MOCK = RAW_BASE === ""
const BASE = RAW_BASE.replace(/\/+$/, "")
const demoEnv = import.meta.env.VITE_DEMO_MODE as string | undefined
/** Build-time demo flag. The shell prefers the server's own flag from /health when it reports one. */
export const DEMO_MODE = demoEnv !== undefined ? demoEnv === "true" : USING_MOCK

let token: string | null = null
export function setToken(t: string | null) {
  token = t
}
export function getToken(): string | null {
  return token
}

type Query = Record<string, string | number | undefined | null | boolean>

function qs(q?: Query) {
  if (!q) return ""
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ""
}

async function request(
  method: string,
  path: string,
  opts: { body?: unknown; query?: Query } = {},
): Promise<unknown> {
  let status: number
  let json: unknown
  // Literal env check so production builds pointed at a backend drop the mock chunk entirely.
  if (!import.meta.env.VITE_API_BASE_URL) {
    const { mockRequest } = await import("../mocks/server")
    const res = await mockRequest(
      method,
      path,
      (opts.query ?? {}) as Record<string, string | number | undefined | null>,
      opts.body,
      token,
    )
    status = res.status
    json = res.body
  } else {
    let res: Response
    try {
      res = await fetch(`${BASE}${path}${qs(opts.query)}`, {
        method,
        headers: {
          ...(opts.body !== undefined
            ? { "Content-Type": "application/json" }
            : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      })
    } catch {
      throw new ApiError(
        0,
        "network.unreachable",
        "Cannot reach the Sentinel API.",
        undefined,
        undefined,
        true,
      )
    }
    status = res.status
    json = await res.json().catch(() => null)
  }
  if (status >= 400) {
    const e = (json as ApiErrorBody | null)?.error
    // FastAPI's own 422s use {detail: [...]} instead of the Sentinel envelope
    const detail = (json as { detail?: unknown } | null)?.detail
    const fallback = Array.isArray(detail)
      ? detail
          .map(
            (d: { loc?: unknown[]; msg?: string }) =>
              `${(d.loc ?? []).join(".")}: ${d.msg}`,
          )
          .join("; ")
      : undefined
    throw new ApiError(
      status,
      e?.code ?? (status === 422 ? "validation.failed" : "http.error"),
      e?.message ?? fallback ?? `Request failed (${status})`,
      e?.details,
      e?.request_id,
    )
  }
  return json
}

type Opts<R extends Route> = {
  path?: [Paths[R]["path"]] extends [never] ? never : Paths[R]["path"]
  query?: [Paths[R]["query"]] extends [never] ? never : Paths[R]["query"]
  body?: [Paths[R]["body"]] extends [never] ? never : Paths[R]["body"]
}

/** Typed call keyed by "METHOD /path/{param}" from the OpenAPI spec. */
function call<R extends Route>(
  route: R,
  opts: Opts<R> = {} as Opts<R>,
): Promise<unknown> {
  const [method, tpl] = (route as string).split(" ") as [string, string]
  const params = (opts.path ?? {}) as Record<string, string | number>
  const path = tpl.replace(/\{(\w+)\}/g, (_, k: string) =>
    encodeURIComponent(String(params[k])),
  )
  return request(method, path, {
    query: opts.query as Query | undefined,
    body: opts.body ?? (method === "POST" ? {} : undefined),
  })
}

export const api = {
  // ── Auth ──
  login: (user_id: string, password = "demo") =>
    call("POST /api/v1/auth/login", { body: { user_id, password } }).then(
      (r) => {
        const o = r as { token: string; user: unknown; expires_in?: number }
        return {
          token: o.token,
          user: N.user(o.user),
          expires_in: o.expires_in ?? 0,
        } as LoginResponse
      },
    ),
  users: () =>
    call("GET /api/v1/users").then((r) => N.list(r).map(N.user) as User[]),
  me: () => call("GET /api/v1/auth/me").then(N.user),
  health: () => call("GET /health").then(N.health),

  // ── Sessions + Sandbox ──
  createSession: (agent_id = "supportbot") =>
    call("POST /api/v1/sessions", { body: { agent_id } }).then(N.session),
  getSession: (id: string) =>
    call("GET /api/v1/sessions/{session_id}", {
      path: { session_id: id },
    }).then(N.session),
  resetTaint: (id: string, reason: string) =>
    call("POST /api/v1/sessions/{session_id}/taint/reset", {
      path: { session_id: id },
      body: { reason },
    }) as Promise<{ taint_level: number }>,
  sandboxMessage: (session_id: string, text: string) =>
    call("POST /api/v1/sandbox/message", { body: { session_id, text } }).then(
      (r) => ({ steps: N.steps(r) }),
    ),
  loadReview: (session_id: string, review_id: string) =>
    call("POST /api/v1/sandbox/load-review", {
      body: { session_id, review_id },
    }).then(N.loadReview),
  replayStart: (script_id = "demo-v1", reset = true) =>
    call("POST /api/v1/sandbox/replay", { body: { script_id, reset } }).then(
      N.replayStart,
    ),
  replayStep: (session_id: string, step_id: string) =>
    call("POST /api/v1/sandbox/replay/step", {
      body: { session_id, step_id },
    }).then(N.replayStep),
  outbox: () => call("GET /api/v1/sandbox/outbox").then(N.outbox),
  sandboxReset: () => call("POST /api/v1/sandbox/reset"),

  // ── LLM ──
  llmMode: () => call("GET /api/v1/llm/mode") as Promise<LlmMode>,
  setLlmMode: (mode: LlmModeName) =>
    call("POST /api/v1/llm/mode", { body: { mode } }) as Promise<LlmMode>,

  // ── Decisions + Ledger ──
  decisions: (q: Paths["GET /api/v1/decisions"]["query"]) =>
    call("GET /api/v1/decisions", { query: q }).then(N.decisions),
  ledgerEntry: (seq: number) =>
    call("GET /api/v1/ledger/{seq}", { path: { seq } }).then(N.ledgerEntry),
  ledger: (q: Paths["GET /api/v1/ledger"]["query"] = {}) =>
    call("GET /api/v1/ledger", { query: q }).then((r) =>
      N.list(r).map(N.ledgerEntry),
    ),
  verifyLedger: () =>
    call("GET /api/v1/ledger/verify") as Promise<LedgerVerify>,
  demoTamper: (seq: number, field: string, value: string) =>
    call("POST /api/v1/demo/tamper", {
      body: { seq, field, value },
    }) as Promise<{ tampered_seq: number }>,

  // ── Approvals ──
  approvals: (
    q: { status?: ApprovalStatus | ""; kind?: ApprovalKind | "" } = {},
  ) => call("GET /api/v1/approvals", { query: q }).then(N.approvals),
  approval: (id: string) =>
    call("GET /api/v1/approvals/{approval_id}", {
      path: { approval_id: id },
    }).then(N.approval),
  decideApproval: (
    id: string,
    decision: "approve" | "reject",
    comment: string,
  ) =>
    call("POST /api/v1/approvals/{approval_id}/decision", {
      path: { approval_id: id },
      body: { decision, comment },
    }) as Promise<ApprovalDecisionResponse>,

  // ── BreachPath Graph ──
  graph: () => call("GET /api/v1/graph") as Promise<GraphResponse>,
  graphVersions: () =>
    call("GET /api/v1/graph/versions").then(
      N.list,
    ) as Promise<GraphVersionItem[]>,
  validateGraph: (body: unknown) =>
    request("POST", "/api/v1/graph/validate", { body }) as Promise<{
      valid: boolean
      errors?: unknown[]
      warnings?: string[]
    }>,
  uploadGraph: (body: unknown, format = "json") =>
    request("PUT", "/api/v1/graph", { query: { format }, body }) as Promise<{
      graph_version: number
      warnings?: string[]
    }>,
  graphChanges: (changes: unknown[], expected_version?: number) =>
    call("POST /api/v1/graph/changes", {
      body: { changes, expected_version },
    }) as Promise<{ graph_version: number; diff: GraphDiff }>,
  routes: (max_depth?: number) =>
    call("GET /api/v1/graph/routes", {
      query: max_depth !== undefined ? { max_depth } : {},
    }) as Promise<GraphRoutesResponse>,
  route: (path_id: string) =>
    call("GET /api/v1/graph/routes/{path_id}", {
      path: { path_id },
    }) as Promise<GraphRoute>,
  remediations: () =>
    call("GET /api/v1/graph/remediations") as Promise<RemediationsResponse>,
  previewRemediation: (edge_id: string) =>
    call("POST /api/v1/graph/remediations/{edge_id}/preview", {
      path: { edge_id },
    }) as Promise<RemediationPreviewResponse>,
  applyRemediation: (edge_id: string, expected_version: number) =>
    call("POST /api/v1/graph/remediations/{edge_id}/apply", {
      path: { edge_id },
      body: { expected_version },
    }) as Promise<{ graph_version: number; diff: GraphDiff }>,
  blastRadius: (node_id: string) =>
    call("GET /api/v1/graph/blast/{node_id}", {
      path: { node_id },
    }) as Promise<BlastRadius>,
  deriveEntryPoints: () =>
    call("POST /api/v1/graph/derive-entry-points") as Promise<{
      changed: boolean
      graph_version: number
      warnings: string[]
    }>,

  // ── PromptShield Lab & Benchmark ──
  scan: (
    text: string,
    source_tier: "user" | "retrieved_document" | "tool_output" = "retrieved_document",
  ) =>
    call("POST /api/v1/promptshield/scan", {
      body: { text, source_tier },
    }) as Promise<LabScanResponse>,
  promptshieldPolicy: () =>
    call("GET /api/v1/promptshield/policy") as Promise<unknown>,
  runBenchmark: () =>
    call("POST /api/v1/benchmark/run") as Promise<{
      run_id: string
      metrics: BenchmarkMetrics
    }>,
  latestBenchmark: () =>
    call("GET /api/v1/benchmark/latest") as Promise<BenchmarkMetrics>,
  benchmarkCases: (split = "dev") =>
    call("GET /api/v1/benchmark/cases", {
      query: { split },
    }) as Promise<unknown>,

  // ── Policy ──
  policy: () => call("GET /api/v1/policy") as Promise<PolicyDocument>,
  policyVersions: () =>
    call("GET /api/v1/policy/versions").then(
      N.list,
    ) as Promise<PolicyVersionItem[]>,
  policyVersion: (v: number) =>
    call("GET /api/v1/policy/versions/{v}", {
      path: { v },
    }) as Promise<PolicyDocument>,
  policyDiff: (from: number, to: number) =>
    call("GET /api/v1/policy/diff", { query: { from, to } }).then((r) =>
      Array.isArray(r) ? r : (r as { ops?: unknown[] })?.ops || [],
    ) as Promise<{ op: string; path: string; value?: unknown }[]>,
  proposePolicy: (base_version: number, policyDoc: unknown, note: string) =>
    call("POST /api/v1/policy/proposals", {
      body: {
        base_version,
        policy: policyDoc as Record<string, unknown>,
        note,
      },
    }) as Promise<PolicyProposalResponse>,

  // ── Registries & Tests ──
  registriesAgents: () =>
    call("GET /api/v1/registries/agents").then(N.list) as Promise<unknown[]>,
  registriesActionTypes: () =>
    call("GET /api/v1/registries/action-types").then(
      N.list,
    ) as Promise<unknown[]>,
  runTests: () => call("POST /api/v1/tests/run") as Promise<{ run_id: string }>,
  testReport: () =>
    call("GET /api/v1/tests/report") as Promise<TestReportResponse>,

  // ── System & Admin LLM ──
  systemStatus: () =>
    request("GET", "/api/v1/system/status") as Promise<SystemStatus>,
  adminLlmSettings: () =>
    request("GET", "/api/v1/admin/llm/settings") as Promise<LlmSettings>,
  updateAdminLlmSettings: (body: LlmSettingsUpdate) =>
    request("PUT", "/api/v1/admin/llm/settings", { body }) as Promise<LlmSettings>,
  testAdminLlmConnection: () =>
    request("POST", "/api/v1/admin/llm/test") as Promise<LlmTestResult>,
}
