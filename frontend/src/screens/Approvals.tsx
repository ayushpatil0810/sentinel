import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { api } from '../api/client'
import { ApiError, type ApprovalKind, type ApprovalRecord, type ApprovalSummary } from '../api/types'
import { EmptyState, PageHeader, ErrorBanner, HashText, JsonView, Panel, PathChip, RuleChip, Skeleton, TaintBadge, button } from '../components/ui'
import { useApp, usePoll } from '../state/AppContext'

const KIND_LABEL: Record<ApprovalKind, string> = { action: 'Action', ingress_review: 'Ingress review', 'policy.update': 'Policy change' }

function useNow(ms = 1000) {
  const [n, setN] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setN(Date.now()), ms)
    return () => clearInterval(t)
  }, [ms])
  return n
}

function fmtDur(ms: number) {
  const s = Math.max(0, Math.floor(ms / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

function Queue({ items, selected, tab, setTab }: { items: ApprovalSummary[]; selected?: string; tab: 'pending' | 'decided'; setTab: (t: 'pending' | 'decided') => void }) {
  const now = useNow()
  const list = items.filter((a) => (tab === 'pending' ? a.status === 'pending' : a.status !== 'pending'))
  const pendingCount = items.filter((a) => a.status === 'pending').length
  return (
    <Panel className="lg:sticky lg:top-0">
      <div role="tablist" className="flex border-b border-line">
        {(['pending', 'decided'] as const).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)} className={`flex-1 px-3 py-2.5 text-sm font-semibold capitalize ${tab === t ? 'bg-raised text-fg' : 'text-dim hover:text-fg'}`}>
            {t} {t === 'pending' && `(${pendingCount})`}
          </button>
        ))}
      </div>
      {list.length === 0 ? (
        <div className="p-4">
          <EmptyState title={tab === 'pending' ? 'No held actions' : 'Nothing decided yet'} hint={tab === 'pending' ? 'Held actions, ingress reviews and policy changes appear here.' : undefined} />
        </div>
      ) : (
        <ul>
          {list.map((a) => {
            const left = new Date(a.expires_at).getTime() - now
            const active = a.approval_id === selected
            return (
              <li key={a.approval_id} className="border-b border-line last:border-0">
                <Link to={`/approvals/${a.approval_id}`} className={`block border-l-4 px-4 py-3 hover:bg-raised ${active ? 'border-fg bg-raised' : 'border-transparent'}`}>
                  <div className="flex items-center justify-between gap-2 font-mono text-xs">
                    <span className="uppercase tracking-wider text-hold">{KIND_LABEL[a.kind] ?? a.kind}</span>
                    <span className="text-faint">{a.approval_id}</span>
                  </div>
                  <p className="mt-1 break-words font-semibold leading-snug">{a.summary}</p>
                  <p className="mt-1 flex justify-between font-mono text-xs text-dim">
                    <span>by {a.requester}</span>
                    <span>{a.status === 'pending' ? (left > 0 ? `expires ${fmtDur(left)}` : 'expired') : a.status}</span>
                  </p>
                </Link>
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}

const ERR_TITLE: Record<string, string> = {
  'approval.self_approval': 'Refused: you cannot approve your own request',
  'auth.forbidden_role': 'Refused: your role cannot decide this',
  'approval.not_pending': 'Already decided',
  'approval.expired': 'Expired, the agent must re-propose',
  'approval.fingerprint_mismatch': 'Fingerprint mismatch, a new approval is required',
  'policy.stale_base': 'Policy changed since this was proposed',
  'ledger.unavailable': 'Decision could not be recorded, nothing was executed',
}

function ServerError({ error }: { error: ApiError }) {
  const newId = error.details?.new_approval_id as string | undefined
  return (
    <div role="alert" className="space-y-1 border-2 border-block bg-block/10 p-4">
      <p className="text-base font-semibold text-block">{ERR_TITLE[error.code] ?? 'Request refused'}</p>
      <p>{error.message}</p>
      <p className="flex flex-wrap gap-4 font-mono text-xs text-dim">
        <span>
          {error.code} · HTTP {error.status}
        </span>
        {error.requestId && <span>{error.requestId}</span>}
        {Array.isArray(error.details?.required) && <span>needs: {(error.details!.required as string[]).join(' or ')}</span>}
      </p>
      {newId && (
        <Link to={`/approvals/${newId}`} className="font-semibold underline">
          Open the new approval {newId}
        </Link>
      )}
    </div>
  )
}

function Detail({ id }: { id: string }) {
  const { user, reportError, notify } = useApp()
  const { data: a, error, loading, reload } = usePoll(() => api.approval(id), 2000, [id])
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [actionErr, setActionErr] = useState<ApiError | null>(null)
  const now = useNow()

  useEffect(() => {
    setComment('')
    setActionErr(null)
  }, [id])

  if (loading && !a) return <Skeleton rows={8} />
  if (error && !a) return <ErrorBanner error={error} onRetry={reload} />
  if (!a) return null

  const decide = async (decision: 'approve' | 'reject') => {
    setBusy(true)
    setActionErr(null)
    try {
      const r = await api.decideApproval(a.approval_id, decision, comment)
      notify(`${decision === 'approve' ? 'Approved' : 'Rejected'} ${r.approval_id} as ${r.approver}.`)
      reload()
    } catch (e) {
      if (e instanceof ApiError && !e.network) {
        setActionErr(e)
        reportError(e)
      } else reportError(e)
      reload()
    } finally {
      setBusy(false)
    }
  }

  const expired = a.status === 'expired'
  const pending = a.status === 'pending'
  const isRequester = user?.user_id === a.requester
  const left = new Date(a.expires_at).getTime() - now

  return (
    <div className={`space-y-5 ${expired ? 'opacity-60' : ''}`}>
      <div>
        <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
          <span className="border border-hold px-2 py-0.5 font-bold uppercase text-hold">{KIND_LABEL[a.kind] ?? a.kind}</span>
          <span className="text-dim">{a.approval_id}</span>
          <StatusPill a={a} />
        </div>
        <h2 className="mt-2 break-words text-xl font-semibold leading-tight tracking-tight">{a.summary}</h2>
        <p className="mt-1 font-mono text-sm text-dim">
          requested by <b className="text-fg">{a.requester}</b> · {pending ? (left > 0 ? `expires in ${fmtDur(left)}` : 'past expiry') : a.status}
        </p>
      </div>

      {expired && <p className="rounded-xl border border-line-strong p-3 font-semibold">Expired, the agent must re-propose.</p>}

      <ReviewBody a={a} />

      {!pending ? (
        <div className="rounded-xl border border-line-strong p-4">
          <p className="mb-2 text-sm font-medium text-dim">Decision, read-only</p>
          <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5">
            <dt className="text-dim">Status</dt>
            <dd className="font-semibold capitalize">{a.status}</dd>
            {a.approver && (
              <>
                <dt className="text-dim">Approver</dt>
                <dd className="font-mono">{a.approver}</dd>
              </>
            )}
            {a.comment && (
              <>
                <dt className="text-dim">Comment</dt>
                <dd>{a.comment}</dd>
              </>
            )}
            {a.signature && (
              <>
                <dt className="text-dim">Signature</dt>
                <dd>
                  <HashText value={a.signature} chars={16} />
                </dd>
              </>
            )}
          </dl>
        </div>
      ) : (
        <div className="space-y-3 border-2 border-line-strong p-4">
          <label className="block">
            <span className="mb-1 block text-sm font-medium text-dim">Comment (optional)</span>
            <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="e.g. Recipient is not an Acme address." className="w-full rounded-lg border border-line-strong bg-ink px-3 py-2" />
          </label>
          {isRequester && (
            <p className="text-sm text-hold">
              You are the requester. Sentinel will refuse your approval. The button still sends the request so the refusal is real and ledgered.
            </p>
          )}
          {user && !isRequester && !user.roles.some((r) => (a.kind === 'policy.update' ? r === 'admin' : r === 'approver' || r === 'admin')) && (
            <p className="text-sm text-hold">Your role ({user.roles.join(', ')}) may not decide this. The server will refuse and name the required role.</p>
          )}
          <div className="flex gap-3">
            <button className={button('primary') + ' h-10 flex-1'} disabled={busy} onClick={() => decide('approve')}>
              Approve
            </button>
            <button className={button('danger') + ' h-10 flex-1'} disabled={busy} onClick={() => decide('reject')}>
              Reject
            </button>
          </div>
        </div>
      )}
      {actionErr && <ServerError error={actionErr} />}
    </div>
  )
}

function StatusPill({ a }: { a: ApprovalRecord }) {
  const cls = a.status === 'pending' ? 'text-hold border-hold' : a.status === 'approved' ? 'text-allow border-allow' : a.status === 'rejected' ? 'text-block border-block' : 'text-dim border-line-strong'
  return <span className={`border px-2 py-0.5 font-bold uppercase ${cls}`}>{a.status}</span>
}

function ReviewBody({ a }: { a: ApprovalRecord }) {
  const r = a.review
  const rules = r.rule_ids ?? []
  const to = Array.isArray(r.arguments?.to) ? (r.arguments!.to as unknown[]).filter((x): x is string => typeof x === 'string') : []
  return (
    <div className="space-y-5">
      {r.arguments && (
        <div>
          <p className="mb-1 text-sm font-medium text-dim">Exact arguments, verbatim</p>
          <JsonView value={{ action_type: r.action_type, arguments: r.arguments }} highlight={to} />
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        {r.fingerprint && (
          <div className="rounded-xl border border-line p-3">
            <p className="text-sm font-medium text-dim">Fingerprint</p>
            <HashText value={r.fingerprint} />
          </div>
        )}
        {r.taint_level !== undefined && (
          <div className="rounded-xl border border-line p-3">
            <p className="mb-1 text-sm font-medium text-dim">Session taint</p>
            <TaintBadge taint={r.taint_level} />
          </div>
        )}
        {r.blast && (
          <div className="rounded-xl border border-line p-3">
            <p className="mb-1 text-sm font-medium text-dim">Blast radius</p>
            <span className="font-mono font-bold uppercase text-block">{r.blast.level}</span>
            {r.blast.reason && <span className="ml-2 text-sm text-dim">{r.blast.reason}</span>}
          </div>
        )}
        {r.decision_path && (
          <div className="rounded-xl border border-line p-3">
            <p className="mb-1 text-sm font-medium text-dim">Decision path</p>
            <PathChip path={r.decision_path} />
          </div>
        )}
      </div>

      {rules.length > 0 && (
        <div>
          <p className="mb-2 text-sm font-medium text-dim">Rules that matched</p>
          <ul className="space-y-1.5">
            {rules.map((id) => (
              <li key={id} className="flex items-baseline gap-3">
                <RuleChip id={id} reason={r.rule_reasons?.[id]} />
                <span className="text-dim">{r.rule_reasons?.[id] ?? ''}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {a.kind === 'action' && (
        <div className="border border-path-llm/50 bg-path-llm/5 p-4">
          <p className="mb-1 flex items-center gap-2 text-sm font-medium text-path-llm">
            LLM summary <span className="border border-path-llm px-1.5 font-bold">advisory</span>
          </p>
          {r.llm ? (
            <>
              <p>{r.llm.summary}</p>
              <p className="mt-2 flex flex-wrap gap-1.5">
                {r.llm.risk_flags.map((f) => (
                  <span key={f} className="border border-line-strong px-1.5 font-mono text-xs text-dim">
                    {f}
                  </span>
                ))}
                <span className="font-mono text-xs text-dim">suggests {r.llm.suggested_outcome}. Rules decide, not the model.</span>
              </p>
            </>
          ) : (
            <p className="text-dim">Unavailable, decided by rules.</p>
          )}
        </div>
      )}

      {r.diff && (
        <div>
          <p className="mb-1 text-sm font-medium text-dim">Structural diff</p>
          <JsonView value={r.diff} />
        </div>
      )}

      {r.findings && (
        <div>
          <p className="mb-1 text-sm font-medium text-dim">Redacted findings</p>
          <ul className="space-y-1">
            {r.findings.map((f, i) => (
              <li key={i} className="font-mono text-sm">
                {f.type} · {f.detector} · {f.confidence_pct}% · <span className="text-dim">{f.evidence}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {r.text_redacted && (
        <div>
          <p className="mb-1 text-sm font-medium text-dim">Text, redacted</p>
          <pre className="whitespace-pre-wrap break-words border border-line bg-ink p-3 font-mono text-sm">{r.text_redacted}</pre>
        </div>
      )}
    </div>
  )
}

export default function Approvals() {
  const { id } = useParams()
  const nav = useNavigate()
  const [tab, setTab] = useState<'pending' | 'decided'>('pending')
  const list = usePoll(() => api.approvals({ status: '' }), 2000)

  useEffect(() => {
    if (!id && list.data?.length) {
      const first = list.data.find((a) => a.status === 'pending')
      if (first) nav(`/approvals/${first.approval_id}`, { replace: true })
    }
  }, [id, list.data, nav])

  return (
    <div className="space-y-5 p-5 lg:p-6">
      <PageHeader title="Approvals" lead="Risky actions wait here for a human." />
      {list.error != null && !list.data && <ErrorBanner error={list.error} onRetry={list.reload} />}
      {list.loading && !list.data && <Skeleton rows={4} />}
      {list.data && (
        <div className="grid items-start gap-5 lg:grid-cols-[22rem_minmax(0,1fr)]">
          <Queue items={list.data} selected={id} tab={tab} setTab={setTab} />
          <section aria-label="Approval detail" className="min-w-0 rounded-xl border border-line bg-panel p-5 lg:p-6">
            {id ? <Detail id={id} /> : <EmptyState title="No held actions" hint="When ActionGate holds an action, it shows up in the queue with its exact arguments." />}
          </section>
        </div>
      )}
    </div>
  )
}
