import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import type { ReplayStatus, SandboxStep } from '../api/types'
import { EmptyState, ErrorBanner, JsonView, OutcomeChip, OutcomeLegend, PageHeader, PathChip, Panel, RuleChip, Skeleton, TaintBadge, button } from '../components/ui'
import { useApp } from '../state/AppContext'
import { useSandbox } from '../state/SandboxContext'

const MARKER = /(\[removed by Sentinel:[^\]]*\])/g

function MarkedText({ text }: { text: string }) {
  return (
    <p className="whitespace-pre-wrap break-words">
      {text.split(MARKER).map((seg, i) =>
        seg.startsWith('[removed by Sentinel:') ? (
          <mark key={i} className="mx-0.5 rounded border border-sanitize/60 bg-sanitize/20 px-1 font-mono text-sm font-semibold text-sanitize">
            {seg}
          </mark>
        ) : (
          <span key={i}>{seg}</span>
        ),
      )}
    </p>
  )
}

function Chips({ s }: { s: SandboxStep }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {s.outcome && <OutcomeChip outcome={s.outcome} />}
      {s.decision_path && <PathChip path={s.decision_path} />}
      {s.rule_ids?.map((r) => <RuleChip key={r} id={r} />)}
    </div>
  )
}

function ChatItem({ s }: { s: SandboxStep }) {
  if (s.kind === 'user')
    return (
      <div className="rise ml-auto max-w-[85%] rounded-2xl rounded-br-md bg-fg px-4 py-2.5 text-ink">
        <p className="whitespace-pre-wrap break-words font-medium">{s.text}</p>
      </div>
    )
  if (s.kind === 'reply')
    return (
      <div className="rise max-w-[85%] rounded-2xl rounded-bl-md border border-line bg-raised px-4 py-2.5">
        <p className="mb-0.5 text-xs font-medium text-faint">SupportBot</p>
        <p className="whitespace-pre-wrap break-words">{s.text}</p>
      </div>
    )
  if (s.kind === 'system')
    return (
      <p className={`rise border-l-2 py-1 pl-3 font-mono text-sm ${s.error_code ? 'border-block text-block' : 'border-line-strong text-dim'}`}>
        {s.text}
        {s.error_code && <span className="ml-2 text-xs opacity-80">({s.error_code})</span>}
      </p>
    )
  if (s.kind === 'ingress')
    return (
      <div className="rise space-y-2 rounded-xl border border-sanitize/30 bg-sanitize/5 p-3">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-semibold text-sanitize">PromptShield</span>
          <TaintBadge taint={s.session?.taint_label} />
        </div>
        <Chips s={s} />
        <MarkedText text={s.text} />
        {s.reason && <p className="text-sm text-dim">{s.reason}</p>}
        {s.approval_id && (
          <Link to={`/approvals/${s.approval_id}`} className="text-sm font-semibold underline">
            Escalated for human review, {s.approval_id}
          </Link>
        )}
      </div>
    )
  // action
  const notApproved = s.error_code === 'approval.not_approved'
  return (
    <div className={`rise space-y-2 rounded-xl border bg-panel p-3 ${s.outcome === 'block' ? 'border-block/60' : s.outcome === 'hold' ? 'border-hold/60' : 'border-line-strong'}`}>
      <span className="text-xs font-semibold text-dim">ActionGate</span>
      <p className="font-semibold">{s.text}</p>
      <Chips s={s} />
      {s.reason && !notApproved && <p className="text-sm text-dim">{s.reason}</p>}
      {s.outcome === 'hold' && s.approval_id && (
        <Link to={`/approvals/${s.approval_id}`} className="inline-block text-sm font-bold text-hold underline">
          Open approval {s.approval_id} →
        </Link>
      )}
      {s.outcome === 'block' && s.rule_ids && s.rule_ids.length > 0 && <p className="font-mono text-sm text-block">Blocked by {s.rule_ids.join(', ')}</p>}
    </div>
  )
}

const STATUS: Record<ReplayStatus, { glyph: string; cls: string }> = {
  pending: { glyph: '○', cls: 'text-faint border-line' },
  running: { glyph: '◔', cls: 'text-sanitize border-sanitize' },
  matched: { glyph: '✓', cls: 'text-allow border-allow/60' },
  mismatch: { glyph: '✕', cls: 'text-block border-block' },
}

function Chat() {
  const { session } = useApp()
  const { items, send, busy, blockedLedger, createSession } = useSandbox()
  const [text, setText] = useState('')
  const end = useRef<HTMLDivElement>(null)
  useEffect(() => {
    end.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [items.length])

  return (
    <Panel title="Chat with SupportBot" className="min-h-[28rem] lg:h-[34rem]">
      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        {!session && (
          <EmptyState title="No session" hint="Start one to chat." action={<button className={button('primary')} onClick={createSession}>New session</button>} />
        )}
        {session && items.length === 0 && <p className="text-dim">Say hi, or try a poisoned review.</p>}
        {items.map((i) => (
          <ChatItem key={i.id} s={i.step} />
        ))}
        {blockedLedger && (
          <div role="alert" className="rounded-xl border border-block bg-block/10 p-3 font-semibold text-block">
            Decision could not be recorded, nothing was executed. (ledger.unavailable)
          </div>
        )}
        <div ref={end} />
      </div>
      <form
        className="flex gap-2 border-t border-line p-3"
        onSubmit={(e) => {
          e.preventDefault()
          const t = text.trim()
          if (!t || !session) return
          setText('')
          void send(t)
        }}
      >
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={!session}
          placeholder={session ? 'Message SupportBot' : 'Create a session first'}
          className="min-w-0 flex-1 rounded-sm border border-line-strong bg-ink px-3 py-2 text-[14px] placeholder:text-faint transition-colors hover:border-faint focus-visible:border-fg disabled:opacity-50"
        />
        <button className={button('primary')} disabled={!session || busy || !text.trim()}>
          Send
        </button>
      </form>
    </Panel>
  )
}

// IDs from the seed data. The API has no list endpoint, so the review text is only shown once the server screens it.
const REVIEWS = [
  { id: 'rv-p1', style: 'Blunt override' },
  { id: 'rv-p2', style: 'Polite directive' },
  { id: 'rv-p3', style: 'Hidden HTML comment' },
  { id: 'rv-p4', style: 'Image beacon' },
  { id: 'rv-p5', style: 'Base64 instruction' },
]

function SessionPanel() {
  const { session, user } = useApp()
  const { createSession, loadReview, busy, resetSandbox } = useSandbox()
  const [sel, setSel] = useState('rv-p2')
  const isAdmin = user?.roles.includes('admin')

  return (
    <Panel title="Try an attack" className="lg:h-[34rem]">
      <div className="flex-1 space-y-5 overflow-y-auto p-4">
        <div className="space-y-2">
          <button className={button('primary') + ' w-full'} onClick={createSession} disabled={busy}>
            New session
          </button>
          <div className="flex items-center justify-between text-sm">
            <span className="text-dim">Session</span>
            <span className="font-mono">{session?.session_id ?? '–'}</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-dim">Owner</span>
            <span className="font-mono">{session?.owner_user_id ?? '–'}</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-dim">Taint</span>
            {session ? <TaintBadge taint={session.taint_label ?? session.taint_level} /> : <span>–</span>}
          </div>
        </div>

        <div className="space-y-2 border-t border-line pt-4">
          <h3 className="text-sm font-semibold">Poisoned product review</h3>
          <select aria-label="Poisoned review" value={sel} onChange={(e) => setSel(e.target.value)} className="w-full rounded-lg border border-line-strong bg-ink px-2 py-2">
            {REVIEWS.map((r) => (
              <option key={r.id} value={r.id}>
                {r.id} · {r.style}
              </option>
            ))}
          </select>
          <button className={button('ghost') + ' w-full'} disabled={!session || busy} onClick={() => loadReview(sel)}>
            Give this review to the agent
          </button>
        </div>

        <div className="space-y-1 border-t border-line pt-4">
          <button className={button('danger') + ' w-full'} disabled={!isAdmin || busy} onClick={() => resetSandbox()} title={isAdmin ? undefined : 'Needs the admin role'}>
            Reset sandbox
          </button>
          
        </div>
      </div>
    </Panel>
  )
}

function OutboxPanel() {
  const { outbox, outboxError, refreshOutbox } = useSandbox()
  const [tab, setTab] = useState<'emails' | 'db'>('emails')
  const emails = outbox?.emails ?? []
  const ops = outbox?.db_ops ?? []
  return (
    <Panel title="What actually happened" className="lg:h-[34rem]">
      <div role="tablist" className="flex border-b border-line">
        {(['emails', 'db'] as const).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)} className={`flex-1 border-b-2 px-3 py-2 text-sm font-semibold ${tab === t ? 'border-fg text-fg' : 'border-transparent text-dim hover:text-fg'}`}>
            {t === 'emails' ? `Emails (${emails.length})` : `Database (${ops.length})`}
          </button>
        ))}
      </div>
      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        {outboxError != null && <ErrorBanner error={outboxError} onRetry={refreshOutbox} />}
        {!outbox && outboxError == null && <Skeleton rows={3} />}
        {outbox && tab === 'emails' && (emails.length === 0 ? <EmptyState title="Nothing yet"  /> : emails.map((m) => (
          <div key={m.outbox_id} className="space-y-1 rounded-xl border border-line p-3">
            <span className="rounded-xs border border-hold/50 px-1.5 font-mono text-[10px] font-medium uppercase tracking-wider text-hold">Simulated</span>
            <p className="font-mono text-sm">To: {m.to.join(', ')}</p>
            <p className="font-semibold">{m.subject}</p>
            <p className="whitespace-pre-wrap break-words text-sm text-dim">{m.body_excerpt}</p>
          </div>
        )))}
        {outbox && tab === 'db' && (ops.length === 0 ? <EmptyState title="Nothing yet"  /> : ops.map((o) => (
          <div key={o.op_id} className="space-y-1 rounded-xl border border-line p-3">
            <span className="rounded-xs border border-hold/50 px-1.5 font-mono text-[10px] font-medium uppercase tracking-wider text-hold">Simulated</span>
            <p className="font-mono text-sm">{o.op} {o.resource}</p>
            <p className="text-sm text-dim">{o.record_count} records</p>
          </div>
        )))}
      </div>
    </Panel>
  )
}

function ReplayBar() {
  const { replay, results, nextStep, startReplay, autoplay, setAutoplay, busy } = useSandbox()
  const [open, setOpen] = useState<string | null>(null)
  const done = replay.length > 0 && replay.every((s) => s.status !== 'pending')
  const openRes = open ? results[open] : null
  return (
    <Panel
      title="Guided demo"
      right={
        <div className="flex items-center gap-2">
          <button className={button('ghost')} onClick={startReplay} disabled={busy}>
            {replay.length ? 'Restart' : 'Start'}
          </button>
          <button className={button('primary')} onClick={() => void nextStep()} disabled={busy || done || autoplay}>
            Next step
          </button>
          <button className={button('ghost')} aria-pressed={autoplay} onClick={() => setAutoplay(!autoplay)} disabled={done}>
            {autoplay ? 'Stop' : 'Auto-play'}
          </button>
        </div>
      }
    >
      {replay.length === 0 ? (
        <p className="p-4 text-dim">Press Next step to begin.</p>
      ) : (
        <ol className="grid gap-px bg-line sm:grid-cols-2 xl:grid-cols-4">
          {replay.map((s) => {
            const st = STATUS[s.status]
            return (
              <li key={s.id} className="bg-panel">
                <button
                  onClick={() => setOpen(open === s.id ? null : s.id)}
                  disabled={!results[s.id]}
                  aria-expanded={open === s.id}
                  className="flex h-full w-full items-start gap-3 p-3 text-left enabled:hover:bg-raised"
                >
                  <span className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border font-mono text-sm font-bold ${st.cls}`} aria-hidden>
                    {st.glyph}
                  </span>
                  <span>
                    <span className="text-xs capitalize text-faint">
                      {s.id} · {s.actor} · {s.status}
                    </span>
                    <span className="block text-sm font-semibold leading-snug">{s.title}</span>
                  </span>
                </button>
              </li>
            )
          })}
        </ol>
      )}
      {openRes && (
        <div className="grid gap-4 border-t border-line p-4 md:grid-cols-2">
          <div>
            <p className="mb-1 text-sm font-medium text-dim">Expected</p>
            <JsonView value={openRes.expected} />
          </div>
          <div>
            <p className={`mb-1 text-sm font-medium ${openRes.match ? 'text-allow' : 'text-block'}`}>Actual · {openRes.match ? 'match' : 'MISMATCH'}</p>
            <JsonView value={openRes.actual} />
          </div>
        </div>
      )}
    </Panel>
  )
}

export default function Sandbox() {
  return (
    <div className="space-y-5 p-5 lg:p-6">
      <PageHeader
        title="Agent Sandbox"
        lead="Watch Sentinel stop an attack on an AI agent."
        right={<OutcomeLegend />}
      />
      <ReplayBar />
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_minmax(0,1fr)]">
        <Chat />
        <SessionPanel />
        <OutboxPanel />
      </div>
    </div>
  )
}
