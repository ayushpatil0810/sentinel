import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import type { DecisionItem, LedgerEntry } from '../api/types'
import { field, EmptyState, PageHeader, OutcomeLegend, ErrorBanner, HashText, JsonView, OutcomeChip, PathChip, RuleChip, Skeleton, TaintBadge, button, timeShort } from '../components/ui'
import { useApp } from '../state/AppContext'

const EDGE: Record<string, string> = {
  allow: '[--edge:var(--color-allow)]',
  sanitize: '[--edge:var(--color-sanitize)]',
  hold: '[--edge:var(--color-hold)]',
  escalate: '[--edge:var(--color-hold)]',
  block: '[--edge:var(--color-block)]',
  refused: '[--edge:var(--color-block)]',
  info: '[--edge:var(--color-line-strong)]',
}
const MODULES = ['promptshield', 'actiongate', 'approvals', 'llm']
const OUTCOMES = ['allow', 'sanitize', 'hold', 'escalate', 'block', 'refused', 'info']
const PATHS = ['rules', 'rules+llm', 'fallback']

function Drawer({ seq, onClose }: { seq: number; onClose: () => void }) {
  const [entry, setEntry] = useState<LedgerEntry | null>(null)
  const [error, setError] = useState<unknown>(null)
  useEffect(() => {
    setEntry(null)
    setError(null)
    api.ledgerEntry(seq).then(setEntry, setError)
  }, [seq])
  return (
    <aside className="rise fixed inset-y-0 right-0 z-40 flex w-[34rem] max-w-full flex-col border-l border-line-strong bg-panel shadow-[-24px_0_48px_-12px_rgba(0,0,0,0.6)]" aria-label={`Ledger entry ${seq}`}>
      <header className="flex items-center justify-between border-b border-line px-5 py-3">
        <h2 className="font-mono text-sm font-semibold">Ledger entry #{seq}</h2>
        <button onClick={onClose} className={button('ghost', 'sm')} autoFocus>
          Close
        </button>
      </header>
      <div className="flex-1 space-y-4 overflow-y-auto p-5">
        {error != null && <ErrorBanner error={error} />}
        {!entry && error == null && <Skeleton rows={6} />}
        {entry && (
          <>
            <dl className="grid grid-cols-[7rem_1fr] gap-y-2.5 text-[13px] [&>dt]:eyebrow [&>dt]:pt-0.5">
              <dt className="text-dim">Event</dt>
              <dd className="font-mono">{entry.event_type}</dd>
              <dt className="text-dim">Module</dt>
              <dd className="font-mono">{entry.module}</dd>
              <dt className="text-dim">Subject</dt>
              <dd className="break-all font-mono">{entry.subject}</dd>
              <dt className="text-dim">Outcome</dt>
              <dd>
                <OutcomeChip outcome={entry.outcome} />
              </dd>
              <dt className="text-dim">Path</dt>
              <dd>
                <PathChip path={entry.decision_path} />
              </dd>
              <dt className="text-dim">Reason</dt>
              <dd>{entry.reason}</dd>
              <dt className="text-dim">Policy</dt>
              <dd className="font-mono">v{entry.policy_version}</dd>
              <dt className="text-dim">prev_hash</dt>
              <dd>
                <HashText value={entry.prev_hash} />
              </dd>
              <dt className="text-dim">hash</dt>
              <dd>
                <HashText value={entry.hash} />
              </dd>
            </dl>
            <div>
              <p className="eyebrow mb-1.5">Redacted payload</p>
              <JsonView value={entry.payload ?? null} />
            </div>
          </>
        )}
      </div>
    </aside>
  )
}

export default function Decisions() {
  const { user } = useApp()
  const [rows, setRows] = useState<DecisionItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)
  const [paused, setPaused] = useState(false)
  const [module, setModule] = useState('')
  const [outcome, setOutcome] = useState('')
  const [path, setPath] = useState('')
  const [subject, setSubject] = useState('')
  const [open, setOpen] = useState<number | null>(null)
  const nextSeq = useRef(0)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    nextSeq.current = 0
    setRows([])
    setLoading(true)
  }, [module, outcome, reloadKey])

  useEffect(() => {
    if (!user || paused) return
    let stop = false
    const run = async () => {
      if (document.hidden) return
      try {
        const res = await api.decisions({ since_seq: nextSeq.current, module, outcome, limit: 100 })
        if (stop) return
        if (res.items.length) setRows((cur) => [...res.items, ...cur].slice(0, 500))
        nextSeq.current = res.next_seq
        setError(null)
      } catch (e) {
        if (!stop) setError(e)
      } finally {
        if (!stop) setLoading(false)
      }
    }
    run()
    const t = setInterval(run, 2000)
    return () => {
      stop = true
      clearInterval(t)
    }
  }, [user, paused, module, outcome, reloadKey])

  const shown = rows.filter((r) => (!path || r.decision_path === path) && (!subject || r.subject.toLowerCase().includes(subject.toLowerCase())))
  const sel = field

  return (
    <div className="space-y-5 p-5 lg:p-6">
      <PageHeader
        title="Live Decisions"
        lead="Every verdict, live. Click a row for details."
        right={<OutcomeLegend />}
      />
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="Module" value={module} onChange={(e) => setModule(e.target.value)} className={sel}>
            <option value="">All modules</option>
            {MODULES.map((m) => <option key={m}>{m}</option>)}
          </select>
          <select aria-label="Outcome" value={outcome} onChange={(e) => setOutcome(e.target.value)} className={sel}>
            <option value="">All outcomes</option>
            {OUTCOMES.map((m) => <option key={m}>{m}</option>)}
          </select>
          <select aria-label="Decision path" value={path} onChange={(e) => setPath(e.target.value)} className={sel}>
            <option value="">All paths</option>
            {PATHS.map((m) => <option key={m}>{m}</option>)}
          </select>
          <input aria-label="Subject filter" placeholder="Filter subject" value={subject} onChange={(e) => setSubject(e.target.value)} className={sel + ' w-40'} />
          <button className={button(paused ? 'primary' : 'ghost')} onClick={() => setPaused((p) => !p)}>
            {paused ? 'Resume' : 'Pause'}
          </button>
        </div>
      </div>

      {error != null && <ErrorBanner error={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      {loading && rows.length === 0 && <Skeleton rows={6} />}
      {!loading && shown.length === 0 && error == null && (
        <EmptyState title="No decisions yet." hint={rows.length ? 'No rows match the current filters.' : 'Send a message in the Sandbox.'} />
      )}

      {shown.length > 0 && (
        <div className="overflow-x-auto rounded-sm border border-line">
          <table className="w-full min-w-[64rem] border-collapse text-left text-[13px]">
            <caption className="sr-only">Decisions feed, newest first</caption>
            <thead className="bg-panel">
              <tr>
                {['Time', 'Module', 'Subject', 'Event', 'Outcome', 'Reason', 'Rules', 'Path', 'Taint'].map((h) => (
                  <th key={h} scope="col" className="eyebrow px-3 py-2 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr
                  key={r.seq}
                  tabIndex={0}
                  onClick={() => setOpen(r.seq)}
                  onKeyDown={(e) => e.key === 'Enter' && setOpen(r.seq)}
                  className={`cursor-pointer border-t border-line align-top shadow-[inset_3px_0_0_var(--edge)] transition-colors hover:bg-raised ${EDGE[r.outcome] ?? EDGE.info}`}
                >
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-dim">
                    <span className="text-faint">#{r.seq}</span> {timeShort(r.ts)}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{r.module}</td>
                  <td className="max-w-48 break-words px-3 py-2 font-mono text-xs">{r.subject}</td>
                  <td className="px-3 py-2 font-mono text-xs text-dim">{r.event_type}</td>
                  <td className="px-3 py-2">
                    <OutcomeChip outcome={r.outcome} />
                  </td>
                  <td className="max-w-80 px-3 py-2">{r.reason}</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">{r.rule_ids.map((id) => <RuleChip key={id} id={id} />)}</div>
                  </td>
                  <td className="px-3 py-2">
                    <PathChip path={r.decision_path} />
                  </td>
                  <td className="px-3 py-2">
                    <TaintBadge taint={r.session_taint} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {open !== null && <Drawer seq={open} onClose={() => setOpen(null)} />}
    </div>
  )
}
