import { useState, type ReactNode } from 'react'
import type { DecisionPath, Outcome, TaintLabel, TaintLevel } from '../api/types'
import { ApiError } from '../api/types'

const OUTCOME_STYLE: Record<string, { cls: string; glyph: string }> = {
  allow: { cls: 'text-allow border-allow/50 bg-allow/10', glyph: '●' },
  ok: { cls: 'text-allow border-allow/50 bg-allow/10', glyph: '●' },
  sanitize: { cls: 'text-sanitize border-sanitize/50 bg-sanitize/10', glyph: '◐' },
  hold: { cls: 'text-hold border-hold/50 bg-hold/10', glyph: '❙❙' },
  escalate: { cls: 'text-hold border-hold/50 bg-hold/10', glyph: '▲' },
  block: { cls: 'text-block border-block/60 bg-block/10', glyph: '■' },
  refused: { cls: 'text-block border-block/60 bg-block/10', glyph: '■' },
  info: { cls: 'text-dim border-line-strong bg-raised', glyph: '○' },
}

export function OutcomeChip({ outcome, size = 'md' }: { outcome: Outcome | string; size?: 'sm' | 'md' | 'lg' }) {
  const s = OUTCOME_STYLE[outcome] ?? OUTCOME_STYLE.info
  const sz = size === 'lg' ? 'px-2.5 py-1 text-xs' : size === 'sm' ? 'px-1.5 py-0 text-[10px]' : 'px-2 py-0.5 text-[11px]'
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-xs border font-mono font-semibold uppercase leading-5 tracking-wider ${sz} ${s.cls}`}>
      <span aria-hidden className="text-[0.8em] leading-none">
        {s.glyph}
      </span>
      {outcome}
    </span>
  )
}

const PATH_STYLE: Record<string, string> = {
  rules: 'text-path-rules border-path-rules/40',
  'rules+llm': 'text-path-llm border-path-llm/50 bg-path-llm/10',
  fallback: 'text-path-fallback border-path-fallback/60 bg-path-fallback/10',
  'n/a': 'text-faint border-line',
}
export function PathChip({ path }: { path: DecisionPath | string }) {
  return <span className={`inline-block rounded-xs border px-1.5 py-0 font-mono text-[11px] font-medium ${PATH_STYLE[path] ?? PATH_STYLE['n/a']}`}>{path}</span>
}

export function RuleChip({ id, reason }: { id: string; reason?: string }) {
  return (
    <span title={reason ?? id} className="inline-block rounded-xs border border-line bg-raised px-1.5 py-0 font-mono text-[11px] text-fg">
      {id}
    </span>
  )
}

const TAINT: Record<TaintLabel, { cls: string; dot: string }> = {
  clean: { cls: 'text-allow border-allow/50', dot: 'bg-allow' },
  untrusted_present: { cls: 'text-hold border-hold/50', dot: 'bg-hold' },
  flagged: { cls: 'text-block border-block/60', dot: 'bg-block' },
}
const TAINT_TEXT: Record<TaintLabel, string> = { clean: 'Clean', untrusted_present: 'Untrusted content', flagged: 'Flagged' }
const LABELS: TaintLabel[] = ['clean', 'untrusted_present', 'flagged']

export function normalizeTaint(t: unknown): TaintLabel | null {
  if (t === null || t === undefined) return null
  if (typeof t === 'number') return LABELS[t] ?? null
  if (typeof t === 'string') return (LABELS as string[]).includes(t) ? (t as TaintLabel) : null
  if (typeof t === 'object') {
    const o = t as { taint_label?: TaintLabel; taint_level?: TaintLevel }
    return o.taint_label ?? (o.taint_level !== undefined ? LABELS[o.taint_level] : null)
  }
  return null
}

export function TaintBadge({ taint, onClick, title }: { taint: unknown; onClick?: () => void; title?: string }) {
  const l = normalizeTaint(taint)
  if (!l) return <span className="text-faint">–</span>
  const s = TAINT[l]
  const Tag = onClick ? 'button' : 'span'
  return (
    <Tag
      onClick={onClick}
      title={title}
      className={`inline-flex items-center gap-1.5 rounded-xs border px-1.5 py-0 text-xs font-medium ${s.cls} ${onClick ? 'cursor-pointer hover:bg-raised' : ''}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} aria-hidden />
      {TAINT_TEXT[l]}
    </Tag>
  )
}

export function Skeleton({ rows = 5, className = '' }: { rows?: number; className?: string }) {
  return (
    <div className={`space-y-2 ${className}`} role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton h-9 rounded-xs" style={{ opacity: 1 - i * 0.12 }} />
      ))}
    </div>
  )
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="rise flex flex-col items-start gap-1.5 border border-dashed border-line-strong px-6 py-10">
      <p className="eyebrow">Nothing to show</p>
      <p className="text-base font-semibold">{title}</p>
      {hint && <p className="max-w-prose text-dim">{hint}</p>}
      {action}
    </div>
  )
}

export function ErrorBanner({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const e = error instanceof ApiError ? error : null
  const msg = e ? e.message : error instanceof Error ? error.message : 'Something went wrong.'
  return (
    <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xs border border-block/50 border-l-4 border-l-block bg-block/10 px-4 py-2.5">
      <span className="font-mono text-xs font-bold uppercase tracking-wider text-block">Error{e ? ` ${e.code}` : ''}</span>
      <span className="flex-1">{msg}</span>
      {e?.requestId && <CopyText text={e.requestId} label={e.requestId} />}
      {onRetry && (
        <button onClick={onRetry} className={button("ghost", "sm")}>
          Retry
        </button>
      )}
    </div>
  )
}

export function CopyText({ text, label }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      title="Copy"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1200)
        })
      }}
      className="font-mono text-xs text-dim underline decoration-dotted underline-offset-2 hover:text-fg"
    >
      {done ? 'copied' : (label ?? text)}
    </button>
  )
}

export function HashText({ value, chars = 12 }: { value: string; chars?: number }) {
  return (
    <span className="inline-flex items-center gap-2 font-mono text-sm">
      <span>{value.slice(0, chars)}…</span>
      <CopyText text={value} label="copy" />
    </span>
  )
}

export function Panel({ title, hint, right, children, className = '' }: { title?: ReactNode; hint?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`flex min-h-0 flex-col overflow-hidden rounded-sm border border-line bg-panel ${className}`}>
      {(title || right) && (
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <div className="min-w-0">
            <h2 className="eyebrow !text-dim">{title}</h2>
            {hint && <p className="mt-0.5 text-xs text-faint">{hint}</p>}
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  )
}

export function JsonView({ value, highlight = [] }: { value: unknown; highlight?: string[] }) {
  const text = JSON.stringify(value, null, 2) ?? ''
  const parts: ReactNode[] = []
  if (highlight.length) {
    const re = new RegExp(`(${highlight.map((h) => h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'g')
    text.split(re).forEach((seg, i) => parts.push(highlight.includes(seg) ? <mark key={i} className="bg-block/30 px-0.5 font-bold text-block">{seg}</mark> : seg))
  } else parts.push(text)
  return (
    <div className="relative">
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-xs border border-line bg-ink p-3 font-mono text-xs leading-relaxed">{parts}</pre>
      <div className="absolute right-2 top-2 bg-ink/80 px-1">
        <CopyText text={text} label="copy" />
      </div>
    </div>
  )
}

export const field =
  'h-8 rounded-sm border border-line-strong bg-ink px-2.5 text-[13px] text-fg placeholder:text-faint transition-colors hover:border-faint focus-visible:border-fg'

export function timeShort(ts: string) {
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleTimeString([], { hour12: false })
}

export function button(kind: 'primary' | 'ghost' | 'danger' = 'ghost', size: 'md' | 'sm' = 'md') {
  const dim = size === 'sm' ? 'h-7 px-2.5 text-xs ' : 'h-8 px-3.5 text-[13px] '
  const base = `inline-flex ${dim}shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-sm font-semibold transition-colors active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40 `
  if (kind === 'primary') return base + 'bg-fg text-ink hover:bg-white'
  if (kind === 'danger') return base + 'border border-block/60 bg-block/5 text-block hover:bg-block hover:text-ink'
  return base + 'border border-line-strong text-dim hover:border-fg hover:bg-raised hover:text-fg'
}

export function PageHeader({ title, lead, right }: { title: string; lead?: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 border-b border-line pb-4">
      <div className="max-w-3xl">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {lead && <p className="mt-0.5 text-[13px] text-dim">{lead}</p>}
      </div>
      {right}
    </div>
  )
}

const LEGEND: { o: Outcome | string; text: string }[] = [
  { o: 'allow', text: '' },
  { o: 'sanitize', text: '' },
  { o: 'hold', text: '' },
  { o: 'block', text: '' },
]
export function OutcomeLegend() {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {LEGEND.map((l) => (
        <OutcomeChip key={l.o} outcome={l.o} size="sm" />
      ))}
    </div>
  )
}
