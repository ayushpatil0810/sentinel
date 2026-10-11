import { useEffect, useState, useCallback, useRef } from "react"
import { api } from "../api/client"
import type { LedgerEntry, LedgerVerify } from "../api/types"
import {
  field,
  EmptyState,
  PageHeader,
  OutcomeLegend,
  ErrorBanner,
  HashText,
  JsonView,
  OutcomeChip,
  PathChip,
  RuleChip,
  Skeleton,
  button,
  timeShort,
} from "../components/ui"
import { useApp } from "../state/AppContext"

const MODULES = ["promptshield", "actiongate", "breachpath", "policy", "auth"]
const OUTCOMES = [
  "allow",
  "sanitize",
  "hold",
  "escalate",
  "block",
  "refused",
  "info",
]
const EVENT_TYPES = [
  "action.decided",
  "ingress.screened",
  "approval.requested",
  "approval.granted",
  "approval.rejected",
  "graph.uploaded",
  "graph.remediation_applied",
  "policy.activated",
  "auth.refused",
]

function Drawer({ seq, onClose }: { seq: number; onClose: () => void }) {
  const [entry, setEntry] = useState<LedgerEntry | null>(null)
  const [error, setError] = useState<unknown>(null)

  useEffect(() => {
    setEntry(null)
    setError(null)
    api.ledgerEntry(seq).then(setEntry, setError)
  }, [seq])

  return (
    <aside
      className="rise fixed inset-y-0 right-0 z-40 flex w-[36rem] max-w-full flex-col border-l border-line-strong bg-panel shadow-[-24px_0_48px_-12px_rgba(0,0,0,0.6)]"
      aria-label={`Ledger entry ${seq}`}
    >
      <header className="flex items-center justify-between border-b border-line px-5 py-3">
        <h2 className="font-mono text-sm font-semibold">
          Ledger entry #{seq}
        </h2>
        <button onClick={onClose} className={button("ghost", "sm")} autoFocus>
          Close
        </button>
      </header>
      <div className="flex-1 space-y-4 overflow-y-auto p-5">
        {error != null && <ErrorBanner error={error} />}
        {!entry && error == null && <Skeleton rows={8} />}
        {entry && (
          <>
            <dl className="grid grid-cols-[8rem_1fr] gap-y-2.5 text-[13px] [&>dt]:eyebrow [&>dt]:pt-0.5">
              <dt className="text-dim">Sequence</dt>
              <dd className="font-mono font-bold">#{entry.seq}</dd>
              <dt className="text-dim">Timestamp</dt>
              <dd className="font-mono">{entry.ts}</dd>
              <dt className="text-dim">Module</dt>
              <dd className="font-mono">{entry.module}</dd>
              <dt className="text-dim">Event</dt>
              <dd className="font-mono">{entry.event_type}</dd>
              <dt className="text-dim">Subject</dt>
              <dd className="break-all font-mono">{entry.subject}</dd>
              <dt className="text-dim">Outcome</dt>
              <dd>
                <OutcomeChip outcome={entry.outcome} />
              </dd>
              <dt className="text-dim">Decision path</dt>
              <dd>
                <PathChip path={entry.decision_path} />
              </dd>
              <dt className="text-dim">Reason</dt>
              <dd>{entry.reason}</dd>
              <dt className="text-dim">Rule IDs</dt>
              <dd>
                <div className="flex flex-wrap gap-1">
                  {entry.rule_ids.length ? (
                    entry.rule_ids.map((id) => <RuleChip key={id} id={id} />)
                  ) : (
                    <span className="text-faint">–</span>
                  )}
                </div>
              </dd>
              <dt className="text-dim">Policy</dt>
              <dd className="font-mono">v{entry.policy_version}</dd>
              <dt className="text-dim">prev_hash</dt>
              <dd>
                <HashText value={entry.prev_hash} chars={16} />
              </dd>
              <dt className="text-dim">hash</dt>
              <dd>
                <HashText value={entry.hash} chars={16} />
              </dd>
              {entry.payload_digest && (
                <>
                  <dt className="text-dim">payload_digest</dt>
                  <dd>
                    <HashText value={entry.payload_digest} chars={16} />
                  </dd>
                </>
              )}
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

function TamperModal({
  seq,
  onClose,
  onTampered,
}: {
  seq: number
  onClose: () => void
  onTampered: () => void
}) {
  const [fieldVal, setFieldVal] = useState("outcome")
  const [value, setValue] = useState("tampered")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const handleTamper = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.demoTamper(seq, fieldVal, value)
      onTampered()
      onClose()
    } catch (err) {
      setError(err)
      setBusy(false)
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="tamper-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs"
    >
      <div className="w-full max-w-md rounded-sm border-2 border-block/80 bg-panel p-6 shadow-2xl">
        <h2 id="tamper-title" className="text-base font-bold text-block">
          Tamper with row #{seq} (demo only)
        </h2>
        <p className="mt-2 text-sm leading-relaxed text-dim">
          This operation mutates SQLite directly via SQL, bypassing the append-only ledger triggers.
          It simulates an insider attacker altering historical records. Sentinel&apos;s cryptographic hash chain will detect this immediately upon verification.
        </p>

        {error != null && (
          <div className="mt-3">
            <ErrorBanner error={error} />
          </div>
        )}

        <form onSubmit={handleTamper} className="mt-4 space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-semibold text-dim">
              Field to mutate
            </span>
            <select
              value={fieldVal}
              onChange={(e) => setFieldVal(e.target.value)}
              className={`w-full ${field}`}
            >
              <option value="outcome">outcome</option>
              <option value="reason">reason</option>
              <option value="subject">subject</option>
              <option value="decision_path">decision_path</option>
            </select>
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-semibold text-dim">
              Tampered value
            </span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              className={`w-full ${field}`}
              required
            />
          </label>
          <div className="mt-5 flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={busy}
              className={button("ghost")}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className={button("danger")}
            >
              {busy ? "Tampering…" : "Tamper row"}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Ledger() {
  const { user, demoMode, ledgerVerify, verifyLedger } = useApp()
  const [rows, setRows] = useState<LedgerEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)
  const [verifying, setVerifying] = useState(false)
  const [module, setModule] = useState("")
  const [eventType, setEventType] = useState("")
  const [outcome, setOutcome] = useState("")
  const [subject, setSubject] = useState("")
  const [openDrawer, setOpenDrawer] = useState<number | null>(null)
  const [tamperSeq, setTamperSeq] = useState<number | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  const activeReq = useRef(0)

  const isAdmin = user?.roles.includes("admin")

  const loadData = useCallback(async () => {
    const id = ++activeReq.current
    try {
      const list = await api.ledger({
        module: module || undefined,
        event_type: eventType || undefined,
        outcome: outcome || undefined,
        subject: subject || undefined,
        limit: 200,
      })
      if (id === activeReq.current) {
        setRows(list)
        setError(null)
      }
    } catch (err) {
      if (id === activeReq.current) {
        setError(err)
      }
    } finally {
      if (id === activeReq.current) {
        setLoading(false)
      }
    }
  }, [module, eventType, outcome, subject])

  useEffect(() => {
    setLoading(true)
    loadData()
    const t = setInterval(() => {
      if (!document.hidden) void loadData()
    }, 2000)
    return () => clearInterval(t)
  }, [loadData, reloadKey])

  const runVerify = async () => {
    setVerifying(true)
    try {
      await verifyLedger()
    } finally {
      setVerifying(false)
    }
  }

  const handleTampered = () => {
    setReloadKey((k) => k + 1)
    void runVerify()
  }

  const brokenSeq = ledgerVerify && !ledgerVerify.valid ? ledgerVerify.first_broken_seq : null

  return (
    <div className="space-y-5 p-5 lg:p-6">
      <PageHeader
        title="Audit Ledger"
        lead="Hash-chained append-only record of every decision and event."
        right={
          <div className="flex flex-wrap items-center gap-3">
            {verifying ? (
              <span className="font-mono text-xs text-dim">Verifying…</span>
            ) : ledgerVerify ? (
              ledgerVerify.valid ? (
                <span className="inline-flex items-center gap-1.5 rounded-xs border border-allow/60 bg-allow/10 px-2.5 py-1 font-mono text-xs font-semibold text-allow">
                  <span className="h-2 w-2 rounded-full bg-allow" />
                  Valid ({ledgerVerify.checked} checked)
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-xs border border-block bg-block/15 px-2.5 py-1 font-mono text-xs font-bold text-block">
                  <span className="h-2 w-2 rounded-full bg-block" />
                  BROKEN at seq {ledgerVerify.first_broken_seq} ({ledgerVerify.reason})
                </span>
              )
            ) : null}
            <button
              className={button("primary")}
              onClick={() => void runVerify()}
              disabled={verifying}
            >
              Verify chain
            </button>
            <OutcomeLegend />
          </div>
        }
      />

      {/* Filter toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <select
          aria-label="Filter module"
          value={module}
          onChange={(e) => setModule(e.target.value)}
          className={field}
        >
          <option value="">All modules</option>
          {MODULES.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter event type"
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          className={field}
        >
          <option value="">All event types</option>
          {EVENT_TYPES.map((et) => (
            <option key={et} value={et}>
              {et}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter outcome"
          value={outcome}
          onChange={(e) => setOutcome(e.target.value)}
          className={field}
        >
          <option value="">All outcomes</option>
          {OUTCOMES.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <input
          aria-label="Filter subject"
          placeholder="Filter subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          className={`${field} w-44`}
        />
      </div>

      {error != null && (
        <ErrorBanner error={error} onRetry={() => setReloadKey((k) => k + 1)} />
      )}
      {loading && rows.length === 0 && <Skeleton rows={8} />}

      {!loading && rows.length === 0 && error == null && (
        <EmptyState
          title="No ledger entries found."
          hint="Try clearing your filters or create an action in the Sandbox."
        />
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-sm border border-line">
          <table className="w-full min-w-[70rem] border-collapse text-left text-[13px]">
            <caption className="sr-only">Audit Ledger entries in append order</caption>
            <thead className="bg-panel">
              <tr>
                {[
                  "Seq",
                  "Time",
                  "Module",
                  "Event",
                  "Subject",
                  "Outcome",
                  "Reason",
                  "Rules",
                  "Path",
                  "Policy",
                  "Hash",
                  ...(demoMode && isAdmin ? ["Tamper (Demo)"] : []),
                ].map((h) => (
                  <th key={h} scope="col" className="eyebrow px-3 py-2 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const isBroken = brokenSeq !== null && r.seq === brokenSeq
                const isAfterBreak = brokenSeq !== null && r.seq > brokenSeq

                let rowCls = "cursor-pointer border-t border-line align-top transition-colors hover:bg-raised"
                if (isBroken) {
                  rowCls = "cursor-pointer border-y-2 border-block bg-block/15 transition-colors"
                } else if (isAfterBreak) {
                  rowCls = "cursor-pointer border-t border-line align-top opacity-60 hover:bg-raised"
                }

                return (
                  <tr
                    key={r.seq}
                    tabIndex={0}
                    onClick={() => setOpenDrawer(r.seq)}
                    onKeyDown={(e) => e.key === "Enter" && setOpenDrawer(r.seq)}
                    className={rowCls}
                  >
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">
                      <span className="font-bold text-fg">#{r.seq}</span>
                      {isBroken && (
                        <span className="ml-2 rounded-xs border border-block bg-block px-1 py-0.5 font-mono text-[10px] font-bold uppercase text-ink">
                          BROKEN
                        </span>
                      )}
                      {isAfterBreak && (
                        <span className="ml-2 font-mono text-[10px] text-hold">
                          after break
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-dim">
                      {timeShort(r.ts)}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{r.module}</td>
                    <td className="px-3 py-2 font-mono text-xs text-dim">
                      {r.event_type}
                    </td>
                    <td className="max-w-44 break-words px-3 py-2 font-mono text-xs">
                      {r.subject}
                    </td>
                    <td className="px-3 py-2">
                      <OutcomeChip outcome={r.outcome} size="sm" />
                    </td>
                    <td className="max-w-64 break-words px-3 py-2">
                      {r.reason}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {r.rule_ids.slice(0, 2).map((id) => (
                          <RuleChip key={id} id={id} />
                        ))}
                        {r.rule_ids.length > 2 && (
                          <span className="font-mono text-[10px] text-faint">
                            +{r.rule_ids.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <PathChip path={r.decision_path} />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-dim">
                      v{r.policy_version}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-dim">
                      <span title={r.hash}>{r.hash.slice(0, 8)}…</span>
                    </td>
                    {demoMode && isAdmin && (
                      <td
                        className="px-3 py-2"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          type="button"
                          onClick={() => setTamperSeq(r.seq)}
                          className="rounded-xs border border-block/60 bg-block/5 px-2 py-0.5 font-mono text-[11px] font-semibold text-block transition-colors hover:bg-block hover:text-ink active:translate-y-px"
                        >
                          Tamper
                        </button>
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {openDrawer !== null && (
        <Drawer seq={openDrawer} onClose={() => setOpenDrawer(null)} />
      )}

      {tamperSeq !== null && (
        <TamperModal
          seq={tamperSeq}
          onClose={() => setTamperSeq(null)}
          onTampered={handleTampered}
        />
      )}
    </div>
  )
}
