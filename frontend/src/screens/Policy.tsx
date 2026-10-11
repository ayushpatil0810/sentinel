import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { api } from '../api/client'
import type {
  PolicyDocument,
  PolicyProposalResponse,
  PolicyVersionItem,
} from '../api/types'
import {
  OutcomeChip,
  PageHeader,
  Panel,
  EmptyState,
  ErrorBanner,
  JsonView,
  button,
  field,
} from '../components/ui'
import { useApp } from '../state/AppContext'

const THREAT_TYPES = [
  'override',
  'extraction',
  'exfil_target',
  'protected_value',
  'hidden_content',
  'directive',
]

const TIERS = ['user', 'retrieved_document', 'tool_output']

export default function Policy() {
  const { user, notify, reportError } = useApp()
  const isAdmin = Boolean(user?.roles.includes('admin'))

  const [activePolicy, setActivePolicy] = useState<PolicyDocument | null>(null)
  const [versions, setVersions] = useState<PolicyVersionItem[]>([])
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null)
  const [viewedDoc, setViewedDoc] = useState<PolicyDocument | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)

  // Diff state
  const [diffFrom, setDiffFrom] = useState<number>(1)
  const [diffTo, setDiffTo] = useState<number>(1)
  const [diffOps, setDiffOps] = useState<
    Array<{ op: string; path: string; value?: unknown }> | null
  >(null)
  const [diffLoading, setDiffLoading] = useState(false)

  // Propose modal state
  const [showProposeModal, setShowProposeModal] = useState(false)
  const [proposalJson, setProposalJson] = useState('')
  const [proposalNote, setProposalNote] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [proposalResult, setProposalResult] =
    useState<PolicyProposalResponse | null>(null)

  const loadData = async () => {
    setLoading(true)
    setError(null)
    try {
      const [pol, vers] = await Promise.all([
        api.policy(),
        api.policyVersions(),
      ])
      setActivePolicy(pol)
      setVersions(vers)
      setSelectedVersion(pol.version)
      setViewedDoc(pol)
      if (vers.length >= 2) {
        setDiffFrom(vers[vers.length - 2].version)
        setDiffTo(vers[vers.length - 1].version)
      } else if (vers.length === 1) {
        setDiffFrom(vers[0].version)
        setDiffTo(vers[0].version)
      }
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadData()
  }, [])

  const handleSelectVersion = async (ver: number) => {
    setSelectedVersion(ver)
    try {
      const doc = await api.policyVersion(ver)
      setViewedDoc(doc)
    } catch (err) {
      reportError(err)
    }
  }

  const handleComputeDiff = async () => {
    setDiffLoading(true)
    try {
      const ops = await api.policyDiff(diffFrom, diffTo)
      setDiffOps(ops)
    } catch (err) {
      reportError(err)
    } finally {
      setDiffLoading(false)
    }
  }

  const handleOpenPropose = () => {
    if (!activePolicy) return
    setProposalJson(JSON.stringify(activePolicy, null, 2))
    setProposalNote('')
    setProposalResult(null)
    setShowProposeModal(true)
  }

  const handleSubmitProposal = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!activePolicy) return

    let parsed: unknown
    try {
      parsed = JSON.parse(proposalJson)
    } catch {
      notify('Invalid JSON in policy proposal.')
      return
    }

    setSubmitting(true)
    try {
      const res = await api.proposePolicy(
        activePolicy.version,
        parsed,
        proposalNote,
      )
      setProposalResult(res)
      notify(
        `Proposal ${res.proposal_id} created. Second admin approval required.`,
      )
    } catch (err) {
      reportError(err)
    } finally {
      setSubmitting(false)
    }
  }

  // Extract ingress rules table from viewedDoc safely
  const ingressTable =
    (
      (viewedDoc as unknown as { ingress_rules?: { table?: Record<string, Record<string, string>> } })
        ?.ingress_rules?.table
    ) ||
    (
      (viewedDoc as unknown as { ingress?: { table?: Record<string, Record<string, string>> } })
        ?.ingress?.table
    ) ||
    {}

  return (
    <div className="flex h-full flex-col space-y-4 p-5 lg:p-6 overflow-hidden">
      <PageHeader
        title="Policy Editor"
        lead="Deterministic security policy controlling ingress sanitization and post-model ActionGate rules."
        right={
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-dim">
              Active: v{activePolicy?.version ?? 1}
            </span>
            {isAdmin ? (
              <button
                onClick={handleOpenPropose}
                className={button('primary', 'sm')}
              >
                Propose Policy Change
              </button>
            ) : (
              <span className="rounded border border-line bg-raised px-2.5 py-1 text-xs text-dim">
                Read-only (Admin role required to propose changes)
              </span>
            )}
          </div>
        }
      />

      {error ? <ErrorBanner error={error} onRetry={() => void loadData()} /> : null}

      <div className="grid flex-1 grid-cols-1 gap-5 overflow-hidden lg:grid-cols-12">
        {/* Left: Version History (3 cols) */}
        <section
          aria-label="Version history"
          className="flex min-h-0 flex-col rounded-sm border border-line bg-panel lg:col-span-3 overflow-hidden"
        >
          <header className="border-b border-line px-4 py-2.5">
            <h2 className="eyebrow !text-dim">
              Versions ({versions.length})
            </h2>
          </header>

          <div className="flex-1 divide-y divide-line/40 overflow-y-auto">
            {versions.map((v) => {
              const isSelected = selectedVersion === v.version
              const isActive = activePolicy?.version === v.version
              return (
                <button
                  key={v.version}
                  type="button"
                  onClick={() => void handleSelectVersion(v.version)}
                  className={`w-full text-left p-3 transition-colors ${
                    isSelected ? 'bg-raised' : 'hover:bg-raised/40'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-fg">
                      Version {v.version}
                    </span>
                    {isActive && (
                      <span className="rounded bg-allow/15 px-1.5 py-0.5 font-mono text-[10px] font-bold text-allow">
                        Active
                      </span>
                    )}
                  </div>
                  <div className="mt-1 space-y-0.5 font-mono text-[11px] text-faint">
                    <p>Created by: {v.created_by}</p>
                    {v.approved_by && <p>Approved by: {v.approved_by}</p>}
                    <p className="truncate" title={v.content_hash}>
                      Hash: {v.content_hash.slice(0, 12)}…
                    </p>
                  </div>
                </button>
              )
            })}
          </div>

          {/* Quick Version Diff Trigger */}
          <div className="border-t border-line bg-ink/40 p-3 text-xs space-y-2">
            <span className="eyebrow block">Compare Versions</span>
            <div className="flex items-center gap-2">
              <select
                aria-label="Diff from version"
                value={diffFrom}
                onChange={(e) => setDiffFrom(Number(e.target.value))}
                className={`flex-1 ${field}`}
              >
                {versions.map((v) => (
                  <option key={v.version} value={v.version}>
                    v{v.version}
                  </option>
                ))}
              </select>
              <span className="text-dim">→</span>
              <select
                aria-label="Diff to version"
                value={diffTo}
                onChange={(e) => setDiffTo(Number(e.target.value))}
                className={`flex-1 ${field}`}
              >
                {versions.map((v) => (
                  <option key={v.version} value={v.version}>
                    v{v.version}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              onClick={() => void handleComputeDiff()}
              disabled={diffLoading}
              className={`w-full ${button('ghost', 'sm')}`}
            >
              {diffLoading ? 'Diffing...' : 'View RFC 6902 Diff'}
            </button>
          </div>
        </section>

        {/* Center / Right: Policy Document & Matrix (9 cols) */}
        <section
          aria-label="Policy content"
          className="flex min-h-0 flex-col space-y-4 rounded-sm border border-line bg-panel p-4 lg:col-span-9 overflow-y-auto"
        >
          {loading ? (
            <div className="flex h-64 items-center justify-center">
              <p className="text-xs font-mono text-dim">Loading policy...</p>
            </div>
          ) : !viewedDoc ? (
            <EmptyState
              title="No policy loaded"
              hint="Select a version from the left panel."
            />
          ) : (
            <>
              {/* Document Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-fg">
                    Policy Document v{viewedDoc.version}
                  </h3>
                  <p className="text-xs text-dim">
                    Deterministic policy specification enforced by the core policy engine.
                  </p>
                </div>
                <span className="font-mono text-xs text-faint">
                  Version {viewedDoc.version} of {versions.length}
                </span>
              </div>

              {/* Ingress Threat Outcome Matrix (3x6 Grid) */}
              <Panel
                title="PromptShield Ingress Matrix"
                hint="Deterministic outcome mapping by source tier and threat type (PE-01, PS-06)"
              >
                <div className="overflow-x-auto p-3">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-line font-mono text-[11px] text-dim">
                      <tr>
                        <th className="px-3 py-2">Source Tier</th>
                        {THREAT_TYPES.map((t) => (
                          <th key={t} className="px-3 py-2 text-center">
                            {t}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line/40 font-mono text-[11px]">
                      {TIERS.map((tier) => (
                        <tr key={tier} className="hover:bg-raised/40">
                          <td className="px-3 py-2 font-bold text-fg">
                            {tier}
                          </td>
                          {THREAT_TYPES.map((threat) => {
                            const outcome =
                              ingressTable[tier]?.[threat] || 'allow'
                            const isPinnedFloor =
                              tier === 'user' && threat === 'override'
                            return (
                              <td
                                key={threat}
                                className="px-3 py-2 text-center"
                              >
                                <div className="inline-flex items-center gap-1">
                                  <OutcomeChip outcome={outcome} size="sm" />
                                  {isPinnedFloor && (
                                    <span
                                      title="Floor invariant: User override must block (PE-01)"
                                      className="text-dim cursor-help"
                                    >
                                      🔒
                                    </span>
                                  )}
                                </div>
                              </td>
                            )
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>

              {/* Structural JSON Diff View (if active) */}
              {diffOps && (
                <Panel
                  title={`JSON Diff: v${diffFrom} → v${diffTo} (${diffOps.length} ops)`}
                  hint="RFC 6902 structural operations between versions"
                  right={
                    <button
                      onClick={() => setDiffOps(null)}
                      className="text-xs text-dim hover:text-fg"
                    >
                      Dismiss
                    </button>
                  }
                >
                  <div className="p-3">
                    {diffOps.length === 0 ? (
                      <p className="text-xs font-mono text-allow">
                        ✓ Both policy versions are structurally identical.
                      </p>
                    ) : (
                      <ul className="space-y-1 font-mono text-xs max-h-48 overflow-y-auto">
                        {diffOps.map((op, idx) => (
                          <li
                            key={idx}
                            className={`p-1.5 rounded ${
                              op.op === 'add'
                                ? 'bg-allow/10 text-allow'
                                : op.op === 'remove'
                                  ? 'bg-block/10 text-block'
                                  : 'bg-hold/10 text-hold'
                            }`}
                          >
                            <span className="font-bold uppercase">[{op.op}]</span>{' '}
                            <span className="text-dim">{op.path}</span>
                            {op.value !== undefined && (
                              <span className="ml-2 text-fg">
                                → {JSON.stringify(op.value)}
                              </span>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </Panel>
              )}

              {/* Complete Policy JSON Viewer */}
              <Panel
                title="Full Policy Schema"
                hint="ActionGate rules, thresholds, and ingress configuration in canonical form"
              >
                <div className="p-3">
                  <JsonView value={viewedDoc} />
                </div>
              </Panel>
            </>
          )}
        </section>
      </div>

      {/* Propose Change Modal (Admin only, PE-06, X-07) */}
      {showProposeModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs"
        >
          <div className="w-full max-w-2xl rounded-sm border border-line bg-panel p-6 shadow-2xl">
            <h2 className="text-base font-bold text-fg">
              Propose Policy Change (PE-06, X-07)
            </h2>
            <p className="mt-1 text-xs text-dim">
              Policy modifications cannot be self-activated. Proposing creates a
              pending change approval that requires a second authenticated
              administrator to approve.
            </p>

            {proposalResult && (
              <div className="mt-3 rounded border border-allow bg-allow/10 p-3 text-xs text-allow">
                <p className="font-bold">
                  ✓ Proposal Created Successfully ({proposalResult.proposal_id})
                </p>
                <p className="mt-1 text-dim">
                  A second admin must approve approval ID{' '}
                  <strong className="font-mono text-fg">
                    {proposalResult.approval_id}
                  </strong>
                  .
                </p>
                <div className="mt-2">
                  <Link
                    to={`/approvals/${proposalResult.approval_id}`}
                    className={`inline-block ${button('primary', 'sm')}`}
                  >
                    View in Approvals Screen →
                  </Link>
                </div>
              </div>
            )}

            <form onSubmit={handleSubmitProposal} className="mt-4 space-y-3">
              <div>
                <label className="block text-xs font-semibold text-dim mb-1">
                  Base Version (Locked)
                </label>
                <input
                  type="text"
                  readOnly
                  value={`v${activePolicy?.version ?? 1}`}
                  className={`w-full font-mono text-xs ${field} opacity-70`}
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-dim mb-1">
                  Change Note / Rationale
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Tighten tool_output extraction outcome to block"
                  value={proposalNote}
                  onChange={(e) => setProposalNote(e.target.value)}
                  className={`w-full text-xs ${field}`}
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-dim mb-1">
                  Proposed Policy JSON
                </label>
                <textarea
                  rows={10}
                  required
                  value={proposalJson}
                  onChange={(e) => setProposalJson(e.target.value)}
                  className={`w-full font-mono text-xs leading-relaxed ${field} h-52 p-3`}
                />
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowProposeModal(false)}
                  className={button('ghost')}
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={submitting || !proposalNote.trim()}
                  className={button('primary')}
                >
                  {submitting
                    ? 'Submitting...'
                    : 'Propose (Second Admin Must Approve)'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
