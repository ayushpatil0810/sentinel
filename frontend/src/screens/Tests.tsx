import { useEffect, useState } from 'react'
import { api } from '../api/client'
import type { TestReportResponse } from '../api/types'
import {
  PageHeader,
  Panel,
  EmptyState,
  ErrorBanner,
  button,
} from '../components/ui'

const REQUIREMENT_PREFIXES = [
  { prefix: 'ALL', label: 'All Requirements' },
  { prefix: 'AG', label: 'ActionGate (AG)' },
  { prefix: 'BP', label: 'BreachPath (BP)' },
  { prefix: 'PS', label: 'PromptShield (PS)' },
  { prefix: 'X', label: 'Integration (X)' },
  { prefix: 'PE', label: 'Policy Engine (PE)' },
  { prefix: 'LG', label: 'Ledger (LG)' },
  { prefix: 'LA', label: 'LLM Adapter (LA)' },
  { prefix: 'SS', label: 'Sessions & Taint (SS)' },
  { prefix: 'AU', label: 'Auth Planes (AU)' },
]

export default function Tests() {
  const [report, setReport] = useState<TestReportResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [statusFilter, setStatusFilter] = useState<'all' | 'failed' | 'passed'>('all')
  const [selectedPrefix, setSelectedPrefix] = useState('ALL')
  const [expandedReqs, setExpandedReqs] = useState<Set<string>>(new Set())

  const loadReport = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.testReport()
      setReport(res)
    } catch {
      // 404 tests.none is expected before any tests are run
      setReport(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadReport()
  }, [])

  const handleRunTests = async () => {
    setRunning(true)
    setError(null)
    try {
      await api.runTests()
      // Poll every 2s until report updates
      const pollInterval = setInterval(async () => {
        try {
          const rep = await api.testReport()
          setReport(rep)
          setRunning(false)
          clearInterval(pollInterval)
        } catch {
          // Still running
        }
      }, 2000)
    } catch (err) {
      setError(err)
      setRunning(false)
    }
  }

  const toggleReq = (reqId: string) => {
    setExpandedReqs((prev) => {
      const next = new Set(prev)
      if (next.has(reqId)) next.delete(reqId)
      else next.add(reqId)
      return next
    })
  }

  const expandAll = () => {
    if (!report) return
    setExpandedReqs(new Set(Object.keys(report.by_requirement)))
  }

  const collapseAll = () => {
    setExpandedReqs(new Set())
  }

  // Filter requirements by prefix
  const filteredReqEntries = Object.entries(report?.by_requirement || {}).filter(
    ([reqId]) => {
      if (selectedPrefix === 'ALL') return true
      return reqId.startsWith(selectedPrefix)
    },
  )

  return (
    <div className="flex h-full flex-col space-y-4 p-5 lg:p-6 overflow-y-auto">
      <PageHeader
        title="Test Report"
        lead="Automated acceptance matrix results grouped by requirement ID across backend test suites."
        right={
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => void handleRunTests()}
              disabled={running}
              className={button('primary', 'md')}
            >
              {running ? 'Running pytest suite...' : 'Run Test Suite'}
            </button>
          </div>
        }
      />

      {error ? <ErrorBanner error={error} onRetry={() => void handleRunTests()} /> : null}

      {loading ? (
        <div className="flex h-64 items-center justify-center">
          <p className="text-xs font-mono text-dim">Loading test report...</p>
        </div>
      ) : !report ? (
        <EmptyState
          title="No test run completed yet"
          hint="Click 'Run Test Suite' above to execute the pytest verification matrix."
          action={
            <button
              onClick={() => void handleRunTests()}
              disabled={running}
              className={`mt-3 ${button('primary', 'md')}`}
            >
              Run Tests Now
            </button>
          }
        />
      ) : (
        <div className="space-y-4">
          {/* Metadata & Totals */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">Tests Passed</span>
              <span className="font-mono text-2xl font-bold text-allow">
                {report.totals.passed}
              </span>
              <span className="block text-[11px] text-faint">Verified passing</span>
            </div>

            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">Tests Failed</span>
              <span
                className={`font-mono text-2xl font-bold ${
                  report.totals.failed > 0 ? 'text-block' : 'text-fg'
                }`}
              >
                {report.totals.failed}
              </span>
              <span className="block text-[11px] text-faint">Must be zero</span>
            </div>

            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">Requirements Covered</span>
              <span className="font-mono text-2xl font-bold text-fg">
                {Object.keys(report.by_requirement).length}
              </span>
              <span className="block text-[11px] text-faint">
                Across Sentinel modules
              </span>
            </div>

            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">Untested Requirements</span>
              <span
                className={`font-mono text-2xl font-bold ${
                  report.untested_requirements.length > 0
                    ? 'text-hold'
                    : 'text-allow'
                }`}
              >
                {report.untested_requirements.length}
              </span>
              <span className="block text-[11px] text-faint">
                {report.untested_requirements.length === 0
                  ? '100% MVP coverage'
                  : 'Gaps remaining'}
              </span>
            </div>
          </div>

          {/* Untested Requirements Notice */}
          {report.untested_requirements.length === 0 ? (
            <div className="rounded-xs border border-allow/40 bg-allow/10 p-3 text-xs text-allow font-mono">
              ✓ All MVP security requirements (AG, BP, PS, X, PE, LG, AU, SS, LA) are verified by automated tests!
            </div>
          ) : (
            <div className="rounded-xs border border-hold/50 bg-hold/10 p-3 text-xs text-hold">
              <strong className="block mb-1">
                Untested Requirements ({report.untested_requirements.length}):
              </strong>
              <div className="flex flex-wrap gap-1.5 font-mono">
                {report.untested_requirements.map((req) => (
                  <span
                    key={req}
                    className="rounded bg-hold/20 px-1.5 py-0.5 text-[11px]"
                  >
                    {req}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
            <div className="flex flex-wrap items-center gap-1.5">
              {REQUIREMENT_PREFIXES.map((p) => (
                <button
                  key={p.prefix}
                  onClick={() => setSelectedPrefix(p.prefix)}
                  className={`rounded-xs px-2.5 py-1 text-xs font-mono transition-colors ${
                    selectedPrefix === p.prefix
                      ? 'bg-fg text-ink font-bold'
                      : 'border border-line bg-panel text-dim hover:text-fg'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1 text-xs">
                {(['all', 'failed', 'passed'] as const).map((st) => (
                  <button
                    key={st}
                    onClick={() => setStatusFilter(st)}
                    className={`rounded-xs px-2 py-0.5 capitalize text-xs ${
                      statusFilter === st
                        ? 'bg-raised font-bold text-fg'
                        : 'text-dim hover:text-fg'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
              <span className="text-dim">|</span>
              <button
                onClick={expandAll}
                className="text-xs text-dim hover:text-fg"
              >
                Expand all
              </button>
              <button
                onClick={collapseAll}
                className="text-xs text-dim hover:text-fg"
              >
                Collapse all
              </button>
            </div>
          </div>

          {/* Requirement Groups List */}
          <div className="space-y-2">
            {filteredReqEntries.map(([reqId, tests]) => {
              const matchesFilter = tests.filter((t) => {
                if (statusFilter === 'all') return true
                return t.status === statusFilter
              })
              if (matchesFilter.length === 0) return null

              const isExpanded = expandedReqs.has(reqId)
              const allPassed = tests.every((t) => t.status === 'passed')

              return (
                <Panel key={reqId} className="border-line/70">
                  <header
                    onClick={() => toggleReq(reqId)}
                    className="flex cursor-pointer items-center justify-between border-b border-line/40 px-4 py-2.5 hover:bg-raised/40 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-xs font-bold text-fg">
                        {reqId}
                      </span>
                      <span
                        className={`rounded px-1.5 py-0.2 font-mono text-[10px] font-bold ${
                          allPassed
                            ? 'bg-allow/15 text-allow'
                            : 'bg-block/15 text-block'
                        }`}
                      >
                        {allPassed ? 'PASSED' : 'HAS FAILURES'}
                      </span>
                      <span className="text-xs text-dim">
                        ({tests.length} {tests.length === 1 ? 'test' : 'tests'})
                      </span>
                    </div>
                    <span className="font-mono text-xs text-dim">
                      {isExpanded ? '▲' : '▼'}
                    </span>
                  </header>

                  {isExpanded && (
                    <div className="divide-y divide-line/30 bg-ink/30">
                      {matchesFilter.map((t) => (
                        <div
                          key={t.test}
                          className="flex items-center justify-between px-4 py-2 font-mono text-xs"
                        >
                          <span className="text-fg">{t.test}</span>
                          <div className="flex items-center gap-3">
                            <span className="text-[11px] text-faint">
                              {t.duration_ms} ms
                            </span>
                            <span
                              className={`rounded px-1.5 py-0.2 font-bold text-[10px] uppercase ${
                                t.status === 'passed'
                                  ? 'text-allow bg-allow/10'
                                  : t.status === 'failed'
                                    ? 'text-block bg-block/10'
                                    : 'text-dim bg-raised'
                              }`}
                            >
                              {t.status}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
