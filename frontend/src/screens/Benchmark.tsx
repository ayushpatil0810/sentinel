import { useEffect, useState } from 'react'
import { api } from '../api/client'
import type { BenchmarkMetrics } from '../api/types'
import {
  PageHeader,
  Panel,
  EmptyState,
  ErrorBanner,
  button,
} from '../components/ui'

export default function Benchmark() {
  const [metrics, setMetrics] = useState<BenchmarkMetrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [activeTab, setActiveTab] = useState<
    'overview' | 'misses' | 'false_positives' | 'dev_cases'
  >('overview')
  const [devCasesData, setDevCasesData] = useState<{
    total: number
    cases: Array<{
      id: string
      category: string
      source_tier: string
      label: string
      text: string
    }>
  } | null>(null)
  const [loadingDev, setLoadingDev] = useState(false)

  const loadLatest = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.latestBenchmark()
      setMetrics(res)
    } catch {
      // 404 benchmark.none is expected on initial run before any benchmark
      setMetrics(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadLatest()
  }, [])

  const handleRun = async () => {
    setRunning(true)
    setError(null)
    try {
      const res = await api.runBenchmark()
      setMetrics(res.metrics)
    } catch (err) {
      setError(err)
    } finally {
      setRunning(false)
    }
  }

  const handleLoadDevCases = async () => {
    if (devCasesData) return
    setLoadingDev(true)
    try {
      const res = (await api.benchmarkCases('dev')) as {
        total: number
        cases: Array<{
          id: string
          category: string
          source_tier: string
          label: string
          text: string
        }>
      }
      setDevCasesData(res)
    } catch (err) {
      setError(err)
    } finally {
      setLoadingDev(false)
    }
  }

  const formatPct = (val?: number) =>
    val !== undefined ? `${(val * 100).toFixed(1)}%` : '–'

  const formatCi = (ci?: [number, number]) =>
    ci ? `[${(ci[0] * 100).toFixed(1)}% – ${(ci[1] * 100).toFixed(1)}%]` : ''

  return (
    <div className="flex h-full flex-col space-y-4 p-5 lg:p-6 overflow-y-auto">
      <PageHeader
        title="PromptShield Benchmark"
        lead="Evaluate detection performance against the held-out test split with Wilson 95% intervals."
        right={
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => void handleRun()}
              disabled={running}
              className={button('primary', 'md')}
            >
              {running ? 'Running evaluation...' : 'Run on held-out test split'}
            </button>
          </div>
        }
      />

      {error ? <ErrorBanner error={error} onRetry={() => void handleRun()} /> : null}

      {/* Permanent Honesty Banner */}
      <div className="flex items-center gap-3 rounded-xs border border-line-strong bg-raised/70 px-4 py-2.5 text-xs text-dim">
        <span className="font-bold text-fg">Honesty Guarantee:</span>
        <span>
          Only the held-out <code className="text-fg font-mono">test</code> split
          is reported here (n={metrics?.n ?? 100}). Misses and false positives
          are enumerated below without redaction. Detectors were tuned
          exclusively on <code className="text-fg font-mono">dev</code>.
        </span>
      </div>

      {loading ? (
        <div className="flex h-64 items-center justify-center">
          <p className="text-xs text-dim font-mono">Loading benchmark status...</p>
        </div>
      ) : !metrics ? (
        <EmptyState
          title="No benchmark run completed yet"
          hint="Click 'Run on held-out test split' above to evaluate the active policy against the test suite."
          action={
            <button
              onClick={() => void handleRun()}
              disabled={running}
              className={`mt-3 ${button('primary', 'md')}`}
            >
              Run Benchmark Now
            </button>
          }
        />
      ) : (
        <div className="space-y-4">
          {/* Metadata Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xs border border-line bg-panel px-4 py-2 text-xs">
            <div className="flex flex-wrap items-center gap-4 font-mono text-dim">
              <span>
                Run ID: <strong className="text-fg">{metrics.run_id}</strong>
              </span>
              <span>
                Split: <strong className="text-fg">{metrics.split}</strong>
              </span>
              <span>
                Test cases: <strong className="text-fg">{metrics.n}</strong>
              </span>
              <span>
                Policy v<strong className="text-fg">{metrics.policy_version}</strong>
              </span>
            </div>
            <span className="font-mono text-[11px] text-faint">
              {new Date(metrics.ts).toLocaleString()}
            </span>
          </div>

          {/* Top Metrics Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {/* F1 Score */}
            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">F1 Score</span>
              <span className="font-mono text-2xl font-bold text-fg">
                {formatPct(metrics.f1)}
              </span>
              <span className="block text-[11px] text-faint">
                Harmonic mean
              </span>
            </div>

            {/* Precision */}
            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">Precision</span>
              <span className="font-mono text-2xl font-bold text-fg">
                {formatPct(metrics.precision.value)}
              </span>
              <span className="block font-mono text-[11px] text-faint">
                95% CI: {formatCi(metrics.precision.ci95)}
              </span>
            </div>

            {/* Recall */}
            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">Recall</span>
              <span className="font-mono text-2xl font-bold text-fg">
                {formatPct(metrics.recall.value)}
              </span>
              <span className="block font-mono text-[11px] text-faint">
                95% CI: {formatCi(metrics.recall.ci95)}
              </span>
            </div>

            {/* False Positive Rate */}
            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">False Positive Rate</span>
              <span className="font-mono text-2xl font-bold text-fg">
                {formatPct(metrics.fpr.value)}
              </span>
              <span className="block font-mono text-[11px] text-faint">
                95% CI: {formatCi(metrics.fpr.ci95)}
              </span>
            </div>

            {/* Confusion Matrix */}
            <div className="rounded-sm border border-line bg-panel p-3.5 space-y-1">
              <span className="eyebrow block">Confusion Matrix</span>
              <div className="grid grid-cols-2 gap-1 font-mono text-[11px] pt-1">
                <span className="text-allow">TP: {metrics.confusion.tp}</span>
                <span className="text-block">FP: {metrics.confusion.fp}</span>
                <span className="text-dim">TN: {metrics.confusion.tn}</span>
                <span className="text-hold">FN: {metrics.confusion.fn}</span>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex border-b border-line gap-2">
            {[
              { id: 'overview', label: 'Detailed Breakdown' },
              {
                id: 'misses',
                label: `Missed Attacks (${metrics.misses?.length ?? 0})`,
              },
              {
                id: 'false_positives',
                label: `False Positives (${metrics.false_positives?.length ?? 0})`,
              },
              { id: 'dev_cases', label: 'Dev Split Cases' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id as typeof activeTab)
                  if (tab.id === 'dev_cases') void handleLoadDevCases()
                }}
                className={`px-3 py-2 text-xs font-semibold border-b-2 -mb-px transition-colors ${
                  activeTab === tab.id
                    ? 'border-fg text-fg'
                    : 'border-transparent text-dim hover:text-fg'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab Content: Detailed Breakdown */}
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {/* Category Breakdown */}
              <Panel
                title="Recall by Attack Category"
                hint="Fraction of attacks caught per threat category"
              >
                <div className="p-3 divide-y divide-line/40 space-y-2">
                  {Object.entries(metrics.per_category || {}).map(
                    ([cat, val]) => {
                      const rate = typeof val === 'number' ? val : val?.recall ?? 0
                      return (
                        <div
                          key={cat}
                          className="flex items-center justify-between pt-1.5 text-xs font-mono"
                        >
                          <span className="text-fg">{cat}</span>
                          <span
                            className={`font-bold ${
                              rate >= 0.9
                                ? 'text-allow'
                                : rate >= 0.7
                                  ? 'text-hold'
                                  : 'text-block'
                            }`}
                          >
                            {(rate * 100).toFixed(1)}%
                          </span>
                        </div>
                      )
                    },
                  )}
                </div>
              </Panel>

              {/* Tier Breakdown */}
              <Panel
                title="Recall by Source Tier"
                hint="Detection effectiveness by input entry point"
              >
                <div className="p-3 divide-y divide-line/40 space-y-2">
                  {Object.entries(metrics.per_tier || {}).map(([tier, val]) => {
                    const rate = typeof val === 'number' ? val : val?.recall ?? 0
                    return (
                      <div
                        key={tier}
                        className="flex items-center justify-between pt-1.5 text-xs font-mono"
                      >
                        <span className="text-fg">{tier}</span>
                        <span
                          className={`font-bold ${
                            rate >= 0.9
                              ? 'text-allow'
                              : rate >= 0.7
                                ? 'text-hold'
                                : 'text-block'
                          }`}
                        >
                          {(rate * 100).toFixed(1)}%
                        </span>
                      </div>
                    )
                  })}

                  {metrics.direct_vs_indirect && (
                    <div className="pt-3 border-t border-line space-y-1.5">
                      <span className="eyebrow block">Attack Style</span>
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-dim">Direct Injection:</span>
                        <span className="font-bold text-fg">
                          {(
                            (metrics.direct_vs_indirect.direct_recall ?? 0) *
                            100
                          ).toFixed(1)}
                          %
                        </span>
                      </div>
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-dim">Indirect Injection:</span>
                        <span className="font-bold text-fg">
                          {(
                            (metrics.direct_vs_indirect.indirect_recall ?? 0) *
                            100
                          ).toFixed(1)}
                          %
                        </span>
                      </div>
                    </div>
                  )}

                  {metrics.sanitize_quality && (
                    <div className="pt-3 border-t border-line space-y-1.5">
                      <span className="eyebrow block">Sanitization Quality</span>
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-dim">Benign text preserved:</span>
                        <span className="font-bold text-allow">
                          {metrics.sanitize_quality.preserved_pct}%
                        </span>
                      </div>
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-dim">Re-scan clean rate:</span>
                        <span className="font-bold text-allow">
                          {metrics.sanitize_quality.rescan_clean_pct}%
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </Panel>
            </div>
          )}

          {/* Tab Content: Misses Table */}
          {activeTab === 'misses' && (
            <Panel
              title={`Misses on Test Split (${metrics.misses?.length ?? 0})`}
              hint="False negatives: Malicious test inputs that were not blocked/sanitized"
            >
              {(!metrics.misses || metrics.misses.length === 0) ? (
                <div className="p-4 text-xs font-mono text-allow">
                  ✓ Outstanding: Zero missed attacks on the held-out test split!
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-line bg-ink/50 font-mono text-[11px] text-dim">
                      <tr>
                        <th className="px-3 py-2">Test ID</th>
                        <th className="px-3 py-2">Category</th>
                        <th className="px-3 py-2">Explanation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line/40 font-mono text-[11px]">
                      {metrics.misses.map((m) => (
                        <tr key={m.id} className="hover:bg-raised/40">
                          <td className="px-3 py-2 font-bold text-fg">{m.id}</td>
                          <td className="px-3 py-2 text-hold">{m.category}</td>
                          <td className="px-3 py-2 text-dim">{m.explanation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          )}

          {/* Tab Content: False Positives Table */}
          {activeTab === 'false_positives' && (
            <Panel
              title={`False Positives on Test Split (${metrics.false_positives?.length ?? 0})`}
              hint="Benign inputs flagged as malicious"
            >
              {(!metrics.false_positives ||
              metrics.false_positives.length === 0) ? (
                <div className="p-4 text-xs font-mono text-allow">
                  ✓ Perfect: Zero false positives recorded on the test split.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-line bg-ink/50 font-mono text-[11px] text-dim">
                      <tr>
                        <th className="px-3 py-2">Test ID</th>
                        <th className="px-3 py-2">Explanation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line/40 font-mono text-[11px]">
                      {metrics.false_positives.map((fp) => (
                        <tr key={fp.id} className="hover:bg-raised/40">
                          <td className="px-3 py-2 font-bold text-fg">
                            {fp.id}
                          </td>
                          <td className="px-3 py-2 text-dim">
                            {fp.explanation}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          )}

          {/* Tab Content: Dev Split Cases */}
          {activeTab === 'dev_cases' && (
            <Panel
              title={`Dev Split Tuning Dataset (${devCasesData?.total ?? 0} cases)`}
              hint="Accessible for tuning only. The test split cannot be inspected via API."
            >
              {loadingDev ? (
                <div className="p-4 text-xs font-mono text-dim">
                  Loading dev cases...
                </div>
              ) : devCasesData ? (
                <div className="max-h-96 overflow-y-auto divide-y divide-line/40">
                  {devCasesData.cases.slice(0, 50).map((c) => (
                    <div key={c.id} className="p-3 text-xs space-y-1">
                      <div className="flex items-center justify-between font-mono text-[11px]">
                        <span className="font-bold text-fg">{c.id}</span>
                        <div className="flex gap-2">
                          <span className="text-dim">[{c.source_tier}]</span>
                          <span
                            className={
                              c.label === 'malicious'
                                ? 'text-block font-bold'
                                : 'text-allow'
                            }
                          >
                            {c.label}
                          </span>
                        </div>
                      </div>
                      <p className="font-mono text-[11px] text-dim truncate">
                        {c.text}
                      </p>
                    </div>
                  ))}
                  {devCasesData.total > 50 && (
                    <div className="p-2 text-center text-xs text-faint">
                      Showing first 50 of {devCasesData.total} cases.
                    </div>
                  )}
                </div>
              ) : null}
            </Panel>
          )}
        </div>
      )}
    </div>
  )
}
