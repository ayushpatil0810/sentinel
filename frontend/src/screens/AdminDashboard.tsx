import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { api } from '../api/client'
import type { LlmSettings, LlmTestResult, SystemStatus } from '../api/types'
import { EmptyState, ErrorBanner, JsonView, Panel, Skeleton, button, field } from '../components/ui'
import { useApp } from '../state/AppContext'

// Embedded sub-screens for seamless admin navigation
import AttackGraph from './AttackGraph'
import Benchmark from './Benchmark'
import Ledger from './Ledger'
import Policy from './Policy'
import Tests from './Tests'

type AdminTab = 'llm' | 'policy' | 'graph' | 'registries' | 'ledger' | 'benchmark' | 'tests'

export default function AdminDashboard() {
  const { tab: urlTab } = useParams<{ tab?: string }>()
  const navigate = useNavigate()
  const { user, users, switchUser, systemStatus, refreshSystemStatus, health, notify } = useApp()

  const [activeTab, setActiveTab] = useState<AdminTab>((urlTab as AdminTab) || 'llm')

  // LLM Settings Form State
  const [agentMode, setAgentMode] = useState<'live' | 'simulation'>('simulation')
  const [guardMode, setGuardMode] = useState<'live' | 'rules_only'>('live')
  const [model, setModel] = useState('gpt-4o-mini')
  const [timeoutSeconds, setTimeoutSeconds] = useState(5)
  const [apiKey, setApiKey] = useState('')
  const [hasApiKey, setHasApiKey] = useState(false)
  const [savingSettings, setSavingSettings] = useState(false)

  // Connection Test State
  const [testingConnection, setTestingConnection] = useState(false)
  const [testResult, setTestResult] = useState<LlmTestResult | null>(null)

  // Registries State
  const [agents, setAgents] = useState<any[]>([])
  const [actionTypes, setActionTypes] = useState<any[]>([])
  const [loadingRegistries, setLoadingRegistries] = useState(false)

  const isAdmin = user?.roles.includes('admin')

  // Sync tab from URL if present
  useEffect(() => {
    if (urlTab && ['llm', 'policy', 'graph', 'registries', 'ledger', 'benchmark', 'tests'].includes(urlTab)) {
      setActiveTab(urlTab as AdminTab)
    }
  }, [urlTab])

  // Load Admin LLM Settings
  useEffect(() => {
    if (!isAdmin) return
    let cancel = false
    api
      .adminLlmSettings()
      .then((s) => {
        if (cancel) return
        setAgentMode(s.agent_mode)
        setGuardMode(s.guard_mode)
        setModel(s.model)
        setTimeoutSeconds(s.timeout_seconds)
        setHasApiKey(s.has_api_key)
      })
      .catch(() => {})
    return () => {
      cancel = true
    }
  }, [isAdmin])

  // Load Registries when registries tab is active
  useEffect(() => {
    if (activeTab === 'registries' && isAdmin) {
      setLoadingRegistries(true)
      Promise.all([api.registriesAgents(), api.registriesActionTypes()])
        .then(([ag, act]) => {
          setAgents(ag)
          setActionTypes(act)
        })
        .catch(() => {})
        .finally(() => setLoadingRegistries(false))
    }
  }, [activeTab, isAdmin])

  const handleTabChange = (t: AdminTab) => {
    setActiveTab(t)
    navigate(`/admin/${t}`, { replace: true })
  }

  const handleSaveLlmSettings = async (e: React.FormEvent) => {
    e.preventDefault()
    setSavingSettings(true)
    try {
      const updatePayload: any = {
        agent_mode: agentMode,
        guard_mode: guardMode,
        model,
        timeout_seconds: Number(timeoutSeconds),
      }
      if (apiKey.trim()) {
        updatePayload.api_key = apiKey.trim()
      }
      const updated = await api.updateAdminLlmSettings(updatePayload)
      setHasApiKey(updated.has_api_key)
      setApiKey('')
      await refreshSystemStatus()
      notify('LLM settings saved and ledgered (llm.settings_changed)', 'info')
    } catch (err: any) {
      notify(err?.message || 'Failed to update LLM settings', 'error')
    } finally {
      setSavingSettings(false)
    }
  }

  const handleTestConnection = async () => {
    setTestingConnection(true)
    setTestResult(null)
    try {
      const res = await api.testAdminLlmConnection()
      setTestResult(res)
      if (res.success) {
        notify(`Connection test succeeded (${res.latency_ms}ms)`, 'info')
      } else {
        notify(`Connection test failed: ${res.error}`, 'error')
      }
    } catch (err: any) {
      setTestResult({
        success: false,
        provider: systemStatus?.provider || 'unknown',
        latency_ms: 0,
        error: err?.message || 'Connection test request failed',
      })
      notify(err?.message || 'Connection test failed', 'error')
    } finally {
      setTestingConnection(false)
    }
  }

  // ── Access Denied for Non-Admins (AU-05) ──────────────────────────────────
  if (!isAdmin) {
    return (
      <div className="min-h-full flex flex-col justify-center items-center p-8 bg-ink text-fg">
        <div className="max-w-lg w-full p-8 rounded-lg border border-block/60 bg-raised/90 shadow-2xl space-y-5 text-center">
          <div className="inline-flex h-14 w-14 rounded-full bg-block/10 text-block items-center justify-center border border-block/40 mx-auto">
            <svg viewBox="0 0 24 24" className="h-7 w-7" fill="none" stroke="currentColor" strokeWidth="2.2">
              <circle cx="12" cy="12" r="10" />
              <line x1="15" y1="9" x2="9" y2="15" />
              <line x1="9" y1="9" x2="15" y2="15" />
            </svg>
          </div>

          <div className="space-y-2">
            <h2 className="text-xl font-bold text-block">Access Denied: Admin Role Required</h2>
            <p className="font-mono text-xs text-dim">Requirement AU-05 · Server-Enforced Role Separation</p>
          </div>

          <p className="text-sm text-dim leading-relaxed">
            The Sentinel Admin Console is restricted to authenticated users with the <code className="text-fg">admin</code> role.
            Your current identity <strong className="text-fg">{user?.display_name}</strong> possesses roles: [
            <span className="text-hold">{user?.roles.join(', ')}</span>].
          </p>

          <div className="p-3.5 rounded border border-line bg-panel text-xs text-faint text-left space-y-1">
            <p className="font-semibold text-fg">Security Architecture Principle:</p>
            <p>
              Requesters and Approvers are strictly prevented from modifying security policies, attack graphs, runtime models, or ledger states.
            </p>
          </div>

          <div className="pt-2 flex flex-col sm:flex-row items-center gap-2 justify-center">
            <button
              onClick={() => switchUser('admin')}
              className={button('primary') + ' w-full sm:w-auto'}
            >
              Switch to Admin
            </button>
            <button
              onClick={() => switchUser('dana')}
              className={button('secondary') + ' w-full sm:w-auto'}
            >
              Switch to Dana (Co-Admin)
            </button>
            <Link to="/user" className={button('ghost') + ' w-full sm:w-auto'}>
              Back to User Portal
            </Link>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full bg-ink text-fg overflow-hidden">
      {/* Top Admin Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-line bg-panel px-6 py-3">
        <div className="flex items-center gap-3">
          <span className="flex h-7 w-7 items-center justify-center rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </span>
          <div>
            <h1 className="text-base font-bold tracking-tight text-fg flex items-center gap-2">
              Sentinel Admin Console
              <span className="text-[11px] px-2 py-0.2 rounded font-mono font-semibold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                Admin
              </span>
            </h1>
            <p className="text-xs text-dim">Runtime Configuration, Security Policies, Graph Analysis, &amp; Non-repudiation</p>
          </div>
        </div>

        {/* Status Badges */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="border border-line rounded px-2.5 py-1 bg-raised text-dim">
            Policy: <strong className="text-fg">v{health?.policy_version ?? 1}</strong>
          </span>
          <span className="border border-line rounded px-2.5 py-1 bg-raised text-dim">
            Graph: <strong className="text-fg">v{health?.graph_version ?? 1}</strong>
          </span>
          <span className="border border-line rounded px-2.5 py-1 bg-raised text-dim">
            Ledger: <strong className="text-allow">Verified</strong>
          </span>
        </div>
      </header>

      {/* Admin Subnav Tabs */}
      <nav aria-label="Admin Sections" className="flex border-b border-line bg-raised/70 overflow-x-auto px-4">
        {[
          { id: 'llm', label: 'LLM Settings & Test', icon: '⚡' },
          { id: 'policy', label: 'Policy Editor', icon: '🛡️' },
          { id: 'graph', label: 'Attack Graph', icon: '🕸️' },
          { id: 'registries', label: 'Registries', icon: '📋' },
          { id: 'ledger', label: 'Audit Ledger', icon: '📜' },
          { id: 'benchmark', label: 'Benchmark', icon: '🎯' },
          { id: 'tests', label: 'Test Report', icon: '✅' },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => handleTabChange(t.id as AdminTab)}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono font-semibold border-b-2 whitespace-nowrap transition-colors ${
              activeTab === t.id
                ? 'border-fg text-fg bg-panel shadow-[inset_0_-2px_0_var(--color-fg)]'
                : 'border-transparent text-dim hover:text-fg hover:bg-raised'
            }`}
          >
            <span>{t.icon}</span>
            <span>{t.label}</span>
          </button>
        ))}
      </nav>

      {/* Tab Panels */}
      <div className="flex-1 overflow-y-auto min-h-0 bg-ink">
        {/* Tab 1: LLM Settings & Connection Test */}
        {activeTab === 'llm' && (
          <div className="max-w-5xl mx-auto p-6 space-y-6">
            {/* System Overview Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-4 rounded-md border border-line bg-panel space-y-1">
                <p className="eyebrow text-faint">Agent Runtime Mode</p>
                <p className="text-lg font-bold font-mono text-fg uppercase">{systemStatus?.agent_mode || agentMode}</p>
                <p className="text-xs text-dim">
                  {agentMode === 'live' ? 'OpenAI function calling active' : 'Scripted deterministic agent'}
                </p>
              </div>

              <div className="p-4 rounded-md border border-line bg-panel space-y-1">
                <p className="eyebrow text-faint">Guard Mode</p>
                <p className="text-lg font-bold font-mono text-fg uppercase">{systemStatus?.guard_mode || guardMode}</p>
                <p className="text-xs text-dim">
                  {guardMode === 'live' ? 'Rules + Advisory LLM' : 'Strict deterministic rules only'}
                </p>
              </div>

              <div className="p-4 rounded-md border border-line bg-panel space-y-1">
                <p className="eyebrow text-faint">Active Model</p>
                <p className="text-lg font-bold font-mono text-fg">{systemStatus?.model || model}</p>
                <p className="text-xs text-dim">Timeout: {systemStatus?.timeout_seconds || timeoutSeconds}s</p>
              </div>

              <div className="p-4 rounded-md border border-line bg-panel space-y-1">
                <p className="eyebrow text-faint">Provider Health</p>
                <div className="flex items-center gap-2">
                  <span className={`h-2.5 w-2.5 rounded-full ${systemStatus?.provider_health?.status === 'healthy' ? 'bg-allow' : 'bg-hold'}`} />
                  <p className="text-lg font-bold font-mono text-fg capitalize">
                    {systemStatus?.provider_health?.status || 'Unknown'}
                  </p>
                </div>
                <p className="text-xs text-dim">API Key: {hasApiKey ? 'Configured (sk-...)' : 'Not set'}</p>
              </div>
            </div>

            {/* Settings Form + Test Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Form (7 cols) */}
              <div className="lg:col-span-7 space-y-4">
                <Panel title="Runtime LLM Configuration" className="p-5">
                  <form onSubmit={handleSaveLlmSettings} className="space-y-4 text-xs">
                    {/* Agent Mode Toggle */}
                    <div className="space-y-1.5">
                      <label className="font-semibold text-fg block">Agent Execution Mode (AGENT_MODE)</label>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() => setAgentMode('simulation')}
                          className={`p-2.5 rounded border text-left transition-colors ${
                            agentMode === 'simulation'
                              ? 'border-fg bg-raised text-fg font-bold'
                              : 'border-line bg-ink text-dim hover:text-fg'
                          }`}
                        >
                          <div className="font-mono text-xs">SIMULATION</div>
                          <div className="text-[11px] text-dim font-normal">Deterministic ScriptedAgent (Offline)</div>
                        </button>
                        <button
                          type="button"
                          onClick={() => setAgentMode('live')}
                          className={`p-2.5 rounded border text-left transition-colors ${
                            agentMode === 'live'
                              ? 'border-allow bg-allow/10 text-allow font-bold'
                              : 'border-line bg-ink text-dim hover:text-fg'
                          }`}
                        >
                          <div className="font-mono text-xs">LIVE</div>
                          <div className="text-[11px] text-dim font-normal">Real OpenAI API + Structured Output</div>
                        </button>
                      </div>
                    </div>

                    {/* Guard Mode Toggle */}
                    <div className="space-y-1.5">
                      <label className="font-semibold text-fg block">Guard Evaluation Mode (GUARD_MODE)</label>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() => setGuardMode('live')}
                          className={`p-2.5 rounded border text-left transition-colors ${
                            guardMode === 'live'
                              ? 'border-fg bg-raised text-fg font-bold'
                              : 'border-line bg-ink text-dim hover:text-fg'
                          }`}
                        >
                          <div className="font-mono text-xs">LIVE GUARD</div>
                          <div className="text-[11px] text-dim font-normal">Rules + Advisory LLM Signals</div>
                        </button>
                        <button
                          type="button"
                          onClick={() => setGuardMode('rules_only')}
                          className={`p-2.5 rounded border text-left transition-colors ${
                            guardMode === 'rules_only'
                              ? 'border-path-fallback bg-path-fallback/10 text-path-fallback font-bold'
                              : 'border-line bg-ink text-dim hover:text-fg'
                          }`}
                        >
                          <div className="font-mono text-xs">RULES ONLY</div>
                          <div className="text-[11px] text-dim font-normal">Deterministic Policy Engine Only</div>
                        </button>
                      </div>
                    </div>

                    {/* Model Selector */}
                    <div className="space-y-1.5">
                      <label className="font-semibold text-fg block">OpenAI Model</label>
                      <select
                        value={model}
                        onChange={(e) => setModel(e.target.value)}
                        className={`w-full ${field}`}
                      >
                        <option value="gpt-4o-mini">gpt-4o-mini (Default / Fast / Cost-effective)</option>
                        <option value="gpt-4o">gpt-4o (High capability)</option>
                        <option value="gpt-3.5-turbo">gpt-3.5-turbo (Legacy)</option>
                      </select>
                    </div>

                    {/* Timeout */}
                    <div className="space-y-1.5">
                      <label className="font-semibold text-fg block">LLM Timeout (Seconds)</label>
                      <input
                        type="number"
                        min={1}
                        max={60}
                        value={timeoutSeconds}
                        onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                        className={`w-full ${field}`}
                      />
                      <p className="text-[11px] text-faint">
                        Calls exceeding timeout automatically trigger fail-safe fallback with decision_path = fallback.
                      </p>
                    </div>

                    {/* API Key */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <label className="font-semibold text-fg">OpenAI API Key</label>
                        <span className="text-[11px] font-mono text-dim">
                          {hasApiKey ? 'Key is set in server environment' : 'No key set'}
                        </span>
                      </div>
                      <input
                        type="password"
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        placeholder={hasApiKey ? '•••••••••••••••••••••••• (leave blank to keep existing)' : 'sk-...'}
                        className={`w-full font-mono ${field}`}
                      />
                      <p className="text-[11px] text-faint">
                        Secrets are never logged or stored in the audit ledger. Keys are held in memory/secure settings.
                      </p>
                    </div>

                    <div className="pt-2 flex items-center justify-between">
                      <span className="text-[11px] text-dim">Modifications are ledgered as policy / llm.settings_changed</span>
                      <button
                        type="submit"
                        disabled={savingSettings}
                        className={button('primary')}
                      >
                        {savingSettings ? 'Saving Settings…' : 'Save Configuration'}
                      </button>
                    </div>
                  </form>
                </Panel>
              </div>

              {/* Connection Test & Health (5 cols) */}
              <div className="lg:col-span-5 space-y-4">
                <Panel title="Round-Trip Connectivity Test (LA-10)" className="p-5 space-y-4">
                  <p className="text-xs text-dim leading-relaxed">
                    Test the active LLM provider with a structured test request. Verifies API key validity, latency, and schema parsing.
                  </p>

                  <button
                    onClick={handleTestConnection}
                    disabled={testingConnection}
                    className={button('secondary') + ' w-full py-2.5 font-mono text-xs'}
                  >
                    {testingConnection ? 'Testing Connection (Sending probe)…' : '▶ Run Connection Probe'}
                  </button>

                  {testResult && (
                    <div
                      className={`p-4 rounded-md border space-y-2 text-xs ${
                        testResult.success
                          ? 'border-allow/50 bg-allow/10 text-allow'
                          : 'border-block/50 bg-block/10 text-block'
                      }`}
                    >
                      <div className="flex items-center justify-between font-bold">
                        <span>{testResult.success ? '✓ Connection Succeeded' : '✕ Connection Probe Failed'}</span>
                        <span className="font-mono">{testResult.latency_ms}ms</span>
                      </div>

                      <div className="font-mono text-[11px] space-y-0.5 text-fg">
                        <div>Provider: {testResult.provider}</div>
                        {testResult.model && <div>Model: {testResult.model}</div>}
                      </div>

                      {testResult.error && (
                        <div className="mt-2 p-2 rounded bg-ink/70 border border-current font-mono text-[11px] text-block break-words">
                          {testResult.error}
                        </div>
                      )}
                    </div>
                  )}

                  <div className="p-3 rounded border border-line bg-raised/50 text-[11px] text-dim space-y-1">
                    <p className="font-semibold text-fg">Non-Negotiable Guard Principles:</p>
                    <ul className="list-disc list-inside space-y-0.5 text-faint">
                      <li>Deterministic rules decide; LLM is strictly advisory.</li>
                      <li>LLM signals can only tighten outcomes (never loosen).</li>
                      <li>Timeouts &amp; errors fail-closed to deterministic fallback.</li>
                    </ul>
                  </div>
                </Panel>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Policy Editor */}
        {activeTab === 'policy' && <Policy />}

        {/* Tab 3: Attack Graph */}
        {activeTab === 'graph' && <AttackGraph />}

        {/* Tab 4: Registries */}
        {activeTab === 'registries' && (
          <div className="max-w-5xl mx-auto p-6 space-y-6">
            <Panel title="ActionGate Agent Registry (AG-01)" className="p-5">
              {loadingRegistries ? (
                <Skeleton rows={3} />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="border-b border-line text-faint uppercase text-[10px]">
                      <tr>
                        <th className="py-2 px-3">Agent ID</th>
                        <th className="py-2 px-3">Name</th>
                        <th className="py-2 px-3">Status</th>
                        <th className="py-2 px-3">Graph Node ID</th>
                        <th className="py-2 px-3">Allowed Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {agents.map((ag) => (
                        <tr key={ag.agent_id} className="hover:bg-raised/50">
                          <td className="py-2.5 px-3 font-bold text-fg">{ag.agent_id}</td>
                          <td className="py-2.5 px-3 text-dim">{ag.name}</td>
                          <td className="py-2.5 px-3">
                            <span className="px-1.5 py-0.5 rounded bg-allow/10 text-allow border border-allow/30">
                              {ag.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-faint">{ag.graph_node_id}</td>
                          <td className="py-2.5 px-3">
                            <div className="flex flex-wrap gap-1">
                              {ag.allowed_action_types?.map((act: string) => (
                                <span key={act} className="px-1.5 py-0.5 rounded bg-panel border border-line text-fg text-[10px]">
                                  {act}
                                </span>
                              ))}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>

            <Panel title="ActionGate Action Type Registry (AG-02)" className="p-5">
              {loadingRegistries ? (
                <Skeleton rows={5} />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="border-b border-line text-faint uppercase text-[10px]">
                      <tr>
                        <th className="py-2 px-3">Action Type</th>
                        <th className="py-2 px-3">Description</th>
                        <th className="py-2 px-3">Sensitivity</th>
                        <th className="py-2 px-3">Reversible</th>
                        <th className="py-2 px-3">Ingests Untrusted</th>
                        <th className="py-2 px-3">Target Node</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {actionTypes.map((act) => (
                        <tr key={act.action_type} className="hover:bg-raised/50">
                          <td className="py-2.5 px-3 font-bold text-fg">{act.action_type}</td>
                          <td className="py-2.5 px-3 text-dim font-sans text-xs">{act.description}</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                              act.base_sensitivity === 'high'
                                ? 'bg-block/10 text-block border border-block/30'
                                : act.base_sensitivity === 'medium'
                                ? 'bg-hold/10 text-hold border border-hold/30'
                                : 'bg-allow/10 text-allow border border-allow/30'
                            }`}>
                              {act.base_sensitivity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3">{act.reversible ? 'Yes' : 'No'}</td>
                          <td className="py-2.5 px-3">{act.ingests_untrusted ? '⚠️ Yes' : 'No'}</td>
                          <td className="py-2.5 px-3 text-faint">{act.target_node_default ?? '–'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          </div>
        )}

        {/* Tab 5: Audit Ledger */}
        {activeTab === 'ledger' && <Ledger />}

        {/* Tab 6: Benchmark */}
        {activeTab === 'benchmark' && <Benchmark />}

        {/* Tab 7: Test Report */}
        {activeTab === 'tests' && <Tests />}
      </div>
    </div>
  )
}
