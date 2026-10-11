import { useState, type ReactNode } from 'react'
import { NavLink, Outlet } from 'react-router'
import { USING_MOCK } from '../api/client'
import type { LlmModeName } from '../api/types'
import { useApp } from '../state/AppContext'
import { SandboxProvider } from '../state/SandboxContext'
import { TaintBadge, CopyText, field } from './ui'

const NAV_GROUPS = [
  {
    label: 'Dashboards',
    items: [
      { to: '/user', label: 'User Portal' },
      { to: '/admin', label: 'Admin Console' },
    ],
  },
  {
    label: 'Live demo',
    items: [
      { to: '/sandbox', label: 'Agent Sandbox' },
      { to: '/decisions', label: 'Live Decisions' },
      { to: '/approvals', label: 'Approvals' },
      { to: '/graph', label: 'Attack Graph' },
    ],
  },
  {
    label: 'Under the hood',
    items: [
      { to: '/lab', label: 'PromptShield Lab' },
      { to: '/benchmark', label: 'Benchmark' },
      { to: '/policy', label: 'Policy Editor' },
      { to: '/ledger', label: 'Audit Ledger' },
      { to: '/tests', label: 'Test Report' },
    ],
  },
]
const NAV = NAV_GROUPS.flatMap((g) => g.items)

const MODES: { m: LlmModeName; label: string }[] = [
  { m: 'ok', label: 'Healthy' },
  { m: 'down', label: 'Offline' },
  { m: 'says_safe_always', label: 'Compromised (always says safe)' },
  { m: 'timeout', label: 'Times out' },
  { m: 'garbage', label: 'Returns garbage' },
]

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <span className="text-dim">{label}</span>
      <span className="font-mono">{value ?? '–'}</span>
    </div>
  )
}

function VerifyDot({ v }: { v: { valid: boolean; first_broken_seq: number | null } | null }) {
  const cls = !v ? 'bg-faint' : v.valid ? 'bg-allow' : 'bg-block'
  const label = !v ? 'Ledger not verified' : v.valid ? 'Ledger valid' : `Ledger broken at seq ${v.first_broken_seq}`
  return <span role="img" aria-label={label} title={label} className={`h-2.5 w-2.5 rounded-full ${cls}`} />
}

function SystemMenu() {
  const { health, llm, setLlm, ledgerVerify, verifyLedger } = useApp()
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button onClick={() => setOpen((v) => !v)} aria-expanded={open} className="h-8 rounded-sm border border-line-strong px-3 text-[13px] font-medium text-dim transition-colors hover:border-fg hover:text-fg">
        System
      </button>
      {open && (
        <div className="rise absolute right-0 top-10 z-30 w-80 rounded-sm border border-line-strong bg-raised p-4 shadow-2xl shadow-black/60">
          <Row label="Policy version" value={health ? `v${health.policy_version}` : undefined} />
          <Row label="Graph version" value={health ? `v${health.graph_version}` : undefined} />
          <Row
            label="Ledger"
            value={
              <button onClick={() => void verifyLedger()} className="inline-flex items-center gap-2 hover:underline" title="Verify chain">
                {health?.ledger_head ?? '–'}
                <VerifyDot v={ledgerVerify} />
              </button>
            }
          />
          <label className="eyebrow mt-3 block border-t border-line pt-3">
            Simulate LLM failure
            <select
              aria-label="LLM mode"
              value={llm?.mode ?? 'ok'}
              onChange={(e) => setLlm(e.target.value as LlmModeName)}
              className={`mt-1.5 w-full normal-case tracking-normal ${field}`}
            >
              {MODES.map((m) => (
                <option key={m.m} value={m.m}>
                  {m.label}
                </option>
              ))}
            </select>
          </label>
          
        </div>
      )}
    </div>
  )
}

function TopBar() {
  const { user, users, switchUser, llm, setLlm, session, systemStatus } = useApp()
  const [showTaint, setShowTaint] = useState(false)
  const killed = llm?.mode === 'down'
  const degraded = llm ? llm.mode !== 'ok' : false

  return (
    <header className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-line bg-panel px-5 py-2">
      <div className="flex items-center gap-3">
        <NavLink to="/" className="flex items-center gap-3 hover:opacity-90 transition-opacity">
          <span aria-hidden className="flex h-7 w-7 items-center justify-center rounded-sm bg-fg">
            <svg viewBox="0 0 24 24" className="h-4 w-4 text-ink" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round">
              <path d="M12 3 4 6v6c0 4.5 3.4 8 8 9 4.6-1 8-4.5 8-9V6l-8-3Z" />
            </svg>
          </span>
          <div className="leading-tight">
            <p className="text-[15px] font-bold tracking-tight">Sentinel</p>
          </div>
        </NavLink>
      </div>

      <div role="group" aria-label="Signed in as" className="flex items-center gap-1 rounded-sm border border-line p-0.5">
        {users.map((u) => (
          <button
            key={u.user_id}
            onClick={() => switchUser(u.user_id)}
            aria-pressed={user?.user_id === u.user_id}
            title={u.roles.join(', ')}
            className={`rounded-xs px-3 py-1 text-[13px] font-medium transition-colors ${user?.user_id === u.user_id ? 'bg-fg text-ink font-semibold' : 'text-dim hover:text-fg'}`}
          >
            {u.display_name}
            {u.roles.includes('admin') && <span className="ml-1 text-[11px] opacity-75">👑</span>}
          </button>
        ))}
      </div>

      {systemStatus && (
        <div
          className={`hidden md:inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-mono font-medium border ${
            systemStatus.agent_mode === 'live'
              ? 'border-allow/50 bg-allow/10 text-allow'
              : 'border-blue-500/50 bg-blue-500/10 text-blue-400'
          }`}
          title={systemStatus.agent_mode === 'live' ? `Live Model: ${systemStatus.model}` : 'Deterministic Simulation'}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              systemStatus.agent_mode === 'live' ? 'bg-allow animate-pulse' : 'bg-blue-400'
            }`}
          />
          <span>{systemStatus.agent_mode === 'live' ? `LIVE (${systemStatus.model})` : 'SIMULATION'}</span>
        </div>
      )}

      <div className="ml-auto flex items-center gap-3">
        {session && (
          <div className="relative flex items-center gap-2 text-sm text-dim">
            <TaintBadge taint={session.taint_label ?? session.taint_level} onClick={() => setShowTaint((v) => !v)} title="Why is the session marked this way?" />
            {showTaint && (
              <div className="rise absolute right-0 top-9 z-30 w-72 rounded-sm border border-line-strong bg-raised p-4 shadow-2xl shadow-black/60">
                <p className="mb-1 text-sm font-semibold text-fg">Why this label</p>
                {session.taint_reasons?.length ? (
                  <ul className="list-inside list-disc text-sm text-fg">
                    {session.taint_reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm">No untrusted content has been read yet.</p>
                )}
                <p className="mt-2 font-mono text-xs text-faint">{session.session_id}</p>
              </div>
            )}
          </div>
        )}

        <button
          role="switch"
          aria-checked={killed}
          onClick={() => setLlm(killed ? 'ok' : 'down')}
          aria-live="polite"
          className={`flex h-8 items-center gap-2.5 rounded-sm border px-3 text-[13px] font-semibold transition-colors ${degraded ? 'border-path-fallback/70 bg-path-fallback/10 text-path-fallback' : 'border-line-strong hover:border-fg'}`}
        >
          <span className={`relative h-4 w-7 rounded-full transition-colors ${killed ? 'bg-path-fallback' : 'bg-line-strong'}`}>
            <span className={`absolute top-0.5 h-3 w-3 rounded-full bg-ink transition-all ${killed ? 'left-[14px]' : 'left-0.5'}`} />
          </span>
          {!llm ? 'LLM …' : killed ? 'LLM off, rules only' : degraded ? `LLM degraded` : 'Kill the LLM'}
        </button>

        <NavLink
          to="/login"
          title="Switch accounts / Login"
          className="text-xs font-mono text-dim hover:text-fg px-2.5 py-1.5 rounded border border-line hover:border-line-strong transition-colors"
        >
          Login
        </NavLink>

        <SystemMenu />
      </div>
    </header>
  )
}

function Toasts() {
  const { toasts, dismissToast } = useApp()
  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-50 flex w-[26rem] max-w-[calc(100vw-2rem)] flex-col gap-2" aria-live="assertive">
      {toasts.map((t) => (
        <div key={t.id} role="alert" className={`rise pointer-events-auto rounded-sm border border-line-strong border-l-4 bg-raised p-3.5 shadow-2xl shadow-black/60 ${t.tone === 'error' ? 'border-block' : 'border-fg'}`}>
          <div className="flex items-start justify-between gap-3">
            <p className="text-[13px] font-semibold leading-snug">{t.message}</p>
            <button onClick={() => dismissToast(t.id)} aria-label="Dismiss" className="text-dim hover:text-fg">
              ✕
            </button>
          </div>
          {(t.code || t.requestId) && (
            <p className="mt-2 flex gap-3 font-mono text-xs text-dim">
              {t.code && <span>{t.code}</span>}
              {t.requestId && <CopyText text={t.requestId} label={t.requestId} />}
            </p>
          )}
        </div>
      ))}
    </div>
  )
}

export default function Shell() {
  const { pendingApprovals, offline, retryOffline, bootError, user, demoMode } = useApp()
  return (
    <SandboxProvider>
      <div className="flex h-full flex-col">
        {demoMode && (
          <div className="border-b border-hold/30 bg-hold/10 px-5 py-1 text-center font-mono text-[11px] font-medium uppercase tracking-wider text-hold">
            Demo mode, side effects are simulated{USING_MOCK ? ' · mock API' : ''}
          </div>
        )}
        {offline && (
          <div role="alert" className="flex items-center justify-center gap-4 bg-block px-5 py-2 text-sm font-bold text-ink">
            Cannot reach the Sentinel API.
            <button onClick={retryOffline} className="rounded-sm border border-ink px-3 py-0.5 hover:bg-ink hover:text-block">
              Retry
            </button>
          </div>
        )}
        <TopBar />
        <div className="flex min-h-0 flex-1">
          <nav aria-label="Screens" className="hidden w-56 shrink-0 flex-col gap-6 overflow-y-auto border-r border-line bg-panel px-2 py-4 md:flex">
            {NAV_GROUPS.map((g) => (
              <div key={g.label}>
                <p className="eyebrow mb-1.5 px-3">{g.label}</p>
                <div className="space-y-0.5">
                  {g.items.map((n) => (
                    <NavLink
                      key={n.to}
                      to={n.to}
                      className={({ isActive }) => `flex items-center gap-2 rounded-sm px-3 py-1.5 shadow-[inset_2px_0_0_transparent] transition-colors ${isActive ? 'bg-raised text-fg !shadow-[inset_2px_0_0_var(--color-fg)]' : 'text-dim hover:bg-raised/60 hover:text-fg'}`}
                    >
                      <span className="min-w-0 flex-1">
                        <span className="block text-[13px] font-medium leading-snug">{n.label}</span>
                                              </span>
                      {n.to === '/approvals' && pendingApprovals > 0 && (
                        <span className="min-w-5 rounded-xs bg-hold px-1 text-center font-mono text-[11px] font-bold text-ink" aria-label={`${pendingApprovals} pending`}>
                          {pendingApprovals}
                        </span>
                      )}
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </nav>
          <nav aria-label="Screens" className="flex w-full gap-1 overflow-x-auto border-b border-line bg-panel px-2 py-1 md:hidden">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} className={({ isActive }) => `whitespace-nowrap rounded-xs px-3 py-1.5 text-[13px] font-medium ${isActive ? 'bg-fg text-ink' : 'text-dim'}`}>
                {n.label}
              </NavLink>
            ))}
          </nav>
          <main className="min-w-0 flex-1 overflow-auto">
            {user ? (
              <Outlet />
            ) : (
              <div className="p-10 text-dim">{bootError ? `Could not sign in: ${bootError}` : 'Signing in…'}</div>
            )}
          </main>
        </div>
      </div>
      <Toasts />
    </SandboxProvider>
  )
}
