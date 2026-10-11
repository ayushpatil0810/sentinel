import { useState } from 'react'
import { useNavigate } from 'react-router'
import { api, setToken } from '../api/client'
import { useApp } from '../state/AppContext'

interface DemoPersona {
  id: string
  name: string
  title: string
  roles: string[]
  dest: string
  desc: string
  color: string
}

const PERSONAS: DemoPersona[] = [
  {
    id: 'alice',
    name: 'Alice',
    title: 'Support Specialist',
    roles: ['requester'],
    dest: '/user',
    desc: 'Interacts with SupportBot, initiates customer actions. Cannot self-approve.',
    color: 'from-blue-500/20 to-cyan-500/10 border-blue-500/40 text-blue-400',
  },
  {
    id: 'bob',
    name: 'Bob',
    title: 'Compliance Approver',
    roles: ['approver'],
    dest: '/user',
    desc: 'Authorized to review and approve held actions. Evaluates risk and blast radius.',
    color: 'from-amber-500/20 to-orange-500/10 border-amber-500/40 text-amber-400',
  },
  {
    id: 'admin',
    name: 'Admin',
    title: 'Security Administrator',
    roles: ['admin', 'approver'],
    dest: '/admin',
    desc: 'Full control plane access: LLM settings, policy editor, attack graph, and audit ledger.',
    color: 'from-emerald-500/20 to-teal-500/10 border-emerald-500/40 text-emerald-400',
  },
  {
    id: 'dana',
    name: 'Dana',
    title: 'Secondary Admin',
    roles: ['admin', 'approver'],
    dest: '/admin',
    desc: 'Dual-admin gate participant. Co-approves policy amendments and graph updates.',
    color: 'from-purple-500/20 to-pink-500/10 border-purple-500/40 text-purple-400',
  },
]

export default function Login() {
  const navigate = useNavigate()
  const { notify } = useApp()
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('demo')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleLogin = async (userId: string, pass = 'demo') => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.login(userId, pass)
      setToken(res.token)
      notify(`Signed in as ${res.user.display_name} (${res.user.roles.join(', ')})`, 'info')
      navigate(res.redirect_to || (res.user.roles.includes('admin') ? '/admin' : '/user'))
    } catch (e: any) {
      setError(e?.message || 'Authentication failed. Please check credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-full flex flex-col justify-center items-center px-4 py-12 bg-radial from-raised via-ink to-ink text-fg">
      <div className="w-full max-w-4xl space-y-8">
        {/* Brand Header */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center gap-2.5 px-3 py-1.5 rounded-full border border-line-strong bg-raised/80 backdrop-blur-md shadow-lg shadow-black/40">
            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-fg text-ink">
              <svg viewBox="0 0 24 24" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinejoin="round">
                <path d="M12 3 4 6v6c0 4.5 3.4 8 8 9 4.6-1 8-4.5 8-9V6l-8-3Z" />
              </svg>
            </span>
            <span className="font-mono text-xs font-semibold tracking-wider uppercase text-dim">Sentinel Security Control Plane</span>
            <span className="h-1.5 w-1.5 rounded-full bg-allow animate-pulse" />
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
            Role-Based Access &amp; Gateway
          </h1>
          <p className="max-w-xl mx-auto text-sm sm:text-base text-dim">
            Enforcing deterministic rules, prompt boundary screening, post-model action authorization, and immutable ledger audit.
          </p>
        </div>

        {/* Demo Personas Grid */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="eyebrow text-faint">Select a Demo Persona (One-Click Sign In)</p>
            <span className="text-xs font-mono text-dim">AU-05 Server Role Enforcement</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {PERSONAS.map((p) => (
              <button
                key={p.id}
                type="button"
                disabled={loading}
                onClick={() => handleLogin(p.id, 'demo')}
                className={`relative group flex flex-col justify-between p-4 rounded-md border bg-panel hover:bg-raised transition-all duration-200 text-left hover:scale-[1.02] hover:shadow-xl hover:shadow-black/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-fg ${p.color}`}
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-base font-bold text-fg group-hover:underline">{p.name}</span>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border border-current bg-ink/60">
                      {p.roles[0]}
                    </span>
                  </div>
                  <p className="text-xs font-medium text-dim">{p.title}</p>
                  <p className="text-xs text-faint leading-relaxed">{p.desc}</p>
                </div>

                <div className="mt-4 pt-3 border-t border-line/60 flex items-center justify-between text-xs font-mono">
                  <span className="text-dim">Target: {p.dest}</span>
                  <span className="font-semibold group-hover:translate-x-1 transition-transform">→</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Divider / Manual Form */}
        <div className="max-w-md mx-auto pt-4 border-t border-line space-y-4">
          <div className="text-center">
            <p className="text-xs text-dim">Or authenticate with explicit credentials</p>
          </div>

          {error && (
            <div role="alert" className="p-3 rounded-sm border border-block/60 bg-block/10 text-block text-xs font-semibold">
              {error}
            </div>
          )}

          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (username) handleLogin(username, password)
            }}
            className="space-y-3 bg-panel p-5 rounded-md border border-line-strong shadow-xl"
          >
            <div>
              <label className="block text-xs font-mono text-dim mb-1">User Identifier</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full rounded-sm border border-line-strong bg-ink px-3 py-2 text-sm text-fg placeholder:text-faint focus-visible:border-fg"
                placeholder="alice, bob, admin, or dana"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-dim mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full rounded-sm border border-line-strong bg-ink px-3 py-2 text-sm text-fg placeholder:text-faint focus-visible:border-fg"
                placeholder="demo"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !username}
              className="w-full mt-2 py-2.5 px-4 rounded-sm bg-fg text-ink font-semibold text-sm hover:bg-white active:scale-[0.99] transition-all disabled:opacity-50"
            >
              {loading ? 'Authenticating…' : 'Sign In'}
            </button>

            <p className="text-[11px] text-center text-faint">
              Demo credentials: password is <code className="text-dim">demo</code> for all seeded accounts.
            </p>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center text-xs text-faint space-y-1">
          <p>Two Auth Planes · Human Plane (/api/v1) &amp; Agent Plane (/agent/v1) strictly isolated.</p>
          <p>Audit Ledger: Append-only hash chain guarantees non-repudiation of all decisions.</p>
        </div>
      </div>
    </div>
  )
}
