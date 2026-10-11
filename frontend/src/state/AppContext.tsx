import type React from 'react'
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { api, DEMO_MODE, setToken } from '../api/client'
import { ApiError, type Health, type LedgerVerify, type LlmMode, type LlmModeName, type Session, type User } from '../api/types'

export interface Toast {
  id: number
  message: string
  code?: string
  requestId?: string
  tone: 'error' | 'info'
}

interface Ctx {
  user: User | null
  users: User[]
  switchUser: (userId: string) => Promise<void>
  health: Health | null
  llm: LlmMode | null
  setLlm: (m: LlmModeName) => Promise<void>
  session: Session | null
  setSession: (s: Session | null) => void
  refreshSession: () => Promise<void>
  pendingApprovals: number
  toasts: Toast[]
  dismissToast: (id: number) => void
  notify: (message: string, tone?: Toast['tone']) => void
  reportError: (e: unknown) => void
  offline: boolean
  retryOffline: () => void
  bootError: string | null
  demoMode: boolean
  ledgerVerify: LedgerVerify | null
  verifyLedger: () => Promise<LedgerVerify | null>
}

// Kept on globalThis so hot reloads of this module reuse the same context object; otherwise the
// mounted provider and freshly reloaded consumers disagree and throw "provider missing".
const g = globalThis as unknown as { __sentinelAppCtx?: React.Context<Ctx | null> }
const AppCtx = (g.__sentinelAppCtx ??= createContext<Ctx | null>(null))
export const useApp = () => {
  const c = useContext(AppCtx)
  if (!c) throw new Error('AppProvider missing')
  return c
}

// The switcher shows these three demo personas. Roles come from the server's /users list when it answers.
const SWITCHER_IDS = ['alice', 'bob', 'admin']
const FALLBACK_USERS: User[] = [
  { user_id: 'alice', display_name: 'Alice', roles: ['requester'] },
  { user_id: 'bob', display_name: 'Bob', roles: ['approver'] },
  { user_id: 'admin', display_name: 'Admin', roles: ['admin'] },
]

export function AppProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [users, setUsers] = useState<User[]>(FALLBACK_USERS)
  const [ledgerVerify, setLedgerVerify] = useState<LedgerVerify | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [llm, setLlmState] = useState<LlmMode | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [pendingApprovals, setPending] = useState(0)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [offline, setOffline] = useState(false)
  const [bootError, setBootError] = useState<string | null>(null)
  const toastId = useRef(0)
  const userRef = useRef<User | null>(null)
  userRef.current = user

  const notify = useCallback((message: string, tone: Toast['tone'] = 'info') => {
    const id = ++toastId.current
    setToasts((t) => [...t, { id, message, tone }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000)
  }, [])

  const reportError = useCallback((e: unknown) => {
    if (e instanceof ApiError) {
      if (e.network) {
        setOffline(true)
        return
      }
      const id = ++toastId.current
      const roleHint = e.code === 'auth.forbidden_role' && Array.isArray(e.details?.required) ? ` Required role: ${(e.details!.required as string[]).join(' or ')}.` : ''
      setToasts((t) => [...t, { id, message: e.message + roleHint, code: e.code, requestId: e.requestId, tone: 'error' }])
      setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 9000)
    } else {
      notify(e instanceof Error ? e.message : 'Unexpected error', 'error')
    }
  }, [notify])

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), [])

  const switchUser = useCallback(
    async (userId: string) => {
      try {
        const res = await api.login(userId, 'demo')
        setToken(res.token)
        setUser(res.user)
        setOffline(false)
      } catch (e) {
        reportError(e)
      }
    },
    [reportError],
  )

  useEffect(() => {
    api
      .login('alice', 'demo')
      .then((res) => {
        setToken(res.token)
        setUser(res.user)
        api
          .users()
          .then((all) => {
            const picked = SWITCHER_IDS.map((id) => all.find((u) => u.user_id === id)).filter((u): u is User => !!u)
            if (picked.length) setUsers(picked)
          })
          .catch(() => {})
        api.verifyLedger().then(setLedgerVerify, () => {})
      })
      .catch((e) => {
        if (e instanceof ApiError && e.network) setOffline(true)
        setBootError(e instanceof Error ? e.message : 'Sign-in failed')
      })
  }, [])

  const refreshSession = useCallback(async () => {
    if (!session) return
    try {
      setSession(await api.getSession(session.session_id))
    } catch {
      /* ignore */
    }
  }, [session])

  // Global poll: health, llm mode, pending approvals.
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!user) return
    let stop = false
    const run = async () => {
      if (document.hidden) return
      try {
        const [h, l, a] = await Promise.all([api.health(), api.llmMode(), api.approvals({ status: 'pending' })])
        if (stop) return
        setHealth(h)
        setLlmState(l)
        setPending(a.length)
        setOffline(false)
      } catch (e) {
        if (e instanceof ApiError && e.network) setOffline(true)
      }
    }
    run()
    const t = setInterval(run, 2000)
    return () => {
      stop = true
      clearInterval(t)
    }
  }, [user, tick])

  const setLlm = useCallback(
    async (m: LlmModeName) => {
      try {
        setLlmState(await api.setLlmMode(m))
      } catch (e) {
        reportError(e)
      }
    },
    [reportError],
  )

  // Never cached: every call recomputes on the server.
  const verifyLedger = useCallback(async () => {
    try {
      const r = await api.verifyLedger()
      setLedgerVerify(r)
      return r
    } catch (e) {
      reportError(e)
      return null
    }
  }, [reportError])
  const demoMode = typeof health?.demo_mode === 'boolean' ? health.demo_mode : DEMO_MODE

  const value = useMemo<Ctx>(
    () => ({
      user,
      users,
      switchUser,
      health,
      llm,
      setLlm,
      session,
      setSession,
      refreshSession,
      pendingApprovals,
      toasts,
      dismissToast,
      notify,
      reportError,
      offline,
      retryOffline: () => {
        setOffline(false)
        setTick((t) => t + 1)
      },
      bootError,
      demoMode,
      ledgerVerify,
      verifyLedger,
    }),
    [user, users, switchUser, health, llm, setLlm, session, refreshSession, pendingApprovals, toasts, dismissToast, notify, reportError, offline, bootError, demoMode, ledgerVerify, verifyLedger],
  )
  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>
}

export function usePoll<T>(fn: () => Promise<T>, ms: number | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const fnRef = useRef(fn)
  fnRef.current = fn
  const [n, setN] = useState(0)
  const { user } = useApp()
  useEffect(() => {
    if (!user) return
    let stop = false
    const run = async (first: boolean) => {
      if (document.hidden && !first) return
      try {
        const d = await fnRef.current()
        if (!stop) {
          setData(d)
          setError(null)
        }
      } catch (e) {
        if (!stop) setError(e)
      } finally {
        if (!stop) setLoading(false)
      }
    }
    setLoading(true)
    run(true)
    if (ms === null) return () => void (stop = true)
    const t = setInterval(() => run(false), ms)
    return () => {
      stop = true
      clearInterval(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, ms, n, ...deps])
  return { data, error, loading, reload: () => setN((x) => x + 1), setData }
}
