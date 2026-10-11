import type React from 'react'
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import { ApiError, type Outbox, type ReplayStepInfo, type ReplayStepResult, type SandboxStep } from '../api/types'
import { useApp } from './AppContext'

export interface ChatItem {
  id: number
  step: SandboxStep
}

interface Ctx {
  items: ChatItem[]
  busy: boolean
  blockedLedger: boolean
  outbox: Outbox | null
  outboxError: unknown
  createSession: () => Promise<void>
  send: (text: string) => Promise<void>
  loadReview: (reviewId: string) => Promise<void>
  replay: ReplayStepInfo[]
  results: Record<string, ReplayStepResult>
  startReplay: () => Promise<void>
  nextStep: () => Promise<void>
  autoplay: boolean
  setAutoplay: (v: boolean) => void
  resetSandbox: () => Promise<void>
  refreshOutbox: () => Promise<void>
}

// Kept on globalThis so hot reloads of this module reuse the same context object; otherwise the
// mounted provider and freshly reloaded consumers disagree and throw "provider missing".
const g = globalThis as unknown as { __sentinelSandboxCtx?: React.Context<Ctx | null> }
const C = (g.__sentinelSandboxCtx ??= createContext<Ctx | null>(null))
export const useSandbox = () => {
  const c = useContext(C)
  if (!c) throw new Error('SandboxProvider missing')
  return c
}

export function SandboxProvider({ children }: { children: ReactNode }) {
  const { session, setSession, reportError, user } = useApp()
  const [items, setItems] = useState<ChatItem[]>([])
  const [busy, setBusy] = useState(false)
  const [blockedLedger, setBlockedLedger] = useState(false)
  const [outbox, setOutbox] = useState<Outbox | null>(null)
  const [outboxError, setOutboxError] = useState<unknown>(null)
  const [replay, setReplay] = useState<ReplayStepInfo[]>([])
  const [results, setResults] = useState<Record<string, ReplayStepResult>>({})
  const [autoplay, setAutoplay] = useState(false)
  const idRef = useRef(0)

  const push = useCallback((steps: SandboxStep[]) => setItems((cur) => [...cur, ...steps.map((step) => ({ id: ++idRef.current, step }))]), [])

  const refreshOutbox = useCallback(async () => {
    try {
      setOutbox(await api.outbox())
      setOutboxError(null)
    } catch (e) {
      setOutboxError(e)
    }
  }, [])

  useEffect(() => {
    if (!user) return
    refreshOutbox()
    const t = setInterval(() => !document.hidden && refreshOutbox(), 2000)
    return () => clearInterval(t)
  }, [user, refreshOutbox])

  const syncSession = useCallback(
    async (id: string) => {
      try {
        setSession(await api.getSession(id))
      } catch {
        /* ignore */
      }
    },
    [setSession],
  )

  const guard = useCallback(
    async (fn: () => Promise<void>) => {
      setBusy(true)
      setBlockedLedger(false)
      try {
        await fn()
      } catch (e) {
        if (e instanceof ApiError && e.code === 'ledger.unavailable') setBlockedLedger(true)
        else reportError(e)
        setAutoplay(false)
      } finally {
        setBusy(false)
      }
    },
    [reportError],
  )

  const createSession = useCallback(
    () =>
      guard(async () => {
        const s = await api.createSession('supportbot')
        setSession(s)
        setItems([])
        push([{ kind: 'system', text: `New session ${s.session_id}, owner ${s.owner_user_id}.` }])
      }),
    [guard, push, setSession],
  )

  const send = useCallback(
    (text: string) =>
      guard(async () => {
        if (!session) return
        push([{ kind: 'user', text }])
        const res = await api.sandboxMessage(session.session_id, text)
        push(res.steps)
        await syncSession(session.session_id)
        await refreshOutbox()
      }),
    [guard, push, session, syncSession, refreshOutbox],
  )

  const loadReview = useCallback(
    (reviewId: string) =>
      guard(async () => {
        if (!session) return
        push([{ kind: 'system', text: `Agent reads product review ${reviewId}` }])
        push(await api.loadReview(session.session_id, reviewId))
        await syncSession(session.session_id)
        await refreshOutbox()
      }),
    [guard, push, session, syncSession, refreshOutbox],
  )

  const startReplay = useCallback(
    () =>
      guard(async () => {
        const res = await api.replayStart('demo-v1', true)
        setReplay(res.steps)
        setResults({})
        setItems([])
        setSession(await api.getSession(res.session_id))
        push([{ kind: 'system', text: `Scripted replay ready on ${res.session_id}. Press Next step.` }])
        await refreshOutbox()
      }),
    [guard, push, setSession, refreshOutbox],
  )

  const nextStep = useCallback(async () => {
    if (!replay.length) {
      await startReplay()
      return
    }
    const next = replay.find((s) => s.status === 'pending')
    if (!next || !session) return
    await guard(async () => {
      setReplay((r) => r.map((s) => (s.id === next.id ? { ...s, status: 'running' } : s)))
      try {
        const res = await api.replayStep(session.session_id, next.id)
        setResults((r) => ({ ...r, [next.id]: res }))
        setReplay((r) => r.map((s) => (s.id === next.id ? { ...s, status: res.match ? 'matched' : 'mismatch' } : s)))
        push([{ kind: 'system', text: `${next.id}. ${next.title}` }, ...(res.steps ?? [])])
        await syncSession(session.session_id)
        await refreshOutbox()
      } catch (e) {
        setReplay((r) => r.map((s) => (s.id === next.id ? { ...s, status: 'pending' } : s)))
        throw e
      }
    })
  }, [replay, session, guard, push, startReplay, syncSession, refreshOutbox])

  useEffect(() => {
    if (!autoplay || busy) return
    if (!replay.some((s) => s.status === 'pending')) {
      if (replay.length) setAutoplay(false)
      return
    }
    const t = setTimeout(() => void nextStep(), replay.some((s) => s.status !== 'pending') ? 3000 : 300)
    return () => clearTimeout(t)
  }, [autoplay, busy, replay, nextStep])

  const resetSandbox = useCallback(
    () =>
      guard(async () => {
        await api.sandboxReset()
        setItems([])
        setReplay([])
        setResults({})
        setSession(null)
        await refreshOutbox()
      }),
    [guard, setSession, refreshOutbox],
  )

  return (
    <C.Provider
      value={{ items, busy, blockedLedger, outbox, outboxError, createSession, send, loadReview, replay, results, startReplay, nextStep, autoplay, setAutoplay, resetSandbox, refreshOutbox }}
    >
      {children}
    </C.Provider>
  )
}
