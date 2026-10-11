import { createBrowserRouter, Navigate, useRouteError } from 'react-router'
import Shell from './components/Shell'
import Login from './screens/Login'
import UserDashboard from './screens/UserDashboard'
import AdminDashboard from './screens/AdminDashboard'
import Sandbox from './screens/Sandbox'
import Decisions from './screens/Decisions'
import Approvals from './screens/Approvals'
import AttackGraph from './screens/AttackGraph'
import Ledger from './screens/Ledger'
import Placeholder from './screens/Placeholder'
import Lab from './screens/Lab'
import Benchmark from './screens/Benchmark'
import Policy from './screens/Policy'
import Tests from './screens/Tests'
import { useApp } from './state/AppContext'

function RootRedirect() {
  const { user } = useApp()
  if (!user) return <Navigate to="/login" replace />
  if (user.roles.includes('admin')) return <Navigate to="/admin" replace />
  return <Navigate to="/user" replace />
}

function RouteError() {
  const error = useRouteError() as any
  return (
    <div className="min-h-full flex flex-col justify-center items-center p-8 bg-ink text-fg">
      <div className="max-w-md w-full p-6 rounded-md border border-block/60 bg-panel text-center space-y-4 shadow-xl">
        <div className="h-12 w-12 rounded-full bg-block/10 text-block mx-auto flex items-center justify-center border border-block/40">
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        </div>
        <h2 className="text-lg font-bold text-fg">Application Notice</h2>
        <p className="text-xs text-dim">
          {error?.statusText || error?.message || 'An unexpected error occurred while rendering the page.'}
        </p>
        <div className="flex items-center justify-center gap-2 pt-2">
          <a href="/" className="px-4 py-2 rounded bg-fg text-ink font-semibold text-xs hover:bg-white transition-colors">
            Return to Home
          </a>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 rounded border border-line text-xs text-fg hover:bg-raised transition-colors"
          >
            Reload
          </button>
        </div>
      </div>
    </div>
  )
}

export const router = createBrowserRouter([
  { path: '/login', Component: Login, ErrorBoundary: RouteError },
  {
    path: '/',
    Component: Shell,
    ErrorBoundary: RouteError,
    children: [
      { index: true, Component: RootRedirect },
      { path: 'user', Component: UserDashboard },
      { path: 'admin', Component: AdminDashboard },
      { path: 'admin/:tab', Component: AdminDashboard },
      { path: 'sandbox', Component: Sandbox },
      { path: 'decisions', Component: Decisions },
      { path: 'approvals', Component: Approvals },
      { path: 'approvals/:id', Component: Approvals },
      { path: 'graph', Component: AttackGraph },
      { path: 'lab', Component: Lab },
      { path: 'benchmark', Component: Benchmark },
      { path: 'policy', Component: Policy },
      { path: 'ledger', Component: Ledger },
      { path: 'tests', Component: Tests },
      { path: '*', element: <Placeholder title="Not found" step="" /> },
    ],
  },
])
