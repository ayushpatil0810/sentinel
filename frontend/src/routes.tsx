import { createBrowserRouter, Navigate } from 'react-router'
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

export const router = createBrowserRouter([
  { path: '/login', Component: Login },
  {
    path: '/',
    Component: Shell,
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
