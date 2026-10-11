import { createBrowserRouter, Navigate } from 'react-router'
import Shell from './components/Shell'
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

export const router = createBrowserRouter([
  {
    path: '/',
    Component: Shell,
    children: [
      { index: true, element: <Navigate to="/sandbox" replace /> },
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
