import { createBrowserRouter, Navigate } from 'react-router'
import Shell from './components/Shell'
import Sandbox from './screens/Sandbox'
import Decisions from './screens/Decisions'
import Approvals from './screens/Approvals'
import Placeholder from './screens/Placeholder'

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
      { path: 'graph', element: <Placeholder title="Attack Graph" step="Step 4" /> },
      { path: 'lab', element: <Placeholder title="PromptShield Lab" step="Step 6" /> },
      { path: 'benchmark', element: <Placeholder title="Benchmark" step="Step 6" /> },
      { path: 'policy', element: <Placeholder title="Policy Editor" step="Step 6" /> },
      { path: 'ledger', element: <Placeholder title="Audit Ledger" step="Step 5" /> },
      { path: 'tests', element: <Placeholder title="Test Report" step="Step 6" /> },
      { path: '*', element: <Placeholder title="Not found" step="" /> },
    ],
  },
])
