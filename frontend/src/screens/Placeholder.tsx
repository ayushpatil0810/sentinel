import { EmptyState, PageHeader } from '../components/ui'

export default function Placeholder({ title, step }: { title: string; step: string }) {
  return (
    <div className="space-y-5 p-5 lg:p-6">
      <PageHeader title={title} />
      <EmptyState title={step ? `Not built yet (${step})` : 'Nothing here'} hint={step ? undefined : undefined} />
    </div>
  )
}
