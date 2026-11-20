import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

function WorkloadsPage() {
  return <PageHeader title={copy.page.workloads} />
}

export const workloadsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/workloads',
  validateSearch: explorerSearchFor('workloads'),
  component: WorkloadsPage,
})
