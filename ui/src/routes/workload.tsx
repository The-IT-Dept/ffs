import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { parseWorkloadSearch } from '@/lib/query'
import { rootRoute } from './root'

function WorkloadPage() {
  return <PageHeader title={copy.page.workload} />
}

export const workloadRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/workloads/$kind/$namespace/$name',
  validateSearch: parseWorkloadSearch,
  component: WorkloadPage,
})
