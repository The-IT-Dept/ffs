import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { parseCoverageSearch } from '@/lib/query'
import { rootRoute } from './root'

function CoveragePage() {
  return <PageHeader title={copy.page.coverage} />
}

export const coverageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/coverage',
  validateSearch: parseCoverageSearch,
  component: CoveragePage,
})
