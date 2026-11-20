import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

function PackagesPage() {
  return <PageHeader title={copy.page.packages} />
}

export const packagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/packages',
  validateSearch: explorerSearchFor('packages'),
  component: PackagesPage,
})
