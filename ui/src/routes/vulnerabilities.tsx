import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

function VulnerabilitiesPage() {
  return <PageHeader title={copy.page.vulnerabilities} />
}

export const vulnerabilitiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/vulnerabilities',
  validateSearch: explorerSearchFor('findings'),
  component: VulnerabilitiesPage,
})
