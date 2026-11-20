import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

function AdvisoryPage() {
  return <PageHeader title={copy.page.advisory} />
}

export const advisoryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/vulnerabilities/$id',
  component: AdvisoryPage,
})
