import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { parseNamespaceSearch } from '@/lib/query'
import { rootRoute } from './root'

function NamespacePage() {
  return <PageHeader title={copy.page.namespace} />
}

export const namespaceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/namespaces/$namespace',
  validateSearch: parseNamespaceSearch,
  component: NamespacePage,
})
