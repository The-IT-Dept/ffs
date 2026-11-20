import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

function NodesPage() {
  return <PageHeader title={copy.page.nodes} />
}

export const nodesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/nodes',
  component: NodesPage,
})
