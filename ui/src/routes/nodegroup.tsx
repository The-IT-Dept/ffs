import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { parseNodeGroupSearch } from '@/lib/query'
import { rootRoute } from './root'

function NodeGroupPage() {
  return <PageHeader title={copy.page.nodegroup} />
}

export const nodeGroupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/nodegroups/$id',
  validateSearch: parseNodeGroupSearch,
  component: NodeGroupPage,
})
