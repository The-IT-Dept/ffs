import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

function NodePage() {
  return <PageHeader title={copy.page.node} />
}

export const nodeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/nodes/$name',
  component: NodePage,
})
