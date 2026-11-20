import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

function FeedsPage() {
  return <PageHeader title={copy.page.feeds} />
}

export const feedsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/feeds',
  component: FeedsPage,
})
