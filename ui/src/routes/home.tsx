import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { parseHomeSearch } from '@/lib/query'
import { rootRoute } from './root'

function HomePage() {
  return <PageHeader title={copy.page.home} />
}

export const homeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  validateSearch: parseHomeSearch,
  component: HomePage,
})
