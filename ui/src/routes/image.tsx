import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { parseImageSearch } from '@/lib/query'
import { rootRoute } from './root'

function ImagePage() {
  return <PageHeader title={copy.page.image} />
}

export const imageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/images/$digest',
  validateSearch: parseImageSearch,
  component: ImagePage,
})
