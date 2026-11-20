import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

function ImagesPage() {
  return <PageHeader title={copy.page.images} />
}

export const imagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/images',
  validateSearch: explorerSearchFor('images'),
  component: ImagesPage,
})
