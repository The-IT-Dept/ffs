import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

function ExceptionsPage() {
  return <PageHeader title={copy.page.exceptions} />
}

export const exceptionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/exceptions',
  component: ExceptionsPage,
})
