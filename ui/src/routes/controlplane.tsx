import { createRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

function ControlPlanePage() {
  return <PageHeader title={copy.page.controlplane} />
}

export const controlPlaneRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/controlplane',
  component: ControlPlanePage,
})
