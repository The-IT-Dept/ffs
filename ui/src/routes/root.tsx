import type { QueryClient } from '@tanstack/react-query'
import { createRootRouteWithContext, Outlet, type RouteIds, useRouterState } from '@tanstack/react-router'
import { useEffect } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { copy } from '@/lib/copy'
import type { AppRouter } from '@/router'
import { NotFoundPage } from './notfound'

export interface RouterContext {
  queryClient: QueryClient
}

// pageTitles names every route's page; a route added without a title fails the typecheck here.
const pageTitles: Record<Exclude<RouteIds<AppRouter['routeTree']>, '__root__'>, string> = {
  '/': copy.page.home,
  '/vulnerabilities': copy.page.vulnerabilities,
  '/vulnerabilities/$id': copy.page.advisory,
  '/workloads': copy.page.workloads,
  '/workloads/$kind/$namespace/$name': copy.page.workload,
  '/images': copy.page.images,
  '/images/$digest': copy.page.image,
  '/packages': copy.page.packages,
  '/namespaces/$namespace': copy.page.namespace,
  '/nodes': copy.page.nodes,
  '/nodegroups/$id': copy.page.nodegroup,
  '/nodes/$name': copy.page.node,
  '/controlplane': copy.page.controlplane,
  '/coverage': copy.page.coverage,
  '/exceptions': copy.page.exceptions,
  '/settings': copy.page.settings,
  '/feeds': copy.page.feeds,
}

// documentTitle is the tab title of a route: "<page> · ffs"; a path no route matches is not found.
export function documentTitle(routeId: string): string {
  const page = (pageTitles as Record<string, string | undefined>)[routeId] ?? copy.page.notFound
  return `${page} · ffs`
}

function RootLayout() {
  const routeId = useRouterState({ select: (s) => (s.matches.at(-1)?.routeId as string | undefined) ?? '__root__' })
  useEffect(() => {
    document.title = documentTitle(routeId)
  }, [routeId])
  return (
    <AppShell>
      <Outlet />
    </AppShell>
  )
}

export const rootRoute = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
  notFoundComponent: NotFoundPage,
})
