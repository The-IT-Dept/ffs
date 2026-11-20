import type { QueryClient } from '@tanstack/react-query'
import { createRouter, type RouterHistory } from '@tanstack/react-router'
import { parseSearchParams, stringifySearchParams } from './lib/query'
import { coverageRoute } from './routes/coverage'
import { exceptionsRoute } from './routes/exceptions'
import { feedsRoute } from './routes/feeds'
import { homeRoute } from './routes/home'
import { imagesRoute } from './routes/images'
import { advisoryRoute, controlPlaneRoute, imageRoute, namespaceRoute, nodeGroupRoute, nodeRoute, workloadRoute } from './routes/lazy'
import { nodesRoute } from './routes/nodes'
import { packagesRoute } from './routes/packages'
import { rootRoute } from './routes/root'
import { settingsRoute } from './routes/settings'
import { vulnerabilitiesRoute } from './routes/vulnerabilities'
import { workloadsRoute } from './routes/workloads'

export const routeTree = rootRoute.addChildren([
  homeRoute,
  vulnerabilitiesRoute,
  advisoryRoute,
  workloadsRoute,
  workloadRoute,
  imagesRoute,
  imageRoute,
  packagesRoute,
  namespaceRoute,
  nodesRoute,
  nodeGroupRoute,
  nodeRoute,
  controlPlaneRoute,
  coverageRoute,
  exceptionsRoute,
  settingsRoute,
  feedsRoute,
])

// createAppRouter builds the router over every page. Search params use comma-joined arrays and
// readable ", : / @" (TanStack's default serialiser would JSON-encode arrays). From the lg
// breakpoint the page scrolls inside #main, not the window: a new page starts #main at the top,
// and back and forward restore it.
export function createAppRouter(o: { queryClient: QueryClient; history?: RouterHistory }) {
  return createRouter({
    routeTree,
    context: { queryClient: o.queryClient },
    ...(o.history ? { history: o.history } : {}),
    parseSearch: parseSearchParams,
    stringifySearch: stringifySearchParams,
    scrollRestoration: true,
    scrollToTopSelectors: ['#main'],
  })
}

export type AppRouter = ReturnType<typeof createAppRouter>

declare module '@tanstack/react-router' {
  interface Register {
    router: AppRouter
  }
}
