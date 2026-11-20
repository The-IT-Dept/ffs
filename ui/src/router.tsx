import type { QueryClient } from '@tanstack/react-query'
import { createRouter, type RouterHistory } from '@tanstack/react-router'
import { parseSearchParams, stringifySearchParams } from './lib/query'
import { advisoryRoute } from './routes/advisory'
import { controlPlaneRoute } from './routes/controlplane'
import { coverageRoute } from './routes/coverage'
import { exceptionsRoute } from './routes/exceptions'
import { feedsRoute } from './routes/feeds'
import { homeRoute } from './routes/home'
import { imageRoute } from './routes/image'
import { imagesRoute } from './routes/images'
import { namespaceRoute } from './routes/namespace'
import { nodeRoute } from './routes/node'
import { nodeGroupRoute } from './routes/nodegroup'
import { nodesRoute } from './routes/nodes'
import { packagesRoute } from './routes/packages'
import { rootRoute } from './routes/root'
import { settingsRoute } from './routes/settings'
import { vulnerabilitiesRoute } from './routes/vulnerabilities'
import { workloadRoute } from './routes/workload'
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
// readable ", : / @" (TanStack's default serialiser would JSON-encode arrays).
export function createAppRouter(o: { queryClient: QueryClient; history?: RouterHistory }) {
  return createRouter({
    routeTree,
    context: { queryClient: o.queryClient },
    ...(o.history ? { history: o.history } : {}),
    parseSearch: parseSearchParams,
    stringifySearch: stringifySearchParams,
    scrollRestoration: true,
  })
}

export type AppRouter = ReturnType<typeof createAppRouter>

declare module '@tanstack/react-router' {
  interface Register {
    router: AppRouter
  }
}
