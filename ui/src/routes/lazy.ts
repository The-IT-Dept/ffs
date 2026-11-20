import { createRoute, redirect } from '@tanstack/react-router'
import { parseImageSearch, parseNamespaceSearch, parseNodeGroupSearch, parseWorkloadSearch, revalidate } from '@/lib/query'
import { formatScope } from '@/lib/scope'
import { rootRoute } from './root'

// The detail pages load their code on first visit: each route is defined here, with its path,
// search validation and redirects, and its page comes from its own module (createLazyRoute there),
// so the first view needs only the shell, the home page and the explorers.

export const advisoryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/vulnerabilities/$id',
}).lazy(() => import('./advisory').then((m) => m.Route))

export const workloadRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/workloads/$kind/$namespace/$name',
  validateSearch: parseWorkloadSearch,
}).lazy(() => import('./workload').then((m) => m.Route))

export const imageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/images/$digest',
  validateSearch: parseImageSearch,
}).lazy(() => import('./image').then((m) => m.Route))

export const namespaceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/namespaces/$namespace',
  validateSearch: parseNamespaceSearch,
  // The namespace's explorer views are the scoped explorers themselves.
  beforeLoad: ({ params, search }) => {
    const { view } = revalidate(parseNamespaceSearch, search)
    if (!view || view === 'exposure') return
    const scoped = { scope: formatScope({ kind: 'namespace', value: params.namespace }) }
    if (view === 'vulnerabilities') throw redirect({ to: '/vulnerabilities', search: scoped, replace: true })
    if (view === 'images') throw redirect({ to: '/images', search: scoped, replace: true })
    throw redirect({ to: '/packages', search: scoped, replace: true })
  },
}).lazy(() => import('./namespace').then((m) => m.Route))

export const nodeGroupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/nodegroups/$id',
  validateSearch: parseNodeGroupSearch,
}).lazy(() => import('./nodegroup').then((m) => m.Route))

export const nodeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/nodes/$name',
}).lazy(() => import('./node').then((m) => m.Route))

export const controlPlaneRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/controlplane',
}).lazy(() => import('./controlplane').then((m) => m.Route))
