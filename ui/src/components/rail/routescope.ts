import type { ViewId } from '@/api/types'
import {
  type ExplorerKind,
  explorerSearchFor,
  parseCoverageSearch,
  parseImageSearch,
  parseNodeGroupSearch,
  parseWorkloadSearch,
} from '@/lib/query'
import { CLUSTER, parseScope, type Scope, ScopeError, workloadScope } from '@/lib/scope'

// RouteScope is what the rail shows for a page: the scope it covers, the active view, and for an
// image reached from a workload, that workload as the breadcrumb parent.
export interface RouteScope {
  scope: Scope
  view?: ViewId
  from?: string
}

// The search is read through each page's own validator, as the page reads it, so the rail never
// shows a scope or view the page itself dropped.
function scopeOf(kind: ExplorerKind, search: Record<string, unknown>): Scope {
  return parseScope(explorerSearchFor(kind)(search).scope)
}

function routeScopeOf(routeId: string, params: Record<string, string>, search: Record<string, unknown>): RouteScope {
  switch (routeId) {
    case '/':
      return { scope: CLUSTER, view: 'exposure' }
    case '/vulnerabilities': {
      const scope = scopeOf('findings', search)
      return { scope, view: scope.kind === 'cluster' || scope.kind === 'namespace' ? 'vulnerabilities' : 'findings' }
    }
    case '/workloads':
      return { scope: scopeOf('workloads', search), view: 'workloads' }
    case '/images':
      return { scope: scopeOf('images', search), view: 'images' }
    case '/packages':
      return { scope: scopeOf('packages', search), view: 'packages' }
    case '/vulnerabilities/$id':
      return { scope: CLUSTER, view: 'vulnerabilities' }
    case '/workloads/$kind/$namespace/$name':
      return {
        scope: workloadScope(params.kind ?? '', params.namespace ?? '', params.name ?? ''),
        view: parseWorkloadSearch(search).view ?? 'findings',
      }
    case '/images/$digest': {
      const { view, from } = parseImageSearch(search)
      return { scope: { kind: 'image', value: params.digest ?? '' }, view: view ?? 'findings', ...(from ? { from } : {}) }
    }
    case '/namespaces/$namespace':
      return { scope: { kind: 'namespace', value: params.namespace ?? '' }, view: 'exposure' }
    case '/nodes':
      return { scope: CLUSTER, view: 'nodes' }
    case '/nodegroups/$id':
      return { scope: { kind: 'nodegroup', value: params.id ?? '' }, view: parseNodeGroupSearch(search).view ?? 'findings' }
    case '/nodes/$name':
      return { scope: { kind: 'node', value: params.name ?? '' } }
    case '/controlplane':
      return { scope: { kind: 'controlplane', value: '' } }
    case '/coverage':
      return { scope: parseScope(parseCoverageSearch(search).scope), view: 'coverage' }
  }
  return { scope: CLUSTER }
}

// routeScope maps the leaf route of the current page to its rail scope. A scope that does not
// parse falls back to the cluster.
export function routeScope(routeId: string, params: Record<string, string>, search: Record<string, unknown>): RouteScope {
  try {
    return routeScopeOf(routeId, params, search)
  } catch (e) {
    if (e instanceof ScopeError) return { scope: CLUSTER }
    throw e
  }
}
