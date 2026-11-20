import type { ApiPath, ChangeKind, S } from './types'

const all: readonly ChangeKind[] = ['findings', 'inventory', 'images', 'feeds', 'nodes', 'exceptions']
const entities: readonly ChangeKind[] = ['images', 'findings', 'inventory']
const nodes: readonly ChangeKind[] = ['nodes', 'findings']

// endpointKinds lists, per endpoint, the change kinds that can alter its answer. It is a Record over
// every path, so adding an endpoint without an entry fails the typecheck.
export const endpointKinds: Record<ApiPath, readonly ChangeKind[]> = {
  '/summary': all,
  '/scope': all,
  '/exposure': ['findings', 'inventory', 'images', 'nodes'],
  '/findings': ['findings'],
  '/transitions': ['findings'],
  '/advisories/{id}': ['findings'],
  '/workloads': ['findings', 'inventory', 'images'],
  '/workloads/{kind}/{namespace}/{name}': ['findings', 'inventory', 'images'],
  '/images': entities,
  '/images/{digest}': entities,
  '/images/{digest}/packages': entities,
  '/packages': entities,
  '/nodegroups': nodes,
  '/nodegroups/{id}': nodes,
  '/nodes/{name}': nodes,
  '/coverage': ['images', 'feeds', 'nodes', 'inventory'],
  '/feeds': ['feeds'],
  '/exceptions': ['exceptions'],
  '/search': [],
  '/settings': [],
}

function isApiPath(v: unknown): v is ApiPath {
  return typeof v === 'string' && Object.hasOwn(endpointKinds, v)
}

// shouldInvalidate reports whether a change event can alter the answer cached under key, a query
// key built by apiKey: the kinds must meet the endpoint's, and the scopes must meet the query's.
export function shouldInvalidate(key: readonly unknown[], ev: S<'ChangeEvent'>): boolean {
  if (key[0] !== 'api' || !isApiPath(key[1])) return false
  if (ev.kinds.includes('all')) return true
  const kinds = endpointKinds[key[1]]
  if (!kinds.some((k) => ev.kinds.includes(k))) return false
  const params = key[2] as { query?: { scope?: unknown } } | undefined
  const scope = params?.query?.scope
  if (typeof scope !== 'string' || scope === '' || scope === 'cluster') return true
  return ev.scopes.includes('*') || ev.scopes.includes(scope) || ev.scopes.includes(`${scope.split(':')[0]}:*`)
}
