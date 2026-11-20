import { queryOptions } from '@tanstack/react-query'
import { apiFetch, apiKey, apiQuery } from '@/api/client'
import type { ApiParams, S } from '@/api/types'
import { EXPLORERS, type ExplorerKind, type ExplorerSearch, toApiQuery } from '@/lib/query'

export const PAGE_LIMIT = 50

export type ExplorerRow<K extends ExplorerKind> = K extends 'findings'
  ? S<'FindingRow'>
  : K extends 'workloads'
    ? S<'WorkloadRow'>
    : K extends 'images'
      ? S<'ImageRow'>
      : S<'PackageRow'>

export type ExplorerData<K extends ExplorerKind> = K extends 'findings'
  ? S<'FindingsPage'>
  : K extends 'workloads'
    ? S<'WorkloadsPage'>
    : K extends 'images'
      ? S<'ImagesPage'>
      : S<'PackagesPage'>

type ExplorerApi = (typeof EXPLORERS)[ExplorerKind]['api']

// findingsQuery asks /findings for an explorer search. The query goes out in the wire form
// toApiQuery builds (arrays already comma-joined), which is also the cache key.
export function findingsQuery(s: ExplorerSearch, o?: { facets?: readonly string[]; limit?: number }) {
  const query = { ...toApiQuery(s, o?.facets ?? []), ...(o?.limit ? { limit: String(o.limit) } : {}) }
  // The one cast: from the comma-joined wire form to the schema's typed array form.
  return apiQuery('/findings', { query } as unknown as ApiParams<'/findings'>)
}

function groupOfKey(key: readonly unknown[]): unknown {
  return (key[2] as { query?: { group?: unknown } } | undefined)?.query?.group
}

// keepWhileGroup is placeholderData that keeps the previous answer on screen only while the
// grouping (the explorer's group, the home table's regroup) is unchanged. Rows of another
// grouping would render with this grouping's cells and links, so a regroup shows a skeleton.
export function keepWhileGroup<T>(group: string | undefined) {
  return (prev: T | undefined, prevQuery: { queryKey: readonly unknown[] } | undefined): T | undefined =>
    prevQuery && groupOfKey(prevQuery.queryKey) === group ? prev : undefined
}

// explorerQuery asks an explorer's endpoint for a search, with that explorer's facets.
export function explorerQuery<K extends ExplorerKind>(kind: K, s: ExplorerSearch) {
  const spec = EXPLORERS[kind]
  // The same cast as findingsQuery, over the four explorer endpoints.
  const params = { query: toApiQuery(s, spec.facets) } as unknown as ApiParams<ExplorerApi>
  return queryOptions({
    queryKey: apiKey(spec.api, params),
    queryFn: ({ signal }) => apiFetch(spec.api, params, signal) as Promise<ExplorerData<K>>,
  })
}
