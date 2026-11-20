import { useQuery } from '@tanstack/react-query'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { type Scope, scopeParam } from '@/lib/scope'

// railQuery is the rail's request for a scope (and, for an image reached from a workload, that
// workload). Pages that read the rail's payload ask through it, so they share its cache entry.
export function railQuery(scope: Scope, from?: string) {
  return apiQuery('/scope', { query: { ...scopeParam(scope), ...(from ? { from } : {}) } })
}

// useScopeTrust reads a scope's trust (coverage and feed freshness) from the rail's own request, so
// an empty state beside the rail costs no extra request. pending holds until the request has
// answered or failed.
export function useScopeTrust(scope: Scope): { trust?: S<'Trust'>; pending: boolean } {
  const q = useQuery(railQuery(scope))
  return { trust: q.data?.trust, pending: q.isPending }
}
