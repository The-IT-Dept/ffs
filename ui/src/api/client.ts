import { QueryClient, queryOptions } from '@tanstack/react-query'
import createClient from 'openapi-fetch'
import type { paths } from './schema'
import type { ApiData, ApiParams, ApiPath, ProblemCode, S } from './types'

type ProblemInit = Omit<S<'Problem'>, 'cluster' | 'generatedAt'> & Partial<Pick<S<'Problem'>, 'cluster' | 'generatedAt'>>

// ApiProblem is an RFC 9457 problem document the API answered with, or one made up for an error
// response that was not a problem document.
export class ApiProblem extends Error {
  readonly status: number
  readonly code: ProblemCode
  readonly title: string
  readonly detail?: string

  constructor(p: ProblemInit) {
    super(p.detail ?? p.title)
    this.name = 'ApiProblem'
    this.status = p.status
    this.code = p.code
    this.title = p.title
    if (p.detail !== undefined) this.detail = p.detail
  }
}

// The paths in the schema are relative to the /api/v1 server. The base URL is absolute so Node's
// Request accepts it under Vitest, and fetch is looked up per call so a stubbed global takes effect.
export const client = createClient<paths>({
  baseUrl: `${location.origin}/api/v1`,
  querySerializer: { array: { style: 'form', explode: false } },
  fetch: (r) => globalThis.fetch(r),
})

export type ApiKey<P extends ApiPath> = readonly ['api', P, ApiParams<P>]

export function apiKey<P extends ApiPath>(path: P, params: ApiParams<P>): ApiKey<P> {
  return ['api', path, params] as const
}

function isProblem(v: unknown): v is S<'Problem'> {
  if (typeof v !== 'object' || v === null) return false
  const p = v as Record<string, unknown>
  return typeof p.code === 'string' && typeof p.status === 'number'
}

export async function apiFetch<P extends ApiPath>(path: P, params: ApiParams<P>, signal?: AbortSignal): Promise<ApiData<P>> {
  // The one cast: openapi-fetch's init type does not resolve over a generic path.
  const { data, error, response } = await client.GET(path, { params, signal } as never)
  if (!response.ok) {
    const body: unknown = error
    if (isProblem(body)) throw new ApiProblem(body)
    throw new ApiProblem({
      type: 'about:blank',
      title: response.statusText || `HTTP ${response.status}`,
      status: response.status,
      code: 'internal',
    })
  }
  return data as ApiData<P>
}

export function apiQuery<P extends ApiPath>(path: P, params: ApiParams<P>) {
  return queryOptions({
    queryKey: apiKey(path, params),
    queryFn: ({ signal }) => apiFetch(path, params, signal),
  })
}

export function createQueryClient(opts?: { retry?: boolean }): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: true,
        // A 4xx problem is an answer, not a fault: retrying it cannot help.
        retry: opts?.retry === false ? false : (n, e) => n < 2 && !(e instanceof ApiProblem && e.status < 500),
      },
    },
  })
}
