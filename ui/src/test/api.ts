import { vi } from 'vitest'
import { endpointKinds } from '@/api/keys'
import type { ApiData, ApiPath, ProblemCode, S } from '@/api/types'
import { scopeCard } from './fixtures'

export const ENV = { cluster: 'test', generatedAt: '2026-11-19T00:00:00Z' } as const

export interface ProblemReply {
  problem: S<'Problem'>
}

const titles: Record<number, string> = { 400: 'Bad Request', 404: 'Not Found', 500: 'Internal Server Error', 503: 'Service Unavailable' }

export function problem(status: number, code: ProblemCode, detail?: string): ProblemReply {
  return {
    problem: { ...ENV, type: 'about:blank', title: titles[status] ?? `HTTP ${status}`, status, code, ...(detail !== undefined ? { detail } : {}) },
  }
}

export type Reply<P extends ApiPath> = ApiData<P> | ProblemReply | Response

export interface MockApi {
  on<P extends ApiPath>(path: P, reply: Reply<P> | ((url: URL) => Reply<P>)): MockApi
  calls(path: ApiPath): URL[]
  readonly unmatched: string[]
}

const PATHS = Object.keys(endpointKinds) as ApiPath[]

// A path template becomes a pattern under /api/v1 where each {param} is one segment, so an
// encoded placeholder image ID stays one segment.
function pattern(path: ApiPath): RegExp {
  const body = path
    .split(/(\{[^}]+\})/)
    .map((part) => (part.startsWith('{') ? '[^/]+' : part.replace(/[.*+?^$()|[\]\\]/g, '\\$&')))
    .join('')
  return new RegExp(`^/api/v1${body}$`)
}

const PATTERNS = PATHS.map((p) => [p, pattern(p)] as const)

function isProblemReply(r: unknown): r is ProblemReply {
  return typeof r === 'object' && r !== null && !(r instanceof Response) && Object.keys(r).length === 1 && 'problem' in r
}

function toResponse(r: unknown): Response {
  if (r instanceof Response) return r.clone()
  if (isProblemReply(r)) {
    return new Response(JSON.stringify(r.problem), { status: r.problem.status, headers: { 'content-type': 'application/problem+json' } })
  }
  return new Response(JSON.stringify(r), { status: 200, headers: { 'content-type': 'application/json' } })
}

// mockApi stubs fetch for the API. It records every request by its schema path; the last on() for
// a path wins; a request no on() answers is recorded in unmatched and answered 404 not_found.
// /scope, which the rail asks on every page, answers scopeCard() until a test sets its own.
export function mockApi(): MockApi {
  const replies = new Map<ApiPath, unknown>()
  const calls = new Map<ApiPath, URL[]>()
  const unmatched: string[] = []

  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(input, init)
    const url = new URL(req.url)
    const match = PATTERNS.find(([, re]) => re.test(url.pathname))
    if (match) calls.set(match[0], [...(calls.get(match[0]) ?? []), url])
    if (!match || !replies.has(match[0])) {
      unmatched.push(url.pathname + url.search)
      return toResponse(problem(404, 'not_found', `no mock for ${url.pathname}`))
    }
    const reply = replies.get(match[0])
    return toResponse(typeof reply === 'function' ? (reply as (u: URL) => unknown)(url) : reply)
  })

  const api: MockApi = {
    on(path, reply) {
      replies.set(path, reply)
      return api
    },
    calls(path) {
      return calls.get(path) ?? []
    },
    unmatched,
  }
  return api.on('/scope', scopeCard())
}
