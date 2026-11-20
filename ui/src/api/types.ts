import type { components, paths } from './schema'

// Every type the UI uses comes from the generated schema; these are short names for it.
export type Schemas = components['schemas']
export type S<N extends keyof Schemas> = Schemas[N]

// ApiPath is every GET operation answered with JSON; the event stream is read by api/live.ts.
export type ApiPath = Exclude<keyof paths, '/stream'>
export type ApiParams<P extends ApiPath> = paths[P]['get']['parameters']
export type ApiData<P extends ApiPath> =
  paths[P]['get'] extends { responses: { 200: { content: { 'application/json': infer T } } } } ? T : never

export type Priority = S<'Priority'>
export type ProblemCode = S<'ProblemCode'>
export type ChangeKind = S<'ChangeKind'>
export type ViewId = S<'ViewId'>
export type GapCode = S<'GapCode'>
export type SearchHit = S<'SearchResult'>['hits'][number]
