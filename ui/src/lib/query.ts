import type { S } from '@/api/types'
import { copy, facetValueLabel } from './copy'
import { COVERAGE_CLASSES, FINDING_STATES, FIX_CLASSES, IMAGE_STATUSES, isOneOf, PRIORITIES, SIGNALS } from './enums'
import { parseScope, type ScopeKind } from './scope'

// ExplorerSearch is an explorer's whole query, as it lives in the URL. Arrays are comma-joined in
// the URL (priority=urgent,high).
export interface ExplorerSearch {
  scope?: string
  state?: string[]
  priority?: string[]
  fix?: string[]
  signal?: string[]
  ecosystem?: string[]
  namespace?: string[]
  kind?: string[]
  coverage?: string[]
  status?: string[]
  source?: string[]
  advisory?: string
  package?: string
  repo?: string
  q?: string
  group?: string
  sort?: string
  cursor?: string
  fixKey?: string // the exact fix key a findings group=fix row carries; chip "Fix: {key}"
}

const ARRAY_KEYS = ['state', 'priority', 'fix', 'signal', 'ecosystem', 'namespace', 'kind', 'coverage', 'status', 'source'] as const
const STRING_KEYS = ['scope', 'advisory', 'package', 'repo', 'q', 'group', 'sort', 'cursor', 'fixKey'] as const
type ArrayKey = (typeof ARRAY_KEYS)[number]
type StringKey = (typeof STRING_KEYS)[number]

function isArrayKey(k: string): k is ArrayKey {
  return (ARRAY_KEYS as readonly string[]).includes(k)
}

const ENUM_VALUES: Partial<Record<ArrayKey, readonly string[]>> = {
  state: FINDING_STATES,
  priority: PRIORITIES,
  fix: FIX_CLASSES,
  signal: SIGNALS,
  coverage: COVERAGE_CLASSES,
  status: IMAGE_STATUSES,
}

export type ExplorerKind = 'findings' | 'workloads' | 'images' | 'packages'

export interface ExplorerSpec {
  path: '/vulnerabilities' | '/workloads' | '/images' | '/packages'
  api: '/findings' | '/workloads' | '/images' | '/packages'
  keys: readonly (keyof ExplorerSearch)[]
  facets: readonly string[]
  sorts: readonly string[] // the default first
  groups: readonly string[]
  scopes: readonly ScopeKind[]
  noun: [one: string, many: string]
}

// EXPLORERS mirrors the API's parameter, facet, sort and group tables for each explorer.
export const EXPLORERS: Record<ExplorerKind, ExplorerSpec> = {
  findings: {
    path: '/vulnerabilities',
    api: '/findings',
    keys: ['scope', 'state', 'priority', 'fix', 'signal', 'ecosystem', 'namespace', 'kind', 'advisory', 'package', 'repo', 'q', 'group', 'sort', 'fixKey', 'cursor'],
    facets: ['state', 'priority', 'fix', 'signal', 'ecosystem', 'namespace', 'kind'],
    sorts: ['-priority', '-severity', '-published', '-epss', 'advisory', 'workload', 'namespace'],
    groups: ['advisory', 'workload', 'image', 'package', 'namespace', 'fix'],
    scopes: ['cluster', 'namespace', 'workload', 'image', 'nodegroup', 'node', 'controlplane'],
    noun: ['finding', 'findings'],
  },
  workloads: {
    path: '/workloads',
    api: '/workloads',
    keys: ['scope', 'kind', 'namespace', 'signal', 'priority', 'coverage', 'q', 'sort', 'cursor'],
    facets: ['kind', 'namespace', 'signal', 'priority', 'coverage'],
    sorts: ['-risk', 'name', 'namespace', '-findings'],
    groups: [],
    scopes: ['cluster', 'namespace'],
    noun: ['workload', 'workloads'],
  },
  images: {
    path: '/images',
    api: '/images',
    keys: ['scope', 'status', 'source', 'coverage', 'namespace', 'priority', 'q', 'sort', 'cursor'],
    facets: ['status', 'source', 'coverage', 'namespace', 'priority'],
    sorts: ['-risk', 'repo', '-workloads'],
    groups: [],
    scopes: ['cluster', 'namespace', 'workload'],
    noun: ['image', 'images'],
  },
  packages: {
    path: '/packages',
    api: '/packages',
    keys: ['scope', 'ecosystem', 'priority', 'q', 'sort', 'cursor'],
    facets: ['ecosystem', 'priority'],
    sorts: ['-risk', 'name', '-images'],
    groups: [],
    scopes: ['cluster', 'namespace', 'workload', 'image'],
    noun: ['package', 'packages'],
  },
}

const ALL_SORTS = new Set(Object.values(EXPLORERS).flatMap((e) => e.sorts))
const ALL_GROUPS = new Set(Object.values(EXPLORERS).flatMap((e) => e.groups))

function scopeKindOf(s: string): ScopeKind | undefined {
  try {
    return parseScope(s).kind
  } catch {
    return undefined
  }
}

// listOf reads an array parameter in either form the router hands over: a comma-joined string
// (from the URL) or a string array (from navigate). Items are split on ",", empty items dropped,
// and duplicates removed in first-seen order.
function listOf(v: unknown): string[] {
  const raw = typeof v === 'string' ? [v] : Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
  const out: string[] = []
  for (const item of raw.flatMap((x) => x.split(','))) {
    if (item !== '' && !out.includes(item)) out.push(item)
  }
  return out
}

function stringOf(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined
}

// parseExplorerSearch keeps the known keys and drops every value the schema would reject.
export function parseExplorerSearch(raw: Record<string, unknown>): ExplorerSearch {
  const out: Record<string, unknown> = {}
  for (const k of ARRAY_KEYS) {
    const allowed = ENUM_VALUES[k]
    const vals = listOf(raw[k]).filter((v) => !allowed || allowed.includes(v))
    if (vals.length) out[k] = vals
  }
  for (const k of STRING_KEYS) {
    const v = stringOf(raw[k])
    if (v === undefined) continue
    if (k === 'scope' && scopeKindOf(v) === undefined) continue
    if (k === 'group' && !ALL_GROUPS.has(v)) continue
    if (k === 'sort' && !ALL_SORTS.has(v)) continue
    out[k] = v
  }
  return out as ExplorerSearch
}

// explorerSearchFor is the router's validateSearch for one explorer: it also drops whatever that
// explorer's endpoint does not take.
export function explorerSearchFor(kind: ExplorerKind): (raw: Record<string, unknown>) => ExplorerSearch {
  const spec = EXPLORERS[kind]
  return (raw) => {
    const s = parseExplorerSearch(raw) as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const k of spec.keys) if (s[k] !== undefined) out[k] = s[k]
    if (typeof out.sort === 'string' && !spec.sorts.includes(out.sort)) delete out.sort
    if (typeof out.group === 'string' && !spec.groups.includes(out.group)) delete out.group
    if (typeof out.scope === 'string') {
      const sk = scopeKindOf(out.scope)
      if (!sk || !spec.scopes.includes(sk)) delete out.scope
    }
    return out as ExplorerSearch
  }
}

function isDefaultState(v: readonly string[]): boolean {
  return v.length === 1 && v[0] === 'open'
}

// toApiQuery is the wire form of an explorer search: arrays comma-joined, and every default left
// out (the cluster scope, the default sorts and the open state), so equal queries share one key.
export function toApiQuery(s: ExplorerSearch, facets: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of ARRAY_KEYS) {
    const v = s[k]
    if (!v || v.length === 0) continue
    if (k === 'state' && isDefaultState(v)) continue
    out[k] = v.join(',')
  }
  for (const k of STRING_KEYS) {
    const v = s[k]
    if (v === undefined || v === '') continue
    if (k === 'scope' && v === 'cluster') continue
    if (k === 'sort' && (v === '-priority' || v === '-risk')) continue
    out[k] = v
  }
  if (facets.length) out.facets = facets.join(',')
  return out
}

export interface Chip {
  key: keyof ExplorerSearch
  value: string
  label: string
}

const CHIP_STRING_KEYS: readonly StringKey[] = ['advisory', 'package', 'repo', 'q', 'fixKey']

// chipsOf lists the removable filters of a search: the scope, then every array value, then the
// single-value filters. Grouping, sorting and paging are not filters. A value reads by the label
// the server gives it in facets, when it gives one.
export function chipsOf(s: ExplorerSearch, facets?: S<'Facets'>): Chip[] {
  const chips: Chip[] = []
  if (s.scope && s.scope !== 'cluster') chips.push({ key: 'scope', value: s.scope, label: `${copy.facetTitle.scope}: ${s.scope}` })
  for (const k of ARRAY_KEYS) {
    for (const v of s[k] ?? []) {
      const label = facets?.[k]?.find((f) => f.value === v)?.label || facetValueLabel(k, v)
      chips.push({ key: k, value: v, label: `${copy.facetTitle[k]}: ${label}` })
    }
  }
  for (const k of CHIP_STRING_KEYS) {
    const v = s[k]
    if (v) chips.push({ key: k, value: v, label: `${copy.facetTitle[k]}: ${v}` })
  }
  return chips
}

// withFacet turns one filter value on or off. It always drops the cursor, never writes the
// default state, and removes a key that ends up empty.
export function withFacet(s: ExplorerSearch, key: keyof ExplorerSearch, value: string, on: boolean): ExplorerSearch {
  const next: Record<string, unknown> = { ...s }
  delete next.cursor
  if (isArrayKey(key)) {
    const base = key === 'state' ? (s.state ?? ['open']) : (s[key] ?? [])
    const vals = on ? (base.includes(value) ? [...base] : [...base, value]) : base.filter((v) => v !== value)
    if (vals.length === 0 || (key === 'state' && isDefaultState(vals))) delete next[key]
    else next[key] = vals
  } else if (on) {
    next[key] = value
  } else {
    delete next[key]
  }
  return next as ExplorerSearch
}

export function removeChip(s: ExplorerSearch, c: Chip): ExplorerSearch {
  if (isArrayKey(c.key)) return withFacet(s, c.key, c.value, false)
  const next: Record<string, unknown> = { ...s }
  delete next[c.key]
  delete next.cursor
  return next as ExplorerSearch
}

// The router's search serialisers. Values are percent-encoded, but ", : / @" stay readable, so
// URLs read like /vulnerabilities?scope=workload:Deployment/shop/web&priority=urgent,high.
function encodeValue(v: string): string {
  return encodeURIComponent(v).replace(/%2C/gi, ',').replace(/%3A/gi, ':').replace(/%2F/gi, '/').replace(/%40/gi, '@')
}

// parseSearchParams is the router's parseSearch. It keeps the last value of each key. The explorer
// array keys come back split on ",", so the parsed location holds the same shape navigate writes;
// the routes' validateSearch then checks every value.
export function parseSearchParams(search: string): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {}
  for (const [k, v] of new URLSearchParams(search.startsWith('?') ? search.slice(1) : search)) {
    out[k] = isArrayKey(k) ? v.split(',') : v
  }
  return out
}

// stringifySearchParams is the router's stringifySearch: keys in insertion order, empty values
// left out, arrays comma-joined; "" when nothing remains.
export function stringifySearchParams(search: object): string {
  const pairs: string[] = []
  for (const [k, v] of Object.entries(search)) {
    if (v === undefined || v === null || v === '') continue
    if (Array.isArray(v)) {
      if (v.length === 0) continue
      pairs.push(`${encodeValue(k)}=${v.map((x) => encodeValue(String(x))).join(',')}`)
    } else {
      pairs.push(`${encodeValue(k)}=${encodeValue(String(v))}`)
    }
  }
  return pairs.length ? `?${pairs.join('&')}` : ''
}

// revalidate runs a route's search validator again over the search a page reads. The router
// merges a route's validated search over the raw URL search, so a key or value the validator
// dropped would otherwise come back (a group on /workloads, an image scope on /coverage).
export function revalidate<T>(validate: (raw: Record<string, unknown>) => T, search: object): T {
  return validate(search as Record<string, unknown>)
}

// Page search params, one parser per page with search state.
export interface HomeSearch {
  group?: 'entry' | 'namespace' | 'node'
  expand?: string // comma-joined row ids
}
export interface WorkloadSearch {
  view?: 'findings' | 'upgrades' | 'exposure' | 'rbac' | 'history'
  group?: 'fix' | 'advisory' | 'package'
}
export interface ImageSearch {
  view?: 'findings' | 'packages' | 'upgrades' | 'sbom'
  q?: string
  from?: string
}
export interface NamespaceSearch {
  view?: 'exposure' | 'vulnerabilities' | 'images' | 'packages'
}
export interface NodeGroupSearch {
  view?: 'findings' | 'hostPackages' | 'kernel' | 'cachedImages' | 'members'
  compare?: string
}
export interface CoverageSearch {
  scope?: string
}

function oneOf<T extends string>(list: readonly T[], v: unknown): T | undefined {
  return isOneOf(list, v) ? v : undefined
}

function compact<T extends object>(o: T): T {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(o)) if (v !== undefined) out[k] = v
  return out as T
}

export function parseHomeSearch(raw: Record<string, unknown>): HomeSearch {
  const expand = listOf(raw.expand)
  return compact({
    group: oneOf(['entry', 'namespace', 'node'] as const, raw.group),
    expand: expand.length ? expand.join(',') : undefined,
  })
}

export function parseWorkloadSearch(raw: Record<string, unknown>): WorkloadSearch {
  return compact({
    view: oneOf(['findings', 'upgrades', 'exposure', 'rbac', 'history'] as const, raw.view),
    group: oneOf(['fix', 'advisory', 'package'] as const, raw.group),
  })
}

export function parseImageSearch(raw: Record<string, unknown>): ImageSearch {
  const from = stringOf(raw.from)
  return compact({
    view: oneOf(['findings', 'packages', 'upgrades', 'sbom'] as const, raw.view),
    q: stringOf(raw.q),
    // The server parses from as a workload scope; anything else is dropped here.
    from: from !== undefined && scopeKindOf(from) === 'workload' ? from : undefined,
  })
}

export function parseNamespaceSearch(raw: Record<string, unknown>): NamespaceSearch {
  return compact({ view: oneOf(['exposure', 'vulnerabilities', 'images', 'packages'] as const, raw.view) })
}

export function parseNodeGroupSearch(raw: Record<string, unknown>): NodeGroupSearch {
  return compact({
    view: oneOf(['findings', 'hostPackages', 'kernel', 'cachedImages', 'members'] as const, raw.view),
    compare: stringOf(raw.compare),
  })
}

export function parseCoverageSearch(raw: Record<string, unknown>): CoverageSearch {
  const scope = stringOf(raw.scope)
  const kind = scope === undefined ? undefined : scopeKindOf(scope)
  return compact({ scope: kind === 'cluster' || kind === 'namespace' || kind === 'workload' ? scope : undefined })
}

// toggleExpand adds id to, or removes it from, a comma-joined expand list.
export function toggleExpand(expand: string | undefined, id: string): string | undefined {
  const ids = (expand ?? '').split(',').filter((x) => x !== '')
  const next = ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]
  return next.length ? next.join(',') : undefined
}

// parsePackageKey splits a package group key, "<ecosystem>/<name>@<version>": the ecosystem ends at
// the first "/", the version starts after the last "@" ("npm/@scope/pkg@1.2.3" is "@scope/pkg").
export function parsePackageKey(key: string): { ecosystem: string; name: string; version: string } {
  const slash = key.indexOf('/')
  const ecosystem = slash < 0 ? '' : key.slice(0, slash)
  const rest = slash < 0 ? key : key.slice(slash + 1)
  const at = rest.lastIndexOf('@')
  if (at <= 0) return { ecosystem, name: rest, version: '' }
  return { ecosystem, name: rest.slice(0, at), version: rest.slice(at + 1) }
}
