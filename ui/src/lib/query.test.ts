import { expect, test } from 'vitest'
import {
  chipsOf,
  type ExplorerSearch,
  explorerSearchFor,
  parseExplorerSearch,
  parseSearchParams,
  removeChip,
  stringifySearchParams,
  toApiQuery,
  toggleExpand,
  withFacet,
} from './query'

const full: ExplorerSearch = {
  scope: 'namespace:shop',
  state: ['open', 'excepted'],
  priority: ['urgent', 'high'],
  fix: ['upgrade', 'fixed'],
  signal: ['exposed', 'epss'],
  ecosystem: ['deb', 'go-module'],
  namespace: ['shop', 'ops'],
  kind: ['Deployment'],
  coverage: ['partial'],
  status: ['pending'],
  source: ['registry'],
  advisory: 'CVE-2026-0001',
  package: 'openssl',
  repo: 'ghcr.io/example/web',
  q: 'web 1,2',
  group: 'advisory',
  sort: '-epss',
  cursor: 'eyJxIjoiYSJ9',
  fixKey: 'package:deb:openssl:3.5.1-1:3.5.2-1',
}

test('round-trips every explorer search through the URL', () => {
  expect(parseExplorerSearch(parseSearchParams(stringifySearchParams(full)))).toEqual(full)
  expect(stringifySearchParams({ priority: ['urgent', 'high'], group: 'advisory', sort: '-priority' })).toBe('?priority=urgent,high&group=advisory&sort=-priority')
  expect(stringifySearchParams({ scope: 'workload:Deployment/shop/web', cursor: undefined })).toBe('?scope=workload:Deployment/shop/web')
  expect(parseExplorerSearch({ priority: ['urgent'] })).toEqual(parseExplorerSearch({ priority: 'urgent' })) // navigate form = URL form
})

test('drops unknown keys and values outside the schema enums', () => {
  expect(parseExplorerSearch({ priority: 'urgent,severe', fix: 'maybe', group: 'colour', sort: 'sideways', scope: 'workload:bad', foo: 'x', state: 'open' })).toEqual({
    priority: ['urgent'],
    state: ['open'],
  })
})

test('changing any filter drops the cursor and never writes the default state', () => {
  expect(withFacet({ priority: ['urgent'], cursor: 'c1' }, 'priority', 'high', true)).toEqual({ priority: ['urgent', 'high'] })
  expect(withFacet({ cursor: 'c1' }, 'state', 'excepted', true)).toEqual({ state: ['open', 'excepted'] })
  expect(withFacet({ state: ['open', 'excepted'] }, 'state', 'excepted', false)).toEqual({})
  const [chip] = chipsOf({ namespace: ['shop'], cursor: 'c1' })
  expect(chip).toEqual({ key: 'namespace', value: 'shop', label: 'Namespace: shop' })
  expect(removeChip({ namespace: ['shop'], cursor: 'c1' }, chip)).toEqual({})
  // The EPSS bump is kept below the threshold that set it, so the chip names the bump, not a threshold.
  expect(chipsOf({ signal: ['epss'] })[0].label).toBe('Signals: EPSS bump')
  expect(toggleExpand(toggleExpand(undefined, 'a'), 'b')).toBe('a,b')
  expect(toggleExpand('a', 'a')).toBeUndefined()
})

test('toApiQuery joins arrays and omits defaults', () => {
  expect(toApiQuery({ scope: 'cluster', state: ['open'], sort: '-priority', priority: ['urgent', 'high'] }, ['priority', 'fix'])).toEqual({
    priority: 'urgent,high',
    facets: 'priority,fix',
  })
  expect(toApiQuery({ scope: 'namespace:shop', sort: 'name', cursor: 'c' }, [])).toEqual({ scope: 'namespace:shop', sort: 'name', cursor: 'c' })
})

test('explorerSearchFor keeps only what the explorer endpoint takes', () => {
  expect(explorerSearchFor('workloads')({ state: 'open', group: 'advisory', sort: '-priority', kind: 'Deployment', coverage: 'none', scope: 'image:sha256:aa' })).toEqual({
    kind: ['Deployment'],
    coverage: ['none'],
  })
  expect(explorerSearchFor('findings')({ coverage: 'none', sort: 'name', group: 'fix', scope: 'node:worker-1' })).toEqual({ group: 'fix', scope: 'node:worker-1' })
})
