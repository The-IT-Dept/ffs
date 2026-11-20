import type { S } from '@/api/types'
import { ENV } from './api'

// Builders for API bodies. Each fills every required field with a neutral value and spreads the
// overrides last.

export const NOW = '2026-11-19T00:00:00Z'

export function counts(p?: Partial<S<'PriorityCounts'>>): S<'PriorityCounts'> {
  return { urgent: 0, high: 0, medium: 0, low: 0, ...p }
}

export function coverageFigure(p?: Partial<S<'CoverageFigure'>>): S<'CoverageFigure'> {
  return { inUse: 6, seenInto: 6, full: 6, ...p }
}

export function feedFreshness(p?: Partial<S<'FeedFreshness'>>): S<'FeedFreshness'> {
  return { fresh: true, stale: [], oldestSuccess: NOW, ...p }
}

export function fixAction(p?: Partial<S<'FixAction'>>): S<'FixAction'> {
  return { kind: 'none', key: 'none', label: 'No fix yet', ...p }
}

export function workloadRef(kind: string, namespace: string, name: string): S<'WorkloadRef'> {
  return { scope: `workload:${kind}/${namespace}/${name}`, kind, namespace, name }
}

export function facet(values: [value: string, count: number, selected?: boolean][]): S<'FacetValue'>[] {
  return values.map(([value, count, selected]) => ({ value, count, selected: selected ?? false }))
}

export function rowSignals(p?: Partial<S<'RowSignals'>>): S<'RowSignals'> {
  return { urgent: 0, high: 0, fixable: 0, exploited: 0, privileged: 0, saPower: 0, coverage: coverageFigure(), bestFix: fixAction(), ...p }
}

export function findingRow(p?: Partial<S<'FindingRow'>>): S<'FindingRow'> {
  return {
    id: 'f1',
    advisory: { id: 'CVE-2026-0001', title: 'Example advisory', kev: false, epss: null },
    workload: workloadRef('Deployment', 'shop', 'web'),
    repo: 'ghcr.io/example/web',
    packages: [{ name: 'openssl', ecosystem: 'deb', installed: '3.5.1-1', fixed: ['3.5.2-1'] }],
    severity: 'high',
    severitySource: 'debian',
    priority: 'high',
    reasons: [],
    state: 'open',
    fixState: 'fixed',
    fixAvailable: true,
    fix: fixAction({ kind: 'rebuild', key: 'rebuild:debian:13', label: 'debian 13 rebuild', title: 'Rebuild to pick up distro fixes' }),
    signals: [],
    ...p,
  }
}

export function groupRow(p?: Partial<S<'FindingGroupRow'>>): S<'FindingGroupRow'> {
  return { key: 'CVE-2026-0001', label: 'CVE-2026-0001', findings: 1, distinct: 1, counts: counts(), fixable: 0, exploited: 0, worst: 'none', ...p }
}

export function findingsPage(p?: Partial<S<'FindingsPage'>>): S<'FindingsPage'> {
  return { ...ENV, total: 0, groups: 0, findings: 0, rows: [], groupRows: [], next: null, facets: {}, ...p }
}
