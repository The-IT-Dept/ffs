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

export function scopeCard(p?: Partial<S<'ScopeCard'>>): S<'ScopeCard'> {
  return {
    ...ENV,
    scope: { scope: 'cluster', kind: 'cluster', label: 'test' },
    clusters: ['test'],
    title: 'test',
    summary: 'Kubernetes 1.35.0 · 3 nodes · 4 namespaces',
    breadcrumbs: [],
    views: [{ id: 'exposure', count: 2, gap: false }],
    related: [],
    trust: { feeds: feedFreshness(), coverage: coverageFigure(), settings: true },
    ...p,
  }
}

export function searchResult(p?: Partial<S<'SearchResult'>>): S<'SearchResult'> {
  return { ...ENV, query: 'web', hits: [], truncated: false, ...p }
}

export function settings(p?: Partial<S<'Settings'>>): S<'Settings'> {
  return {
    ...ENV,
    version: 'v0.0.1',
    clusterName: 'test',
    feeds: [
      { name: 'osv', enabled: true, interval: '1h0m0s', staleAfter: '6h0m0s' },
      { name: 'kev', enabled: true, interval: '6h0m0s', staleAfter: '72h0m0s' },
    ],
    priority: { epssHigh: 0.5, epssBump: 0.1 },
    exposure: { internalIngressClasses: [], internalGatewayClasses: [], internalGateways: [], internalLBAnnotations: {} },
    crd: { minPriority: 'high', maxFindings: 100 },
    events: { minPriority: 'urgent' },
    openReports: { mode: 'off' },
    exceptions: { maxDuration: '2160h0m0s' },
    retention: { resolved: '720h0m0s' },
    upgrades: { enabled: true, dailyAt: '03:00' },
    ...p,
  }
}

export function summary(p?: Partial<S<'Summary'>>): S<'Summary'> {
  return {
    ...ENV,
    scope: { scope: 'cluster', kind: 'cluster', label: 'test' },
    reachable: 0,
    reachableUrgent: 0,
    findings: counts(),
    open: 0,
    fixable: 0,
    exploited: 0,
    coverage: coverageFigure(),
    feeds: feedFreshness(),
    gaps: 0,
    ...p,
  }
}

export function workloadRow(p?: Partial<S<'WorkloadRow'>>): S<'WorkloadRow'> {
  return {
    workload: workloadRef('Deployment', 'shop', 'web'),
    notRunning: false,
    exposed: false,
    privileged: false,
    saPower: false,
    counts: counts(),
    open: 0,
    fixable: 0,
    exploited: 0,
    coverage: coverageFigure(),
    coverageClass: 'full',
    pods: 2,
    ...p,
  }
}

export function imageRow(p?: Partial<S<'ImageRow'>>): S<'ImageRow'> {
  return {
    digest: 'sha256:' + 'a'.repeat(64),
    repo: 'ghcr.io/example/web',
    platform: 'linux/amd64',
    status: 'catalogued',
    statusReason: '',
    source: 'registry',
    coverage: 'full',
    gaps: [],
    workloads: 1,
    counts: counts(),
    fixable: 0,
    ...p,
  }
}

export function packageRow(p?: Partial<S<'PackageRow'>>): S<'PackageRow'> {
  return { ecosystem: 'deb', name: 'openssl', version: '3.5.1-1', images: 1, workloads: 1, counts: counts(), worst: 'none', ...p }
}

export function workloadsPage(p?: Partial<S<'WorkloadsPage'>>): S<'WorkloadsPage'> {
  return { ...ENV, total: 0, rows: [], next: null, facets: {}, ...p }
}

export function imagesPage(p?: Partial<S<'ImagesPage'>>): S<'ImagesPage'> {
  return { ...ENV, total: 0, rows: [], next: null, facets: {}, ...p }
}

export function packagesPage(p?: Partial<S<'PackagesPage'>>): S<'PackagesPage'> {
  return { ...ENV, total: 0, rows: [], next: null, facets: {}, ...p }
}
