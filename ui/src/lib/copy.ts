import type { GapCode, S } from '@/api/types'
import { formatCount, formatPercent, plural } from './format'

// copy holds every user-facing string. The strings marked Contract are the Contract's Copy section
// verbatim; change them there first.
export const copy = {
  page: {
    home: 'Exposure',
    vulnerabilities: 'Vulnerabilities',
    advisory: 'Advisory',
    workloads: 'Workloads',
    workload: 'Workload',
    images: 'Images',
    image: 'Image',
    packages: 'Packages',
    namespace: 'Namespace',
    nodes: 'Nodes',
    nodegroup: 'Node group',
    node: 'Node',
    controlplane: 'Control plane',
    coverage: 'Coverage',
    exceptions: 'Exceptions',
    settings: 'Settings',
    feeds: 'Feeds',
  },
  // Contract: home headline (stat, then label).
  headline: {
    reachable: 'workloads reachable from outside',
    reachableUrgent: 'of them carry urgent findings',
    fixable: 'findings where a fixed version exists',
    coverage: 'images in full detail',
    seenInto: (n: number) => `${formatCount(n)} seen into`,
  },
  // Contract: regroup switch.
  regroup: { entry: 'Exposure', namespace: 'Namespaces', node: 'Nodes' },
  // Contract: columns.
  columns: {
    path: 'Path',
    urgent: 'Urgent',
    high: 'High',
    fixable: 'Fixable',
    privileged: 'Privileged',
    saPower: 'SA power',
    exploited: 'Exploited',
    coverage: 'Coverage',
    bestFix: 'Best fix',
  },
  // Contract: footnote.
  footnote:
    'Reachable means a Gateway or Ingress listener routes to it, a LoadBalancer or NodePort Service selects it, or its pods use the host network or a host port. Entry points marked internal in the ffs configuration are listed separately and do not count. NetworkPolicy is not evaluated, so read reachable as could be reached.',
  fix: { none: 'No fix yet', wontfix: "Won't fix", rebuildTitle: 'Rebuild to pick up distro fixes' },
  // Contract: empty and coverage-first messages.
  empty: 'Nothing needs attention.',
  emptyFiltered: 'Nothing matches these filters.',
  coverageFirst: (n: number, m: number) => `ffs cannot see into ${formatCount(n)} of ${formatCount(m)} images yet, so this may not be everything.`,
  agentMissing: 'Enable the node agent to see host packages, the running kernel and cached images.',
  notFound: 'That page does not exist.',
  facetTitle: {
    state: 'State',
    priority: 'Priority',
    fix: 'Fix',
    signal: 'Signals',
    ecosystem: 'Ecosystem',
    namespace: 'Namespace',
    kind: 'Kind',
    coverage: 'Coverage',
    status: 'Status',
    source: 'Source',
    advisory: 'Advisory',
    package: 'Package',
    repo: 'Image',
    q: 'Search',
    fixKey: 'Fix',
    scope: 'Scope',
  } as Record<string, string>,
  // Contract: facet labels.
  facetValue: {
    state: { open: 'open', excepted: 'excepted', resolved: 'resolved in the last 30 days' },
    fix: { upgrade: 'upgrade available', fixed: 'fixed version exists', none: 'no fix yet', wontfix: "won't fix" },
    signal: {
      exposed: 'exposed',
      privileged: 'privileged',
      sa_power: 'SA power',
      exploited: 'exploited (KEV)',
      malicious: 'malicious',
      provisional: 'provisional',
      not_running: 'not running',
    },
    priority: { urgent: 'urgent', high: 'high', medium: 'medium', low: 'low', none: 'no open findings' },
    coverage: { full: 'full detail', partial: 'partial detail', none: 'not seen into' },
    status: { pending: 'pending', catalogued: 'catalogued', unresolvable: 'unresolvable', catalogFailed: 'cataloguing failed' },
  } as Record<string, Record<string, string> | undefined>,
  epss: (bump: number) => `EPSS ≥ ${formatPercent(bump)}`,
  clusterLevel: 'cluster-level',
  noValue: '—',
  coverageLink: 'Coverage',
  // Contract: the gaps table, "Gap" and "What to do" columns.
  gaps: {
    pending: { gap: 'not catalogued yet', todo: 'Queued; ffs catalogues it shortly.' },
    unresolvable_auth: { gap: 'registry refused access', todo: 'Give ffs a pull secret that can read this repository.' },
    unresolvable_sideloaded: {
      gap: 'loaded onto nodes, not in a registry',
      todo: 'The node agent catalogues side-loaded images from the node.',
    },
    unresolvable_notfound: {
      gap: 'not found in the registry',
      todo: 'Push it to a registry ffs can reach, or let the node agent catalogue it.',
    },
    unresolvable_unreachable: { gap: 'registry not reachable', todo: 'Allow ffs to reach the registry, or configure a mirror.' },
    unresolvable_other: { gap: 'could not be resolved', todo: 'Check the image reference; the reason is shown.' },
    layers_discarded: {
      gap: 'layers discarded on every node',
      todo: 'Pull the image again on a node, or push it to a registry.',
    },
    catalog_failed: { gap: 'cataloguing failed', todo: 'ffs retries after the quarantine; the reason is shown.' },
    attestation_partial: {
      gap: 'attested SBOM lists no executables',
      todo: 'Executables were not measured; ffs relies on the attested package list.',
    },
    unattributed_executables: {
      gap: 'executables without package metadata',
      todo: 'Copied-in binaries carry no package metadata, so ffs cannot match them.',
    },
    rust_no_auditable: {
      gap: 'Rust binaries without cargo-auditable',
      todo: 'Build Rust binaries with cargo-auditable so their crates can be matched.',
    },
    cpe_only_classifier: {
      gap: 'daily, CPE-based coverage only',
      todo: 'Matched daily against CPE data; the fast path does not cover {names}.',
    },
    node_agent_missing: {
      gap: 'kernel and host packages not inventoried',
      todo: 'Enable the node agent, or check why it is not reporting.',
    },
    node_agent_blocked: {
      gap: 'node agent cannot read host paths',
      todo: 'Allow the node agent to read its host paths (SELinux or policy).',
    },
    no_package_database: {
      gap: 'no package database (image-based OS)',
      todo: 'Host packages are not inventoried on image-based operating systems.',
    },
    content_store_unreadable: {
      gap: 'no containerd content store',
      todo: 'Side-loaded images on this node cannot be catalogued from it.',
    },
    feed_stale: { gap: 'feed out of date', todo: 'Check that ffs can reach the {feed} feed; the last error is shown.' },
  } satisfies Record<GapCode, { gap: string; todo: string }>,
  theme: { light: 'Light', dark: 'Dark', system: 'System' },
}

export type CountNoun = 'advisories' | 'workloads' | 'images' | 'packages' | 'namespaces' | 'fixes'

const singular: Record<CountNoun, string> = {
  advisories: 'advisory',
  workloads: 'workload',
  images: 'image',
  packages: 'package',
  namespaces: 'namespace',
  fixes: 'fix',
}

// facetValueLabel is how a facet value reads in a facet list or a chip.
export function facetValueLabel(facet: string, value: string, epssBump: number): string {
  if (facet === 'signal' && value === 'epss') return copy.epss(epssBump)
  return copy.facetValue[facet]?.[value] ?? value
}

// countsLine is the Contract's counts copy: "14 findings · 3 advisories", pluralised.
export function countsLine(findings: number, distinct: number, noun: CountNoun): string {
  return `${plural(findings, 'finding', 'findings')} · ${plural(distinct, singular[noun], noun)}`
}

const introOrder = ['urgent', 'high', 'medium', 'low'] as const

// fixGroupHeader is the Contract's fix group header. Clearing actions say what they clear;
// upgrades also say what they introduce; "No fix yet" and "Won't fix" groups give their counts.
export function fixGroupHeader(row: S<'FindingGroupRow'>): string {
  const fix = row.fix
  const label = fix?.label ?? row.label
  if (!fix || fix.kind === 'none' || fix.kind === 'wontfix') {
    return `${label} · ${countsLine(row.findings, row.distinct, 'advisories')}`
  }
  let s = `${label} · clears ${formatCount(row.counts.urgent)} urgent, ${formatCount(row.counts.high)} high`
  if (fix.kind === 'upgrade' && fix.introduces) {
    const intro = fix.introduces
    const parts = introOrder.filter((p) => intro[p] > 0).map((p) => `${formatCount(intro[p])} ${p}`)
    s += ` · introduces ${parts.length ? parts.join(', ') : 'none'}`
  }
  return s
}

// gapTodo is the "What to do" copy for a gap, with its variable part filled in.
export function gapTodo(g: S<'Gap'>): string {
  return copy.gaps[g.code].todo.replace('{names}', g.detail).replace('{feed}', g.what)
}
