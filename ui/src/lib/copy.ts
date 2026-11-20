import type { GapCode, S, ViewId } from '@/api/types'
import { formatCount, formatDate, formatPercent, plural } from './format'
import type { Scope, ScopeKind } from './scope'

type RelatedSectionId = S<'RelatedSection'>['id']

const viewLabel: Record<ViewId, string> = {
  exposure: 'Exposure',
  vulnerabilities: 'Vulnerabilities',
  workloads: 'Workloads',
  images: 'Images',
  packages: 'Packages',
  nodes: 'Nodes',
  coverage: 'Coverage',
  findings: 'Findings',
  upgrades: 'Upgrades',
  rbac: 'Service account & RBAC',
  history: 'History',
  sbom: 'Coverage & SBOM',
  hostPackages: 'Host packages',
  kernel: 'Kernel & runtime',
  cachedImages: 'Cached images',
  members: 'Nodes',
}

const scopeKindLabel: Record<ScopeKind, string> = {
  cluster: 'Cluster',
  namespace: 'Namespace',
  workload: 'Workload',
  image: 'Image',
  nodegroup: 'Node group',
  node: 'Node',
  controlplane: 'Control plane',
}

const relatedLabel: Record<RelatedSectionId, string> = {
  namespaces: 'Namespaces',
  nodegroups: 'Node groups',
  controlplane: 'Control plane',
  workloads: 'Workloads',
  containers: 'Containers',
  siblings: 'Siblings',
  usedBy: 'Used by',
  notablePackages: 'Notable packages',
  members: 'Nodes',
  exceptions: 'Exceptions',
}

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
  // The kind label of a scope; a workload shows its owner kind, e.g. Deployment.
  scopeKind: (s: Scope) => (s.kind === 'workload' ? s.value.split('/')[0] || scopeKindLabel.workload : scopeKindLabel[s.kind]),
  view: (id: ViewId, kind: ScopeKind) => (id === 'upgrades' && kind === 'image' ? 'Upgrade candidates' : viewLabel[id]),
  related: (id: RelatedSectionId, scope: Scope) =>
    id === 'siblings' && scope.kind === 'workload' ? `Siblings in ${scope.value.split('/')[1] ?? ''}` : relatedLabel[id],
  shell: {
    openNavigation: 'Open navigation',
    navigation: 'Navigation',
    close: 'Close',
  },
  rail: {
    views: 'Views',
    filter: 'Filter',
    more: (n: number) => `+ ${formatCount(n)} more`,
    gap: 'gap',
    switchCluster: 'Switch cluster',
    unavailable: 'Scope details are unavailable.',
  },
  trust: {
    feedsFresh: 'Feeds fresh',
    feedsStale: (names: string[]) => `Feeds stale: ${names.join(', ')}`,
    coverage: 'Coverage',
    sbom: (source: string, tool?: string) => (tool ? `SBOM from ${source} · ${tool}` : `SBOM from ${source}`),
    unattributed: (n: number) => `${plural(n, 'executable', 'executables')} not attributed`,
    exceptions: 'Exceptions',
    settings: 'Settings',
  },
  command: {
    open: 'Search',
    placeholder: 'Search workloads, images, advisories, packages and nodes',
    empty: 'No matches.',
    kind: {
      workload: 'Workload',
      namespace: 'Namespace',
      image: 'Image',
      advisory: 'Advisory',
      package: 'Package',
      nodegroup: 'Node group',
      node: 'Node',
    } satisfies Record<S<'SearchHit'>['kind'], string>,
  },
  explorer: {
    clear: 'Clear filters',
    filters: (n: number) => (n > 0 ? `Filters (${formatCount(n)})` : 'Filters'),
    filtersTitle: 'Filters',
    groupBy: 'Group by',
    page: (n: number, m: number) => `Page ${formatCount(n)} of ${formatCount(m)}`,
    pages: (m: number) => plural(m, 'page', 'pages'),
    pageAlone: (n: number) => `Page ${formatCount(n)}`,
    previous: 'Previous',
    next: 'Next',
    first: 'First page',
    showAll: 'Show all',
    showFewer: 'Show fewer',
    group: { '': 'None', advisory: 'Advisory', workload: 'Workload', image: 'Image', package: 'Package', namespace: 'Namespace', fix: 'Fix' } as Record<
      string,
      string
    >,
    tag: {
      kev: 'KEV',
      provisional: 'provisional',
      notRunning: 'not running',
      excepted: 'excepted',
      exposed: 'exposed',
      privileged: 'privileged',
      saPower: 'SA power',
    },
  },
  col: {
    advisory: 'Advisory',
    priority: 'Priority',
    severity: 'Severity',
    workload: 'Workload',
    package: 'Package',
    fix: 'Fix',
    epss: 'EPSS',
    published: 'Published',
    namespace: 'Namespace',
    urgent: 'Urgent',
    high: 'High',
    findings: 'Findings',
    fixable: 'Fixable',
    exploited: 'Exploited',
    signals: 'Signals',
    coverage: 'Coverage',
    bestFix: 'Best fix',
    pods: 'Pods',
    image: 'Image',
    platform: 'Platform',
    status: 'Status',
    source: 'Source',
    workloads: 'Workloads',
    ecosystem: 'Ecosystem',
    version: 'Version',
    images: 'Images',
    worst: 'Worst',
  },
  funnel: { pods: 'Pods', images: 'Distinct images', catalogued: 'Catalogued', full: 'Full detail', feeds: 'Feeds fresh' },
  gapsTable: { what: 'What', gap: 'Gap', affects: 'Affects', todo: 'What to do' },
  // affects lists the non-zero parts: "2 workloads · 1 image"; nothing affected reads "—".
  affects: (a: { workloads: number; images: number; nodes: number }) => {
    const parts = [
      a.workloads > 0 ? plural(a.workloads, 'workload', 'workloads') : '',
      a.images > 0 ? plural(a.images, 'image', 'images') : '',
      a.nodes > 0 ? plural(a.nodes, 'node', 'nodes') : '',
    ].filter((p) => p !== '')
    return parts.length ? parts.join(' · ') : '—'
  },
  moreGaps: (shown: number, total: number) => `Showing ${formatCount(shown)} of ${formatCount(total)} gaps`,
  // Contract: managed by.
  managedBy: (m: S<'ManagedBy'>) => {
    switch (m.tool) {
      case 'helm':
        return `Helm ${m.name}`
      case 'flux-helmrelease':
      case 'flux-kustomization':
        return `Flux ${m.name}`
      case 'argocd':
        return `Argo CD ${m.name}`
    }
    return `${m.tool} ${m.name}`
  },
  workload: {
    managedBy: (label: string) => `Managed by ${label}`,
    urgent: (n: number) => `${formatCount(n)} urgent`,
    high: (n: number) => `${formatCount(n)} high`,
    fixable: (n: number) => `${formatCount(n)} fixable`,
    exposed: 'exposed',
    notExposed: 'not exposed',
    privileged: 'privileged',
    notPrivileged: 'not privileged',
    coverage: (label: string) => `coverage ${label}`,
    serviceAccount: 'Service account',
    saPower: 'SA power',
    privilegedTitle: 'Privileged',
    yes: 'yes',
    no: 'no',
    containers: { container: 'Container', image: 'Image', status: 'Status', coverage: 'Coverage' },
    exposureCols: { entry: 'Entry', name: 'Name', listener: 'Listener', hostname: 'Hostname', route: 'Route', service: 'Service', internal: 'Internal' },
    history: { when: 'When', advisory: 'Advisory', change: 'Change', priority: 'Priority', trigger: 'Trigger' },
  },
  path: {
    internet: 'Internet',
    pods: (n: number) => plural(n, 'pod', 'pods'),
    notExposed: 'Not exposed',
    internal: 'Internal entry points',
    more: (n: number) => `+ ${formatCount(n)} more paths`,
    noClass: 'Ingress (no class)',
  },
  fixList: {
    more: (n: number) => `+ ${formatCount(n)} more`,
    cols: { advisory: 'Advisory', workload: 'Workload', priority: 'Priority', package: 'Package', installed: 'Installed', why: 'Why', seen: 'Seen' },
  },
  upgrades: {
    none: 'No upgrade candidates.',
    cols: {
      image: 'Image',
      change: 'Change',
      tier: 'Tier',
      fixes: 'Fixes',
      remaining: 'Remaining',
      introduces: 'Introduces',
      net: 'Net change',
      eol: 'End of life',
      checked: 'Checked',
    },
    nothing: 'none',
  },
  image: {
    // "SBOM from attestation · syft 1.57.0"; without a tool, "SBOM from attestation".
    sbom: (source: string, tool?: string, version?: string) =>
      tool ? `SBOM from ${source} · ${tool}${version ? ` ${version}` : ''}` : `SBOM from ${source}`,
    agent: (node: string, version: string) => `From the node agent on ${node} (${version})`,
    unattributed: (n: number) => `${plural(n, 'executable', 'executables')} without package metadata`,
    rust: (n: number) => `${plural(n, 'Rust binary', 'Rust binaries')} without cargo-auditable`,
    searchPackages: 'Search packages',
    usedBy: 'Used by',
    ecosystems: 'Ecosystems',
    lifecycle: 'Lifecycle',
    packageCols: { package: 'Package', version: 'Version', ecosystem: 'Ecosystem', foundBy: 'Found by', path: 'Path', findings: 'Findings', worst: 'Worst' },
  },
  advisory: {
    kev: (d: string) => `KEV · added ${formatDate(d)}`,
    epss: (s: number, p: number) => `EPSS ${formatPercent(s)} · percentile ${formatPercent(p)}`,
    malicious: 'Malicious package',
    withdrawn: 'Withdrawn',
    used: 'used',
    severity: 'Severity by source',
    affected: 'Affected workloads by fix',
    packages: 'Affected packages',
    links: 'Links',
    timeline: { published: 'Published', observed: 'Observed by ffs', firstMatched: 'First matched' },
    uncatalogued: (n: number) => `${plural(n, 'image', 'images')} not seen into`,
    cols: { source: 'Source', severity: 'Severity', package: 'Package', ecosystem: 'Ecosystem', installed: 'Installed', fixed: 'Fixed', findings: 'Findings' },
  },
  agentState: { reporting: 'reporting', stale: 'stale', never: 'never reported', disabled: 'disabled' } satisfies Record<S<'AgentState'>, string>,
  nodes: {
    ready: 'Ready',
    notReady: 'Not ready',
    rebootPending: 'Reboot pending',
    noGroup: 'No node group',
    yes: 'yes',
    no: 'no',
    kubernetes: 'Kubernetes',
    compare: (label: string) => `Compare with ${label}`,
    nodesCount: (n: number) => plural(n, 'node', 'nodes'),
    groupCols: {
      group: 'Group',
      kind: 'Kind',
      osImage: 'OS image',
      kernel: 'Kernel',
      runtime: 'Runtime',
      kubelet: 'Kubelet',
      arch: 'Arch',
      nodes: 'Nodes',
      exposedNodes: 'Exposed nodes',
      urgent: 'Urgent',
      high: 'High',
      fixable: 'Fixable',
      agents: 'Agents',
      reboot: 'Reboot pending',
      drift: 'Drift',
    },
    memberCols: { node: 'Node', ready: 'Ready', exposed: 'Exposed', agent: 'Agent' },
    driftCols: { other: 'Other group', summary: 'Summary', newerHere: 'Newer here', newerThere: 'Newer there', onlyHere: 'Only here', onlyThere: 'Only there' },
    // The compare payload runs from the other group to this one.
    fieldCols: { field: 'Field', from: 'Other group', to: 'This group' },
    changedCols: { package: 'Package', arch: 'Arch', from: 'Other group', to: 'This group', newer: 'Newer' },
    // `newer` in the compare payload is 'from' (the other group) or 'to' (this group).
    newer: { from: 'other group', to: 'this group' } as Record<string, string>,
    kernelCols: { name: 'Name', path: 'Path', module: 'Module', version: 'Version' },
    kernelFields: { release: 'Kernel release', package: 'Kernel package', version: 'Package version', source: 'Source package' },
    packageDb: 'Package database',
    driftTitle: 'Differences from other groups',
    compareTitle: 'Compared fields',
    changedTitle: 'Changed packages',
    onlyThere: 'Only in the other group',
    onlyHere: 'Only in this group',
    imageCols: { image: 'Image', size: 'Size', complete: 'Complete', inUse: 'In use', nodes: 'Nodes', status: 'Status' },
    agentFields: { state: 'State', version: 'Agent version', lastReport: 'Last report', lastFullReport: 'Last full report', kernel: 'Kernel' },
  },
  exceptions: {
    none: 'No exceptions are defined.',
    expired: 'expired',
    cols: {
      exception: 'Exception',
      reason: 'Reason',
      expires: 'Expires',
      matches: 'Matches',
      vex: 'VEX',
      matched: 'Matched findings',
      urgentNotExcepted: 'Urgent not excepted',
    },
  },
  feeds: {
    fresh: 'fresh',
    stale: 'stale',
    sources: 'Sources',
    cols: {
      feed: 'Feed',
      lastSuccess: 'Last success',
      lastAttempt: 'Last attempt',
      staleAfter: 'Stale after',
      status: 'Status',
      lastError: 'Last error',
      source: 'Source',
      licence: 'Licence',
      attribution: 'Attribution',
      url: 'URL',
    },
  },
  settings: { key: 'Key', value: 'Value' },
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
