import type { GapCode, Priority, S, ViewId } from '@/api/types'

// Each list is built from a Record over the schema enum, so a value added to or removed from the
// schema fails the typecheck here instead of being silently dropped from the URL parsers.
function listOf<T extends string>(r: Record<T, true>): readonly T[] {
  return Object.freeze(Object.keys(r) as T[])
}

export const PRIORITIES = listOf<Priority>({ urgent: true, high: true, medium: true, low: true, none: true })
export const FINDING_STATES = listOf<S<'FindingState'>>({ open: true, excepted: true, resolved: true })
export const FIX_CLASSES = listOf<S<'FixClass'>>({ upgrade: true, fixed: true, none: true, wontfix: true })
export const SIGNALS = listOf<S<'Signal'>>({
  exposed: true,
  privileged: true,
  sa_power: true,
  exploited: true,
  malicious: true,
  provisional: true,
  not_running: true,
  epss: true,
})
export const COVERAGE_CLASSES = listOf<S<'CoverageClass'>>({ full: true, partial: true, none: true })
export const IMAGE_STATUSES = listOf<S<'ImageStatus'>>({ pending: true, catalogued: true, unresolvable: true, catalogFailed: true })
export const SCOPE_KINDS = listOf<S<'ScopeKind'>>({
  cluster: true,
  namespace: true,
  workload: true,
  image: true,
  nodegroup: true,
  node: true,
  controlplane: true,
})
export const VIEW_IDS = listOf<ViewId>({
  exposure: true,
  vulnerabilities: true,
  workloads: true,
  images: true,
  packages: true,
  nodes: true,
  coverage: true,
  findings: true,
  upgrades: true,
  rbac: true,
  history: true,
  sbom: true,
  hostPackages: true,
  kernel: true,
  cachedImages: true,
  members: true,
})
export const GAP_CODES = listOf<GapCode>({
  pending: true,
  unresolvable_auth: true,
  unresolvable_sideloaded: true,
  unresolvable_notfound: true,
  unresolvable_unreachable: true,
  unresolvable_other: true,
  layers_discarded: true,
  catalog_failed: true,
  attestation_partial: true,
  unattributed_executables: true,
  rust_no_auditable: true,
  cpe_only_classifier: true,
  node_agent_missing: true,
  node_agent_blocked: true,
  no_package_database: true,
  content_store_unreadable: true,
  host_not_inventoried: true,
  node_agent_unsupported: true,
  feed_stale: true,
})

export function isOneOf<T extends string>(list: readonly T[], v: unknown): v is T {
  return typeof v === 'string' && (list as readonly string[]).includes(v)
}
