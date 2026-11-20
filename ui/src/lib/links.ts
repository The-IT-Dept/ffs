import type { S, SearchHit, ViewId } from '@/api/types'
import { copy } from './copy'
import { EXPLORERS, type ExplorerKind, type ExplorerSearch, stringifySearchParams } from './query'
import { formatScope, parseScope, type Scope } from './scope'

// Every in-app link to an object is built here. Each path segment is percent-encoded on its own,
// so an ID holding "/" or ":" (a placeholder image ID) stays one segment.
const enc = encodeURIComponent

export function workloadPath(kind: string, namespace: string, name: string): string {
  return `/workloads/${enc(kind)}/${enc(namespace === '' ? '-' : namespace)}/${enc(name)}`
}

export function imagePath(digest: string, from?: string): string {
  return `/images/${enc(digest)}${stringifySearchParams({ from })}`
}

export function advisoryPath(id: string): string {
  return `/vulnerabilities/${enc(id)}`
}

export function namespacePath(ns: string): string {
  return `/namespaces/${enc(ns)}`
}

// nodeGroupPath is a node group's page. id is the group's key as the API gives it (a stable name,
// possibly qualified as <name>-<arch>, <name>-nodeinfo or <name>@<node>), used as it is.
export function nodeGroupPath(id: string): string {
  return `/nodegroups/${enc(id)}`
}

export function nodePath(name: string): string {
  return `/nodes/${enc(name)}`
}

export interface OwnerLike {
  kind: string
  namespace: string
  name: string
}

const CLUSTER_LEVEL_KINDS = ['Cluster', 'ContainerRuntime', 'Nodes']

// isClusterLevel mirrors the server's OwnerRef.ClusterLevel: the synthetic owners of Kubernetes,
// container runtime and host package findings, which have no namespace. A namespaced custom
// resource of kind Cluster is a workload.
export function isClusterLevel(o: { kind: string; namespace: string }): boolean {
  return o.namespace === '' && CLUSTER_LEVEL_KINDS.includes(o.kind)
}

// ownerHref is where an owner links: cluster-level owners to their own pages (Kubernetes and the
// container runtime to the control plane, host packages to the nodes), every other owner to its
// workload page. Every link to an owner is built here.
export function ownerHref(o: OwnerLike): string {
  if (isClusterLevel(o)) return o.kind === 'Nodes' ? '/nodes' : '/controlplane'
  return workloadPath(o.kind, o.namespace, o.name)
}

// ownerLabel is how an owner is named in a list: cluster-level owners by what they hold.
export function ownerLabel(o: OwnerLike): string {
  if (isClusterLevel(o)) return o.kind === 'Nodes' ? copy.owner.nodes : copy.owner.controlPlane
  return o.name
}

// ownerOfKey splits an owner key, "Kind/Namespace/Name".
export function ownerOfKey(key: string): OwnerLike {
  const [kind = '', namespace = '', name = ''] = key.split('/')
  return { kind, namespace, name }
}

function ownerPath(key: string): string {
  return ownerHref(ownerOfKey(key))
}

// scopePath is the page of a scope.
export function scopePath(s: Scope): string {
  switch (s.kind) {
    case 'cluster':
      return '/'
    case 'controlplane':
      return '/controlplane'
    case 'namespace':
      return namespacePath(s.value)
    case 'workload':
      return ownerPath(s.value)
    case 'image':
      return imagePath(s.value)
    case 'nodegroup':
      return nodeGroupPath(s.value)
    case 'node':
      return nodePath(s.value)
  }
}

export function explorerHref(kind: ExplorerKind, s: ExplorerSearch): string {
  return EXPLORERS[kind].path + stringifySearchParams(s)
}

// hitPath is where a command-menu hit goes. The control plane and Nodes hits open their pages; a
// workload hit is an owner key and opens the workload's page.
export function hitPath(hit: SearchHit): string {
  if (hit.kind === 'controlplane') return '/controlplane'
  if (hit.kind === 'nodes') return '/nodes'
  if (hit.kind === 'workload') {
    const o = ownerOfKey(hit.id)
    return workloadPath(o.kind, o.namespace, o.name)
  }
  if (hit.kind === 'advisory') return advisoryPath(hit.id)
  if (hit.kind === 'package') {
    const i = hit.id.indexOf('/')
    return i < 0 ? explorerHref('packages', { q: hit.id }) : explorerHref('packages', { ecosystem: [hit.id.slice(0, i)], q: hit.id.slice(i + 1) })
  }
  if (hit.scope) {
    try {
      return scopePath(parseScope(hit.scope))
    } catch {
      // Fall through to the hit's own kind and ID.
    }
  }
  switch (hit.kind) {
    case 'namespace':
      return namespacePath(hit.id)
    case 'image':
      return imagePath(hit.id)
    case 'nodegroup':
      return nodeGroupPath(hit.id)
    case 'node':
      return nodePath(hit.id)
  }
}

export type RelatedSectionId = S<'RelatedSection'>['id']

const explorerOfView: Partial<Record<ViewId, ExplorerKind>> = {
  vulnerabilities: 'findings',
  workloads: 'workloads',
  images: 'images',
  packages: 'packages',
}

// coverageHref is the coverage page of a scope. The page covers the cluster, a namespace or a
// workload; any other scope opens the cluster's.
export function coverageHref(scope?: Scope): string {
  if (!scope || (scope.kind !== 'namespace' && scope.kind !== 'workload')) return '/coverage'
  return `/coverage${stringifySearchParams({ scope: formatScope(scope) })}`
}

// viewHref is where a rail view of a scope goes. A view that is not one of the scope's own falls
// back to the scope's page.
export function viewHref(scope: Scope, id: ViewId, from?: string): string {
  const explorer = explorerOfView[id]
  switch (scope.kind) {
    case 'cluster':
      if (explorer) return explorerHref(explorer, {})
      if (id === 'exposure') return '/'
      if (id === 'nodes') return '/nodes'
      if (id === 'coverage') return '/coverage'
      break
    case 'namespace':
      if (explorer) return explorerHref(explorer, { scope: formatScope(scope) })
      if (id === 'exposure') return namespacePath(scope.value)
      if (id === 'coverage') return coverageHref(scope)
      break
    case 'workload':
      if (id === 'findings') return scopePath(scope)
      if (id === 'upgrades' || id === 'exposure' || id === 'rbac' || id === 'history') return scopePath(scope) + stringifySearchParams({ view: id })
      if (id === 'coverage') return coverageHref(scope)
      break
    case 'image':
      if (id === 'findings') return imagePath(scope.value, from)
      if (id === 'packages' || id === 'upgrades' || id === 'sbom') return `/images/${enc(scope.value)}${stringifySearchParams({ view: id, from })}`
      break
    case 'nodegroup':
      if (id === 'findings') return nodeGroupPath(scope.value)
      if (id === 'hostPackages' || id === 'kernel' || id === 'cachedImages' || id === 'members') return nodeGroupPath(scope.value) + stringifySearchParams({ view: id })
      break
  }
  return scopePath(scope)
}

function namespaceOfWorkload(scope: Scope): string {
  return scope.value.split('/')[1] ?? ''
}

// relatedHref is where the "+ N more" link and the filter of a rail section go; undefined when
// the section has nowhere to go from this scope. Filtering always happens on the server, through
// the explorer or page the section belongs to.
export function relatedHref(scope: Scope, id: RelatedSectionId, q?: string): string | undefined {
  switch (id) {
    case 'namespaces':
      return explorerHref('workloads', { q })
    case 'workloads':
      return explorerHref('workloads', { scope: formatScope(scope), q })
    case 'siblings':
      return scope.kind === 'workload' ? explorerHref('workloads', { scope: `namespace:${namespaceOfWorkload(scope)}`, q }) : undefined
    case 'notablePackages':
      return scope.kind === 'image' ? `/images/${enc(scope.value)}${stringifySearchParams({ view: 'packages', q })}` : undefined
    case 'nodegroups':
      return '/nodes'
    case 'controlplane':
      return '/controlplane'
    case 'usedBy':
      // Used by is listed on the image's SBOM view.
      return scope.kind === 'image' ? viewHref(scope, 'sbom') : undefined
    case 'members':
      return scope.kind === 'nodegroup' ? nodeGroupPath(scope.value) + stringifySearchParams({ view: 'members' }) : undefined
    case 'exceptions':
      return '/exceptions'
    case 'containers':
      return undefined
  }
}

// relatedFilterable reports whether a rail section has a filter box: only where its explorer can
// take the query for this scope.
export function relatedFilterable(id: RelatedSectionId, scope: Scope): boolean {
  return (
    (id === 'namespaces' && scope.kind === 'cluster') ||
    (id === 'workloads' && scope.kind === 'namespace') ||
    (id === 'siblings' && scope.kind === 'workload') ||
    (id === 'notablePackages' && scope.kind === 'image')
  )
}
