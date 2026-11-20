import type { SearchHit } from '@/api/types'
import { EXPLORERS, type ExplorerKind, type ExplorerSearch, stringifySearchParams } from './query'
import { parseScope, type Scope } from './scope'

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

export function nodeGroupPath(id: string): string {
  return `/nodegroups/${enc(id)}`
}

export function nodePath(name: string): string {
  return `/nodes/${enc(name)}`
}

function ownerPath(key: string): string {
  const [kind = '', namespace = '', name = ''] = key.split('/')
  return workloadPath(kind, namespace, name)
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

// hitPath is where a command-menu hit goes.
export function hitPath(hit: SearchHit): string {
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
    case 'workload':
      return ownerPath(hit.id)
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
