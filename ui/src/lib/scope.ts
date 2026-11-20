export type ScopeKind = 'cluster' | 'namespace' | 'workload' | 'image' | 'nodegroup' | 'node' | 'controlplane'

// Scope is the part of the cluster a page or query covers. Value is the namespace, the owner key
// "Kind/Namespace/Name", the image digest, the node group ID or the node name; "" for the cluster
// and control plane.
export interface Scope {
  kind: ScopeKind
  value: string
}

export class ScopeError extends Error {
  constructor(input: string) {
    super(`invalid scope: ${JSON.stringify(input)}`)
    this.name = 'ScopeError'
  }
}

export const CLUSTER: Scope = Object.freeze({ kind: 'cluster', value: '' })

const VALUE_KINDS: readonly ScopeKind[] = ['namespace', 'workload', 'image', 'nodegroup', 'node']

// parseScope mirrors the server's model.ParseScope: "" and "cluster" are the cluster,
// "controlplane" is the control plane, and anything else is "<kind>:<value>" split at the first
// colon (so a digest keeps its own) with a non-empty value. A workload value is an owner key of
// three parts whose kind and name are not empty.
export function parseScope(s: string | undefined): Scope {
  if (s === undefined || s === '' || s === 'cluster') return CLUSTER
  if (s === 'controlplane') return { kind: 'controlplane', value: '' }
  const i = s.indexOf(':')
  if (i < 0) throw new ScopeError(s)
  const kind = s.slice(0, i) as ScopeKind
  const value = s.slice(i + 1)
  if (!VALUE_KINDS.includes(kind) || value === '') throw new ScopeError(s)
  if (kind === 'workload') {
    const parts = value.split('/')
    if (parts.length !== 3 || parts[0] === '' || parts[2] === '') throw new ScopeError(s)
  }
  return { kind, value }
}

export function formatScope(s: Scope): string {
  if (s.kind === 'cluster' || s.kind === 'controlplane') return s.kind
  return `${s.kind}:${s.value}`
}

// workloadScope builds a workload scope from route params, where the namespace "-" means none.
export function workloadScope(kind: string, namespace: string, name: string): Scope {
  const ns = namespace === '-' ? '' : namespace
  return { kind: 'workload', value: `${kind}/${ns}/${name}` }
}

// scopeParam is the scope query parameter for a scope; the cluster is the API default, so it is
// left out.
export function scopeParam(s: Scope): { scope?: string } {
  return s.kind === 'cluster' ? {} : { scope: formatScope(s) }
}
