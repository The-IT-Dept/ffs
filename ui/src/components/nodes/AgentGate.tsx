import type { ReactNode } from 'react'
import type { S } from '@/api/types'
import { EmptyState } from '@/components/layout/EmptyState'
import { copy } from '@/lib/copy'

// hasAgentData reports whether a node's agent has data to show: it is reporting, or its last
// report has gone stale. A node detail carries no agentData flag of its own.
export function hasAgentData(a: S<'AgentStatus'>): boolean {
  return a.state === 'reporting' || a.state === 'stale'
}

// AgentGate shows agent-only sections only when there is agent data, and the agent-missing copy
// otherwise.
export function AgentGate({ agentData, children }: { agentData: boolean; children: ReactNode }) {
  return agentData ? <>{children}</> : <EmptyState message={copy.agentMissing} />
}
