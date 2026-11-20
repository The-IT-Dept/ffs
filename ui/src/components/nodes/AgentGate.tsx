import type { ReactNode } from 'react'
import type { S } from '@/api/types'
import { EmptyState } from '@/components/layout/EmptyState'
import { copy } from '@/lib/copy'
import { NodeGapLines, nodeGapsOf } from './NodeGaps'

// hasAgentData reports whether a node's agent has data to show: it is reporting, or its last
// report has gone stale. A node detail carries no agentData flag of its own.
export function hasAgentData(a: S<'AgentStatus'>): boolean {
  return a.state === 'reporting' || a.state === 'stale'
}

// AgentMissing says why there is no agent data, from the agents' own state: the node agent is not
// enabled, or, hatched, it has not reported, stopped, cannot read the host, has not inventoried
// it, or does not run on these nodes.
export function AgentMissing({ agents }: { agents: readonly S<'AgentStatus'>[] }) {
  const gaps = nodeGapsOf(agents, { inventoried: false })
  if (gaps.length === 0 || agents.every((a) => a.state === 'disabled')) return <EmptyState message={copy.agentMissing} />
  return <EmptyState lead={<NodeGapLines gaps={gaps} total={agents.length} />} />
}

// AgentGate shows agent-only sections only when there is agent data, and why there is none
// otherwise.
export function AgentGate({ agentData, agents, children }: { agentData: boolean; agents: readonly S<'AgentStatus'>[]; children: ReactNode }) {
  return agentData ? <>{children}</> : <AgentMissing agents={agents} />
}
