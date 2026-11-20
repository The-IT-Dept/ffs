import type { GapCode, S } from '@/api/types'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { copy } from '@/lib/copy'
import { cn } from '@/lib/utils'

// HOST_GAP_CODES are the node gaps after which ffs does not see a node's host packages in full (the
// server's hostGapCodes): its agent cannot read the host, there is no package database, the agent
// is not reporting or not scheduled on it, or its host inventory is not stored. A content store the
// agent cannot read concerns side-loaded images only.
export const HOST_GAP_CODES: readonly GapCode[] = [
  'node_agent_blocked',
  'no_package_database',
  'node_agent_missing',
  'host_not_inventoried',
  'node_agent_unsupported',
]

// NodeGapSummary is one thing ffs cannot see on a set of nodes, how many of them it affects and,
// for host packages not inventoried yet, why (each reason once).
export interface NodeGapSummary {
  key: GapCode | 'stale'
  label: string
  todo: string
  nodes: number
  reasons: string[]
  moreReasons: number // distinct reasons past MAX_REASONS
}

// MAX_REASONS is how many distinct reasons a gap line lists.
const MAX_REASONS = 3

// nodeGapLabel is how a node gap reads wherever it is listed: an agent that reports but whose host
// inventory is not stored has not inventoried the host yet.
export function nodeGapLabel(code: GapCode): string {
  return code === 'host_not_inventoried' ? copy.nodes.hostPending : copy.gaps[code].gap
}

function gapLine(key: NodeGapSummary['key']): Omit<NodeGapSummary, 'nodes' | 'reasons' | 'moreReasons'> {
  if (key === 'stale') return { key, label: copy.nodes.agentStale, todo: copy.gaps.node_agent_missing.todo }
  return { key, label: nodeGapLabel(key), todo: copy.gaps[key].todo }
}

// HOST_PENDING_DETAIL is the server's generic host_not_inventoried detail (store detailHostPending),
// which only repeats the headline.
export const HOST_PENDING_DETAIL = 'host packages not inventoried yet'

// hostPendingReason is why a reporting agent's host packages are not inventoried yet: the gap's own
// detail, which the server orders (a quarantine and when it lifts, then the last error), unless that
// is only the generic detail; then the agent's last error, if any.
export function hostPendingReason(a: S<'AgentStatus'>): string {
  const detail = a.gaps.find((g) => g.code === 'host_not_inventoried')?.detail ?? ''
  if (detail && detail !== HOST_PENDING_DETAIL) return detail
  return a.lastError ?? ''
}

// nodeGapsOf is the union of the coverage gaps of nodes' agents, in first-seen order, each with the
// number of nodes it affects. An agent that has never reported (or is disabled) counts as
// node_agent_missing, even when the API lists no gap code for it, and a stale one as stopped. When
// the nodes' host packages were not inventoried (inventoried false: a group without agent data), a
// reporting agent without a gap of its own counts as host_not_inventoried. Host packages not
// inventoried yet carry the agents' reasons.
export function nodeGapsOf(agents: readonly S<'AgentStatus'>[], o: { inventoried: boolean }): NodeGapSummary[] {
  const out = new Map<NodeGapSummary['key'], NodeGapSummary>()
  const seen = new Map<NodeGapSummary['key'], Set<string>>()
  for (const a of agents) {
    const keys = new Set<NodeGapSummary['key']>(a.gaps.map((g) => g.code))
    if (a.state === 'stale') {
      // Stopped is the more precise word for the missing inventory of a stale agent.
      keys.delete('node_agent_missing')
      keys.add('stale')
    } else if (a.state !== 'reporting' && !keys.has('node_agent_unsupported')) keys.add('node_agent_missing')
    else if (a.state === 'reporting' && keys.size === 0 && !o.inventoried) keys.add('host_not_inventoried')
    for (const k of keys) {
      const s = out.get(k) ?? { ...gapLine(k), nodes: 0, reasons: [], moreReasons: 0 }
      s.nodes++
      const why = k === 'host_not_inventoried' ? hostPendingReason(a) : ''
      if (why && !s.reasons.includes(why) && !(seen.get(k)?.has(why) ?? false)) {
        if (s.reasons.length < MAX_REASONS) s.reasons.push(why)
        else s.moreReasons++
        seen.set(k, (seen.get(k) ?? new Set<string>()).add(why))
      }
      out.set(k, s)
    }
  }
  return [...out.values()]
}

// NodeGapLines lists node gaps hatched, each with how many of the total nodes it affects and, unless
// compact, why (host packages not inventoried yet) or else what to do about it.
export function NodeGapLines({ gaps, total, compact, className }: { gaps: NodeGapSummary[]; total: number; compact?: boolean; className?: string }) {
  if (gaps.length === 0) return null
  return (
    <ul className={cn('flex flex-col gap-1', compact && 'flex-row flex-wrap gap-x-3', className)}>
      {gaps.map((g) => (
        <li key={g.key} className="flex flex-wrap items-baseline gap-x-2">
          <CoverageMark>{g.label}</CoverageMark>
          {total > 1 ? <span className="tabular-nums">{copy.nodes.gapNodes(g.nodes, total)}</span> : null}
          {compact ? null : <span className="min-w-0 [overflow-wrap:anywhere]">{g.reasons.length > 0 ? g.reasons.join(' · ') + (g.moreReasons > 0 ? ` · ${copy.nodes.moreReasons(g.moreReasons)}` : '') : g.todo}</span>}
        </li>
      ))}
    </ul>
  )
}

// NodeGapNotice leads a node group's view with its gaps, in the dashed box empty states use.
export function NodeGapNotice({ gaps, total }: { gaps: NodeGapSummary[]; total: number }) {
  if (gaps.length === 0) return null
  return (
    <div role="note" className="mb-2 rounded-md border border-dashed px-3 py-2 text-[12px] text-muted-foreground">
      <NodeGapLines gaps={gaps} total={total} />
    </div>
  )
}
