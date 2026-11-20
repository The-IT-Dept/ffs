import type { S } from '@/api/types'
import { Field, FieldList } from '@/components/layout/FieldList'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { copy } from '@/lib/copy'
import { hostPendingReason } from './NodeGaps'

// AgentStatusView is one node's agent: its state and reports, what it cannot read (hatched), and
// any problems it reported. Host packages not inventoried yet read with their reason, the last
// error when there is one, which is then not repeated below.
export function AgentStatusView({ agent }: { agent: S<'AgentStatus'> }) {
  const f = copy.nodes.agentFields
  const pending = agent.gaps.some((g) => g.code === 'host_not_inventoried')
  const gapLabel = (g: S<'NodeGap'>) => (g.code === 'host_not_inventoried' ? copy.nodes.hostPending : copy.gaps[g.code].gap)
  const gapDetail = (g: S<'NodeGap'>) => (g.code === 'host_not_inventoried' ? hostPendingReason(agent) : g.detail)
  return (
    <div className="text-[12px]">
      <FieldList>
        <Field label={f.state}>{copy.agentState[agent.state]}</Field>
        <Field label={f.version}>{agent.agentVersion ? <Mono wrap>{agent.agentVersion}</Mono> : <span className="text-muted-foreground">{copy.noValue}</span>}</Field>
        <Field label={f.lastReport}>
          <RelativeTime iso={agent.lastReport} />
        </Field>
        <Field label={f.lastFullReport}>
          <RelativeTime iso={agent.lastFullReport} />
        </Field>
        <Field label={f.kernel}>{agent.kernelRelease ? <Mono wrap>{agent.kernelRelease}</Mono> : <span className="text-muted-foreground">{copy.noValue}</span>}</Field>
        <Field label={copy.nodes.rebootPending}>
          {agent.rebootPending ? copy.nodes.yes : copy.nodes.no}
          {agent.rebootPending && agent.rebootReason ? <span className="ml-2 text-muted-foreground">{agent.rebootReason}</span> : null}
        </Field>
      </FieldList>
      {agent.gaps.length > 0 ? (
        <ul className="mt-2 flex flex-col gap-1">
          {agent.gaps.map((g) => (
            <li key={`${g.code}:${g.detail}`} className="flex flex-wrap items-baseline gap-2">
              <CoverageMark>{gapLabel(g)}</CoverageMark>
              {gapDetail(g) ? <span className="min-w-0 text-muted-foreground [overflow-wrap:anywhere]">{gapDetail(g)}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
      {agent.problems.length > 0 ? (
        <ul className="mt-2 list-disc pl-4 text-muted-foreground">
          {agent.problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      ) : null}
      {agent.lastError && !pending ? <p className="mt-2 text-muted-foreground">{agent.lastError}</p> : null}
    </div>
  )
}
