import type { S } from '@/api/types'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { copy } from '@/lib/copy'

// AgentStatusView is one node's agent: its state and reports, what it cannot read (hatched), and
// any problems it reported.
export function AgentStatusView({ agent }: { agent: S<'AgentStatus'> }) {
  const f = copy.nodes.agentFields
  return (
    <div className="text-[12px]">
      <dl className="grid max-w-2xl grid-cols-[10rem_1fr] gap-x-4 gap-y-1.5">
        <dt className="text-muted-foreground">{f.state}</dt>
        <dd>{copy.agentState[agent.state]}</dd>
        <dt className="text-muted-foreground">{f.version}</dt>
        <dd>{agent.agentVersion ? <Mono>{agent.agentVersion}</Mono> : <span className="text-muted-foreground">{copy.noValue}</span>}</dd>
        <dt className="text-muted-foreground">{f.lastReport}</dt>
        <dd>
          <RelativeTime iso={agent.lastReport} />
        </dd>
        <dt className="text-muted-foreground">{f.lastFullReport}</dt>
        <dd>
          <RelativeTime iso={agent.lastFullReport} />
        </dd>
        <dt className="text-muted-foreground">{f.kernel}</dt>
        <dd>{agent.kernelRelease ? <Mono>{agent.kernelRelease}</Mono> : <span className="text-muted-foreground">{copy.noValue}</span>}</dd>
        <dt className="text-muted-foreground">{copy.nodes.rebootPending}</dt>
        <dd>
          {agent.rebootPending ? copy.nodes.yes : copy.nodes.no}
          {agent.rebootPending && agent.rebootReason ? <span className="ml-2 text-muted-foreground">{agent.rebootReason}</span> : null}
        </dd>
      </dl>
      {agent.gaps.length > 0 ? (
        <ul className="mt-2 flex flex-col gap-1">
          {agent.gaps.map((g) => (
            <li key={`${g.code}:${g.detail}`} className="flex flex-wrap items-baseline gap-2">
              <CoverageMark>{copy.gaps[g.code].gap}</CoverageMark>
              {g.detail ? <span className="text-muted-foreground">{g.detail}</span> : null}
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
      {agent.lastError ? <p className="mt-2 text-muted-foreground">{agent.lastError}</p> : null}
    </div>
  )
}
