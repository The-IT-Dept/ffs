import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { Mono } from '@/components/signals/Mono'
import { PriorityCountsText } from '@/components/signals/PriorityCountsText'
import { copy } from '@/lib/copy'
import { cn, touchLink } from '@/lib/utils'

function Version({ name, version, nodes, eol }: { name?: string; version: string; nodes: number; eol?: S<'EOL'> }) {
  return (
    <li className="flex flex-wrap items-baseline gap-2">
      {name ? <span>{name}</span> : null}
      <Mono>{version}</Mono>
      <span className="text-muted-foreground">{copy.nodes.nodesCount(nodes)}</span>
      {eol?.text ? <span className="text-muted-foreground">{eol.text}</span> : null}
    </li>
  )
}

// ControlPlaneBlock is the one control-plane summary: Kubernetes and runtime versions with their
// lifecycle, and the control plane's open findings. The Nodes page links it to its own page.
export function ControlPlaneBlock({ controlPlane, link }: { controlPlane: S<'ControlPlane'>; link?: boolean }) {
  return (
    <section className="mb-4 rounded-md border px-3 py-2 text-[12px]">
      {link ? (
        <AppLink href="/controlplane" className={cn('font-semibold hover:underline', touchLink)}>
          {copy.page.controlplane}
        </AppLink>
      ) : null}
      <ul className="mt-1 flex flex-col gap-0.5">
        {controlPlane.kubernetes.map((k) => (
          <Version key={`k8s:${k.version}`} name={copy.nodes.kubernetes} version={k.version} nodes={k.nodes} eol={k.eol} />
        ))}
        {controlPlane.runtimes.map((r) => (
          <Version key={`rt:${r.name}:${r.version}`} name={r.name} version={r.version} nodes={r.nodes} eol={r.eol} />
        ))}
      </ul>
      <p className="mt-1">
        <PriorityCountsText counts={controlPlane.counts} />
        <span className="text-muted-foreground"> · {copy.workload.fixable(controlPlane.fixable)}</span>
      </p>
    </section>
  )
}
