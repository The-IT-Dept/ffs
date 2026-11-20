import { Fragment } from 'react'
import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { Mono } from '@/components/signals/Mono'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { nodeGroupPath, ownerHref, ownerLabel } from '@/lib/links'

// NODE_GROUPS_SHOWN groups are named in a row; the rest are a count, listed in the title.
const NODE_GROUPS_SHOWN = 3

type Group = S<'FindingNodeGroup'>

function versionsOf(g: Group): string {
  const one = new Set(g.versions.map((v) => v.package)).size <= 1
  return g.versions.map((v) => (one ? v.version : `${v.package} ${v.version}`)).join(', ')
}

function describe(g: Group): string {
  const v = versionsOf(g)
  return `${g.label} · ${copy.nodes.nodesCount(g.nodes)}${v ? ` · ${v}` : ''}`
}

// FindingNodeGroups names the node groups a host finding affects: each links to its group page,
// with its member count and the installed versions of the finding's packages there.
export function FindingNodeGroups({ groups }: { groups: Group[] }) {
  const shown = groups.slice(0, NODE_GROUPS_SHOWN)
  const rest = groups.length - shown.length
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5">
      {shown.map((g, i) => (
        <Fragment key={g.id}>
          {i > 0 ? <span className="text-muted-foreground">,</span> : null}
          <span className="inline-flex items-center gap-1" title={describe(g)}>
            <AppLink href={nodeGroupPath(g.id)} className="hover:underline">
              {g.label}
            </AppLink>
            <span className="text-muted-foreground">{copy.nodes.nodesCount(g.nodes)}</span>
            {g.versions.length > 0 ? <Mono className="text-muted-foreground">{versionsOf(g)}</Mono> : null}
          </span>
        </Fragment>
      ))}
      {rest > 0 ? (
        <span className="text-muted-foreground" title={groups.slice(NODE_GROUPS_SHOWN).map(describe).join('\n')}>
          +{formatCount(rest)}
        </span>
      ) : null}
    </span>
  )
}

// OwnerCell is a finding's owner in a table: the workload with its namespace, or a cluster-level
// owner by what it holds; a host finding then names the node groups it affects.
export function OwnerCell({ owner, nodeGroups, namespace = true }: { owner: S<'WorkloadRef'>; nodeGroups?: Group[]; namespace?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <AppLink href={ownerHref(owner)} className="hover:underline">
        {ownerLabel(owner)}
      </AppLink>
      {namespace && owner.namespace ? <span className="text-muted-foreground">{owner.namespace}</span> : null}
      {nodeGroups && nodeGroups.length > 0 ? <FindingNodeGroups groups={nodeGroups} /> : null}
    </span>
  )
}
