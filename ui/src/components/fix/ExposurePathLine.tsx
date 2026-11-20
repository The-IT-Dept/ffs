import { Fragment } from 'react'
import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { copy } from '@/lib/copy'

type Edge = S<'ExposureEdge'>

const MAX_PATHS = 3

// entryText names an entry point the way the exposure table does.
export function entryText(e: Edge): string {
  switch (e.entry) {
    case 'gateway':
      return `Gateway ${e.entryName}${e.listener ? ` · ${e.listener}` : ''}`
    case 'ingress':
      return e.entryName ? `Ingress class ${e.entryName}` : copy.path.noClass
    case 'loadbalancer':
      return `LoadBalancer Service ${e.entryName}`
    case 'nodeport':
      return `NodePort Service ${e.entryName}`
    case 'externalip':
      return `External IPs ${e.entryName}`
    case 'hostnetwork':
      return 'hostNetwork'
    case 'hostport':
      return `hostPort ${e.listener}`
  }
}

function pillsOf(e: Edge, pods: number | null): string[] {
  const pills = [copy.path.internet, entryText(e)]
  if (e.route) pills.push(`${e.route} · ${e.hostname || '*'}`)
  if (e.service) pills.push(e.service)
  if (pods !== null) pills.push(copy.path.pods(pods))
  return pills
}

function distinct(edges: Edge[]): Edge[] {
  const seen = new Set<string>()
  return edges.filter((e) => {
    const k = [e.entry, e.entryName, e.listener, e.hostname, e.route, e.service].join('\u0000')
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
}

// ExposurePathLine draws how a workload is reached, once per path: Internet → entry point →
// route and host → Service:port → pods. Internal entry points follow on one muted line.
export function ExposurePathLine({ edges, pods, moreHref }: { edges: Edge[]; pods: number | null; moreHref?: string }) {
  const external = distinct(edges.filter((e) => !e.internal))
  const internal = distinct(edges.filter((e) => e.internal))
  return (
    <div className="my-3 flex flex-col gap-1.5 text-[12px]">
      {external.length === 0 ? <p className="text-muted-foreground">{copy.path.notExposed}</p> : null}
      {external.slice(0, MAX_PATHS).map((e, i) => (
        <ol key={i} aria-label="Exposure path" className="flex flex-wrap items-center gap-1.5">
          {pillsOf(e, pods).map((p, j) => (
            <Fragment key={j}>
              {j > 0 ? (
                <span aria-hidden="true" className="text-muted-foreground">
                  →
                </span>
              ) : null}
              <li className="rounded-md border bg-background px-2 py-0.5">{p}</li>
            </Fragment>
          ))}
        </ol>
      ))}
      {external.length > MAX_PATHS && moreHref ? (
        <AppLink href={moreHref} className="text-[11px] text-muted-foreground hover:text-foreground hover:underline">
          {copy.path.more(external.length - MAX_PATHS)}
        </AppLink>
      ) : null}
      {internal.length > 0 ? (
        <p className="text-[11px] text-muted-foreground">
          {copy.path.internal}: {internal.map(entryText).join(', ')}
        </p>
      ) : null}
    </div>
  )
}
