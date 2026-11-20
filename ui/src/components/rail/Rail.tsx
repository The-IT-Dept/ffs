import { useQuery } from '@tanstack/react-query'
import { useRouterState } from '@tanstack/react-router'
import { apiQuery } from '@/api/client'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { scopeParam } from '@/lib/scope'
import { RelatedList } from './RelatedList'
import { routeScope } from './routescope'
import { ScopeCard } from './ScopeCard'
import { TrustFooter } from './TrustFooter'
import { ViewsList } from './ViewsList'

// Rail is the contextual left rail. It has the same four parts at every depth (scope card, views,
// inside or related, trust footer) and rebuilds around whatever page the router lands on.
export function Rail() {
  // Only what the rail needs leaves the selector, all strings, so structural sharing keeps the
  // result stable across unrelated router updates.
  const leaf = useRouterState({
    select: (s) => {
      const m = s.matches[s.matches.length - 1]
      const search = (m?.search ?? {}) as Record<string, unknown>
      const pick = (k: string) => (typeof search[k] === 'string' ? (search[k] as string) : '')
      return {
        routeId: m ? String(m.routeId) : '__root__',
        params: { ...(m?.params ?? {}) } as Record<string, string>,
        scope: pick('scope'),
        view: pick('view'),
        from: pick('from'),
      }
    },
    structuralSharing: true,
  })
  const rs = routeScope(leaf.routeId, leaf.params, { scope: leaf.scope, view: leaf.view, from: leaf.from })
  const q = useQuery(apiQuery('/scope', { query: { ...scopeParam(rs.scope), ...(rs.from ? { from: rs.from } : {}) } }))

  if (q.isPending) {
    return (
      <div className="flex flex-col gap-2 p-3">
        <Skeleton className="h-16" />
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-2/3" />
        <Skeleton className="h-4 w-1/2" />
      </div>
    )
  }
  if (q.isError) return <p className="p-3 text-[12px] text-muted-foreground">{copy.rail.unavailable}</p>

  const card = q.data
  return (
    <div className="flex flex-col gap-4 p-3">
      <ScopeCard card={card} scope={rs.scope} />
      {card.views.length > 0 ? (
        <section className="flex flex-col gap-1">
          <h2 className="px-2 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{copy.rail.views}</h2>
          <ViewsList scope={rs.scope} views={card.views} active={rs.view} from={rs.from} />
        </section>
      ) : null}
      {card.related.map((section) => (
        <RelatedList key={section.id} scope={rs.scope} section={section} />
      ))}
      <TrustFooter trust={card.trust} scope={rs.scope} />
    </div>
  )
}
