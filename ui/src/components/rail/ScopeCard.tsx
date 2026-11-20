import { Fragment } from 'react'
import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { copy } from '@/lib/copy'
import { scopePath } from '@/lib/links'
import { parseScope, type Scope } from '@/lib/scope'

function hrefOf(scope: string): string | undefined {
  try {
    return scopePath(parseScope(scope))
  } catch {
    return undefined
  }
}

// ScopeCard heads the rail: breadcrumbs back up, the kind, the name and a one-line summary. The
// cluster card switches cluster (only one exists for now).
export function ScopeCard({ card, scope }: { card: S<'ScopeCard'>; scope: Scope }) {
  return (
    <div className="rounded-md border bg-background p-2.5 shadow-xs">
      {card.breadcrumbs.length > 0 ? (
        <nav aria-label="Parent scopes" className="mb-1.5 truncate text-[10.5px] text-muted-foreground">
          <span aria-hidden="true">↑ </span>
          {card.breadcrumbs.map((b, i) => {
            const href = hrefOf(b.scope)
            return (
              <Fragment key={b.scope}>
                {i > 0 ? <span aria-hidden="true"> › </span> : null}
                {href ? (
                  <AppLink href={href} className="hover:text-foreground hover:underline max-lg:inline-flex max-lg:min-h-10 max-lg:items-center">
                    {b.label}
                  </AppLink>
                ) : (
                  <span>{b.label}</span>
                )}
              </Fragment>
            )
          })}
        </nav>
      ) : null}
      <div className="flex items-start gap-1">
        <div className="min-w-0 flex-1">
          <div className="text-[9.5px] font-medium tracking-wider text-muted-foreground uppercase">{copy.scopeKind(scope)}</div>
          <div className="truncate text-[13px] font-semibold" title={card.title}>
            {card.title}
          </div>
        </div>
        {scope.kind === 'cluster' ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon-xs" className="max-lg:size-10" aria-label={copy.rail.switchCluster} title={copy.rail.switchCluster}>
                <span aria-hidden="true">⇅</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              {card.clusters.map((c) => (
                <DropdownMenuCheckboxItem key={c} checked={c === card.cluster} onSelect={(e) => e.preventDefault()}>
                  {c}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}
      </div>
      {card.summary ? <p className="mt-1 text-[11px] leading-snug text-muted-foreground">{card.summary}</p> : null}
    </div>
  )
}
