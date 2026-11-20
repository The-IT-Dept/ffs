import { useNavigate } from '@tanstack/react-router'
import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { PriorityDot } from '@/components/signals/PriorityDot'
import { Input } from '@/components/ui/input'
import { copy } from '@/lib/copy'
import { formatCompact } from '@/lib/format'
import { imagePath, relatedFilterable, relatedHref, scopePath } from '@/lib/links'
import { formatScope, parseScope, type Scope } from '@/lib/scope'
import { cn, touchBlock } from '@/lib/utils'

function itemHref(scope: Scope, item: S<'RelatedItem'>): string | undefined {
  if (!item.scope) return undefined
  try {
    const target = parseScope(item.scope)
    // An image reached from a workload keeps the workload as its breadcrumb parent.
    if (target.kind === 'image' && scope.kind === 'workload') return imagePath(target.value, formatScope(scope))
    return scopePath(target)
  } catch {
    return undefined
  }
}

function ItemBody({ item }: { item: S<'RelatedItem'> }) {
  return (
    <>
      <PriorityDot priority={item.worst} gap={item.gap} />
      <span className="min-w-0 flex-1 truncate" title={item.detail ? `${item.label} · ${item.detail}` : item.label}>
        {item.label}
      </span>
      {item.count !== null ? <span className="text-muted-foreground tabular-nums">{formatCompact(item.count)}</span> : null}
    </>
  )
}

// RelatedList is one "inside or related" section of the rail, worst first as the server sends
// it. Its filter never filters the loaded items: Enter opens the section's explorer with the query.
export function RelatedList({ scope, section }: { scope: Scope; section: S<'RelatedSection'> }) {
  const navigate = useNavigate()
  const heading = copy.related(section.id, scope)
  const moreHref = section.more > 0 ? relatedHref(scope, section.id) : undefined
  return (
    <section className="flex flex-col gap-1">
      <h2 className="px-2 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{heading}</h2>
      {relatedFilterable(section.id, scope) ? (
        <Input
          type="search"
          aria-label={`${copy.rail.filter} ${heading}`}
          placeholder={copy.rail.filter}
          className="h-7 bg-background px-2 text-base max-lg:h-10 md:text-[12px]"
          onKeyDown={(e) => {
            if (e.key !== 'Enter') return
            e.preventDefault()
            const q = e.currentTarget.value.trim()
            const href = relatedHref(scope, section.id, q || undefined)
            if (href) void navigate({ href })
          }}
        />
      ) : null}
      <ul className="flex flex-col gap-px">
        {section.items.map((item, i) => {
          const href = itemHref(scope, item)
          const row = 'flex items-center gap-2 rounded-md px-2 py-0.5 text-[12px] max-lg:min-h-10'
          return (
            <li key={`${item.scope ?? item.label}:${i}`}>
              {href ? (
                <AppLink href={href} className={`${row} hover:bg-muted`}>
                  <ItemBody item={item} />
                </AppLink>
              ) : (
                <div className={row}>
                  <ItemBody item={item} />
                </div>
              )}
            </li>
          )
        })}
      </ul>
      {moreHref ? (
        <AppLink href={moreHref} className={cn('px-2 text-[11px] text-muted-foreground hover:text-foreground hover:underline', touchBlock)}>
          {copy.rail.more(section.more)}
        </AppLink>
      ) : null}
    </section>
  )
}
