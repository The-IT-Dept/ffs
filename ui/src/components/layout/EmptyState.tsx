import type { ReactNode } from 'react'
import type { S } from '@/api/types'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { coverageHref } from '@/lib/links'
import type { Scope } from '@/lib/scope'
import { cn } from '@/lib/utils'
import { AppLink } from './AppLink'

// MATCH_FEEDS are the feeds ffs matches images against. Without them findings can be missing; the
// other feeds (KEV, EPSS, lifecycle) only rank what was found.
const MATCH_FEEDS = ['grypedb', 'osv']

// staleMatchFeeds lists the matching feeds that are stale or have never synced.
export function staleMatchFeeds(feeds?: S<'FeedFreshness'>): string[] {
  return feeds ? feeds.stale.filter((f) => MATCH_FEEDS.includes(f)) : []
}

const link = 'underline underline-offset-2 hover:text-foreground'

// CoverageFirstLine is the coverage-first message, shown wherever ffs cannot see into every image
// in use; it renders nothing when it can. Its link opens the coverage page of the scope.
export function CoverageFirstLine({ coverage, scope, className }: { coverage?: S<'CoverageFigure'>; scope?: Scope; className?: string }) {
  if (!coverage || coverage.inUse <= coverage.seenInto) return null
  return (
    <p className={className}>
      <span>{copy.coverageFirst(coverage.inUse - coverage.seenInto, coverage.inUse)}</span>{' '}
      <AppLink href={coverageHref(scope)} className={link}>
        {copy.coverageLink}
      </AppLink>
    </p>
  )
}

// FeedFirstLine says which matching feeds are out of date, hatched, with a link to the feeds page;
// it renders nothing while they are fresh.
export function FeedFirstLine({ feeds, className }: { feeds?: S<'FeedFreshness'>; className?: string }) {
  const stale = staleMatchFeeds(feeds)
  if (stale.length === 0) return null
  return (
    <p className={className}>
      <CoverageMark>{`${copy.gaps.feed_stale.gap}: ${stale.join(', ')}`}</CoverageMark> <span>{copy.feedFirst(stale.length)}</span>{' '}
      <AppLink href="/feeds" className={link}>
        {copy.page.feeds}
      </AppLink>
    </p>
  )
}

// EmptyState says why a view is empty. An empty list is proof of nothing when ffs cannot see all of
// the scope, so whatever it cannot see leads instead of "Nothing needs attention": a matching feed
// out of date, what the caller knows it cannot see (lead: a node group's agent gaps, an image's
// coverage gaps) and images in use it has not seen into. While the coverage and feeds are still
// loading (pending), the clean line waits behind a skeleton line, so it never shows before what may
// replace it. message replaces all of it, for lists that are not findings.
export function EmptyState({
  coverage,
  feeds,
  scope,
  lead,
  filtered,
  pending,
  message,
}: {
  coverage?: S<'CoverageFigure'>
  feeds?: S<'FeedFreshness'>
  scope?: Scope
  lead?: ReactNode
  filtered?: boolean
  pending?: boolean
  message?: string
}) {
  const box = 'rounded-md border border-dashed px-4 py-6 text-[13px] text-muted-foreground'
  if (message) {
    return (
      <div className={box}>
        <p>{message}</p>
      </div>
    )
  }
  const blind = staleMatchFeeds(feeds).length > 0 || Boolean(lead) || (coverage !== undefined && coverage.inUse > coverage.seenInto)
  return (
    <div className={cn(box, 'flex flex-col gap-1')}>
      {filtered ? <p>{copy.emptyFiltered}</p> : blind ? null : pending ? <Skeleton aria-hidden="true" className="my-0.5 h-4 w-40" /> : <p>{copy.empty}</p>}
      <FeedFirstLine feeds={feeds} />
      {lead}
      <CoverageFirstLine coverage={coverage} scope={scope} />
    </div>
  )
}
