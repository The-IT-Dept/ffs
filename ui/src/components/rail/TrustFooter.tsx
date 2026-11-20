import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { CoverageFigureText } from '@/components/signals/CoverageFigureText'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { copy } from '@/lib/copy'
import { formatAge } from '@/lib/format'
import type { Scope } from '@/lib/scope'

// TrustFooter says how far to trust the counts above it: feed freshness, coverage for the scope,
// and at image level the SBOM source and unattributed executables.
export function TrustFooter({ trust }: { trust: S<'Trust'>; scope: Scope }) {
  return (
    <div className="flex flex-col gap-1 border-t pt-2 text-[11px] text-muted-foreground">
      <AppLink href="/feeds" className="hover:text-foreground">
        {trust.feeds.fresh ? (
          <span>
            {copy.trust.feedsFresh}
            {trust.feeds.oldestSuccess ? ` · ${formatAge(trust.feeds.oldestSuccess)}` : ''}
          </span>
        ) : (
          <CoverageMark>{copy.trust.feedsStale(trust.feeds.stale)}</CoverageMark>
        )}
      </AppLink>
      <div>
        <span>{copy.trust.coverage}</span> <CoverageFigureText figure={trust.coverage} secondary />
      </div>
      {trust.sbomSource ? <div>{copy.trust.sbom(trust.sbomSource, trust.sbomTool)}</div> : null}
      {trust.unattributed ? (
        <div>
          <CoverageMark>{copy.trust.unattributed(trust.unattributed)}</CoverageMark>
        </div>
      ) : null}
      {trust.settings ? (
        <div className="flex items-center gap-1.5">
          <span aria-hidden="true">⚙</span>
          <AppLink href="/exceptions" className="hover:text-foreground hover:underline">
            {copy.trust.exceptions}
          </AppLink>
          <span aria-hidden="true">·</span>
          <AppLink href="/settings" className="hover:text-foreground hover:underline">
            {copy.trust.settings}
          </AppLink>
        </div>
      ) : null}
    </div>
  )
}
