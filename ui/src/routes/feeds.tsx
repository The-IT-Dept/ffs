import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { apiQuery } from '@/api/client'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

function Heads({ labels }: { labels: string[] }) {
  return (
    <TableHeader>
      <TableRow className="h-[30px] hover:bg-transparent">
        {labels.map((l) => (
          <TableHead key={l} className="h-[30px] py-0 text-[11px] font-medium text-muted-foreground">
            {l}
          </TableHead>
        ))}
      </TableRow>
    </TableHeader>
  )
}

// FeedsPage is how fresh each vulnerability feed is, and where the data comes from.
function FeedsPage() {
  const q = useQuery(apiQuery('/feeds', {}))
  const c = copy.feeds.cols
  return (
    <div>
      <PageHeader title={copy.page.feeds} />
      {q.data ? (
        <>
          <Table className="text-[12px]">
            <Heads labels={[c.feed, c.lastSuccess, c.lastAttempt, c.staleAfter, c.status, c.lastError]} />
            <TableBody>
              {q.data.feeds.map((f) => (
                <TableRow key={f.name} className="h-[30px]">
                  <TableCell className="py-0">{f.name}</TableCell>
                  <TableCell className="py-0">
                    <RelativeTime iso={f.lastSuccess} />
                  </TableCell>
                  <TableCell className="py-0">
                    <RelativeTime iso={f.lastAttempt} />
                  </TableCell>
                  <TableCell className="py-0">
                    <Mono>{f.staleAfter}</Mono>
                  </TableCell>
                  <TableCell className="py-0">{f.stale ? <CoverageMark>{copy.feeds.stale}</CoverageMark> : copy.feeds.fresh}</TableCell>
                  <TableCell className="max-w-[24rem] truncate py-0 text-muted-foreground" title={f.lastError || undefined}>
                    {f.lastError}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <section className="mt-6">
            <h2 className="mb-1.5 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{copy.feeds.sources}</h2>
            <Table className="text-[12px]">
              <Heads labels={[c.source, c.feed, c.licence, c.attribution, c.url]} />
              <TableBody>
                {q.data.sources.map((s) => (
                  <TableRow key={`${s.feed}:${s.name}`} className="h-[30px]">
                    <TableCell className="py-0">{s.name}</TableCell>
                    <TableCell className="py-0">{s.feed}</TableCell>
                    <TableCell className="py-0">{s.licence}</TableCell>
                    <TableCell className="max-w-[18rem] truncate py-0" title={s.attribution}>
                      {s.attribution}
                    </TableCell>
                    <TableCell className="py-0">
                      <a href={s.url} target="_blank" rel="noreferrer noopener" className="underline underline-offset-2 hover:text-foreground">
                        {s.url}
                      </a>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </section>
        </>
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

export const feedsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/feeds',
  component: FeedsPage,
})
