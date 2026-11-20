import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Mono } from '@/components/signals/Mono'
import { PriorityCount } from '@/components/signals/PriorityCount'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { formatCount, formatDate } from '@/lib/format'
import { cn } from '@/lib/utils'
import { rootRoute } from './root'

const MATCHES_SHOWN = 4

function Matches({ e }: { e: S<'Exception'> }) {
  const all = [...e.advisories, ...e.packages, ...e.imageRepositories, ...e.owners]
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {all.slice(0, MATCHES_SHOWN).map((m) => (
        <Badge key={m} variant="outline" className="font-normal">
          <Mono>{m}</Mono>
        </Badge>
      ))}
      {all.length > MATCHES_SHOWN ? <span className="text-muted-foreground">+{formatCount(all.length - MATCHES_SHOWN)}</span> : null}
    </span>
  )
}

function ExceptionsPage() {
  const q = useQuery(apiQuery('/exceptions', {}))
  const c = copy.exceptions.cols
  const heads = [
    { label: c.exception },
    { label: c.reason },
    { label: c.expires },
    { label: c.matches },
    { label: c.vex },
    { label: c.matched, right: true },
    { label: c.urgentNotExcepted, right: true },
  ]
  let body
  if (q.data) {
    body =
      q.data.exceptions.length === 0 ? (
        <EmptyState message={copy.exceptions.none} />
      ) : (
        <Table className="text-[12px]">
          <TableHeader>
            <TableRow className="h-[30px] hover:bg-transparent">
              {heads.map((h) => (
                <TableHead key={h.label} className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground', h.right && 'text-right')}>
                  {h.label}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {q.data.exceptions.map((e) => (
              <TableRow key={e.id} className="h-[30px]">
                <TableCell className="py-0">
                  <Mono>{`${e.namespace}/${e.name}`}</Mono>
                </TableCell>
                <TableCell className="max-w-[18rem] truncate py-0" title={e.reason}>
                  {e.reason}
                </TableCell>
                <TableCell className="py-0">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="tabular-nums">{formatDate(e.expires)}</span>
                    {e.expired ? (
                      <Badge variant="outline" className="text-muted-foreground">
                        {copy.exceptions.expired}
                      </Badge>
                    ) : null}
                  </span>
                </TableCell>
                <TableCell className="py-0">
                  <Matches e={e} />
                </TableCell>
                <TableCell className="py-0 text-muted-foreground">{[e.vexStatus, e.justification].filter(Boolean).join(' · ')}</TableCell>
                <TableCell className="py-0 text-right tabular-nums">{formatCount(e.matchedFindings)}</TableCell>
                <TableCell className="py-0 text-right">
                  <PriorityCount priority="urgent" n={e.urgentNotExcepted} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )
  } else if (q.error) body = <ProblemNotice error={q.error} />
  else body = <Skeleton className="h-24" />
  return (
    <div>
      <PageHeader title={copy.page.exceptions} />
      {body}
    </div>
  )
}

export const exceptionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/exceptions',
  component: ExceptionsPage,
})
