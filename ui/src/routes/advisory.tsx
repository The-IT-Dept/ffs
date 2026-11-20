import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { Fragment, type ReactNode } from 'react'
import { apiQuery } from '@/api/client'
import { FixGroupList } from '@/components/fix/FixGroupList'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { PriorityCountsText } from '@/components/signals/PriorityCountsText'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy, countsLine } from '@/lib/copy'
import { formatCount, formatDate } from '@/lib/format'
import { rootRoute } from './root'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-5">
      <h2 className="mb-1.5 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{title}</h2>
      {children}
    </section>
  )
}

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

function AdvisoryPage() {
  const { id } = advisoryRoute.useParams()
  const q = useQuery(apiQuery('/advisories/{id}', { path: { id } }))
  const a = q.data
  const c = copy.advisory.cols
  const t = copy.advisory.timeline

  return (
    <div>
      <PageHeader
        kind={copy.page.advisory}
        // The heading names the advisory the server answered for (aliases resolve to it).
        title={a ? <Mono className="text-[17px]">{a.id}</Mono> : <Skeleton className="inline-block h-4 w-40 align-middle" />}
        sub={
          a ? (
            <span className="inline-flex flex-wrap items-center gap-x-2">
              <span>{a.title}</span>
              {a.aliases.map((al) => (
                <Mono key={al}>{al}</Mono>
              ))}
            </span>
          ) : undefined
        }
      />
      {a ? (
        <>
          <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
            {a.kev ? (
              <Badge variant="outline" className="text-(--urgent)">
                {copy.advisory.kev(a.kev.added)}
              </Badge>
            ) : null}
            {a.epss ? <Badge variant="outline">{copy.advisory.epss(a.epss.score, a.epss.percentile)}</Badge> : null}
            {a.malicious ? <Badge variant="outline">{copy.advisory.malicious}</Badge> : null}
            {a.withdrawn ? <Badge variant="outline">{copy.advisory.withdrawn}</Badge> : null}
            <span className="ml-1">
              <PriorityCountsText counts={a.counts} />
            </span>
            <span className="text-muted-foreground">· {countsLine(a.findings, a.workloads, 'workloads')}</span>
          </div>

          <Section title={copy.advisory.severity}>
            <Table className="max-w-md text-[12px]">
              <Heads labels={[c.source, c.severity]} />
              <TableBody>
                {a.severities.map((s) => (
                  <TableRow key={s.source} className="h-[30px]">
                    <TableCell className="py-0">{s.source}</TableCell>
                    <TableCell className="py-0">
                      <span className="inline-flex items-center gap-2">
                        {s.severity}
                        {s.used ? (
                          <Badge variant="outline" className="text-muted-foreground">
                            {copy.advisory.used}
                          </Badge>
                        ) : null}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Section>

          <ol className="mt-4 flex flex-wrap items-center gap-2 text-[12px]">
            {[
              { label: t.published, at: a.timeline.published },
              { label: t.observed, at: a.timeline.observed },
              { label: t.firstMatched, at: a.timeline.firstMatched },
            ].map((step, i) => (
              <Fragment key={step.label}>
                {i > 0 ? (
                  <span aria-hidden="true" className="text-muted-foreground">
                    →
                  </span>
                ) : null}
                <li className="inline-flex items-baseline gap-1.5">
                  <span className="text-muted-foreground">{step.label}</span>
                  <span className="tabular-nums">{step.at ? formatDate(step.at) : copy.noValue}</span>
                </li>
              </Fragment>
            ))}
          </ol>

          <Section title={copy.advisory.affected}>
            {a.byFix.length > 0 ? <FixGroupList rows={a.byFix} group="fix" base={{ advisory: a.id }} /> : <EmptyState />}
          </Section>

          {a.packages.length > 0 ? (
            <Section title={copy.advisory.packages}>
              <Table className="text-[12px]">
                <Heads labels={[c.package, c.ecosystem, c.installed, c.fixed, c.findings]} />
                <TableBody>
                  {a.packages.map((p) => (
                    <TableRow key={`${p.ecosystem}/${p.name}@${p.installed}`} className="h-[30px]">
                      <TableCell className="py-0">{p.name}</TableCell>
                      <TableCell className="py-0">{p.ecosystem}</TableCell>
                      <TableCell className="py-0">
                        <Mono>{p.installed}</Mono>
                      </TableCell>
                      <TableCell className="py-0">{p.fixed.length ? <Mono>{p.fixed.join(', ')}</Mono> : <span className="text-muted-foreground">{copy.noValue}</span>}</TableCell>
                      <TableCell className="py-0 tabular-nums">{formatCount(p.findings)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Section>
          ) : null}

          {a.uncatalogued > 0 ? (
            <p className="mt-3 text-[12px]">
              <CoverageMark>{copy.advisory.uncatalogued(a.uncatalogued)}</CoverageMark>{' '}
              <AppLink href="/coverage" className="text-muted-foreground underline underline-offset-2 hover:text-foreground">
                {copy.coverageLink}
              </AppLink>
            </p>
          ) : null}

          {a.links.length > 0 ? (
            <Section title={copy.advisory.links}>
              <ul className="flex flex-col gap-0.5 text-[12px]">
                {a.links.map((l) => (
                  <li key={l}>
                    <a href={l} target="_blank" rel="noreferrer noopener" className="break-all underline underline-offset-2 hover:text-foreground">
                      {l}
                    </a>
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}
        </>
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

export const advisoryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/vulnerabilities/$id',
  component: AdvisoryPage,
})
