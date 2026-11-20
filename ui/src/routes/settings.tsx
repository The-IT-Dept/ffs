import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Mono } from '@/components/signals/Mono'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { rootRoute } from './root'

type Value = string | number | boolean | readonly string[]

function show(v: Value): string {
  if (Array.isArray(v)) return v.length ? v.join(', ') : copy.noValue
  return String(v)
}

// rowsOf flattens the settings into configuration key paths, in the order the docs list them.
function rowsOf(s: S<'Settings'>): [string, Value][] {
  const rows: [string, Value][] = [
    ['version', s.version],
    ['clusterName', s.clusterName],
  ]
  for (const f of s.feeds) {
    rows.push([`feeds.${f.name}.enabled`, f.enabled], [`feeds.${f.name}.interval`, f.interval], [`feeds.${f.name}.staleAfter`, f.staleAfter])
  }
  rows.push(
    ['priority.epssHigh', s.priority.epssHigh],
    ['priority.epssBump', s.priority.epssBump],
    ['exposure.internalIngressClasses', s.exposure.internalIngressClasses],
    ['exposure.internalGatewayClasses', s.exposure.internalGatewayClasses],
    ['exposure.internalGateways', s.exposure.internalGateways],
  )
  for (const [k, v] of Object.entries(s.exposure.internalLBAnnotations)) rows.push([`exposure.internalLBAnnotations.${k}`, v])
  rows.push(
    ['crd.minPriority', s.crd.minPriority],
    ['crd.maxFindings', s.crd.maxFindings],
    ['events.minPriority', s.events.minPriority],
    ['openReports.mode', s.openReports.mode],
    ['exceptions.maxDuration', s.exceptions.maxDuration],
    ['retention.resolved', s.retention.resolved],
    ['upgrades.enabled', s.upgrades.enabled],
    ['upgrades.dailyAt', s.upgrades.dailyAt],
  )
  if (s.nodeAgent) rows.push(['nodeAgent.enabled', s.nodeAgent.enabled], ['nodeAgent.staleAfter', s.nodeAgent.staleAfter])
  return rows
}

// SettingsPage shows the running configuration, read-only; it is changed in the chart values.
function SettingsPage() {
  const q = useQuery(apiQuery('/settings', {}))
  return (
    <div>
      <PageHeader title={copy.page.settings} />
      {q.data ? (
        <Table className="max-w-3xl text-[12px]">
          <TableHeader>
            <TableRow className="h-[30px] hover:bg-transparent">
              <TableHead className="h-[30px] py-0 text-[11px] font-medium text-muted-foreground">{copy.settings.key}</TableHead>
              <TableHead className="h-[30px] py-0 text-[11px] font-medium text-muted-foreground">{copy.settings.value}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rowsOf(q.data).map(([k, v]) => (
              <TableRow key={k} className="h-[30px]">
                <TableCell className="py-0">
                  <Mono>{k}</Mono>
                </TableCell>
                <TableCell className="py-0">
                  <Mono>{show(v)}</Mono>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

export const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/settings',
  component: SettingsPage,
})
